#!/usr/bin/env python3
"""Confirmation-gated rotation and recovery for an Autonomous Database ADMIN secret.

ADMIN is the authority credential: a mistake here can lock you out of the
database until ADMIN is reset in the OCI Console. This runner therefore has
three separately confirmed modes, each bound to exact Vault version numbers:

  (default)          rotate-admin:<env>:<secret>:v<current>
  --recover-pending  recover-admin:<env>:<secret>:current-v<c>:pending-v<p>
  --resume-pending   resume-admin:<env>:<secret>:current-v<c>:pending-v<p>

Recover is for a stop *after* ALTER USER: it tests both versions and promotes
PENDING only when PENDING authenticates and CURRENT does not. Resume is for a
stop *before* ALTER USER: it applies the already-staged PENDING value without
generating another password.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import vaultlib as v


def rotation_confirmation(env: str, secret: str, version: int) -> str:
    return f"rotate-admin:{env}:{secret}:v{version}"


def recovery_confirmation(env: str, secret: str, current: int, pending: int) -> str:
    return f"recover-admin:{env}:{secret}:current-v{current}:pending-v{pending}"


def resume_confirmation(env: str, secret: str, current: int, pending: int) -> str:
    return f"resume-admin:{env}:{secret}:current-v{current}:pending-v{pending}"


def admin_preflight(cfg: dict[str, Any], env: str, secret: str, *, allow_pending: bool):
    db_key, db, username = v.resolve_target(cfg, env, secret)
    if username != "ADMIN" or db.get("admin_secret") != secret:
        raise v.OpsError("This runner accepts only a database's configured admin_secret")
    client, detail = v.find_secret(cfg, env, secret)
    tag = v.tag_of(detail, cfg)
    checks, details = v.connectivity(cfg, env, db_key)
    checks.append(v.route_check(tag, ["ADB"]))
    checks.append(v.Check("admin_authority_secret", "PASS", secret))
    pending = v.pending_versions(client, detail.id)
    if not allow_pending:
        checks.append(v.Check("no_pending_version", "PASS" if not pending else "FAIL",
                              "none" if not pending else f"pending v{pending}; use --recover-pending or --resume-pending"))
    if not v.all_pass(checks):
        for check in checks:
            v.event("preflight_check", name=check.name, status=check.status, detail=check.detail)
        raise v.OpsError("ADMIN preflight is blocked; no credential mutation was made")
    return client, detail, db, details, int(detail.current_version_number), pending


def _read_both(cfg, env, detail, db, current_version, pending_version):
    current = v.read_secret_value(cfg, env, detail.id, current_version)
    pending = v.read_secret_value(cfg, env, detail.id, pending_version)
    wallet_pw = v.wallet_password(cfg, env, db)
    return current, pending, wallet_pw


def run_recovery(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, detail, db, details, current_version, pending = admin_preflight(cfg, args.env, args.secret, allow_pending=True)
    if len(pending) != 1:
        raise v.OpsError("ADMIN recovery requires exactly one pending Vault version")
    pending_version = pending[0]
    restore_policy = not bool(detail.is_auto_generation_enabled) and detail.secret_generation_context is not None
    phrase = recovery_confirmation(args.env, args.secret, current_version, pending_version)
    v.event("admin_recovery_plan_ready", environment=args.env, secret=args.secret, current_version=current_version,
            pending_version=pending_version, auto_generation_restore_planned=restore_policy, confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending ADMIN versions")

    current_pw = pending_pw = wallet_pw = None
    try:
        current_pw, pending_pw, wallet_pw = _read_both(cfg, args.env, detail, db, current_version, pending_version)
        current_works = v.can_login(db, details["wallet_dir"], "ADMIN", current_pw, wallet_pw)
        pending_works = v.can_login(db, details["wallet_dir"], "ADMIN", pending_pw, wallet_pw)
        v.event("admin_recovery_login_state", current_version_authenticates=current_works,
                pending_version_authenticates=pending_works)
        if pending_works and not current_works:
            promoted = v.promote_pending_version(client, detail.id, pending_version)
            if restore_policy:
                try:
                    v.set_auto_generation(client, detail.id, True, detail.secret_generation_context)
                    v.event("vault_auto_generation_restored", secret=args.secret)
                except Exception as exc:
                    v.event("admin_recovery_stopped", result="POLICY_RESTORE_REQUIRED",
                            state="DATABASE_AND_VAULT_CURRENT_MATCH", **v.safe_error_fields(exc))
                    return 2
            v.event("admin_recovery_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                    current_version=promoted)
            return 0
        if current_works and not pending_works:
            v.event("admin_recovery_stopped", result="NO_MUTATION",
                    state="DATABASE_MATCHES_CURRENT_PENDING_REMAINS",
                    next_step="Use --resume-pending to apply the staged value, or cancel the pending version")
            return 2
        v.event("admin_recovery_stopped", result="MANUAL_RECOVERY_REQUIRED", state="AMBIGUOUS_LOGIN_STATE",
                next_step="Reset ADMIN in the OCI Console, then reconcile Vault")
        return 2
    finally:
        current_pw = pending_pw = wallet_pw = None


def run_resume(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, detail, db, details, current_version, pending = admin_preflight(cfg, args.env, args.secret, allow_pending=True)
    if len(pending) != 1:
        raise v.OpsError("ADMIN resume requires exactly one pending Vault version")
    pending_version = pending[0]
    phrase = resume_confirmation(args.env, args.secret, current_version, pending_version)
    v.event("admin_resume_plan_ready", environment=args.env, secret=args.secret, current_version=current_version,
            pending_version=pending_version, confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending ADMIN versions")

    current_pw = pending_pw = wallet_pw = None
    database_changed = False
    try:
        current_pw, pending_pw, wallet_pw = _read_both(cfg, args.env, detail, db, current_version, pending_version)
        current_works = v.can_login(db, details["wallet_dir"], "ADMIN", current_pw, wallet_pw)
        pending_works = v.can_login(db, details["wallet_dir"], "ADMIN", pending_pw, wallet_pw)
        v.event("admin_resume_login_state", current_version_authenticates=current_works,
                pending_version_authenticates=pending_works)
        if not current_works or pending_works:
            v.event("admin_resume_stopped", result="NO_MUTATION", state="RESUME_PRECONDITION_NOT_MET",
                    next_step="Resume requires CURRENT to authenticate and PENDING not to; try --recover-pending")
            return 2
        fresh = client.get_secret(detail.id).data
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, detail.id) != [pending_version]:
            raise v.OpsError("ADMIN Vault state changed before resume; no database change was made")

        connection = v.connect(db, details["wallet_dir"], "ADMIN", current_pw, wallet_pw)
        try:
            with connection.cursor() as cursor:
                cursor.execute(f'ALTER USER ADMIN IDENTIFIED BY "{pending_pw}"')
            connection.commit()
        finally:
            connection.close()
        database_changed = True
        v.event("database_password_changed", database_user="ADMIN", database_service=details["service_alias"])
        v.verify_login(db, details["wallet_dir"], "ADMIN", pending_pw, wallet_pw)
        v.event("database_login_verified", database_user="ADMIN")
        promoted = v.promote_pending_version(client, detail.id, pending_version)
        v.event("vault_version_promoted", secret=args.secret, previous_version=current_version, current_version=promoted)
        v.event("admin_resume_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                current_version=promoted)
        return 0
    except Exception as exc:
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("admin_resume_stopped",
                result="MANUAL_RECOVERY_REQUIRED" if database_changed else "NO_CREDENTIAL_MUTATION",
                state="DATABASE_EXPECTED_TO_MATCH_PENDING_VERSION" if database_changed
                else "DATABASE_EXPECTED_TO_MATCH_CURRENT_VERSION", **fields)
        return 2
    finally:
        current_pw = pending_pw = wallet_pw = None


def run_rotation(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, target, db, details, current_version, _ = admin_preflight(cfg, args.env, args.secret, allow_pending=False)
    phrase = rotation_confirmation(args.env, args.secret, current_version)
    v.event("admin_rotation_plan_ready", environment=args.env, secret=args.secret, current_version=current_version,
            database_user="ADMIN", database_service=details["service_alias"],
            auto_generation_enabled=bool(target.is_auto_generation_enabled), confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current ADMIN secret version")

    current_pw = new_pw = wallet_pw = None
    stage_attempted = database_changed = auto_generation_disabled = False
    promoted: int | None = None
    original_auto_generation = bool(target.is_auto_generation_enabled)
    original_context = target.secret_generation_context
    try:
        current_pw = v.read_secret_value(cfg, args.env, target.id, current_version)
        wallet_pw = v.wallet_password(cfg, args.env, db)
        v.verify_login(db, details["wallet_dir"], "ADMIN", current_pw, wallet_pw)
        v.event("admin_current_login_verified", database_service=details["service_alias"])

        new_pw = v.password_from_policy(cfg, "ADMIN")
        if original_auto_generation:
            v.set_auto_generation(client, target.id, False)
            auto_generation_disabled = True
            v.event("vault_auto_generation_temporarily_disabled", secret=args.secret)

        fresh = client.get_secret(target.id).data
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, target.id):
            raise v.OpsError("ADMIN Vault state changed before staging; no database change was made")

        stage_attempted = True
        pending_version = v.stage_pending(client, target.id, new_pw)
        v.event("vault_version_staged", secret=args.secret, pending_version=pending_version)

        connection = v.connect(db, details["wallet_dir"], "ADMIN", current_pw, wallet_pw)
        try:
            with connection.cursor() as cursor:
                cursor.execute(f'ALTER USER ADMIN IDENTIFIED BY "{new_pw}"')
            connection.commit()
        finally:
            connection.close()
        database_changed = True
        v.event("database_password_changed", database_user="ADMIN", database_service=details["service_alias"])

        v.verify_login(db, details["wallet_dir"], "ADMIN", new_pw, wallet_pw)
        v.event("database_login_verified", database_user="ADMIN")

        promoted = v.promote_pending_version(client, target.id, pending_version)
        v.event("vault_version_promoted", secret=args.secret, previous_version=current_version, current_version=promoted)
        if auto_generation_disabled:
            v.set_auto_generation(client, target.id, True, original_context)
            auto_generation_disabled = False
            v.event("vault_auto_generation_restored", secret=args.secret)
        v.event("admin_rotation_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                current_version=promoted)
        return 0
    except Exception as exc:
        if promoted is not None:
            result, state = "POLICY_RESTORE_REQUIRED", "DATABASE_AND_VAULT_CURRENT_MATCH"
        elif database_changed:
            result, state = "MANUAL_RECOVERY_REQUIRED", "DATABASE_EXPECTED_TO_MATCH_PENDING_VERSION"
        elif stage_attempted:
            result, state = "MANUAL_RECOVERY_REQUIRED", "DATABASE_EXPECTED_TO_MATCH_CURRENT_VERSION"
        else:
            result, state = "NO_CREDENTIAL_MUTATION", "DATABASE_AND_VAULT_UNCHANGED"
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("admin_rotation_stopped", result=result, state=state, secret=args.secret, **fields)
        return 2
    finally:
        if auto_generation_disabled:
            try:
                v.set_auto_generation(client, target.id, True, original_context)
                v.event("vault_auto_generation_restored_after_stop", secret=args.secret)
            except Exception as restore_exc:
                v.event("vault_auto_generation_restore_failed", secret=args.secret, **v.safe_error_fields(restore_exc))
        current_pw = new_pw = wallet_pw = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Confirmation-gated Autonomous Database ADMIN rotation and recovery")
    parser.add_argument("--config", help=f"default: $OCI_VAULT_OPS_CONFIG or {v.DEFAULT_CONFIG}")
    parser.add_argument("--env", required=True)
    parser.add_argument("--secret", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--recover-pending", action="store_true", help="resolve a stop that happened after ALTER USER")
    mode.add_argument("--resume-pending", action="store_true", help="continue a stop that happened before ALTER USER")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        cfg = v.load_config(args.config)
        if args.recover_pending:
            return run_recovery(cfg, args)
        if args.resume_pending:
            return run_resume(cfg, args)
        return run_rotation(cfg, args)
    except v.OpsError as exc:
        v.event("admin_rotation_blocked", result="NO_MUTATION", reason=str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
