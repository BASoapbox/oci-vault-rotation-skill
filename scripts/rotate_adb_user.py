#!/usr/bin/env python3
"""Confirmation-gated password rotation for one Autonomous Database user.

Transaction order, which keeps Vault CURRENT authoritative until the database
has accepted and verified the new value:

  1. verify the ADMIN credential authenticates
  2. stage the generated value as Vault PENDING   (CURRENT unchanged)
  3. ALTER USER to the staged value
  4. verify a fresh login as the user
  5. promote PENDING to CURRENT

The default is a dry run. ``--execute`` also requires the version-bound
``--confirm`` phrase the dry run prints. ADMIN is rejected here; use
rotate_adb_admin.py.

If a rotation stopped and left a PENDING version (OCI will not delete a PENDING
version, so it cannot simply be discarded), resolve it with one of:

  --recover-pending  recover:<env>:<secret>:current-v<c>:pending-v<p>
                     tests both versions as the user; promotes PENDING only when
                     PENDING authenticates and CURRENT does not
  --resume-pending   resume:<env>:<secret>:current-v<c>:pending-v<p>
                     when CURRENT still authenticates, applies the already-staged
                     PENDING value as ADMIN, verifies it, and promotes it
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

import vaultlib as v


def confirmation(env: str, secret: str, version: int) -> str:
    return f"rotate:{env}:{secret}:v{version}"


def recovery_confirmation(env: str, secret: str, current: int, pending: int) -> str:
    return f"recover:{env}:{secret}:current-v{current}:pending-v{pending}"


def resume_confirmation(env: str, secret: str, current: int, pending: int) -> str:
    return f"resume:{env}:{secret}:current-v{current}:pending-v{pending}"


def preflight(cfg: dict[str, Any], env: str, secret: str, *, allow_pending: bool = False):
    db_key, db, username = v.resolve_target(cfg, env, secret)
    if username == "ADMIN":
        raise v.OpsError("ADMIN rotation is not handled by this runner; use rotate_adb_admin.py")
    client, detail = v.find_secret(cfg, env, secret)
    tag = v.tag_of(detail, cfg)
    checks, details = v.connectivity(cfg, env, db_key)
    checks.append(v.route_check(tag, ["ADB"]))
    checks.append(v.Check("target_user", "PASS", username))
    pending = v.pending_versions(client, detail.id)
    if not allow_pending:
        checks.append(v.Check("no_pending_version", "PASS" if not pending else "FAIL",
                              "none" if not pending else f"pending v{pending}; use --recover-pending or --resume-pending"))
    if not v.all_pass(checks):
        for check in checks:
            v.event("preflight_check", name=check.name, status=check.status, detail=check.detail)
        raise v.OpsError("Preflight is blocked; no mutation was made")
    return client, detail, db, details, username, pending


def execute(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, target, db, details, username, _ = preflight(cfg, args.env, args.secret)
    current_version = int(target.current_version_number)
    phrase = confirmation(args.env, args.secret, current_version)
    v.event("rotation_plan_ready", environment=args.env, secret=args.secret, current_version=current_version,
            database_user=username, database_service=details["service_alias"],
            auto_generation_enabled=bool(target.is_auto_generation_enabled), confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current secret version; no mutation was made")

    wallet_dir = details["wallet_dir"]
    admin_password = wallet_pw = new_password = None
    stage_attempted = database_changed = auto_generation_disabled = False
    promoted: int | None = None
    original_auto_generation = bool(target.is_auto_generation_enabled)
    original_context = target.secret_generation_context
    try:
        _, admin_detail = v.find_secret(cfg, args.env, db["admin_secret"])
        admin_password = v.read_secret_value(cfg, args.env, admin_detail.id)
        wallet_pw = v.wallet_password(cfg, args.env, db)
        v.verify_login(db, wallet_dir, "ADMIN", admin_password, wallet_pw)
        v.event("admin_login_verified", database_service=details["service_alias"])

        new_password = v.password_from_policy(cfg, username)
        if original_auto_generation:
            v.set_auto_generation(client, target.id, False)
            auto_generation_disabled = True
            v.event("vault_auto_generation_temporarily_disabled", secret=args.secret)

        fresh = client.get_secret(target.id).data
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, target.id):
            raise v.OpsError("Secret state changed before staging; no database change was made")

        stage_attempted = True
        pending_version = v.stage_pending(client, target.id, new_password)
        v.event("vault_version_staged", secret=args.secret, pending_version=pending_version)

        connection = v.connect(db, wallet_dir, "ADMIN", admin_password, wallet_pw)
        try:
            with connection.cursor() as cursor:
                # username matches SAFE_DB_USER; the generated value cannot contain a double quote.
                cursor.execute(f'ALTER USER {username} IDENTIFIED BY "{new_password}"')
            connection.commit()
        finally:
            connection.close()
        database_changed = True
        v.event("database_password_changed", database_user=username, database_service=details["service_alias"])

        v.verify_login(db, wallet_dir, username, new_password, wallet_pw)
        v.event("database_login_verified", database_user=username)

        promoted = v.promote_pending_version(client, target.id, pending_version)
        v.event("vault_version_promoted", secret=args.secret, previous_version=current_version, current_version=promoted)
        if auto_generation_disabled:
            v.set_auto_generation(client, target.id, True, original_context)
            auto_generation_disabled = False
            v.event("vault_auto_generation_restored", secret=args.secret)
        v.event("rotation_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                database_user=username, current_version=promoted)
        return 0
    except Exception as exc:
        if promoted is not None:
            result, state = "POLICY_RESTORE_REQUIRED", "DATABASE_AND_VAULT_CURRENT_MATCH"
        elif database_changed:
            result, state = "MANUAL_RECOVERY_REQUIRED", "DATABASE_EXPECTED_TO_MATCH_PENDING_VERSION"
        elif stage_attempted:
            result, state = "MANUAL_RECOVERY_REQUIRED", "DATABASE_EXPECTED_TO_MATCH_CURRENT_VERSION"
        else:
            result, state = "NO_MUTATION", "DATABASE_AND_VAULT_UNCHANGED"
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("rotation_stopped", result=result, state=state, secret=args.secret, **fields)
        return 2
    finally:
        if auto_generation_disabled:
            try:
                v.set_auto_generation(client, target.id, True, original_context)
                v.event("vault_auto_generation_restored_after_stop", secret=args.secret)
            except Exception as restore_exc:
                v.event("vault_auto_generation_restore_failed", secret=args.secret, **v.safe_error_fields(restore_exc))
        # Best-effort reference release; Python cannot zeroize immutable strings.
        admin_password = wallet_pw = new_password = None


def _pending_plan(cfg: dict[str, Any], args: argparse.Namespace, kind: str):
    client, detail, db, details, username, pending = preflight(cfg, args.env, args.secret, allow_pending=True)
    if len(pending) != 1:
        raise v.OpsError(f"{kind.capitalize()} requires exactly one pending Vault version; found {len(pending)}")
    current_version, pending_version = int(detail.current_version_number), pending[0]
    maker = recovery_confirmation if kind == "recovery" else resume_confirmation
    phrase = maker(args.env, args.secret, current_version, pending_version)
    v.event(f"{kind}_plan_ready", environment=args.env, secret=args.secret, database_user=username,
            current_version=current_version, pending_version=pending_version, confirmation=phrase)
    return client, detail, db, details, username, current_version, pending_version, phrase


def _login_state(cfg, args, detail, db, details, username, current_version, pending_version):
    current = v.read_secret_value(cfg, args.env, detail.id, current_version)
    pending = v.read_secret_value(cfg, args.env, detail.id, pending_version)
    wallet_pw = v.wallet_password(cfg, args.env, db)
    current_works = v.can_login(db, details["wallet_dir"], username, current, wallet_pw)
    pending_works = v.can_login(db, details["wallet_dir"], username, pending, wallet_pw)
    return current, pending, wallet_pw, current_works, pending_works


def run_recovery(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, detail, db, details, username, current_version, pending_version, phrase = _pending_plan(cfg, args, "recovery")
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending versions")
    current = pending = wallet_pw = None
    try:
        current, pending, wallet_pw, current_works, pending_works = _login_state(
            cfg, args, detail, db, details, username, current_version, pending_version)
        v.event("recovery_login_state", database_user=username, current_version_authenticates=current_works,
                pending_version_authenticates=pending_works)
        if pending_works and not current_works:
            promoted = v.promote_pending_version(client, detail.id, pending_version)
            v.event("recovery_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                    database_user=username, current_version=promoted)
            return 0
        if current_works and not pending_works:
            v.event("recovery_stopped", result="NO_MUTATION", state="DATABASE_MATCHES_CURRENT_PENDING_REMAINS",
                    next_step="Use --resume-pending to apply the staged value")
            return 2
        v.event("recovery_stopped", result="MANUAL_RECOVERY_REQUIRED", state="AMBIGUOUS_LOGIN_STATE",
                next_step="Reset the user's password as ADMIN, then reconcile Vault")
        return 2
    finally:
        current = pending = wallet_pw = None


def run_resume(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, detail, db, details, username, current_version, pending_version, phrase = _pending_plan(cfg, args, "resume")
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending versions")
    current = pending = wallet_pw = admin_password = None
    database_changed = False
    try:
        current, pending, wallet_pw, current_works, pending_works = _login_state(
            cfg, args, detail, db, details, username, current_version, pending_version)
        v.event("resume_login_state", database_user=username, current_version_authenticates=current_works,
                pending_version_authenticates=pending_works)
        if not current_works or pending_works:
            v.event("resume_stopped", result="NO_MUTATION", state="RESUME_PRECONDITION_NOT_MET",
                    next_step="Resume requires CURRENT to authenticate and PENDING not to; try --recover-pending")
            return 2
        fresh = client.get_secret(detail.id).data
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, detail.id) != [pending_version]:
            raise v.OpsError("Vault state changed before resume; no database change was made")
        _, admin_detail = v.find_secret(cfg, args.env, db["admin_secret"])
        admin_password = v.read_secret_value(cfg, args.env, admin_detail.id)
        connection = v.connect(db, details["wallet_dir"], "ADMIN", admin_password, wallet_pw)
        try:
            with connection.cursor() as cursor:
                cursor.execute(f'ALTER USER {username} IDENTIFIED BY "{pending}"')
            connection.commit()
        finally:
            connection.close()
        database_changed = True
        v.event("database_password_changed", database_user=username, database_service=details["service_alias"])
        v.verify_login(db, details["wallet_dir"], username, pending, wallet_pw)
        v.event("database_login_verified", database_user=username)
        promoted = v.promote_pending_version(client, detail.id, pending_version)
        v.event("resume_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                database_user=username, current_version=promoted)
        return 0
    except Exception as exc:
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("resume_stopped", result="MANUAL_RECOVERY_REQUIRED" if database_changed else "NO_CREDENTIAL_MUTATION",
                state="DATABASE_EXPECTED_TO_MATCH_PENDING_VERSION" if database_changed
                else "DATABASE_EXPECTED_TO_MATCH_CURRENT_VERSION", **fields)
        return 2
    finally:
        current = pending = wallet_pw = admin_password = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Confirmation-gated Autonomous Database user rotation")
    parser.add_argument("--config", help=f"default: $OCI_VAULT_OPS_CONFIG or {v.DEFAULT_CONFIG}")
    parser.add_argument("--env", required=True)
    parser.add_argument("--secret", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--recover-pending", action="store_true", help="resolve a stop that happened after ALTER USER")
    mode.add_argument("--resume-pending", action="store_true", help="continue a stop that happened before ALTER USER")
    parser.add_argument("--execute", action="store_true", help="perform the approved operation")
    parser.add_argument("--confirm", help="exact phrase printed by the dry run")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        cfg = v.load_config(args.config)
        if args.recover_pending:
            return run_recovery(cfg, args)
        if args.resume_pending:
            return run_resume(cfg, args)
        return execute(cfg, args)
    except v.OpsError as exc:
        v.event("rotation_blocked", result="NO_MUTATION", reason=str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
