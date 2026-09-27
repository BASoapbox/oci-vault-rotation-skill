#!/usr/bin/env python3
"""Confirmation-gated P1 (Vault-only) rotation.

For secrets with nothing downstream: the new value only has to exist in Vault.
Two gates, as for every rotation: the secret is tagged P1 in Vault *and* listed
under environments.<env>.vault_only_secrets in the reviewed config.

Transaction:
  1. disable Vault auto-generation, if enabled
  2. stage a generated value as the sole PENDING version   (CURRENT unchanged)
  3. read the PENDING version back and compare it, in memory, to what was generated
  4. promote PENDING to CURRENT
  5. restore auto-generation

Fits values you generate yourself (shared random tokens, internal passwords).
A key issued by a provider cannot be generated locally: tag it MANUAL.

  (default)          rotate-p1:<env>:<secret>:v<current>
  --resume-pending   resume-p1:<env>:<secret>:current-v<c>:pending-v<p>
                     promotes a PENDING version left by a stopped run; with nothing
                     downstream there is no target to test first
"""

from __future__ import annotations

import argparse
import hmac
import sys
from typing import Any

import vaultlib as v


def confirmation(env: str, secret: str, version: int) -> str:
    return f"rotate-p1:{env}:{secret}:v{version}"


def resume_confirmation(env: str, secret: str, current: int, pending: int) -> str:
    return f"resume-p1:{env}:{secret}:current-v{current}:pending-v{pending}"


def preflight(cfg: dict[str, Any], env: str, secret: str, *, allow_pending: bool = False):
    client, detail = v.find_secret(cfg, env, secret)
    checks = [v.route_check(v.tag_of(detail, cfg), [])]
    listed = secret in v.vault_only_secrets(cfg, env)
    checks.append(v.Check("config_vault_only", "PASS" if listed else "FAIL",
                          "listed in vault_only_secrets" if listed else "not in environments.<env>.vault_only_secrets"))
    try:
        mapped = v.resolve_target(cfg, env, secret)[2]
    except v.OpsError:
        mapped = None
    checks.append(v.Check("no_database_mapping", "PASS" if not mapped else "FAIL",
                          "none" if not mapped else f"mapped to {mapped}; a database secret is P2:ADB, not P1"))
    pending = v.pending_versions(client, detail.id)
    if not allow_pending:
        checks.append(v.Check("no_pending_version", "PASS" if not pending else "FAIL",
                              "none" if not pending else f"pending v{pending}; use --resume-pending"))
    if not v.all_pass(checks):
        for check in checks:
            v.event("preflight_check", name=check.name, status=check.status, detail=check.detail)
        raise v.OpsError("Preflight is blocked; no mutation was made")
    return client, detail, pending


def run_rotation(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, target, _ = preflight(cfg, args.env, args.secret)
    current_version = int(target.current_version_number)
    phrase = confirmation(args.env, args.secret, current_version)
    v.event("p1_rotation_plan_ready", environment=args.env, secret=args.secret, current_version=current_version,
            downstream="NONE", auto_generation_enabled=bool(target.is_auto_generation_enabled), confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current secret version; no mutation was made")

    new_value = staged_value = None
    stage_attempted = auto_generation_disabled = False
    promoted: int | None = None
    original_auto_generation = bool(target.is_auto_generation_enabled)
    original_context = target.secret_generation_context
    try:
        new_value = v.password_from_policy(cfg, "")
        if original_auto_generation:
            v.set_auto_generation(client, target.id, False)
            auto_generation_disabled = True
            v.event("vault_auto_generation_temporarily_disabled", secret=args.secret)

        fresh = v.wait_for_active(client, target.id)
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, target.id):
            raise v.OpsError("Secret state changed before staging; nothing was staged")

        stage_attempted = True
        pending_version = v.stage_pending(client, target.id, new_value)
        v.event("vault_version_staged", secret=args.secret, pending_version=pending_version)

        staged_value = v.read_secret_value(cfg, args.env, target.id, pending_version)
        if not hmac.compare_digest(staged_value, new_value):
            raise v.OpsError("Staged version does not match the generated value; not promoting")
        v.event("vault_pending_verified", secret=args.secret, pending_version=pending_version)

        promoted = v.promote_pending_version(client, target.id, pending_version)
        v.event("vault_version_promoted", secret=args.secret, previous_version=current_version, current_version=promoted)
        if auto_generation_disabled:
            v.set_auto_generation(client, target.id, True, original_context)
            auto_generation_disabled = False
            v.event("vault_auto_generation_restored", secret=args.secret)
        v.event("p1_rotation_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                current_version=promoted)
        return 0
    except Exception as exc:
        if promoted is not None:
            result, state = "POLICY_RESTORE_REQUIRED", "VAULT_ROTATED"
        elif stage_attempted:
            result, state = "RESUME_AVAILABLE", "PENDING_VERSION_MAY_EXIST"
        else:
            result, state = "NO_MUTATION", "VAULT_UNCHANGED"
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("p1_rotation_stopped", result=result, state=state, secret=args.secret, **fields)
        return 2
    finally:
        if auto_generation_disabled:
            try:
                v.set_auto_generation(client, target.id, True, original_context)
                v.event("vault_auto_generation_restored_after_stop", secret=args.secret)
            except Exception as restore_exc:
                v.event("vault_auto_generation_restore_failed", secret=args.secret, **v.safe_error_fields(restore_exc))
        new_value = staged_value = None


def run_resume(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, detail, pending = preflight(cfg, args.env, args.secret, allow_pending=True)
    if len(pending) != 1:
        raise v.OpsError(f"Resume requires exactly one pending version; found {len(pending)}")
    current_version, pending_version = int(detail.current_version_number), pending[0]
    phrase = resume_confirmation(args.env, args.secret, current_version, pending_version)
    v.event("p1_resume_plan_ready", environment=args.env, secret=args.secret, current_version=current_version,
            pending_version=pending_version, confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending versions")
    fresh = v.wait_for_active(client, detail.id)
    if int(fresh.current_version_number) != current_version or v.pending_versions(client, detail.id) != [pending_version]:
        raise v.OpsError("Vault state changed before resume; nothing was promoted")
    promoted = v.promote_pending_version(client, detail.id, pending_version)
    if not bool(fresh.is_auto_generation_enabled) and fresh.secret_generation_context is not None:
        v.set_auto_generation(client, detail.id, True, fresh.secret_generation_context)
        v.event("vault_auto_generation_restored", secret=args.secret)
    v.event("p1_resume_complete", result="SUCCESS", environment=args.env, secret=args.secret, current_version=promoted)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Confirmation-gated P1 (Vault-only) rotation")
    parser.add_argument("--config", help=f"default: $OCI_VAULT_OPS_CONFIG or {v.DEFAULT_CONFIG}")
    parser.add_argument("--env", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--resume-pending", action="store_true", help="promote a PENDING version left by a stopped run")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        cfg = v.load_config(args.config)
        return run_resume(cfg, args) if args.resume_pending else run_rotation(cfg, args)
    except v.OpsError as exc:
        v.event("p1_rotation_blocked", result="NO_MUTATION", reason=str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
