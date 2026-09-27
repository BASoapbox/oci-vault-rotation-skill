#!/usr/bin/env python3
"""Verification and recovery discovery. Never alters Vault or the database.

  vault-state    metadata for one secret: state, versions, pending, class
  recovery-scan  every secret in an environment with a PENDING version
                 (the signature of a rotation that stopped mid-transaction)
  adb-login      proves Vault CURRENT authenticates to the database; reads the
                 value into memory only after --authorize-credential-read and
                 the version-bound --confirm phrase
"""

from __future__ import annotations

import argparse
import sys

import vaultlib as v


def vault_state(cfg, args) -> int:
    client, detail = v.find_secret(cfg, args.env, args.secret, require_active=False)
    try:
        mapped = v.resolve_target(cfg, args.env, args.secret)[2]
    except v.OpsError:
        mapped = None
    v.event("vault_state", environment=args.env, secret=args.secret, state=detail.lifecycle_state,
            current_version=int(detail.current_version_number),
            pending_versions=v.pending_versions(client, detail.id),
            rotation_tag=v.tag_of(detail, cfg), mapped_database_user=mapped,
            vault_only_listed=args.secret in v.vault_only_secrets(cfg, args.env),
            auto_generation=bool(detail.is_auto_generation_enabled), mutation="NONE")
    return 0


def recovery_scan(cfg, args) -> int:
    client = v.vault_client(cfg, args.env)
    candidates = {}
    for summary in v.list_env_secrets(cfg, args.env, client):
        if summary.lifecycle_state != "ACTIVE":
            continue
        pending = v.pending_versions(client, summary.id)
        if pending:
            candidates[summary.secret_name] = pending
    v.event("recovery_scan", environment=args.env, count=len(candidates), candidates=candidates,
            next_step="Dry-run the same runner that staged it: --resume-pending for rotate_vault_only.py (P1), "
                      "--recover-pending for rotate_adb_user.py / rotate_adb_admin.py (P2:ADB); "
                      "see references/rotation-lifecycle.md" if candidates else None,
            mutation="NONE")
    return 0


def adb_login(cfg, args) -> int:
    db_key, db, username = v.resolve_target(cfg, args.env, args.secret)
    _, detail = v.find_secret(cfg, args.env, args.secret)
    checks, details = v.connectivity(cfg, args.env, db_key)
    failed = [c.name for c in checks if c.status == "FAIL"]
    phrase = f"verify-login:{args.env}:{args.secret}:v{int(detail.current_version_number)}"
    v.event("adb_login_verification_plan", environment=args.env, secret=args.secret, database_user=username,
            database_service=details["service_alias"], prerequisites="READY" if not failed else "BLOCKED",
            failed_checks=failed, confirmation=phrase, mutation="NONE")
    if not args.authorize_credential_read:
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Credential-read confirmation does not match the current secret version")
    if failed:
        v.event("adb_login_verification_result", result="INDETERMINATE", reason="prerequisite_failed", mutation="NONE")
        return 2
    current = wallet_pw = None
    try:
        current = v.read_secret_value(cfg, args.env, detail.id)
        wallet_pw = v.wallet_password(cfg, args.env, db)
        ok = v.can_login(db, details["wallet_dir"], username, current, wallet_pw)
        v.event("adb_login_verification_result", environment=args.env, secret=args.secret, database_user=username,
                result="PASS" if ok else "FAIL", mutation="NONE")
        return 0 if ok else 2
    finally:
        current = wallet_pw = None


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Vault and database verification")
    parser.add_argument("--config")
    parser.add_argument("--env", required=True)
    parser.add_argument("--check", required=True, choices=("vault-state", "recovery-scan", "adb-login"))
    parser.add_argument("--secret")
    parser.add_argument("--authorize-credential-read", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    if args.check != "recovery-scan" and not args.secret:
        parser.error("--secret is required for this check")
    cfg = v.load_config(args.config)
    return {"vault-state": vault_state, "recovery-scan": recovery_scan, "adb-login": adb_login}[args.check](cfg, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except v.OpsError as exc:
        v.event("verification_blocked", result="NO_MUTATION", reason=str(exc))
        sys.exit(2)
    except Exception as exc:
        v.event("verification_failed", result="NO_MUTATION", **v.safe_error_fields(exc))
        sys.exit(2)
