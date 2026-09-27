#!/usr/bin/env python3
"""Draft a config by reading tenancy metadata. Read-only against OCI.

Finds compartments, vault secrets, and Autonomous Databases, groups them into
environments by compartment name (dev/test/qa/stage/uat/prod), and guesses
which secret belongs to which database user from the naming pattern
``...<database-display-name>-<user>-pwd``.

The output is a DRAFT. Review every mapping before tagging anything P2:ADB:
a wrong mapping would point a rotation at the wrong account.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import oci

ENV_TOKENS = ("dev", "test", "qa", "stage", "uat", "prod")
SUFFIX = re.compile(r"-(?:pwd|password|pass)$", re.I)


def env_for(compartment_name: str) -> str:
    tokens = re.split(r"[-_.\s]+", compartment_name.lower())
    return next((t for t in ENV_TOKENS if t in tokens), compartment_name.lower())


def map_secret(secret_name: str, db_display: str) -> str | None:
    """Return ADMIN, a username, or None when the secret does not name this database."""
    idx = secret_name.lower().find(db_display.lower())
    if idx < 0:
        return None
    rest = SUFFIX.sub("", secret_name[idx + len(db_display):]).strip("-_")
    if not rest:
        return None
    return "ADMIN" if rest.lower() == "admin" else rest.upper().replace("-", "_")


def main() -> int:
    parser = argparse.ArgumentParser(description="Draft oci-vault-operations config from tenancy metadata")
    parser.add_argument("--profile", required=True, help="OCI config profile (never assumes DEFAULT)")
    parser.add_argument("--region")
    parser.add_argument("--wallet-root", help="directory containing Wallet_<dbname> folders")
    parser.add_argument("--output", required=True)
    parser.add_argument("--force", action="store_true", help="overwrite an existing output file")
    args = parser.parse_args()

    out = Path(args.output).expanduser()
    if out.exists() and not args.force:
        print(json.dumps({"event": "discover_blocked", "reason": f"{out} exists; pass --force to overwrite"}))
        return 2

    sdk = oci.config.from_file(profile_name=args.profile)
    if args.region:
        sdk["region"] = args.region
    identity = oci.identity.IdentityClient(sdk)
    vaults = oci.vault.VaultsClient(sdk)
    dbs = oci.database.DatabaseClient(sdk)
    compartments = [(sdk["tenancy"], "root")] + [
        (c.id, c.name) for c in oci.pagination.list_call_get_all_results(
            identity.list_compartments, sdk["tenancy"], compartment_id_in_subtree=True, lifecycle_state="ACTIVE").data
        if c.name != "ManagedCompartmentForPaaS"]

    envs: dict[str, dict] = {}
    all_secrets: dict[str, list[str]] = {}
    for cid, cname in compartments:
        env = env_for(cname)
        secrets = [s for s in oci.pagination.list_call_get_all_results(vaults.list_secrets, cid).data
                   if s.lifecycle_state == "ACTIVE"]
        adbs = [a for a in oci.pagination.list_call_get_all_results(dbs.list_autonomous_databases, cid).data
                if a.lifecycle_state not in ("TERMINATED", "TERMINATING")]
        if not secrets and not adbs:
            continue
        slot = envs.setdefault(env, {"secret_compartments": [], "vault_only_secrets": [], "databases": {},
                                     "_compartments": []})
        slot["_compartments"].append(cname)
        if secrets:
            slot["secret_compartments"].append(cid)
            all_secrets.setdefault(env, []).extend(s.secret_name for s in secrets)
        for adb in adbs:
            wallet = None
            if args.wallet_root:
                candidate = Path(args.wallet_root).expanduser() / f"Wallet_{adb.db_name}"
                wallet = str(candidate) if candidate.is_dir() else None
            slot["databases"][adb.display_name.lower()] = {
                "ocid": adb.id,
                "connection": "ssh_tunnel" if adb.private_endpoint else "public",
                "service_alias": f"{adb.db_name.lower()}_low",
                "wallet_dir": wallet or f"~/path/to/Wallet_{adb.db_name}",
                "wallet_password_secret": None,
                "admin_secret": None,
                "user_secrets": {},
                "_display_name": adb.display_name,
                "_lifecycle_state_at_discovery": adb.lifecycle_state,
            }

    # Map secrets to databases in the same environment, or in any environment
    # when the database lives in a separate db compartment of the same env token.
    for env, slot in envs.items():
        unmapped = []
        for name in all_secrets.get(env, []):
            hits = [(key, db, user) for e2 in envs.values() for key, db in e2["databases"].items()
                    if (user := map_secret(name, db["_display_name"]))]
            if len(hits) != 1:
                unmapped.append(name)
                continue
            _, db, user = hits[0]
            if user == "ADMIN":
                db["admin_secret"] = name
            else:
                db["user_secrets"][name] = user
        slot["_unmapped_secrets"] = sorted(unmapped)

    for slot in envs.values():
        for db in slot["databases"].values():
            if db["connection"] == "ssh_tunnel":
                db["ssh_host"] = "your-ssh-config-host-with-LocalForward"
    envs = {k: v for k, v in envs.items() if v["secret_compartments"] or v["databases"]}

    draft = {
        "_comment": "DRAFT from discover_config.py. Review every mapping. Keys starting with _ are informational.",
        "oci": {"profile": args.profile, "region": sdk["region"]},
        "tag_key": "rotationTag",
        "password_policy": {"length": 20, "min_upper": 2, "min_lower": 2, "min_digits": 2, "min_special": 1,
                            "special_chars": "#_-"},
        "audit_journal": "~/.config/oci-vault-ops/journal.jsonl",
        "environments": envs,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(draft, indent=2) + "\n")
    os.chmod(out, 0o600)
    summary = {env: {"databases": len(s["databases"]), "secret_compartments": len(s["secret_compartments"]),
                     "unmapped_secrets": len(s["_unmapped_secrets"])} for env, s in envs.items()}
    print(json.dumps({"event": "draft_config_written", "output": str(out), "environments": summary,
                      "mutation": "LOCAL_FILE_ONLY"}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        fields = {"error_type": type(exc).__name__}
        if isinstance(exc, oci.exceptions.ServiceError):
            fields.update({"oci_http_status": exc.status, "oci_code": exc.code})
        print(json.dumps({"event": "discover_failed", **fields}))
        sys.exit(2)
