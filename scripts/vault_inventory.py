#!/usr/bin/env python3
"""Read-only Vault inventory: secret definitions and version metadata only.

Never retrieves secret content. Safe to run at any time.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import oci

import vaultlib as v


def describe(cfg, client, kms, vault_names, summary):
    detail = client.get_secret(summary.id).data
    versions = oci.pagination.list_call_get_all_results(client.list_secret_versions, secret_id=summary.id).data
    current = next((x for x in versions if int(x.version_number) == int(detail.current_version_number)), None)
    created = current.time_created if current else None
    if detail.vault_id not in vault_names:
        try:
            vault_names[detail.vault_id] = kms.get_vault(detail.vault_id).data.display_name
        except oci.exceptions.ServiceError:
            vault_names[detail.vault_id] = detail.vault_id[-12:]
    return {
        "secret": detail.secret_name,
        "state": detail.lifecycle_state,
        "rotation_tag": v.tag_of(detail, cfg),
        "vault": vault_names[detail.vault_id],
        "current_version": int(detail.current_version_number),
        "pending_versions": sorted(int(x.version_number) for x in versions if "PENDING" in (x.stages or [])),
        "current_version_created": created.strftime("%Y-%m-%d") if created else None,
        "age_days": (datetime.now(timezone.utc) - created.astimezone(timezone.utc)).days if created else None,
        "auto_generation": bool(detail.is_auto_generation_enabled),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only OCI Vault secret inventory")
    parser.add_argument("--config")
    parser.add_argument("--env", action="append", help="repeat for several; default: all configured")
    parser.add_argument("--older-than-days", type=int)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", help="write to this file instead of stdout")
    args = parser.parse_args()

    cfg = v.load_config(args.config)
    envs = args.env or sorted(cfg.get("environments", {}))
    report: dict[str, list[dict]] = {}
    vault_names: dict[str, str] = {}
    for env in envs:
        client = v.vault_client(cfg, env)
        kms = oci.key_management.KmsVaultClient(v.sdk_config(cfg, env))
        summaries = v.list_env_secrets(cfg, env, client)
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows = list(pool.map(lambda s: describe(cfg, client, kms, vault_names, s), summaries))
        if args.older_than_days is not None:
            rows = [r for r in rows if r["age_days"] is not None and r["age_days"] >= args.older_than_days]
        report[env] = sorted(rows, key=lambda r: r["secret"])

    if args.format == "json":
        text = json.dumps({"generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           "scope": "metadata only; no secret values retrieved", "environments": report}, indent=2)
    else:
        lines = ["# OCI Vault Secret Inventory", "",
                 f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC",
                 "Scope: secret and version metadata only; no secret values were retrieved.", ""]
        for env, rows in report.items():
            lines += [f"## {env} ({len(rows)} secrets)", "",
                      "| # | Secret | State | Tag | Vault | Ver | Created | Age | Pending | AutoGen |",
                      "|---|---|---|---|---|---|---|---|---|---|"]
            for i, r in enumerate(rows, 1):
                lines.append(f"| {i} | `{r['secret']}` | {r['state']} | {r['rotation_tag']} | {r['vault']} | "
                             f"v{r['current_version']} | {r['current_version_created'] or '—'} | "
                             f"{'—' if r['age_days'] is None else str(r['age_days']) + 'd'} | "
                             f"{','.join('v' + str(p) for p in r['pending_versions']) or '—'} | "
                             f"{'yes' if r['auto_generation'] else 'no'} |")
            lines.append("")
        text = "\n".join(lines)
    if args.output:
        Path(args.output).expanduser().write_text(text + "\n")
        v.event("inventory_written", output=args.output, environments=envs, mutation="NONE")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except v.OpsError as exc:
        v.event("inventory_blocked", result="NO_MUTATION", reason=str(exc))
        sys.exit(2)
    except Exception as exc:
        v.event("inventory_failed", result="NO_MUTATION", **v.safe_error_fields(exc))
        sys.exit(2)
