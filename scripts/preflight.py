#!/usr/bin/env python3
"""Read-only connectivity prerequisites for one configured Autonomous Database.

Checks the database state, connection mode, wallet, TNS alias, that the wallet
belongs to this database, the wallet-password source, the python-oracledb
runtime, and (ssh_tunnel mode) the SSH LocalForward and local listener. It
does not read secret values or authenticate.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

import vaultlib as v


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only database connectivity preflight")
    parser.add_argument("--config")
    parser.add_argument("--env", required=True)
    parser.add_argument("--database", required=True, help="database key under environments.<env>.databases")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    cfg = v.load_config(args.config)
    checks, details = v.connectivity(cfg, args.env, args.database)
    ready = v.all_pass(checks)
    if args.json:
        print(json.dumps({"environment": args.env, "database": args.database, "status": "READY" if ready else "BLOCKED",
                          "checks": [asdict(c) for c in checks], "details": details}, indent=2))
    else:
        print(f"\n{args.env} / {args.database} connectivity: {'READY' if ready else 'BLOCKED'}\n")
        for c in checks:
            print(f"  {c.status:<4}  {c.name:<24} {c.detail}")
        print()
    return 0 if ready else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except v.OpsError as exc:
        v.event("preflight_blocked", result="NO_MUTATION", reason=str(exc))
        sys.exit(2)
    except Exception as exc:
        v.event("preflight_failed", result="NO_MUTATION", **v.safe_error_fields(exc))
        sys.exit(2)
