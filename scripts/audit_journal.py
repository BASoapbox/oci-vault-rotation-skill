#!/usr/bin/env python3
"""Append-only, redacted JSONL journal of Vault operations.

The journal is history, not truth: always run a fresh preflight before acting,
even when the journal says an operation completed or is ready. Keep it in a
private location (optionally a private Git repo if a team shares it).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import vaultlib as v

EVENTS = {"plan_created", "rotation_completed", "rotation_stopped", "recovery_completed",
          "verification_passed", "verification_failed", "tag_updated"}
STATUSES = {"READY", "SUCCESS", "STOPPED", "BLOCKED", "PASS", "FAIL", "INDETERMINATE"}
SENSITIVE = re.compile(r"password|passwd|pwd=|token|wallet|private.?key|authorization|bearer|secret.?value", re.I)


def journal_path(args, cfg) -> Path:
    path = args.journal or (cfg or {}).get("audit_journal")
    if not path:
        raise v.OpsError("No journal path: pass --journal or set audit_journal in config")
    return Path(path).expanduser()


def record(args, cfg) -> int:
    if args.detail and SENSITIVE.search(args.detail):
        raise v.OpsError("Detail contains a disallowed sensitive-data term; describe the outcome, not the credential")
    entry = {"time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"), "event": args.event,
             "status": args.status, "environment": args.env, "secret": args.secret,
             "actor": args.actor or (cfg or {}).get("audit_actor", "unknown")}
    entry.update({k: val for k, val in {"database_user": args.database_user, "version": args.version,
                                         "detail": args.detail}.items() if val is not None})
    path = journal_path(args, cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    v.event("audit_journal_recorded", journal=str(path), status=args.status, mutation="LOCAL_JOURNAL_ONLY")
    return 0


def report(args, cfg) -> int:
    path = journal_path(args, cfg)
    latest: dict[tuple[str, str], dict] = {}
    entries = 0
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict) and {"environment", "secret", "status"} <= entry.keys():
                entries += 1
                latest[(entry["environment"], entry["secret"])] = entry
    v.event("audit_journal_report", journal=str(path), entries=entries,
            latest=sorted(latest.values(), key=lambda e: (e["environment"], e["secret"])), mutation="NONE")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Redacted Vault operations journal")
    parser.add_argument("--config", help="optional; supplies audit_journal and audit_actor")
    parser.add_argument("--journal")
    sub = parser.add_subparsers(dest="command", required=True)
    rec = sub.add_parser("record")
    rec.add_argument("--event", required=True, choices=sorted(EVENTS))
    rec.add_argument("--status", required=True, choices=sorted(STATUSES))
    rec.add_argument("--env", required=True)
    rec.add_argument("--secret", required=True)
    rec.add_argument("--actor")
    rec.add_argument("--database-user")
    rec.add_argument("--version", type=int)
    rec.add_argument("--detail", help="short redacted outcome")
    sub.add_parser("report")
    args = parser.parse_args()
    cfg = None
    if args.config or not args.journal:
        try:
            cfg = v.load_config(args.config)
        except v.OpsError:
            cfg = None
    return record(args, cfg) if args.command == "record" else report(args, cfg)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except v.OpsError as exc:
        v.event("audit_journal_blocked", reason=str(exc))
        sys.exit(2)
