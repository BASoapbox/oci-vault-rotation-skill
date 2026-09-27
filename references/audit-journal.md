# Audit journal

An optional, append-only JSONL file of redacted outcomes. It answers "what was
done, by whom, and when" without holding anything sensitive.

```bash
python scripts/audit_journal.py record --event rotation_completed --status SUCCESS \
  --env stage --secret app-user-pwd --database-user APP_USER --version 5 \
  --detail "rotated and verified"
python scripts/audit_journal.py report
```

The path comes from `--journal` or the config's `audit_journal`.

## Rules

- Only defined event and status values are accepted.
- `--detail` is rejected if it contains terms such as password, token, wallet,
  private key, or bearer. Describe the outcome, not the credential.
- **The journal is history, not truth.** Live Vault and database state are
  authoritative. Run a fresh preflight before acting, even when the journal says
  an operation completed.

## Sharing with a team

Put the journal in a **private** Git repository that each operator clones, and
point `audit_journal` at their clone. Protect the default branch, and require
review before one operator resumes another's stopped rotation. Pushing is an
external action: do it only when the user asks.
