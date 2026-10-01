# OCI Vault Rotation Skill

An AI agent skill for inventorying, tagging, verifying and **safely rotating**
[OCI Vault](https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm)
secrets, including Autonomous Database user and `ADMIN` passwords, without
leaving Vault and the database disagreeing.

Written for [Claude Code](https://claude.com/claude-code) and OpenAI Codex
(the standard `SKILL.md` format), but every script is a plain Python command-line
tool you can run by hand.

> Personal project. Not an official Oracle product, and not affiliated with or
> supported by Oracle. Use at your own risk, and try it on a throwaway secret first.

## Why

A database password stored in Vault lives in two places. Rotating it means
changing both, and if the process stops in between, every application reading
Vault gets a password the database no longer accepts.

This skill keeps **Vault `CURRENT` authoritative until the database has accepted
and verified the new value**, using Vault's `PENDING` version stage:

1. Verify the `ADMIN` credential logs in
2. Stage a generated password as the only `PENDING` version (`CURRENT` untouched)
3. `ALTER USER` to the staged value
4. Log in as that user with the new value
5. Promote `PENDING` to `CURRENT`

If it stops anywhere after step 2, `--recover-pending` and `--resume-pending`
finish the job from whatever state it was left in, without guessing.

## Safety model

- **Read-only by default.** Every change is a dry run first.
- **Version-bound confirmation.** The dry run prints a phrase such as
  `rotate:stage:app-user-pwd:v4`. Execution refuses to run without that exact
  phrase, so an approval cannot drift onto a different version.
- **Values never leave process memory.** Scripts print names, versions and
  states only. An agent running them never sees a secret, and exception text
  (which can echo a password) is never printed.
- **Two gates per rotation.** The secret's Vault tag *and* a config file you
  review must both allow it.
- **No partial rotations.** A secret whose tag names a downstream system the
  skill cannot update yet is not rotated at all.

## Rotation tags

Each secret carries a tag in its metadata (`rotationTag`):

| Tag | Meaning | Rotated by |
|---|---|---|
| `P1` | Vault-only; nothing downstream | `rotate_vault_only.py` |
| `P2` | Has downstream consumers, not yet named | Blocked until a handler is named |
| `P2:<H>[:<H>...]` | Vault plus each downstream handler, in order | The runner for those handlers |
| `EXEMPT` | Does not require rotation | Nothing |
| `MANUAL` | Rotates, but this skill cannot perform it | A person |

Implemented handlers:

- **`ADB`**: Autonomous Database users and `ADMIN`
- **`PG`**: a PostgreSQL role, for Postgres running in Docker
- **`COMPOSE`**: a variable in a Docker Compose env file, plus recreating the services that read it

Handlers chain in tag order: `P2:PG:COMPOSE` changes the database password, then
the app's env file. See [references/handlers.md](references/handlers.md).

## Tools

| Script | Purpose | Changes anything? |
|---|---|---|
| `discover_config.py` | Draft a config from your tenancy's metadata | Local file only |
| `vault_inventory.py` | Secrets, versions, age, tags | No |
| `preflight.py` | Database connectivity prerequisites | No |
| `tag_secret.py` | Set a rotation tag | Metadata, after confirmation |
| `rotate_vault_only.py` | `P1` rotation | After confirmation |
| `rotate_adb_user.py` | `P2:ADB` rotation of a database user | After confirmation |
| `rotate_adb_admin.py` | `P2:ADB` rotation of `ADMIN` | After confirmation |
| `rotate_secret.py` | `P2` rotation through `PG` / `COMPOSE` handlers | After confirmation |
| `import_secret.py` | Bring a value a system already uses into Vault | Vault, after confirmation |
| `verify.py` | Vault state, stranded `PENDING` versions, login proof, consumer sync | No |
| `audit_journal.py` | Append-only redacted operations log | Local file only |

## Requirements

- Python 3.10+ with `oci` and `oracledb` (`pip install -r requirements.txt`)
- An OCI CLI config profile with permission to manage secrets in the vault
- For `PG` / `COMPOSE`: SSH access to the host, Docker Compose v2, and `python3` on the host
- A downloaded wallet for each Autonomous Database, and its wallet password
  stored in Vault if the wallet key is encrypted (it is by default)

## Install

```bash
git clone https://github.com/BASoapbox/oci-vault-rotation-skill.git
# Claude Code
ln -s "$PWD/oci-vault-rotation-skill" ~/.claude/skills/oci-vault-operations
# Codex
ln -s "$PWD/oci-vault-rotation-skill" ~/.codex/skills/oci-vault-operations
```

## Configure

Draft a config from your tenancy (read-only against OCI), then **review every
database mapping** before tagging anything `P2:ADB`:

```bash
python scripts/discover_config.py --profile YOUR_PROFILE \
  --wallet-root ~/wallets --output ~/.config/oci-vault-ops/config.json
python scripts/vault_inventory.py
```

Or start from [config/vault-ops.example.json](config/vault-ops.example.json).
Every key is documented in [references/configuration.md](references/configuration.md).
Keep the real config out of version control; it describes your tenancy.

## Use

Ask your agent in plain language: *"Vault status"*, *"Tag app-user-pwd as
P2:ADB"*, *"Rotate app-user-pwd in stage"*, *"Find incomplete rotations"*. It
will show you each plan and wait for the confirmation phrase.

Or by hand:

```bash
python scripts/rotate_adb_user.py --env stage --secret app-user-pwd
python scripts/rotate_adb_user.py --env stage --secret app-user-pwd \
  --execute --confirm 'rotate:stage:app-user-pwd:v4'
```

**Start with a throwaway database user that nothing depends on.** Rotate it,
then interrupt a rotation on purpose and recover it, before tagging anything real.

## Documentation

- [SKILL.md](SKILL.md): what the agent reads
- [references/rotation-lifecycle.md](references/rotation-lifecycle.md): the transaction and recovery
- [references/admin-rotation.md](references/admin-rotation.md): `ADMIN`-specific rules
- [references/classification.md](references/classification.md): the tag scheme
- [references/handlers.md](references/handlers.md): `PG`, `COMPOSE`, bindings, adding a handler
- [references/configuration.md](references/configuration.md): every config key
- [references/audit-journal.md](references/audit-journal.md): the operations log

## Tests

```bash
python -m unittest discover -s tests -t tests
```

The suite mocks OCI and the database entirely; nothing in it touches a tenancy.

## Background

The write-up behind this skill, including what broke in testing:
[Rotating Database Passwords Without Breaking Anything](https://basoapbox.com/blog/rotating-database-passwords-oci-vault).

## License

[MIT](LICENSE)
