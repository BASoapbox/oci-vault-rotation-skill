---
name: oci-vault-operations
description: Safely inventory, tag, verify, and rotate OCI Vault secrets, including Vault-only (P1) rotation, confirmation-gated Autonomous Database user and ADMIN password rotation (P2:ADB), and rotation through downstream handlers such as Postgres and MongoDB in Docker, Docker Compose env files, and credential files (P2:PG, P2:MDB, P2:COMPOSE, P2:FILE), keeping Vault and every consumer in sync. Use when the user asks for a Vault inventory, Vault status or menu, to show or audit secrets, to tag or classify secrets for rotation, to rotate a database password stored in OCI Vault, to verify a secret still authenticates, or to find and recover incomplete rotations. Defaults to read-only reporting and requires an exact confirmation phrase before any change.
---

# OCI Vault Operations

A controlled interface for OCI Vault secrets. Everything defaults to read-only.
Every mutation is a two-step process: a dry run that prints a version-bound
confirmation phrase, then an execution that refuses to run unless that exact
phrase is supplied.

## Before running anything

1. **Find the config.** Use `--config` if the user names one; otherwise the
   scripts read `$OCI_VAULT_OPS_CONFIG` or `~/.config/oci-vault-ops/config.json`.
   If none exists, offer `scripts/discover_config.py` (read-only) to draft one,
   and have the user review every database mapping before continuing. Read
   `references/configuration.md` before editing a config.
2. **Pick the interpreter.** Scripts need a Python that imports both `oci` and
   `oracledb`. If the config has a top-level `"python"` key, use that
   interpreter. Otherwise test `python3 -c "import oci, oracledb"`; if it fails,
   ask the user rather than installing packages.
3. **Confirm the OCI profile.** The config must name `oci.profile` explicitly.
   Never substitute DEFAULT or another profile, even if one exists: a machine
   can hold profiles for unrelated tenancies.

Run scripts from the skill directory, for example
`<python> scripts/vault_inventory.py --env stage`.

## Simple entry points

Normal language should route here; users should not need to remember commands.

- **"Vault menu"**: offer Inventory & Reports, Tag, Connectivity,
  Rotation Plan, Execute Approved Rotation, and Verify / Recover / Audit.
- **"Vault status"** / **"Show my secrets"**: `vault_inventory.py`. Ask for the
  environment if several are configured and the user did not name one.
- **"Which secrets are stale?"**: `vault_inventory.py --older-than-days N`.
- **"Tag [secret] as [P1|P2:<HANDLER>|EXEMPT|MANUAL]"**: `tag_secret.py` dry run,
  then execute only with its exact `tag:` phrase. Read
  `references/classification.md` first, and relay any warnings it prints.
- **"Can I reach [database]?"**: `preflight.py --env E --database D`.
- **"Rotate [secret] in [env]"**: pick the runner from the secret's tag (`P1` →
  `rotate_vault_only.py`; `P2:ADB` → `rotate_adb_user.py` or, for ADMIN,
  `rotate_adb_admin.py`; any other `P2:<handlers>` → `rotate_secret.py`), run it
  **without** `--execute`, and present the plan.
  Never rotate in the same step as planning. Any other tag cannot rotate here;
  say why.
- **"Rotate all eligible secrets"**: produce one dry-run plan per `P1` or
  `P2:ADB` secret and list exclusions with reasons. Each rotation still needs its own
  confirmation phrase; do not batch approvals.
- **"Verify [secret]"**: `verify.py --check vault-state`; add `adb-login` only
  when the user wants proof the credential authenticates.
- **"Find incomplete rotations"**: `verify.py --check recovery-scan`.
- **"Is [secret] in sync?"**: `verify.py --check consumer-sync` compares Vault
  CURRENT with every configured consumer (confirmation-gated read).
- **"Put [secret] in Vault"** / fix drift: `import_secret.py` reads the live value
  from the host into memory and writes it to Vault after its `import:` phrase.

## Safety rules

- **Never retrieve, print, store, or place secret values** in chat, logs,
  reports, files, or command arguments. That includes passwords, tokens, wallet
  contents, and private keys. Do not call `oci secrets secret-bundle get` or
  write code that decodes a bundle. The executors are the narrow exception:
  after approval they read only the values their transaction needs into process
  memory and never emit them.
- **Confirmation is per operation and immediate.** A phrase approves exactly the
  secret and version numbers inside it. If a version changes, the phrase is
  void; re-run the dry run. Never construct a phrase yourself and pass it
  without the user seeing the plan it came from.
- **Scope explicitly.** Operate on a named environment and named secret(s).
  Never infer "all environments" or "all secrets".
- **Two gates for every rotation.** The Vault tag and the reviewed config must
  agree: `P2:ADB` needs a database mapping, `P1` needs the secret listed in
  `vault_only_secrets`. Never edit the config to get past a failed gate without
  the user asking for that specific change.
- **No partial rotations.** A tag naming a handler that does not exist yet (e.g.
  `P2:REDIS`), or a combination not supported yet (`P2:ADB:COMPOSE`), blocks
  rotation. Do not rotate only the parts the
  skill can handle; report the missing handler instead.
- **Never tag an application's secret `P1`.** If anything reads a copy of the
  value, rotating Vault alone breaks it; it needs a `P2` handler.
- **Stop downstream work when an upstream step fails.** Report the stopped state;
  never retry a mutation automatically.
- If a script's output contains anything that looks like a credential, stop and
  tell the user instead of repeating it.

## Rotation

Read `references/rotation-lifecycle.md` before proposing or executing a rotation.

**Downstream handlers (`P2:PG`, `P2:MDB`, `P2:COMPOSE`, `P2:FILE`):** `scripts/rotate_secret.py`.
Read `references/handlers.md` first. It refuses unless every consumer already
holds Vault CURRENT; if not, the fix is `import_secret.py`, never an edit to the
consumer. It connects to the configured hosts over SSH and recreates the named
containers, so say which services will restart when presenting the plan.

**Vault-only (`P1`):** `scripts/rotate_vault_only.py`. The dry run prints
`rotate-p1:<env>:<secret>:v<current>`. Execution stages a generated value as
PENDING, reads it back and compares it in memory, then promotes. A stopped run
is finished with `--resume-pending`.

**Database users (not ADMIN):** `scripts/rotate_adb_user.py`

1. Dry run. It checks mapping, the `P2:ADB` tag, connectivity, and that no
   PENDING version exists, then prints `rotate:<env>:<secret>:v<current>`.
2. Present the plan and wait for the user to approve that exact phrase.
3. Execute with `--execute --confirm '<phrase>'`. The approval covers the whole
   transaction: verify ADMIN, stage PENDING, `ALTER USER`, verify the new login,
   promote. Bounded promotion retries on transient OCI errors are part of it.

**ADMIN:** `scripts/rotate_adb_admin.py`. Read `references/admin-rotation.md`
first. The user runner deliberately rejects ADMIN.

If a rotation stops after staging, **do not start another rotation.** Run
`verify.py --check recovery-scan`, read the stopped `state`, then use the same
runner's `--recover-pending` or `--resume-pending` dry run and follow
`references/rotation-lifecycle.md`. Each needs its own version-bound phrase.
A PENDING version cannot be deleted in OCI, so do not suggest discarding it.

## Verify and audit

- `verify.py --check vault-state` and `--check recovery-scan` read metadata only.
- `verify.py --check adb-login` prints a `verify-login:` phrase and reads the
  CURRENT value into memory only with `--authorize-credential-read --confirm`.
- `audit_journal.py record` appends a redacted outcome after a completed plan,
  rotation, recovery, verification, or tag change, if the user keeps a
  journal. Read `references/audit-journal.md`. The journal is history, not
  truth: always run a fresh preflight before acting on it.

## Output

Scripts emit one JSON event per line. Summarize them for the user in plain
language, and keep the confirmation phrase verbatim so it can be approved.
Reports may include names, OCIDs, states, version numbers, timestamps, and age;
never values.
