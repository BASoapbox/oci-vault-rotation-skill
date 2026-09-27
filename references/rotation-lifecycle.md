# Rotation lifecycle

This document covers `P2:ADB` rotations in detail. `P1` (Vault-only) rotation is
the same transaction with no downstream target; see the section at the end.

A database password lives in two places: Vault and the database. Rotation has
to change both without ever leaving them disagreeing in a way nobody can see.

## The invariant

**Vault `CURRENT` stays authoritative until the database has accepted and
verified the new value.** Consumers read `CURRENT`, so it must always be a
password that works.

OCI Vault supports this directly through version stages. A new value can be
written as `PENDING` without touching `CURRENT`, and promoted later.

## The transaction

| Step | Action | If it stops here |
|---|---|---|
| 1 | Verify the ADMIN credential authenticates | Nothing changed |
| 2 | Disable Vault auto-generation, if enabled | Policy restored in `finally` |
| 3 | Re-check version; confirm no PENDING exists | Nothing changed |
| 4 | Stage generated value as sole `PENDING` | DB matches `CURRENT`; a PENDING exists |
| 5 | `ALTER USER ... IDENTIFIED BY` the staged value | DB matches `PENDING` |
| 6 | Verify a fresh login as the user | DB matches `PENDING` |
| 7 | Promote `PENDING` to `CURRENT` | DB and Vault match |
| 8 | Restore auto-generation | Only the policy needs attention |

Step 7 retries up to six times, and only on transient OCI errors. After every
transient response it reads the secret first, because OCI can accept an update
while the client sees a failure. It never generates or stages a second value.

## Why each guard exists

- **Stage before `ALTER USER`.** If the order were reversed and staging failed,
  the only copy of the new password would be in process memory, and it would
  vanish with the process.
- **Verify before promote.** `ALTER USER` succeeding proves the statement ran,
  not that the account can log in. Password verify functions, locked accounts,
  and profile limits all surface only at login.
- **Block when a PENDING already exists.** A leftover PENDING version is evidence
  of an interrupted rotation. Staging on top of it would destroy that evidence.
- **Disable auto-generation first.** Vault could otherwise generate a competing
  value mid-transaction.
- **Bind confirmation to the version number.** An approval for `v4` must not
  authorize a rotation of whatever `v5` turns out to be.
- **Never emit exception text.** Database drivers can echo the statement that
  failed, which contains the password. Only the exception type and OCI
  status/code are reported.

## Reading a stopped result

Every stop reports `result` and `state`:

| result | state | Meaning |
|---|---|---|
| `NO_MUTATION` | `DATABASE_AND_VAULT_UNCHANGED` | Stopped before staging. Safe to fix and retry. |
| `MANUAL_RECOVERY_REQUIRED` | `DATABASE_EXPECTED_TO_MATCH_CURRENT_VERSION` | Staged, but DB not changed. A PENDING version exists. |
| `MANUAL_RECOVERY_REQUIRED` | `DATABASE_EXPECTED_TO_MATCH_PENDING_VERSION` | DB changed; Vault `CURRENT` is now stale. **Consumers will fail.** |
| `POLICY_RESTORE_REQUIRED` | `DATABASE_AND_VAULT_CURRENT_MATCH` | Rotation succeeded; only re-enabling auto-generation failed. |

`state` says what the database is *expected* to match. Confirm it before acting:
`verify.py --check adb-login` tests `CURRENT`.

## Recovering a stopped rotation

OCI will not delete a secret version unless its rotation state is `DEPRECATED`,
so a stranded `PENDING` version cannot simply be discarded. Resolve it instead,
with the same runner that created it: `rotate_adb_user.py` for users,
`rotate_adb_admin.py` for ADMIN (see `references/admin-rotation.md`). Both
runners block new rotations while a PENDING version exists.

1. `verify.py --check recovery-scan --env <env>` confirms which secrets have a
   pending version.
2. Run the runner with `--recover-pending` **without** `--execute`. It prints a
   phrase bound to both version numbers.
3. After approval, recovery reads both versions into memory and tests each login
   as the user:

| CURRENT logs in | PENDING logs in | Recovery does | Next |
|---|---|---|---|
| no | yes | Promotes PENDING | Done |
| yes | no | Nothing: the database never changed | `--resume-pending` |
| yes | yes | Stops: ambiguous | Manual |
| no | no | Stops | Manual |

4. **`--resume-pending`** applies the already-staged PENDING value (as ADMIN for
   users, as the current ADMIN for ADMIN itself), verifies the new login, and
   promotes. It requires CURRENT to authenticate and PENDING not to, re-checks
   the Vault versions first, and never generates another password.

**Manual** means: reset the password directly (as ADMIN for a user; in the OCI
Console for ADMIN itself), confirm the login, then make Vault match. If the reset
used the pending value, promote it with
`oci vault secret update --secret-id <ocid> --current-version-number <pending>`.
Never guess which value the database holds: test it.

## P1: Vault-only rotation

With nothing downstream, the transaction shrinks to Vault alone:

| Step | Action | If it stops here |
|---|---|---|
| 1 | Disable auto-generation, if enabled | Policy restored in `finally` |
| 2 | Re-check version; confirm no PENDING exists | Nothing changed |
| 3 | Stage generated value as sole `PENDING` | A PENDING exists; `CURRENT` unchanged |
| 4 | Read `PENDING` back and compare in memory | Mismatch: not promoted |
| 5 | Promote `PENDING` to `CURRENT` | Done |
| 6 | Restore auto-generation | Only the policy needs attention |

Step 4 is the P1 equivalent of the database login: proof that what Vault now
holds is what was generated, before anything reads it.

A stop after staging reports `RESUME_AVAILABLE`. `--resume-pending` promotes the
single pending version, with its own `resume-p1:` phrase. There is no recover
mode: with no downstream system there is no second copy to test against.
