# ADMIN rotation

ADMIN is the authority credential: the user runner needs it to change every
other password. A stranded ADMIN password locks you out of the database until
you reset ADMIN in the OCI Console, so it has a dedicated runner with its own
recovery paths.

## Invariants

- Use `scripts/rotate_adb_admin.py` only. `rotate_adb_user.py` rejects ADMIN.
- The secret must be the database's configured `admin_secret`, be `ACTIVE`, and
  be tagged `P2:ADB`.
- A dry run reads metadata and connectivity only: no values, no mutation.
- The runner authenticates with the *current* ADMIN value, changes ADMIN to the
  staged value, verifies a new ADMIN login, and only then promotes.
- Vault `CURRENT` is unchanged while the replacement is staged as sole `PENDING`.
- Auto-generation is disabled for the transaction and restored after, as part of
  the same approval.

## Confirmation phrases

| Mode | Phrase |
|---|---|
| Rotate | `rotate-admin:<env>:<secret>:v<current>` |
| Recover | `recover-admin:<env>:<secret>:current-v<c>:pending-v<p>` |
| Resume | `resume-admin:<env>:<secret>:current-v<c>:pending-v<p>` |

## Choosing recover or resume

Both need exactly one PENDING version. Run each without `--execute` first.

**`--recover-pending`** is for a stop *after* `ALTER USER`. It reads both
versions into memory and tests both logins:

| CURRENT logs in | PENDING logs in | Action |
|---|---|---|
| no | yes | Promote PENDING (and restore policy if needed) |
| yes | no | No change; database never moved. Consider `--resume-pending` |
| yes | yes | Stop: ambiguous |
| no | no | Stop: reset ADMIN in the OCI Console |

**`--resume-pending`** is for a stop *before* `ALTER USER`. It requires CURRENT
to log in and PENDING not to, re-checks the Vault versions, then applies the
already-staged value. It never generates or stages another password.

## Last resort

If both values fail, reset ADMIN in the OCI Console (Autonomous Database →
More actions → Administrator password), then bring Vault in line by staging
that value through a fresh rotation.
