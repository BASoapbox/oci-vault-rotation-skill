# Rotation tags

Each secret carries one rotation tag in its Vault metadata, under the key
`rotationTag` (configurable via `tag_key`). The tag records *how* the secret
rotates, including everything downstream that has to change with it.

| Tag | Meaning | Rotated by |
|---|---|---|
| `P1` | Vault-only: nothing downstream reads a copy | `rotate_vault_only.py` |
| `P2` | Has downstream consumers, not yet named | Nothing, until a handler is added |
| `P2:<H>` | Vault plus downstream handler `H` | The runner for `H` |
| `P2:<H1>:<H2>` | Vault plus several handlers, applied in order | A runner covering all of them |
| `EXEMPT` | Does not require rotation | Nothing |
| `MANUAL` | Rotates, but this skill cannot perform it | A person |
| *(none)* | Reported as `UNTAGGED` | Nothing |

A value that does not match the grammar is reported as `UNRECOGNIZED` and
treated like an untagged secret.

## Handlers

A handler knows how to apply a new value to one downstream system and prove it
took. Implemented today:

| Handler | Runner | Applies and verifies by |
|---|---|---|
| `ADB` | `rotate_adb_user.py`, `rotate_adb_admin.py` | `ALTER USER`, then a fresh login |

A tag may name handlers that do not exist yet, such as `P2:JNR_APP` or
`P2:ADB:JWT`. Tagging it records the intent; **rotation stays blocked** until
every named handler exists. The skill never runs some of a secret's handlers and
skips the rest, because a half-rotated secret is worse than an unrotated one.

## Choosing a tag

Ask what has to change when the value changes.

- **Nothing else** → `P1`. Suits values you generate yourself: a shared random
  token, an internal password only Vault hands out.
- **A database account** → `P2:ADB`, once mapped in config.
- **An application that reads it** → `P2:<APP>`, naming a handler for that
  application. The handler updates, restarts or verifies the application.
- **A database and an application** → `P2:ADB:<APP>`.
- **Its value comes from someone else** (an API key a provider issues, SMTP
  credentials a cloud service generates) → `MANUAL`, unless a handler can obtain
  the new value from that provider.
- **Changing it would break something you cannot regenerate** (a wallet password
  tied to wallet files already downloaded) → `EXEMPT`.

## Two gates, on purpose

A tag alone never makes a secret rotatable. The config must also say so:
`P2:ADB` secrets must be mapped to a database user, and `P1` secrets must be
listed under `vault_only_secrets`. Tags live in Vault, where anyone with
`manage secret-family` can change them; the config is a file you review.
A rotation needs both to agree.

## Mechanics

`tag_secret.py` validates the tag, warns when it cannot rotate yet and why,
writes only the tag key (removing the legacy `rotationClass` key if present),
preserves every other metadata entry, sends the secret's ETag so a concurrent
edit fails rather than being overwritten, and verifies the result. Metadata
updates do not create a new secret version.
