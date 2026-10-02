# Downstream handlers

A handler applies a new value to one system that uses the secret, and proves
the system accepts it. `P2` tags list handlers in the order they run:
`P2:PG:COMPOSE` changes the Postgres password, then updates the app's env file.

| Handler | System | Runner |
|---|---|---|
| `ADB` | Autonomous Database user / `ADMIN` | `rotate_adb_user.py`, `rotate_adb_admin.py` |
| `PG` | PostgreSQL role, Postgres in a Docker container | `rotate_secret.py` |
| `COMPOSE` | Variable in a Docker Compose env file, and the services reading it | `rotate_secret.py` |
| `MDB` | MongoDB user, MongoDB in a Docker container | `rotate_secret.py` |
| `FILE` | Value inside one or more files on a host | `rotate_secret.py` |

Tags may name handlers that do not exist yet (for example `P2:REDIS`);
rotation stays blocked until every one exists. `ADB` does not combine with the
others yet.

## Bindings

Each handler needs a binding in the reviewed config (the second gate):

```json
"secret_bindings": {
  "app-db-pwd": {
    "value": {"format": "password"},
    "handlers": {
      "PG": {"host": "app-host", "container": "app-db", "role": "app_user", "database": "app"},
      "COMPOSE": {"host": "app-host", "project_dir": "/srv/app", "env_var": "POSTGRES_PASSWORD",
                  "services": ["app-db", "api"], "url_embedded": true,
                  "container_env": [{"service": "api", "var": "DATABASE_URL", "match": "contains"}],
                  "verify_command": ["docker", "exec", "api", "python", "-c", "from database import engine; engine.connect().close()"]}
    }
  }
}
```

`value.format`: `password` (the password policy, minus every character any
handler forbids) or `hex` with `bytes` (signing keys). `hosts.<name>.ssh` holds
an ssh alias or `user@host`.

### PG
`host`, `container`, `role`, `database`, optional `admin_user` (default: `role`).
Changes the password with `ALTER ROLE` over the container's local socket, which
the official image trusts. Proves it with a real password login over TCP to the
container's own address. Preflight checks that a random wrong password is
**rejected**; if Postgres trusted every connection the login proof would mean
nothing, so the handler refuses. Forbids quotes and backslash.

### COMPOSE
`host`, `project_dir`, `env_var`, `services`, optional `env_file`,
`url_embedded`, `container_env`, `verify_command`, `verify_timeout`,
`start_timeout`. Rewrites one env-file line atomically (mode and owner kept),
then `docker compose up -d --no-deps --pull never <services>`, and waits for
running/healthy. Verification: the env file holds the value, the containers were
really recreated, `container_env` matches, `verify_command` passes (retried).
Forbids `$ # " ' \` backtick and whitespace; `url_embedded` also forbids
`@ : / ? % & + = [ ]`.

Only the named services are recreated. `--no-deps` keeps Compose from touching
anything else in the project, which matters when unrelated sites share it.

### MDB
`host`, `container`, `user`, `auth_db` (the user's authSource), `admin_secret`,
optional `admin_user` (default `admin`), `admin_auth_db` (default `admin`), `port`
(default 27017). An ordinary user usually cannot change its own password
(`readWrite` lacks `changeOwnPassword`), so the handler authenticates as the
administrator, whose password it reads from `admin_secret`'s Vault `CURRENT` at
apply time only, then runs `changeUserPassword`. `admin_secret` may be the
secret being rotated: rotating the administrator itself works because `CURRENT`
stays the old password until the rotation promotes. Proves the new value with a
real login as the user. Preflight checks that the server refuses
unauthenticated commands and rejects a random wrong password, and that
`admin_secret` exists (metadata only). Scripts run as `mongosh --nodb
/dev/stdin` with values as JSON string literals on stdin; only a status token is
read back.

### FILE
`host`, `files` (a list of `{path, format, key}`), optional `verify_commands`
(argv lists, run with empty stdin, must exit 0) and `verify_timeout`. Formats:
`whole` (the file is the value; a trailing newline is kept as it was), `env`
(`KEY=value`), `yaml` (`key: value`, unquoted). Each file is rewritten
atomically: temp file in the same directory, then rename, mode and owner kept.
FILE restarts nothing, so it suits values read when used. A container that
mounts the **directory** sees the new file; one that mounts the single file
keeps the old inode, so mount directories. Forbids, per format used: newline;
for `env`, `$ # " ' \` backtick and whitespace; for `yaml`, also
`: { } [ ] , & * ! | > % @`.

## Before the first rotation: Vault must hold the live value

`rotate_secret.py` reads Vault `CURRENT` and requires every handler to hold it
before changing anything. If a consumer was edited by hand, the rotation stops.
Check and fix:

```bash
python scripts/verify.py --env stage --check consumer-sync --secret app-db-pwd
python scripts/import_secret.py --env stage --secret app-db-pwd --host app-host \
  --env-file /srv/app/.env --env-var POSTGRES_PASSWORD
```

`import_secret.py` also creates secrets that are not in Vault yet
(`--create-like`, `--tag`), reading the value from an env file or a file on the
host straight into memory.

## Interrupted rotations

A stop is reported with `handlers_applied`. Run `--recover-pending` first: it
tests every handler with both versions and promotes only if all already hold
`PENDING`. Otherwise `--resume-pending` applies `PENDING` to the handlers still
on `CURRENT`, in order, verifies all of them, and promotes. A handler that
accepts both values or neither stops both modes.

In recovery and resume, consumer health checks (`verify_command`, services
running) are warnings, not blockers: a half-finished rotation is exactly when
they fail, and they must not block the repair.

## Adding a handler

Subclass `handlers.base.Handler`: `preflight(recovery)`, `apply(value)`,
`verify(value)`, `probe(value)`, `forbidden_chars`, `required_keys`. Register it
in `handlers/__init__.py`. Pass values to hosts on stdin only (`hostexec.run`),
never in argv, and never emit output from a command that received a value.
