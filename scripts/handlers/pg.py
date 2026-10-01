"""PG: a PostgreSQL role's password, for Postgres running in a Docker container.

Binding:
  host        key under hosts
  container   Postgres container name
  role        role whose password rotates
  database    database to authenticate against
  admin_user  role used to run ALTER ROLE over the container's local socket
              (default: role). Requires the image's default local `trust` rule.

apply()  ALTER ROLE ... PASSWORD, sent as SQL on stdin to psql inside the container.
probe()  a real password login over TCP to the container's own address, which
         bypasses the loopback/socket `trust` rules and hits password auth.

Preflight proves the probe is meaningful: a random wrong password must be
rejected, otherwise every probe would pass regardless of the password.
"""

from __future__ import annotations

import re
import secrets

import hostexec
import vaultlib as v

from .base import Handler, HandlerError

SAFE_IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
SAFE_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

# Login probe: password read from stdin, never argv. -w: never prompt.
PROBE_SH = ('IFS= read -r PGPASSWORD; export PGPASSWORD; '
            'exec psql -h "$(hostname -i | cut -d" " -f1)" -U "$1" -d "$2" -w -tAc "select 1"')


class PgHandler(Handler):
    name = "PG"
    forbidden_chars = "'\"\\"
    required_keys = ("host", "container", "role", "database")

    def __init__(self, cfg, env, secret, binding):
        super().__init__(cfg, env, secret, binding)
        for key in ("role", "database"):
            if not SAFE_IDENT.fullmatch(binding[key]):
                raise v.OpsError(f"PG binding {key} must be a lower-case identifier")
        if not SAFE_CONTAINER.fullmatch(binding["container"]):
            raise v.OpsError("PG binding container name is not a valid container name")
        self.admin_user = binding.get("admin_user") or binding["role"]
        if not SAFE_IDENT.fullmatch(self.admin_user):
            raise v.OpsError("PG binding admin_user must be a lower-case identifier")

    def describe(self):
        return {"handler": self.name, "host": self.host, "container": self.binding["container"],
                "role": self.binding["role"], "database": self.binding["database"]}

    def _psql_local(self, sql: str) -> hostexec.Result:
        b = self.binding
        return hostexec.run(self.cfg, self.host, ["docker", "exec", "-i", b["container"], "psql", "-U", self.admin_user,
                                                  "-d", b["database"], "-v", "ON_ERROR_STOP=1", "-qtA", "-f", "-"],
                            stdin=sql)

    def preflight(self, recovery: bool = False):
        b = self.binding
        running = hostexec.run(self.cfg, self.host, ["docker", "inspect", "-f", "{{.State.Running}}", b["container"]])
        checks = [v.Check("pg_container_running", "PASS" if running.stdout.strip() == "true" else "FAIL",
                          f"{self.host}/{b['container']}")]
        if checks[0].status == "FAIL":
            return checks
        role = self._psql_local(f"select count(*) from pg_roles where rolname = '{b['role']}';")
        checks.append(v.Check("pg_role_exists", "PASS" if role.ok and role.stdout.strip() == "1" else "FAIL", b["role"]))
        rejected = not self.probe("wrong-" + secrets.token_hex(12))
        checks.append(v.Check("pg_password_auth_enforced", "PASS" if rejected else "FAIL",
                              "a wrong password is rejected over TCP" if rejected
                              else "a wrong password was accepted; the login probe would prove nothing"))
        return checks

    def apply(self, value: str) -> None:
        if any(c in value for c in self.forbidden_chars):
            raise HandlerError("Value contains characters PG cannot accept in a literal")
        result = self._psql_local(f"ALTER ROLE \"{self.binding['role']}\" WITH PASSWORD '{value}';")
        if not result.ok:
            raise HandlerError(f"ALTER ROLE failed (exit {result.rc})")

    def probe(self, value: str) -> bool:
        b = self.binding
        result = hostexec.run(self.cfg, self.host,
                              ["docker", "exec", "-i", b["container"], "sh", "-c", PROBE_SH, "_", b["role"], b["database"]],
                              stdin=value + "\n")
        return result.ok and result.stdout.strip() == "1"
