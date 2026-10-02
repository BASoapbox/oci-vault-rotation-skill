"""MDB: a MongoDB user's password, for MongoDB running in a Docker container.

Binding:
  host           key under hosts
  container      Mongo container name
  user           user whose password rotates
  auth_db        database the user is defined in (its authSource)
  admin_secret   Vault secret holding the administering user's password. May be
                 this same secret, to rotate the administrator itself.
  admin_user     default "admin"
  admin_auth_db  default "admin"
  port           port inside the container, default 27017

An ordinary user usually cannot change its own password (readWrite does not
grant changeOwnPassword), so apply() authenticates as the administrator. Its
password is read from admin_secret's Vault CURRENT at apply time only. When the
administrator rotates its own password, CURRENT is still the old value until the
rotation promotes PENDING, so the same rule holds.

apply()  authenticate as admin_user, then changeUserPassword(user, value).
probe()  authenticate as user with the value: True only on success,
         False on AuthenticationFailed or any error.

Every script runs as `mongosh --nodb /dev/stdin` inside the container. Values are
embedded in that stdin script as JSON string literals, never in argv, and the
output is reduced to one status token that is never emitted.
"""

from __future__ import annotations

import json
import re
import secrets

import hostexec
import vaultlib as v

from .base import Handler, HandlerError

SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
SAFE_CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class MdbHandler(Handler):
    name = "MDB"
    # Values travel as JSON string literals, so nothing is unsafe in the script;
    # control characters are refused anyway to keep stdin line-safe.
    forbidden_chars = "\n\r\x00"
    required_keys = ("host", "container", "user", "auth_db", "admin_secret")

    def __init__(self, cfg, env, secret, binding):
        super().__init__(cfg, env, secret, binding)
        self.admin_user = binding.get("admin_user", "admin")
        self.admin_auth_db = binding.get("admin_auth_db", "admin")
        for key, val in (("user", binding["user"]), ("auth_db", binding["auth_db"]),
                         ("admin_user", self.admin_user), ("admin_auth_db", self.admin_auth_db)):
            if not SAFE_NAME.fullmatch(str(val)):
                raise v.OpsError(f"MDB binding {key} is not a plain name")
        if not SAFE_CONTAINER.fullmatch(binding["container"]):
            raise v.OpsError("MDB binding container name is not a valid container name")
        self.port = int(binding.get("port", 27017))
        self.self_admin = binding["admin_secret"] == secret

    def describe(self):
        return {"handler": self.name, "host": self.host, "container": self.binding["container"],
                "user": self.binding["user"], "auth_db": self.binding["auth_db"],
                "administered_by": "itself" if self.self_admin else self.admin_user}

    def _url(self, db: str) -> str:
        return f"mongodb://127.0.0.1:{self.port}/{db}"

    def _mongosh(self, script: str) -> str:
        """Run a script on stdin; return its single status token (never other output)."""
        result = hostexec.run(self.cfg, self.host,
                              ["docker", "exec", "-i", self.binding["container"],
                               "mongosh", "--quiet", "--nodb", "/dev/stdin"],
                              stdin=script)
        tokens = [w for w in result.stdout.split() if w.startswith("VO_")]
        return tokens[-1] if tokens else f"VO_NO_STATUS_RC_{result.rc}"

    def preflight(self, recovery: bool = False):
        b = self.binding
        running = hostexec.run(self.cfg, self.host, ["docker", "inspect", "-f", "{{.State.Running}}", b["container"]])
        checks = [v.Check("mdb_container_running", "PASS" if running.stdout.strip() == "true" else "FAIL",
                          f"{self.host}/{b['container']}")]
        if checks[0].status == "FAIL":
            return checks
        status = self._mongosh(
            f"const c = connect({json.dumps(self._url('admin'))});\n"
            "try { c.adminCommand({listDatabases: 1}); console.log('VO_OPEN'); }\n"
            "catch (e) { console.log(e.codeName === 'Unauthorized' ? 'VO_ENFORCED' : 'VO_ERROR'); }\n")
        checks.append(v.Check("mdb_authorization_enforced", "PASS" if status == "VO_ENFORCED" else "FAIL",
                              "unauthenticated commands are refused" if status == "VO_ENFORCED"
                              else "server reachable without credentials" if status == "VO_OPEN"
                              else f"could not check ({status})"))
        rejected = not self.probe("wrong-" + secrets.token_hex(12))
        checks.append(v.Check("mdb_password_auth_enforced", "PASS" if rejected else "FAIL",
                              f"a wrong password for {b['user']} is rejected" if rejected
                              else "a wrong password was accepted; the login probe would prove nothing"))
        try:
            v.find_secret(self.cfg, self.env, b["admin_secret"])
            checks.append(v.Check("mdb_admin_secret", "PASS",
                                  "this secret (self-administered)" if self.self_admin else b["admin_secret"]))
        except v.OpsError as exc:
            checks.append(v.Check("mdb_admin_secret", "FAIL", str(exc)))
        return checks

    def _admin_password(self) -> str:
        """Read the administrator's password from Vault CURRENT. Callers must never emit it."""
        _, detail = v.find_secret(self.cfg, self.env, self.binding["admin_secret"])
        return v.read_secret_value(self.cfg, self.env, detail.id)

    def apply(self, value: str) -> None:
        if any(c in value for c in self.forbidden_chars):
            raise HandlerError("Value contains characters MDB refuses")
        b = self.binding
        admin_pw = None
        try:
            admin_pw = self._admin_password()
            status = self._mongosh(
                f"const c = connect({json.dumps(self._url(self.admin_auth_db))});\n"
                f"try {{ c.auth({json.dumps(self.admin_user)}, {json.dumps(admin_pw)}); }}\n"
                "catch (e) { console.log('VO_ADMIN_AUTH_FAILED'); quit(0); }\n"
                f"try {{ c.getSiblingDB({json.dumps(b['auth_db'])}).changeUserPassword("
                f"{json.dumps(b['user'])}, {json.dumps(value)}); console.log('VO_CHANGED'); }}\n"
                "catch (e) { console.log('VO_CHANGE_FAILED_' + (e.codeName || 'ERROR')); }\n")
        finally:
            admin_pw = None
        if status == "VO_ADMIN_AUTH_FAILED":
            raise HandlerError(f"{self.admin_user} could not authenticate with {b['admin_secret']} CURRENT; "
                               "nothing was changed in MongoDB")
        if status != "VO_CHANGED":
            raise HandlerError(f"changeUserPassword failed ({status})")

    def probe(self, value: str) -> bool:
        b = self.binding
        status = self._mongosh(
            f"const c = connect({json.dumps(self._url(b['auth_db']))});\n"
            f"try {{ c.auth({json.dumps(b['user'])}, {json.dumps(value)}); console.log('VO_ACCEPTED'); }}\n"
            "catch (e) { console.log(e.codeName === 'AuthenticationFailed' ? 'VO_REJECTED' : 'VO_ERROR'); }\n")
        return status == "VO_ACCEPTED"
