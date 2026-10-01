"""COMPOSE: a variable in a Docker Compose project's env file, read by its services.

Binding:
  host            key under hosts
  project_dir     directory holding docker-compose.yml and the env file
  env_var         variable in the env file
  services        services to recreate so they pick up the new value
  env_file        default ".env", relative to project_dir
  url_embedded    true when the value is interpolated into a URL (e.g. a
                  database URL); forbids URL-reserved characters
  container_env   optional list of {"service", "var", "match": "exact"|"contains"}:
                  after recreation, the running container must carry the value
  verify_command  optional argv run on the host after recreation; must exit 0.
                  Retried for up to verify_timeout seconds (default 60).

apply()   rewrite the one env-file line atomically (mode and owner kept), then
          `docker compose up -d --no-deps --pull never <services>`, then wait
          for each service to be running and, if it has a healthcheck, healthy.
verify()  env file holds the value, services were recreated, container_env
          matches, verify_command passes.
probe()   env file holds the value.
"""

from __future__ import annotations

import json
import posixpath
import re
import time

import hostexec
import vaultlib as v

from .base import Handler, HandlerError

SAFE_SERVICE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SAFE_VAR = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
COMPOSE_SH = 'cd "$1" && shift && exec docker compose "$@"'


class ComposeHandler(Handler):
    name = "COMPOSE"
    # $ is interpolation, # a comment, quotes/backslash/whitespace change parsing.
    forbidden_chars = "$#\"'\\ \t\n`"
    required_keys = ("host", "project_dir", "env_var", "services")

    def __init__(self, cfg, env, secret, binding):
        super().__init__(cfg, env, secret, binding)
        if not SAFE_VAR.fullmatch(binding["env_var"]):
            raise v.OpsError("COMPOSE env_var must be an upper-case variable name")
        if not all(SAFE_SERVICE.fullmatch(s) for s in binding["services"]):
            raise v.OpsError("COMPOSE services must be plain service names")
        if not posixpath.isabs(binding["project_dir"]):
            raise v.OpsError("COMPOSE project_dir must be absolute")
        if binding.get("url_embedded"):
            self.forbidden_chars = self.forbidden_chars + "@:/?%&+=[]"
        self.env_path = posixpath.join(binding["project_dir"], binding.get("env_file", ".env"))
        self._before: dict[str, str] = {}

    def describe(self):
        b = self.binding
        return {"handler": self.name, "host": self.host, "env_file": self.env_path, "env_var": b["env_var"],
                "services": b["services"]}

    def _compose(self, *args: str) -> hostexec.Result:
        return hostexec.run(self.cfg, self.host, ["sh", "-c", COMPOSE_SH, "_", self.binding["project_dir"], *args])

    def _container_ids(self) -> dict[str, str]:
        ids = {}
        for service in self.binding["services"]:
            r = self._compose("ps", "-q", service)
            ids[service] = r.stdout.strip() if r.ok else ""
        return ids

    def _states(self) -> dict[str, tuple[str, str]]:
        r = self._compose("ps", "--format", "json", *self.binding["services"])
        states: dict[str, tuple[str, str]] = {}
        text = r.stdout.strip()
        rows = json.loads(text) if text.startswith("[") else [json.loads(l) for l in text.splitlines() if l.strip()]
        for row in rows:
            states[row.get("Service", "")] = (row.get("State", ""), row.get("Health", ""))
        return states

    def preflight(self, recovery: bool = False):
        broken = "WARN" if recovery else "FAIL"
        b = self.binding
        present = hostexec.run(self.cfg, self.host, ["python3", "-c", hostexec.ENV_COMPARE, self.env_path, b["env_var"]],
                               stdin="")
        word = hostexec.status_word(present)
        checks = [v.Check("compose_env_var", "PASS" if word in ("MATCH", "DIFFERENT") else "FAIL",
                          f"{b['env_var']} in {self.env_path}" if word in ("MATCH", "DIFFERENT") else f"{word}: {self.env_path}")]
        services = self._compose("config", "--services")
        known = set(services.stdout.split()) if services.ok else set()
        missing = [s for s in b["services"] if s not in known]
        checks.append(v.Check("compose_services_defined", "PASS" if services.ok and not missing else "FAIL",
                              ", ".join(b["services"]) if not missing else f"not in project: {', '.join(missing) or 'compose config failed'}"))
        states = self._states() if services.ok else {}
        down = [s for s in b["services"] if states.get(s, ("", ""))[0] != "running"]
        checks.append(v.Check("compose_services_running", "PASS" if not down else broken,
                              "all running" if not down else f"not running: {', '.join(down)}"))
        if b.get("verify_command"):
            passed = self._run_verify_command(once=True)
            checks.append(v.Check("compose_verify_command", "PASS" if passed else broken,
                                  "passes" if passed else "fails" + (" (expected mid-rotation)" if recovery else "")))
        return checks

    def _run_verify_command(self, once: bool = False) -> bool:
        cmd = self.binding.get("verify_command")
        if not cmd:
            return True
        deadline = time.monotonic() + (0 if once else int(self.binding.get("verify_timeout", 60)))
        while True:
            if hostexec.run(self.cfg, self.host, list(cmd)).ok:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(3)

    def apply(self, value: str) -> None:
        if not value or any(c in value for c in self.forbidden_chars):
            raise HandlerError("Value contains characters the env file or its consumers cannot take unquoted")
        self._before = self._container_ids()
        written = hostexec.run(self.cfg, self.host, ["python3", "-c", hostexec.ENV_WRITE, self.env_path,
                                                     self.binding["env_var"]], stdin=value)
        if hostexec.status_word(written) != "WRITTEN":
            raise HandlerError(f"Env file update failed ({hostexec.status_word(written)})")
        up = self._compose("up", "-d", "--no-deps", "--pull", "never", *self.binding["services"])
        if not up.ok:
            raise HandlerError(f"docker compose up failed (exit {up.rc}); env file already holds the new value")
        deadline = time.monotonic() + int(self.binding.get("start_timeout", 120))
        while True:
            states = self._states()
            ready = all(states.get(s, ("", ""))[0] == "running" and states.get(s, ("", ""))[1] in ("", "healthy")
                        for s in self.binding["services"])
            if ready:
                return
            if time.monotonic() >= deadline:
                raise HandlerError("Services did not become running/healthy after recreation")
            time.sleep(3)

    def verify(self, value: str) -> None:
        if not self.probe(value):
            raise HandlerError("Env file does not hold the new value")
        if self._before:
            after = self._container_ids()
            stale = [s for s in self.binding["services"] if after.get(s) and after.get(s) == self._before.get(s)]
            if stale:
                raise HandlerError(f"Services were not recreated: {', '.join(stale)}")
        for check in self.binding.get("container_env") or []:
            ids = self._container_ids()
            cid = ids.get(check["service"]) or self._compose("ps", "-q", check["service"]).stdout.strip()
            r = hostexec.run(self.cfg, self.host, ["python3", "-c", hostexec.CONTAINER_ENV_COMPARE, cid, check["var"],
                                                   check.get("match", "exact")], stdin=value)
            if hostexec.status_word(r) != "MATCH":
                raise HandlerError(f"Container {check['service']} does not carry the new {check['var']}")
        if not self._run_verify_command():
            raise HandlerError("verify_command did not pass with the new value")

    def probe(self, value: str) -> bool:
        r = hostexec.run(self.cfg, self.host, ["python3", "-c", hostexec.ENV_COMPARE, self.env_path,
                                               self.binding["env_var"]], stdin=value)
        return hostexec.status_word(r) == "MATCH"
