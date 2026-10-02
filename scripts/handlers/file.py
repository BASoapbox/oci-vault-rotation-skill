"""FILE: a value stored in one or more files on a host, read by consumers at use time.

Binding:
  host             key under hosts
  files            list of {"path": absolute path,
                            "format": "whole" | "env" | "yaml",
                            "key": name (env and yaml only)}
                   whole  the file is the value (a trailing newline is kept as it was)
                   env    one KEY=value line
                   yaml   one `key: value` line, written unquoted
  verify_commands  optional list of argv lists run on the host after writing, with
                   empty stdin; each must exit 0. Retried for up to
                   verify_timeout seconds (default 30). Output is never emitted.

FILE restarts nothing: it suits values that are read when used (a password file
read per connection, a config read per run). A value baked into a running
process belongs to a handler that restarts it, such as COMPOSE.

apply()   rewrite each file atomically, in binding order: a temp file in the same
          directory, then rename, keeping mode and owner. A bind mount of the
          *directory* sees the new file; a bind mount of the single file would
          keep the old inode, so mount directories, not files.
verify()  every file holds the value, and every verify_command passes.
probe()   every file holds the value.
"""

from __future__ import annotations

import posixpath
import re
import time

import hostexec
import vaultlib as v

from .base import Handler, HandlerError

FORMATS = ("whole", "env", "yaml")
SAFE_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
# Characters that would change how each format parses an unquoted value.
FORBIDDEN = {
    "whole": "\n\r\x00",
    "env": "$#\"'\\ \t\n\r`\x00",
    "yaml": "#:{}[],&*!|>%@`\"'\\ \t\n\r\x00",
}


class FileHandler(Handler):
    name = "FILE"
    required_keys = ("host", "files")

    def __init__(self, cfg, env, secret, binding):
        super().__init__(cfg, env, secret, binding)
        files = binding["files"]
        if not isinstance(files, list) or not files:
            raise v.OpsError("FILE binding files must be a non-empty list")
        forbidden = set()
        for f in files:
            path, fmt, key = f.get("path", ""), f.get("format"), f.get("key", "")
            if not posixpath.isabs(path) or "\x00" in path or ".." in path.split("/"):
                raise v.OpsError("FILE paths must be absolute, without '..'")
            if fmt not in FORMATS:
                raise v.OpsError(f"FILE format must be one of {', '.join(FORMATS)}")
            if fmt != "whole" and not SAFE_KEY.fullmatch(key):
                raise v.OpsError(f"FILE {fmt} entries need a plain key")
            forbidden |= set(FORBIDDEN[fmt])
        self.forbidden_chars = "".join(sorted(forbidden))
        cmds = binding.get("verify_commands") or []
        if not all(isinstance(c, list) and c and all(isinstance(a, str) for a in c) for c in cmds):
            raise v.OpsError("FILE verify_commands must be a list of argv lists")

    def describe(self):
        return {"handler": self.name, "host": self.host,
                "files": [f"{f['path']}" + (f" [{f['key']}]" if f.get("key") else "") for f in self.binding["files"]],
                "verify_commands": len(self.binding.get("verify_commands") or [])}

    def _compare(self, f: dict, value: str) -> str:
        return hostexec.status_word(hostexec.run(
            self.cfg, self.host, ["python3", "-c", hostexec.FILE_COMPARE, f["path"], f["format"], f.get("key", "")],
            stdin=value))

    def _run_verify_commands(self, once: bool = False) -> bool:
        cmds = self.binding.get("verify_commands") or []
        if not cmds:
            return True
        deadline = time.monotonic() + (0 if once else int(self.binding.get("verify_timeout", 30)))
        while True:
            if all(hostexec.run(self.cfg, self.host, c, stdin="").ok for c in cmds):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(3)

    def preflight(self, recovery: bool = False):
        broken = "WARN" if recovery else "FAIL"
        checks = []
        for f in self.binding["files"]:
            # An empty comparison value proves the file is readable and the key unique,
            # without sending any secret.
            word = self._compare(f, "")
            label = f["path"] + (f" [{f['key']}]" if f.get("key") else "")
            checks.append(v.Check("file_present", "PASS" if word in ("MATCH", "DIFFERENT") else "FAIL",
                                  label if word in ("MATCH", "DIFFERENT") else f"{word}: {label}"))
        if self.binding.get("verify_commands"):
            passed = self._run_verify_commands(once=True)
            checks.append(v.Check("file_verify_commands", "PASS" if passed else broken,
                                  "pass" if passed else "fail" + (" (expected mid-rotation)" if recovery else "")))
        return checks

    def apply(self, value: str) -> None:
        if any(c in value for c in self.forbidden_chars):
            raise HandlerError("Value contains characters a FILE format cannot hold unquoted")
        for f in self.binding["files"]:
            result = hostexec.run(self.cfg, self.host,
                                  ["python3", "-c", hostexec.FILE_WRITE, f["path"], f["format"], f.get("key", "")],
                                  stdin=value)
            if hostexec.status_word(result) != "WRITTEN":
                raise HandlerError(f"Could not write {f['path']} ({hostexec.status_word(result)})")

    def probe(self, value: str) -> bool:
        return all(self._compare(f, value) == "MATCH" for f in self.binding["files"])

    def verify(self, value: str) -> None:
        if not self.probe(value):
            raise HandlerError("A file does not hold the new value")
        if not self._run_verify_commands():
            raise HandlerError("A verify_command did not pass with the new value")
