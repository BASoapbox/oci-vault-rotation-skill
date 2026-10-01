"""Run commands on a configured host over SSH, passing secret values only on stdin.

Rules every caller relies on:
  - A secret value is never placed in argv (local or remote), where it would be
    visible in process listings and shell history. It travels on stdin only.
  - Output from a command that received a secret on stdin is parsed for status
    words and never emitted: a failing remote tool could echo what it was given.
"""

from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Any

import vaultlib as v


@dataclass
class Result:
    rc: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def ssh_target(cfg: dict[str, Any], host_key: str) -> str:
    host = (cfg.get("hosts") or {}).get(host_key)
    if not host or not host.get("ssh"):
        raise v.OpsError(f"Host '{host_key}' is not configured under hosts.<name>.ssh")
    target = str(host["ssh"])
    if not v.SAFE_SSH_HOST.fullmatch(target.replace("@", "")):
        raise v.OpsError("hosts.<name>.ssh must be an ssh alias or user@host")
    return target


def run(cfg: dict[str, Any], host_key: str, argv: list[str], stdin: str | None = None,
        timeout: int = 180) -> Result:
    """Run argv on the host. The remote login shell receives one safely quoted string."""
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", ssh_target(cfg, host_key),
           "--", shlex.join(argv)]
    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return Result(124, "", "timeout")
    return Result(proc.returncode, proc.stdout, proc.stderr)


# Remote helpers. Each is passed as argv to `python3 -c`, so the script text is
# visible but contains no secret; values arrive on stdin.

ENV_COMPARE = r'''
import hmac, sys
path, key = sys.argv[1], sys.argv[2]
want = sys.stdin.read()
try:
    lines = open(path).read().splitlines()
except FileNotFoundError:
    print("NO_FILE"); sys.exit(0)
vals = [l.split("=", 1)[1] for l in lines if l.startswith(key + "=")]
if len(vals) != 1:
    print("MISSING" if not vals else "DUPLICATE"); sys.exit(0)
val = vals[0].strip()
if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
    val = val[1:-1]
print("MATCH" if hmac.compare_digest(val.encode(), want.encode()) else "DIFFERENT")
'''

ENV_READ = r'''
import sys
path, key = sys.argv[1], sys.argv[2]
vals = [l.split("=", 1)[1] for l in open(path).read().splitlines() if l.startswith(key + "=")]
if len(vals) != 1:
    sys.exit(3)
val = vals[0].strip()
if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
    val = val[1:-1]
sys.stdout.write(val)
'''

ENV_WRITE = r'''
import os, sys, tempfile
path, key = sys.argv[1], sys.argv[2]
val = sys.stdin.read()
lines = open(path).read().splitlines(keepends=True)
idx = [i for i, l in enumerate(lines) if l.startswith(key + "=")]
if len(idx) != 1:
    print("KEY_COUNT_%d" % len(idx)); sys.exit(3)
nl = "\n" if lines[idx[0]].endswith("\n") else ""
lines[idx[0]] = key + "=" + val + nl
st = os.stat(path)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".vaultops.")
try:
    with os.fdopen(fd, "w") as fh:
        fh.writelines(lines)
    os.chmod(tmp, st.st_mode & 0o7777)
    try:
        os.chown(tmp, st.st_uid, st.st_gid)
    except PermissionError:
        pass
    os.replace(tmp, path)
except BaseException:
    if os.path.exists(tmp):
        os.unlink(tmp)
    raise
print("WRITTEN")
'''

FILE_READ = r'''
import sys
path, key, mode = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
if mode == "whole":
    sys.stdout.write(text.strip()); sys.exit(0)
sep = "=" if mode == "env" else ":"
vals = [l.split(sep, 1)[1].strip() for l in text.splitlines() if l.strip().startswith(key + sep)]
if len(vals) != 1:
    sys.exit(3)
val = vals[0]
if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
    val = val[1:-1]
sys.stdout.write(val)
'''

CONTAINER_ENV_COMPARE = r'''
import hmac, json, subprocess, sys
container, var, match = sys.argv[1], sys.argv[2], sys.argv[3]
want = sys.stdin.read()
out = subprocess.run(["docker", "inspect", "--format", "{{json .Config.Env}}", container],
                     capture_output=True, text=True)
if out.returncode != 0:
    print("NO_CONTAINER"); sys.exit(0)
vals = [e.split("=", 1)[1] for e in json.loads(out.stdout) if e.startswith(var + "=")]
if len(vals) != 1:
    print("MISSING"); sys.exit(0)
ok = hmac.compare_digest(vals[0].encode(), want.encode()) if match == "exact" else (want in vals[0])
print("MATCH" if ok else "DIFFERENT")
'''


def status_word(result: Result) -> str:
    """First word of stdout, for helpers that print a single status token."""
    words = result.stdout.split()
    return words[0] if words else ("ERROR_RC_%d" % result.rc)
