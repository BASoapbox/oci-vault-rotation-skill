from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import helpers  # noqa: F401
import hostexec
import vaultlib as v
from handlers import build
from handlers.base import HandlerError
from test_handlers import CFG, VALUE, FakeHost, ok

ADMIN_PW = "Admin-Value-Never-In-Argv-3"
MDB = {"host": "box", "container": "app-mongo", "user": "app_user", "auth_db": "appdata", "admin_secret": "mongo-admin-pwd"}
FILES = {"host": "box", "files": [
    {"path": "/home/app/.config/app/app.pw", "format": "whole"},
    {"path": "/home/app/.config/app/dump.yaml", "format": "yaml", "key": "password"},
]}


def vault_with_admin():
    return (patch.object(v, "find_secret", return_value=(None, SimpleNamespace(id="admin-id"))),
            patch.object(v, "read_secret_value", return_value=ADMIN_PW))


class MdbHandlerTests(unittest.TestCase):
    def test_apply_authenticates_as_admin_and_sends_values_on_stdin_only(self):
        fake = FakeHost([(lambda a, s: "mongosh" in a, ok("VO_CHANGED\n"))])
        find, read = vault_with_admin()
        with patch.object(hostexec, "run", fake), find, read:
            build("MDB", CFG, "stage", "app-pwd", MDB).apply(VALUE)
        argv, stdin = fake.calls[0]
        self.assertIn('c.auth("admin", "%s")' % ADMIN_PW, stdin)
        self.assertIn('getSiblingDB("appdata").changeUserPassword("app_user", "%s")' % VALUE, stdin)
        for a in argv:
            self.assertNotIn(VALUE, a)
            self.assertNotIn(ADMIN_PW, a)

    def test_admin_auth_failure_changes_nothing_and_leaks_nothing(self):
        fake = FakeHost([(lambda a, s: "mongosh" in a, ok("VO_ADMIN_AUTH_FAILED\n"))])
        find, read = vault_with_admin()
        with patch.object(hostexec, "run", fake), find, read, self.assertRaises(HandlerError) as ctx:
            build("MDB", CFG, "stage", "app-pwd", MDB).apply(VALUE)
        self.assertIn("nothing was changed", str(ctx.exception))
        self.assertNotIn(ADMIN_PW, str(ctx.exception))

    def test_change_failure_raises(self):
        fake = FakeHost([(lambda a, s: "mongosh" in a, ok("VO_CHANGE_FAILED_UserNotFound\n"))])
        find, read = vault_with_admin()
        with patch.object(hostexec, "run", fake), find, read, self.assertRaises(HandlerError):
            build("MDB", CFG, "stage", "app-pwd", MDB).apply(VALUE)

    def test_values_are_json_escaped_in_the_script(self):
        fake = FakeHost([(lambda a, s: "mongosh" in a, ok("VO_CHANGED"))])
        find, read = vault_with_admin()
        tricky = 'a"b\\c'
        with patch.object(hostexec, "run", fake), find, read:
            build("MDB", CFG, "stage", "app-pwd", MDB).apply(tricky)
        self.assertIn('"a\\"b\\\\c"', fake.calls[0][1])

    def test_probe_true_only_on_successful_login(self):
        for out, want in (("VO_ACCEPTED", True), ("VO_REJECTED", False), ("", False), ("VO_ERROR", False)):
            fake = FakeHost([(lambda a, s: "mongosh" in a, ok(out))])
            with patch.object(hostexec, "run", fake):
                self.assertEqual(build("MDB", CFG, "stage", "s", MDB).probe(VALUE), want, out)

    def test_preflight_fails_when_server_does_not_enforce_auth(self):
        def mongosh(argv, stdin):
            return ok("VO_OPEN" if "listDatabases" in stdin else "VO_REJECTED")
        fake = FakeHost([(lambda a, s: "inspect" in a, ok("true")), (lambda a, s: "mongosh" in a, mongosh)])
        with patch.object(hostexec, "run", fake), patch.object(v, "find_secret", return_value=(None, None)):
            checks = {c.name: c.status for c in build("MDB", CFG, "stage", "s", MDB).preflight()}
        self.assertEqual(checks["mdb_authorization_enforced"], "FAIL")
        self.assertEqual(checks["mdb_password_auth_enforced"], "PASS")

    def test_preflight_fails_when_a_wrong_password_is_accepted(self):
        def mongosh(argv, stdin):
            return ok("VO_ENFORCED" if "listDatabases" in stdin else "VO_ACCEPTED")
        fake = FakeHost([(lambda a, s: "inspect" in a, ok("true")), (lambda a, s: "mongosh" in a, mongosh)])
        with patch.object(hostexec, "run", fake), patch.object(v, "find_secret", return_value=(None, None)):
            checks = {c.name: c.status for c in build("MDB", CFG, "stage", "s", MDB).preflight()}
        self.assertEqual(checks["mdb_password_auth_enforced"], "FAIL")

    def test_preflight_reads_no_secret_value(self):
        fake = FakeHost([(lambda a, s: "inspect" in a, ok("true")), (lambda a, s: "mongosh" in a, ok("VO_ENFORCED"))])
        with patch.object(hostexec, "run", fake), patch.object(v, "find_secret", return_value=(None, None)), \
             patch.object(v, "read_secret_value") as read:
            build("MDB", CFG, "stage", "s", MDB).preflight()
        read.assert_not_called()

    def test_self_administered_secret(self):
        h = build("MDB", CFG, "stage", "mongo-admin-pwd", {**MDB, "user": "admin", "auth_db": "admin"})
        self.assertEqual(h.describe()["administered_by"], "itself")

    def test_bad_binding_is_rejected(self):
        with self.assertRaises(v.OpsError):
            build("MDB", CFG, "stage", "s", {**MDB, "user": 'x"); db.dropDatabase(); ("'})
        with self.assertRaises(v.OpsError):
            build("MDB", CFG, "stage", "s", {k: val for k, val in MDB.items() if k != "admin_secret"})


class FileHandlerTests(unittest.TestCase):
    def test_forbidden_chars_cover_every_format_used(self):
        h = build("FILE", CFG, "stage", "s", FILES)
        for c in ":#\n\"' ":
            self.assertIn(c, h.forbidden_chars)
        self.assertNotIn("_", h.forbidden_chars)

    def test_apply_writes_every_file_in_order_with_value_on_stdin(self):
        fake = FakeHost([(lambda a, s: "python3" in a, ok("WRITTEN"))])
        with patch.object(hostexec, "run", fake):
            build("FILE", CFG, "stage", "s", FILES).apply(VALUE.replace("-", "_"))
        self.assertEqual([c[0][3] for c in fake.calls], [f["path"] for f in FILES["files"]])
        for argv, stdin in fake.calls:
            self.assertEqual(stdin, VALUE.replace("-", "_"))
        fake.assert_value_never_in_argv(self)

    def test_failed_write_raises(self):
        fake = FakeHost([(lambda a, s: "python3" in a, hostexec.Result(3, "KEY_COUNT_0", ""))])
        with patch.object(hostexec, "run", fake), self.assertRaises(HandlerError):
            build("FILE", CFG, "stage", "s", FILES).apply("abc123")

    def test_forbidden_value_is_refused_before_any_write(self):
        fake = FakeHost([])
        with patch.object(hostexec, "run", fake), self.assertRaises(HandlerError):
            build("FILE", CFG, "stage", "s", FILES).apply("has: colon")
        self.assertEqual(fake.calls, [])

    def test_probe_requires_every_file(self):
        answers = iter(["MATCH", "DIFFERENT"])
        fake = FakeHost([(lambda a, s: "python3" in a, lambda a, s: ok(next(answers)))])
        with patch.object(hostexec, "run", fake):
            self.assertFalse(build("FILE", CFG, "stage", "s", FILES).probe("abc"))

    def test_verify_fails_when_a_verify_command_fails(self):
        binding = {**FILES, "verify_commands": [["/usr/local/bin/app-check"]], "verify_timeout": 0}
        fake = FakeHost([(lambda a, s: "python3" in a, ok("MATCH")),
                         (lambda a, s: a == ["/usr/local/bin/app-check"], hostexec.Result(1, "", ""))])
        with patch.object(hostexec, "run", fake), self.assertRaises(HandlerError):
            build("FILE", CFG, "stage", "s", binding).verify("abc")

    def test_preflight_flags_a_missing_file_without_sending_a_value(self):
        fake = FakeHost([(lambda a, s: "python3" in a, ok("NO_FILE"))])
        with patch.object(hostexec, "run", fake):
            checks = build("FILE", CFG, "stage", "s", FILES).preflight()
        self.assertTrue(all(c.status == "FAIL" for c in checks))
        self.assertTrue(all(stdin == "" for _, stdin in fake.calls))

    def test_bad_bindings_are_rejected(self):
        for bad in ({"path": "relative/app.pw", "format": "whole"},
                    {"path": "/x/../etc/passwd", "format": "whole"},
                    {"path": "/x/app.env", "format": "ini"},
                    {"path": "/x/app.env", "format": "env"}):
            with self.subTest(bad=bad), self.assertRaises(v.OpsError):
                build("FILE", CFG, "stage", "s", {"host": "box", "files": [bad]})


class FileHelperScriptTests(unittest.TestCase):
    """Run the real remote helper scripts against temp files on this machine."""

    def run_helper(self, script, path, fmt, key, value):
        out = subprocess.run([sys.executable, "-c", script, str(path), fmt, key],
                             input=value, capture_output=True, text=True)
        return out.stdout.strip()

    def test_whole_file_keeps_absent_trailing_newline_and_mode(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "app.pw"); p.write_text("oldvalue"); os.chmod(p, 0o600)
            self.assertEqual(self.run_helper(hostexec.FILE_WRITE, p, "whole", "", "newvalue"), "WRITTEN")
            self.assertEqual(p.read_text(), "newvalue")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
            self.assertEqual(self.run_helper(hostexec.FILE_COMPARE, p, "whole", "", "newvalue"), "MATCH")

    def test_whole_file_keeps_trailing_newline(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "app.pw"); p.write_text("old\n")
            self.run_helper(hostexec.FILE_WRITE, p, "whole", "", "new")
            self.assertEqual(p.read_text(), "new\n")
            self.assertEqual(self.run_helper(hostexec.FILE_COMPARE, p, "whole", "", "new"), "MATCH")

    def test_yaml_and_env_rewrite_only_their_line(self):
        # Key names are deliberately neutral: the helpers are key-agnostic, and
        # password-named keys read as hardcoded credentials to secret scanners.
        with tempfile.TemporaryDirectory() as d:
            y = Path(d, "dump.yaml"); y.write_text("uri: mongodb://user@localhost/?authSource=x\n  field: old\n")
            e = Path(d, "app.env"); e.write_text("USER=admin\nFIELD=old\nOTHER=keep\n")
            self.run_helper(hostexec.FILE_WRITE, y, "yaml", "field", "new1")
            self.run_helper(hostexec.FILE_WRITE, e, "env", "FIELD", "new2")
            self.assertEqual(y.read_text(), "uri: mongodb://user@localhost/?authSource=x\n  field: new1\n")
            self.assertEqual(e.read_text(), "USER=admin\nFIELD=new2\nOTHER=keep\n")
            self.assertEqual(self.run_helper(hostexec.FILE_COMPARE, y, "yaml", "field", "new1"), "MATCH")
            self.assertEqual(self.run_helper(hostexec.FILE_COMPARE, e, "env", "FIELD", "nope"), "DIFFERENT")

    def test_duplicate_or_missing_key_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "x.env"); p.write_text("FIELD=a\nFIELD=b\n")
            self.assertEqual(self.run_helper(hostexec.FILE_WRITE, p, "env", "FIELD", "c"), "KEY_COUNT_2")
            self.assertEqual(p.read_text(), "FIELD=a\nFIELD=b\n")
            self.assertEqual(self.run_helper(hostexec.FILE_COMPARE, p, "env", "MISSINGKEY", "c"), "MISSING")
            self.assertEqual(self.run_helper(hostexec.FILE_COMPARE, Path(d, "nope"), "whole", "", "c"), "NO_FILE")

    def test_no_temp_file_is_left_behind(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "app.pw"); p.write_text("old")
            self.run_helper(hostexec.FILE_WRITE, p, "whole", "", "new")
            self.assertEqual(sorted(os.listdir(d)), ["app.pw"])


if __name__ == "__main__":
    unittest.main()
