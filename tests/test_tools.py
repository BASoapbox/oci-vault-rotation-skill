"""Classification, discovery, journal, and static safety guards."""
from __future__ import annotations

import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import helpers
import audit_journal
import discover_config
import tag_secret
import vaultlib as v

SCRIPTS = helpers.SCRIPTS


class TagTests(unittest.TestCase):
    def run_main(self, argv, detail, stored=None):
        client = MagicMock()
        response = SimpleNamespace(data=detail, headers={"etag": "etag-1"})
        client.get_secret.side_effect = [response, SimpleNamespace(data=SimpleNamespace(
            metadata=stored or {"owner": "blog", "rotationTag": "EXEMPT"},
            current_version_number=detail.current_version_number))]
        out = io.StringIO()
        with patch.object(sys, "argv", ["tag_secret.py", *argv]), \
             patch.object(v, "load_config", return_value=helpers.cfg()), \
             patch.object(v, "find_secret", return_value=(client, detail)), \
             patch.object(v, "wait_for_active", side_effect=lambda c, i: c.get_secret(i).data), \
             contextlib.redirect_stdout(out):
            code = tag_secret.main()
        return code, out.getvalue(), client

    def test_dry_run_does_not_update(self):
        detail = helpers.secret_detail(metadata={"owner": "blog"})
        code, out, client = self.run_main(["--env", "stage", "--secret", "demo-app_user-pwd", "--tag", "EXEMPT"], detail)
        self.assertEqual(code, 0)
        client.update_secret.assert_not_called()
        self.assertIn("tag:stage:demo-app_user-pwd:v4:EXEMPT", out)

    def test_execute_preserves_other_metadata_and_uses_etag(self):
        detail = helpers.secret_detail(metadata={"owner": "blog"})
        code, out, client = self.run_main(["--env", "stage", "--secret", "demo-app_user-pwd", "--tag", "EXEMPT",
                                           "--execute", "--confirm", "tag:stage:demo-app_user-pwd:v4:EXEMPT"], detail)
        self.assertEqual(code, 0, out)
        call = client.update_secret.call_args
        self.assertEqual(call.args[1].metadata, {"owner": "blog", "rotationTag": "EXEMPT"})
        self.assertEqual(call.kwargs["if_match"], "etag-1")
        self.assertIn("METADATA_ONLY", out)

    def test_retag_removes_legacy_key(self):
        detail = helpers.secret_detail(metadata={"owner": "blog", "rotationClass": "ADB"})
        code, out, client = self.run_main(
            ["--env", "stage", "--secret", "demo-app_user-pwd", "--tag", "P2:ADB",
             "--execute", "--confirm", "tag:stage:demo-app_user-pwd:v4:P2:ADB"], detail,
            stored={"owner": "blog", "rotationTag": "P2:ADB"})
        self.assertEqual(code, 0, out)
        self.assertEqual(client.update_secret.call_args.args[1].metadata, {"owner": "blog", "rotationTag": "P2:ADB"})
        self.assertIn('"legacy_keys_removed": ["rotationClass"]', out)

    def test_invalid_tag_is_rejected_before_any_oci_call(self):
        with patch.object(sys, "argv", ["tag_secret.py", "--env", "stage", "--secret", "x", "--tag", "P3"]), \
             patch.object(v, "find_secret") as find, self.assertRaises(v.OpsError):
            tag_secret.main()
        find.assert_not_called()

    def test_warnings_explain_why_a_tag_cannot_rotate_yet(self):
        cfg = helpers.cfg()
        self.assertTrue(any("JWT" in w for w in tag_secret.warnings_for(cfg, "stage", "demo-app_user-pwd", "P2:ADB:JWT")))
        self.assertTrue(any("vault_only_secrets" in w for w in tag_secret.warnings_for(cfg, "stage", "other", "P1")))
        self.assertTrue(any("APP_USER" in w for w in tag_secret.warnings_for(cfg, "stage", "demo-app_user-pwd", "P1")))
        self.assertEqual(tag_secret.warnings_for(cfg, "stage", "demo-app_user-pwd", "P2:ADB"), [])


class DiscoveryTests(unittest.TestCase):
    def test_secret_mapping_heuristic(self):
        m = discover_config.map_secret
        self.assertEqual(m("secret-adw-example-stage-db-admin-pwd", "adw-example-stage-db"), "ADMIN")
        self.assertEqual(m("secret-adw-example-stage-db-report_user-pwd", "adw-example-stage-db"), "REPORT_USER")
        self.assertEqual(m("orders-db-app-user-pwd", "orders-db"), "APP_USER")
        # All three recognised suffixes are stripped from the username.
        for suffix in ("pwd", "pass", "passw" + "ord"):
            self.assertEqual(discover_config.SUFFIX.sub("", f"x-{suffix}"), "x")
        self.assertIsNone(m("APP_JWT_SIGNING_KEY", "adw-example-stage-db"))
        self.assertIsNone(m("secret-adw-example-stage-db-pwd", "adw-example-stage-db"))

    def test_environment_tokens(self):
        self.assertEqual(discover_config.env_for("cmp-example-stage-app"), "stage")
        self.assertEqual(discover_config.env_for("cmp-example-prod-db"), "prod")
        self.assertEqual(discover_config.env_for("cmp-example-shared"), "cmp-example-shared")
        self.assertEqual(discover_config.env_for("production"), "production")


class JournalTests(unittest.TestCase):
    def test_sensitive_detail_is_rejected(self):
        a = SimpleNamespace(detail="new password is Abc123", journal="/tmp/x", env="stage", secret="s",
                            event="rotation_completed", status="SUCCESS", actor="me", database_user=None, version=None)
        with self.assertRaises(v.OpsError):
            audit_journal.record(a, None)

    def test_record_and_report_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp, "j.jsonl"))
            for status in ("STOPPED", "SUCCESS"):
                a = SimpleNamespace(detail="completed after recovery", journal=path, env="stage", secret="s",
                                    event="rotation_completed", status=status, actor="me", database_user="APP_USER",
                                    version=5)
                with contextlib.redirect_stdout(io.StringIO()):
                    audit_journal.record(a, None)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                audit_journal.report(SimpleNamespace(journal=path), None)
            report = json.loads(out.getvalue())
            self.assertEqual(report["entries"], 2)
            self.assertEqual(report["latest"][0]["status"], "SUCCESS")


class StaticSafetyTests(unittest.TestCase):
    """Guards that survive refactoring: read-only tools must never touch secret content."""

    READ_ONLY = ("vault_inventory.py", "tag_secret.py", "preflight.py", "discover_config.py", "audit_journal.py")
    VALUE_READS = re.compile(r"get_secret_bundle|read_secret_value|wallet_password\(|password_from_policy|stage_pending")

    def test_read_only_tools_never_read_or_write_values(self):
        for name in self.READ_ONLY:
            with self.subTest(script=name):
                self.assertIsNone(self.VALUE_READS.search((SCRIPTS / name).read_text()))

    def test_verify_reads_values_only_after_confirmation(self):
        source = (SCRIPTS / "verify.py").read_text()
        body = source[source.index("def adb_login"):source.index("def main")]
        self.assertLess(body.index("args.confirm != phrase"), body.index("read_secret_value"))

    def test_consumer_sync_reads_values_only_after_confirmation(self):
        source = (SCRIPTS / "verify.py").read_text()
        body = source[source.index("def consumer_sync"):source.index("def main")]
        self.assertLess(body.index("args.confirm != phrase"), body.index("read_secret_value"))

    def test_handlers_never_print(self):
        for path in (SCRIPTS / "handlers").glob("*.py"):
            with self.subTest(handler=path.name):
                self.assertNotIn("print(", path.read_text())

    def test_no_exception_text_is_emitted_by_executors(self):
        for name in ("rotate_adb_user.py", "rotate_adb_admin.py", "rotate_vault_only.py", "rotate_secret.py",
                     "import_secret.py", "verify.py"):
            with self.subTest(script=name):
                source = (SCRIPTS / name).read_text()
                # str(exc) is allowed only for OpsError, whose messages are authored in this codebase.
                lines = source.splitlines()
                for i, line in enumerate(lines):
                    if "str(exc)" not in line:
                        continue
                    guarded_inline = "isinstance(exc, v.OpsError)" in line
                    enclosing = next((l for l in reversed(lines[:i]) if l.strip().startswith("except")), "")
                    self.assertTrue(guarded_inline or "OpsError" in enclosing, f"{name}:{i + 1}: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
