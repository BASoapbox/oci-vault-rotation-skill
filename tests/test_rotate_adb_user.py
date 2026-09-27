from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import MagicMock, patch

import helpers
from helpers import CURRENT_SECRET, NEW_SECRET, Connection
import rotate_adb_user as rot
import vaultlib as v

PHRASE = "rotate:stage:demo-app_user-pwd:v4"


def preflight_result(detail=None, client=None):
    return (client or MagicMock(), detail or helpers.secret_detail(),
            helpers.cfg()["environments"]["stage"]["databases"]["demo"],
            {"wallet_dir": "/wallet", "service_alias": "demodb_low"}, "APP_USER", [])


class UserRotationTests(unittest.TestCase):
    def run_quiet(self, fn, *a):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fn(*a)
        return code, out.getvalue()

    def test_dry_run_reads_no_credentials_and_prints_phrase(self):
        with patch.object(rot, "preflight", return_value=preflight_result()), \
             patch.object(v, "read_secret_value") as read, patch.object(v, "stage_pending") as stage:
            code, out = self.run_quiet(rot.execute, {}, helpers.args())
        self.assertEqual(code, 0)
        read.assert_not_called()
        stage.assert_not_called()
        self.assertIn(PHRASE, out)
        self.assertIn('"result": "NO_MUTATION"', out)

    def test_wrong_confirmation_blocks_before_any_read(self):
        with patch.object(rot, "preflight", return_value=preflight_result()), \
             patch.object(v, "read_secret_value") as read, self.assertRaises(v.OpsError):
            self.run_quiet(rot.execute, {}, helpers.args(execute=True, confirm="rotate:stage:demo-app_user-pwd:v3"))
        read.assert_not_called()

    def test_transaction_order_and_redaction(self):
        events: list[str] = []
        client = MagicMock()
        client.get_secret.return_value.data.current_version_number = 4

        def verify(_db, _w, user, password, _wp):
            events.append(f"verify:{user}:{'new' if password == NEW_SECRET else 'current'}")

        with patch.object(rot, "preflight", return_value=preflight_result(client=client)), \
             patch.object(v, "find_secret", return_value=(client, helpers.secret_detail(name="demo-admin-pwd"))), \
             patch.object(v, "read_secret_value", return_value=CURRENT_SECRET), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "verify_login", side_effect=verify), \
             patch.object(v, "password_from_policy", return_value=NEW_SECRET), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", side_effect=lambda *a: events.append("stage") or 5), \
             patch.object(v, "connect", side_effect=lambda *a: Connection(events)), \
             patch.object(v, "promote_pending_version", side_effect=lambda *a: events.append("promote") or 5):
            code, out = self.run_quiet(rot.execute, {}, helpers.args(execute=True, confirm=PHRASE))

        self.assertEqual(code, 0, out)
        self.assertEqual(events, ["verify:ADMIN:current", "stage", "alter", "commit", "verify:APP_USER:new", "promote"])
        self.assertNotIn(CURRENT_SECRET, out)
        self.assertNotIn(NEW_SECRET, out)
        self.assertIn('"result": "SUCCESS"', out)

    def test_stop_after_alter_reports_pending_state(self):
        client = MagicMock()
        client.get_secret.return_value.data.current_version_number = 4
        calls = {"n": 0}

        def verify(*_a):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError(f"ORA-01017 invalid credential {NEW_SECRET}")

        with patch.object(rot, "preflight", return_value=preflight_result(client=client)), \
             patch.object(v, "find_secret", return_value=(client, helpers.secret_detail())), \
             patch.object(v, "read_secret_value", return_value=CURRENT_SECRET), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "verify_login", side_effect=verify), \
             patch.object(v, "password_from_policy", return_value=NEW_SECRET), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", return_value=5), \
             patch.object(v, "connect", side_effect=lambda *a: Connection([])), \
             patch.object(v, "promote_pending_version") as promote:
            code, out = self.run_quiet(rot.execute, {}, helpers.args(execute=True, confirm=PHRASE))

        self.assertEqual(code, 2)
        promote.assert_not_called()
        self.assertIn("MANUAL_RECOVERY_REQUIRED", out)
        self.assertIn("DATABASE_EXPECTED_TO_MATCH_PENDING_VERSION", out)
        # The driver echoed the password in its message; it must not reach output.
        self.assertNotIn(NEW_SECRET, out)
        self.assertIn('"error_type": "RuntimeError"', out)

    def test_auto_generation_is_disabled_then_restored(self):
        client = MagicMock()
        client.get_secret.return_value.data.current_version_number = 4
        detail = helpers.secret_detail(autogen=True)
        with patch.object(rot, "preflight", return_value=preflight_result(detail=detail, client=client)), \
             patch.object(v, "find_secret", return_value=(client, detail)), \
             patch.object(v, "read_secret_value", return_value=CURRENT_SECRET), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "verify_login"), \
             patch.object(v, "password_from_policy", return_value=NEW_SECRET), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", return_value=5), \
             patch.object(v, "connect", side_effect=lambda *a: Connection([])), \
             patch.object(v, "promote_pending_version", return_value=5), \
             patch.object(v, "set_auto_generation") as autogen:
            code, _ = self.run_quiet(rot.execute, {}, helpers.args(execute=True, confirm=PHRASE))
        self.assertEqual(code, 0)
        self.assertEqual([c.args[2] for c in autogen.call_args_list], [False, True])
        self.assertEqual(autogen.call_args_list[1].args[3], "ctx")

    def pending_run(self, fn, current_works, pending_works, phrase_kind):
        client = MagicMock()
        client.get_secret.return_value.data.current_version_number = 4
        pre = list(preflight_result(client=client)); pre[5] = [5]
        phrase = f"{phrase_kind}:stage:demo-app_user-pwd:current-v4:pending-v5"
        events: list[str] = []
        with patch.object(rot, "preflight", return_value=tuple(pre)), \
             patch.object(v, "read_secret_value", side_effect=[CURRENT_SECRET, NEW_SECRET, "ADMIN_VALUE"]), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "can_login", side_effect=[current_works, pending_works]), \
             patch.object(v, "pending_versions", return_value=[5]), \
             patch.object(v, "find_secret", return_value=(client, helpers.secret_detail(name="demo-admin-pwd"))), \
             patch.object(v, "connect", side_effect=lambda *a: events.append(f"connect:{a[2]}") or Connection(events)), \
             patch.object(v, "verify_login", side_effect=lambda *a: events.append("verify")), \
             patch.object(v, "promote_pending_version", side_effect=lambda *a: events.append("promote") or 5):
            code, out = self.run_quiet(fn, {}, helpers.args(execute=True, confirm=phrase))
        return code, out, events

    def test_recovery_promotes_pending_that_authenticates(self):
        code, out, events = self.pending_run(rot.run_recovery, False, True, "recover")
        self.assertEqual(code, 0, out)
        self.assertEqual(events, ["promote"])
        self.assertNotIn(NEW_SECRET, out)

    def test_recovery_does_not_promote_when_database_uses_current(self):
        code, out, events = self.pending_run(rot.run_recovery, True, False, "recover")
        self.assertEqual(code, 2)
        self.assertEqual(events, [])
        self.assertIn("DATABASE_MATCHES_CURRENT_PENDING_REMAINS", out)

    def test_resume_applies_staged_value_as_admin_then_promotes(self):
        code, out, events = self.pending_run(rot.run_resume, True, False, "resume")
        self.assertEqual(code, 0, out)
        self.assertEqual(events, ["connect:ADMIN", "alter", "commit", "verify", "promote"])
        for value in (CURRENT_SECRET, NEW_SECRET, "ADMIN_VALUE"):
            self.assertNotIn(value, out)

    def test_resume_refuses_when_pending_already_works(self):
        code, out, events = self.pending_run(rot.run_resume, False, True, "resume")
        self.assertEqual(code, 2)
        self.assertEqual(events, [])
        self.assertIn("RESUME_PRECONDITION_NOT_MET", out)

    def test_admin_secret_is_rejected(self):
        with patch.object(v, "find_secret") as find, self.assertRaises(v.OpsError):
            rot.preflight(helpers.cfg(), "stage", "demo-admin-pwd")
        find.assert_not_called()

    def test_unclassified_secret_blocks_preflight(self):
        client = MagicMock()
        detail = helpers.secret_detail(metadata={})
        with patch.object(v, "find_secret", return_value=(client, detail)), \
             patch.object(v, "connectivity", return_value=([v.Check("adb_lifecycle", "PASS", "AVAILABLE")],
                                                          {"wallet_dir": "/w", "service_alias": "a"})), \
             patch.object(v, "pending_versions", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()), self.assertRaises(v.OpsError):
            rot.preflight(helpers.cfg(), "stage", "demo-app_user-pwd")


if __name__ == "__main__":
    unittest.main()
