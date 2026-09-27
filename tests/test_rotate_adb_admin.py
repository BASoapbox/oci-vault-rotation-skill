from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import MagicMock, patch

import helpers
from helpers import CURRENT_SECRET, NEW_SECRET, PENDING_SECRET, Connection
import rotate_adb_admin as admin
import vaultlib as v

SECRET = "demo-admin-pwd"


def preflight_result(client=None, pending=None, autogen=False):
    return (client or MagicMock(), helpers.secret_detail(version=2, autogen=autogen, name=SECRET),
            helpers.cfg()["environments"]["stage"]["databases"]["demo"],
            {"wallet_dir": "/wallet", "service_alias": "demodb_low"}, 2, pending or [])


def quiet(fn, *a):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fn(*a)
    return code, out.getvalue()


class AdminRotationTests(unittest.TestCase):
    def test_dry_run_never_reads_credentials(self):
        with patch.object(admin, "admin_preflight", return_value=preflight_result()), \
             patch.object(v, "read_secret_value") as read:
            code, out = quiet(admin.run_rotation, {}, helpers.args(secret=SECRET))
        self.assertEqual(code, 0)
        read.assert_not_called()
        self.assertIn(f"rotate-admin:stage:{SECRET}:v2", out)

    def test_wrong_confirmation_blocks_before_credential_read(self):
        with patch.object(admin, "admin_preflight", return_value=preflight_result()), \
             patch.object(v, "read_secret_value") as read, self.assertRaises(v.OpsError):
            quiet(admin.run_rotation, {}, helpers.args(secret=SECRET, execute=True, confirm="wrong"))
        read.assert_not_called()

    def test_rotation_stages_before_alter_and_promotes_after_new_login(self):
        events: list[str] = []
        client = MagicMock()
        client.get_secret.return_value.data.current_version_number = 2

        def verify(_db, _w, _u, password, _wp):
            events.append("verify-new" if password == NEW_SECRET else "verify-current")

        with patch.object(admin, "admin_preflight", return_value=preflight_result(client)), \
             patch.object(v, "read_secret_value", return_value=CURRENT_SECRET), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "password_from_policy", return_value=NEW_SECRET), \
             patch.object(v, "verify_login", side_effect=verify), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", side_effect=lambda *a: events.append("stage") or 3), \
             patch.object(v, "connect", side_effect=lambda *a: Connection(events)), \
             patch.object(v, "promote_pending_version", side_effect=lambda *a: events.append("promote") or 3):
            code, out = quiet(admin.run_rotation, {}, helpers.args(secret=SECRET, execute=True,
                                                                    confirm=f"rotate-admin:stage:{SECRET}:v2"))
        self.assertEqual(code, 0, out)
        self.assertEqual(events, ["verify-current", "stage", "alter", "commit", "verify-new", "promote"])
        self.assertNotIn(CURRENT_SECRET, out)
        self.assertNotIn(NEW_SECRET, out)

    def test_policy_restore_failure_after_promotion_is_not_reported_as_rotation_failure(self):
        client = MagicMock()
        client.get_secret.return_value.data.current_version_number = 2
        with patch.object(admin, "admin_preflight", return_value=preflight_result(client, autogen=True)), \
             patch.object(v, "read_secret_value", return_value=CURRENT_SECRET), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "password_from_policy", return_value=NEW_SECRET), \
             patch.object(v, "verify_login"), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", return_value=3), \
             patch.object(v, "connect", side_effect=lambda *a: Connection([])), \
             patch.object(v, "promote_pending_version", return_value=3), \
             patch.object(v, "set_auto_generation", side_effect=[None, RuntimeError("x"), RuntimeError("x")]):
            code, out = quiet(admin.run_rotation, {}, helpers.args(secret=SECRET, execute=True,
                                                                    confirm=f"rotate-admin:stage:{SECRET}:v2"))
        self.assertEqual(code, 2)
        self.assertIn("POLICY_RESTORE_REQUIRED", out)
        self.assertIn("DATABASE_AND_VAULT_CURRENT_MATCH", out)

    def recovery(self, current_works, pending_works):
        client = MagicMock()
        phrase = f"recover-admin:stage:{SECRET}:current-v2:pending-v3"
        with patch.object(admin, "admin_preflight", return_value=preflight_result(client, [3])), \
             patch.object(v, "read_secret_value", side_effect=[CURRENT_SECRET, PENDING_SECRET]), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "can_login", side_effect=[current_works, pending_works]), \
             patch.object(v, "promote_pending_version", return_value=3) as promote:
            code, out = quiet(admin.run_recovery, {}, helpers.args(secret=SECRET, execute=True, confirm=phrase,
                                                                    recover_pending=True))
        return code, out, promote

    def test_recovery_promotes_only_pending_that_authenticates(self):
        code, out, promote = self.recovery(current_works=False, pending_works=True)
        self.assertEqual(code, 0)
        promote.assert_called_once()
        self.assertNotIn(PENDING_SECRET, out)

    def test_recovery_leaves_pending_when_database_uses_current(self):
        code, out, promote = self.recovery(current_works=True, pending_works=False)
        self.assertEqual(code, 2)
        promote.assert_not_called()
        self.assertIn("DATABASE_MATCHES_CURRENT_PENDING_REMAINS", out)

    def test_recovery_stops_on_ambiguous_state(self):
        for both in (True, False):
            code, out, promote = self.recovery(current_works=both, pending_works=both)
            self.assertEqual(code, 2)
            promote.assert_not_called()
            self.assertIn("AMBIGUOUS_LOGIN_STATE", out)

    def test_resume_refuses_when_pending_already_authenticates(self):
        client = MagicMock()
        phrase = f"resume-admin:stage:{SECRET}:current-v2:pending-v3"
        with patch.object(admin, "admin_preflight", return_value=preflight_result(client, [3])), \
             patch.object(v, "read_secret_value", side_effect=[CURRENT_SECRET, PENDING_SECRET]), \
             patch.object(v, "wallet_password", return_value=None), \
             patch.object(v, "can_login", side_effect=[False, True]), \
             patch.object(v, "connect") as connect:
            code, out = quiet(admin.run_resume, {}, helpers.args(secret=SECRET, execute=True, confirm=phrase,
                                                                  resume_pending=True))
        self.assertEqual(code, 2)
        connect.assert_not_called()
        self.assertIn("RESUME_PRECONDITION_NOT_MET", out)

    def test_non_admin_secret_is_rejected(self):
        with patch.object(v, "find_secret") as find, self.assertRaises(v.OpsError):
            admin.admin_preflight(helpers.cfg(), "stage", "demo-app_user-pwd", allow_pending=False)
        find.assert_not_called()


if __name__ == "__main__":
    unittest.main()
