from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import MagicMock, patch

import helpers
from helpers import NEW_SECRET
import rotate_vault_only as p1
import vaultlib as v

SECRET = "demo-webhook-token"
PHRASE = f"rotate-p1:stage:{SECRET}:v4"


def quiet(fn, *a):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fn(*a)
    return code, out.getvalue()


def detail(tag="P1", autogen=False):
    return helpers.secret_detail(name=SECRET, metadata={"rotationTag": tag}, autogen=autogen)


def client_at(version=4):
    client = MagicMock()
    client.get_secret.return_value.data.current_version_number = version
    return client


class PreflightTests(unittest.TestCase):
    def blocked(self, cfg, secret=SECRET, tag="P1"):
        with patch.object(v, "find_secret", return_value=(client_at(), detail(tag))), \
             patch.object(v, "pending_versions", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                p1.preflight(cfg, "stage", secret)
                return None
            except v.OpsError:
                return out.getvalue()

    def test_p1_and_listed_passes(self):
        self.assertIsNone(self.blocked(helpers.cfg()))

    def test_both_gates_are_required(self):
        self.assertIn("config_vault_only", self.blocked(helpers.cfg(_vault_only=[])))
        self.assertIn("rotation_tag", self.blocked(helpers.cfg(), tag="P2:ADB"))
        self.assertIn("rotation_tag", self.blocked(helpers.cfg(), tag="EXEMPT"))

    def test_database_secret_cannot_rotate_vault_only(self):
        cfg = helpers.cfg(_vault_only=["demo-app_user-pwd"])
        self.assertIn("no_database_mapping", self.blocked(cfg, secret="demo-app_user-pwd"))


class RotationTests(unittest.TestCase):
    def run_exec(self, readback, autogen=False):
        events: list[str] = []
        client = client_at()
        d = detail(autogen=autogen)
        with patch.object(p1, "preflight", return_value=(client, d, [])), \
             patch.object(v, "password_from_policy", return_value=NEW_SECRET), \
             patch.object(v, "wait_for_active", return_value=client.get_secret.return_value.data), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", side_effect=lambda *a: events.append("stage") or 5), \
             patch.object(v, "read_secret_value", side_effect=lambda *a: events.append("readback") or readback), \
             patch.object(v, "promote_pending_version", side_effect=lambda *a: events.append("promote") or 5), \
             patch.object(v, "set_auto_generation", side_effect=lambda *a: events.append(f"autogen:{a[2]}")):
            code, out = quiet(p1.run_rotation, {}, helpers.args(secret=SECRET, execute=True, confirm=PHRASE))
        return code, out, events

    def test_dry_run_changes_nothing(self):
        with patch.object(p1, "preflight", return_value=(client_at(), detail(), [])), \
             patch.object(v, "stage_pending") as stage:
            code, out = quiet(p1.run_rotation, {}, helpers.args(secret=SECRET))
        self.assertEqual(code, 0)
        stage.assert_not_called()
        self.assertIn(PHRASE, out)

    def test_order_and_redaction(self):
        code, out, events = self.run_exec(readback=NEW_SECRET)
        self.assertEqual(code, 0, out)
        self.assertEqual(events, ["stage", "readback", "promote"])
        self.assertNotIn(NEW_SECRET, out)

    def test_readback_mismatch_blocks_promotion(self):
        code, out, events = self.run_exec(readback="something-else")
        self.assertEqual(code, 2)
        self.assertNotIn("promote", events)
        self.assertIn("RESUME_AVAILABLE", out)
        self.assertNotIn(NEW_SECRET, out)

    def test_auto_generation_disabled_then_restored(self):
        code, _, events = self.run_exec(readback=NEW_SECRET, autogen=True)
        self.assertEqual(code, 0)
        self.assertEqual(events, ["autogen:False", "stage", "readback", "promote", "autogen:True"])

    def test_wrong_phrase_blocks(self):
        with patch.object(p1, "preflight", return_value=(client_at(), detail(), [])), \
             patch.object(v, "stage_pending") as stage, self.assertRaises(v.OpsError):
            quiet(p1.run_rotation, {}, helpers.args(secret=SECRET, execute=True, confirm="rotate-p1:stage:x:v4"))
        stage.assert_not_called()


class ResumeTests(unittest.TestCase):
    def test_resume_promotes_the_single_pending_version(self):
        client = client_at()
        fresh = client.get_secret.return_value.data
        fresh.is_auto_generation_enabled = False
        fresh.secret_generation_context = None
        phrase = f"resume-p1:stage:{SECRET}:current-v4:pending-v5"
        with patch.object(p1, "preflight", return_value=(client, detail(), [5])), \
             patch.object(v, "wait_for_active", return_value=fresh), \
             patch.object(v, "pending_versions", return_value=[5]), \
             patch.object(v, "promote_pending_version", return_value=5) as promote:
            code, out = quiet(p1.run_resume, {}, helpers.args(secret=SECRET, execute=True, confirm=phrase,
                                                              resume_pending=True))
        self.assertEqual(code, 0, out)
        promote.assert_called_once_with(client, "secret-id", 5)

    def test_resume_refuses_more_than_one_pending(self):
        with patch.object(p1, "preflight", return_value=(client_at(), detail(), [5, 6])), \
             self.assertRaises(v.OpsError):
            quiet(p1.run_resume, {}, helpers.args(secret=SECRET, resume_pending=True))


if __name__ == "__main__":
    unittest.main()
