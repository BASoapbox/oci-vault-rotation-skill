from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import MagicMock, patch

import helpers
from helpers import CURRENT_SECRET, PENDING_SECRET
import rotate_secret as rs
import vaultlib as v
from handlers.base import Handler, HandlerError

SECRET = "app-db-pwd"


class FakeHandler(Handler):
    """Holds one value, like a real consumer; records what happened to it."""
    required_keys = ()

    def __init__(self, name, holds, log, forbidden="", fail_apply=False):
        self.name, self.holds, self.log, self.forbidden_chars, self.fail_apply = name, holds, log, forbidden, fail_apply

    def describe(self):
        return {"handler": self.name}

    def preflight(self, recovery=False):
        return [v.Check(f"{self.name}_ok", "PASS", "")]

    def apply(self, value):
        self.log.append(f"apply:{self.name}")
        if self.fail_apply:
            raise HandlerError(f"{self.name} failed")
        self.holds = value

    def probe(self, value):
        return self.holds == value


def quiet(fn, *a):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fn(*a)
    return code, out.getvalue()


def client_at(version=4):
    client = MagicMock()
    client.get_secret.return_value.data.current_version_number = version
    return client


class RouteTests(unittest.TestCase):
    def blocked(self, tag, binding=None):
        cfg = helpers.cfg()
        if binding is not None:
            cfg["environments"]["stage"]["secret_bindings"] = {SECRET: binding}
        detail = helpers.secret_detail(name=SECRET, metadata={"rotationTag": tag})
        with patch.object(v, "find_secret", return_value=(client_at(), detail)), \
             patch.object(v, "pending_versions", return_value=[]), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            try:
                rs.route(cfg, "stage", SECRET)
                return None
            except v.OpsError:
                return out.getvalue()

    def test_wrong_tags_are_routed_away(self):
        self.assertIn("rotate_vault_only", self.blocked("P1"))
        self.assertIn("rotate_adb_user", self.blocked("P2:ADB"))
        self.assertIn("rotate_adb_user", self.blocked("P2:ADB:COMPOSE"))
        self.assertIn("no handler yet for REDIS", self.blocked("P2:REDIS"))
        self.assertIn("EXEMPT", self.blocked("EXEMPT"))

    def test_every_handler_needs_a_binding(self):
        out = self.blocked("P2:PG:COMPOSE", {"handlers": {"PG": {}}})
        self.assertIn("binding_COMPOSE", out)


class RotationTests(unittest.TestCase):
    def run_rotation(self, handlers, sync=True):
        client = client_at()
        detail = helpers.secret_detail(name=SECRET, metadata={"rotationTag": "P2:PG:COMPOSE"})
        phrase = f"rotate:stage:{SECRET}:v4:{'+'.join(h.name for h in handlers)}"
        values = {"current": CURRENT_SECRET if sync else "stale"}
        generated = {}

        def gen(cfg, spec, exclude):
            generated["exclude"] = exclude
            generated["value"] = "Generated-Value-9"
            return generated["value"]

        def read(cfg, env, sid, version=None):
            return CURRENT_SECRET if version == 4 else generated.get("value")

        with patch.object(rs, "route", return_value=(client, detail, "P2:PG:COMPOSE", handlers, {}, [])), \
             patch.object(v, "read_secret_value", side_effect=read), \
             patch.object(v, "generate_value", side_effect=gen), \
             patch.object(v, "wait_for_active", return_value=client.get_secret.return_value.data), \
             patch.object(v, "pending_versions", return_value=[]), \
             patch.object(v, "stage_pending", return_value=5) as stage, \
             patch.object(v, "promote_pending_version", return_value=5) as promote:
            code, out = quiet(rs.run_rotation, {}, helpers.args(secret=SECRET, execute=True, confirm=phrase))
        return code, out, stage, promote, generated

    def test_full_chain_in_tag_order_then_promote(self):
        log = []
        hs = [FakeHandler("PG", CURRENT_SECRET, log, "'"), FakeHandler("COMPOSE", CURRENT_SECRET, log, "$#")]
        code, out, stage, promote, gen = self.run_rotation(hs)
        self.assertEqual(code, 0, out)
        self.assertEqual(log, ["apply:PG", "apply:COMPOSE"])
        promote.assert_called_once()
        self.assertEqual(set(gen["exclude"]), set("'$#"))
        for secret in (CURRENT_SECRET, gen["value"]):
            self.assertNotIn(secret, out)

    def test_out_of_sync_consumer_stops_before_staging(self):
        log = []
        hs = [FakeHandler("PG", CURRENT_SECRET, log), FakeHandler("COMPOSE", "something-else", log)]
        code, out, stage, promote, _ = self.run_rotation(hs)
        self.assertEqual(code, 2)
        stage.assert_not_called()
        self.assertEqual(log, [])
        self.assertIn("import the live value first", out)

    def test_failure_mid_chain_does_not_promote_and_reports_state(self):
        log = []
        hs = [FakeHandler("PG", CURRENT_SECRET, log), FakeHandler("COMPOSE", CURRENT_SECRET, log, fail_apply=True)]
        code, out, stage, promote, _ = self.run_rotation(hs)
        self.assertEqual(code, 2)
        promote.assert_not_called()
        self.assertIn("SOME_HANDLERS_ON_PENDING", out)
        self.assertIn('"handlers_applied": ["PG"]', out)


class PendingTests(unittest.TestCase):
    def run_mode(self, fn, kind, handlers):
        client = client_at()
        detail = helpers.secret_detail(name=SECRET)
        phrase = f"{kind}:stage:{SECRET}:current-v4:pending-v5"
        with patch.object(rs, "route", return_value=(client, detail, "P2:PG:COMPOSE", handlers, {}, [5])), \
             patch.object(v, "read_secret_value", side_effect=lambda c, e, i, ver=None: CURRENT_SECRET if ver == 4 else PENDING_SECRET), \
             patch.object(v, "wait_for_active", return_value=client.get_secret.return_value.data), \
             patch.object(v, "pending_versions", return_value=[5]), \
             patch.object(v, "promote_pending_version", return_value=5) as promote:
            code, out = quiet(fn, {}, helpers.args(secret=SECRET, execute=True, confirm=phrase,
                                                   recover_pending=kind == "recover", resume_pending=kind == "resume"))
        return code, out, promote

    def test_resume_applies_only_to_handlers_still_on_current(self):
        log = []
        hs = [FakeHandler("PG", PENDING_SECRET, log), FakeHandler("COMPOSE", CURRENT_SECRET, log)]
        code, out, promote = self.run_mode(rs.run_resume, "resume", hs)
        self.assertEqual(code, 0, out)
        self.assertEqual(log, ["apply:COMPOSE"])
        promote.assert_called_once()
        self.assertNotIn(PENDING_SECRET, out)

    def test_recover_promotes_only_when_every_handler_holds_pending(self):
        log = []
        code, _, promote = self.run_mode(rs.run_recovery, "recover",
                                         [FakeHandler("PG", PENDING_SECRET, log), FakeHandler("COMPOSE", PENDING_SECRET, log)])
        self.assertEqual(code, 0)
        promote.assert_called_once()
        code, out, promote = self.run_mode(rs.run_recovery, "recover",
                                           [FakeHandler("PG", PENDING_SECRET, log), FakeHandler("COMPOSE", CURRENT_SECRET, log)])
        self.assertEqual(code, 2)
        promote.assert_not_called()
        self.assertIn("SOME_HANDLERS_ON_CURRENT", out)
        self.assertEqual(log, [])

    def test_ambiguous_handler_stops_resume(self):
        log = []
        code, out, promote = self.run_mode(rs.run_resume, "resume",
                                           [FakeHandler("PG", "neither", log), FakeHandler("COMPOSE", CURRENT_SECRET, log)])
        self.assertEqual(code, 2)
        self.assertEqual(log, [])
        promote.assert_not_called()


class ValueTests(unittest.TestCase):
    def test_hex_and_excluded_password(self):
        self.assertRegex(v.generate_value({}, {"format": "hex", "bytes": 32}), r"^[0-9a-f]{64}$")
        for _ in range(200):
            val = v.generate_value({}, None, exclude="#@:/")
            self.assertFalse(set(val) & set("#@:/"))

    def test_exclusion_that_empties_a_class_is_an_error(self):
        with self.assertRaises(v.OpsError):
            v.generate_value({"password_policy": {"special_chars": "#"}}, None, exclude="#")


if __name__ == "__main__":
    unittest.main()
