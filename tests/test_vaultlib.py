from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import helpers  # noqa: F401  (adds scripts/ to sys.path)
import oci
import vaultlib as v


class PasswordPolicyTests(unittest.TestCase):
    policy = {"password_policy": {"length": 20, "min_upper": 2, "min_lower": 2, "min_digits": 2,
                                  "min_special": 1, "special_chars": "#_-"}}

    def test_generated_values_meet_policy(self):
        for _ in range(300):
            value = v.password_from_policy(self.policy, "APP_USER")
            self.assertEqual(len(value), 20)
            self.assertGreaterEqual(sum(c.isupper() for c in value), 2)
            self.assertGreaterEqual(sum(c.islower() for c in value), 2)
            self.assertGreaterEqual(sum(c.isdigit() for c in value), 2)
            self.assertGreaterEqual(sum(c in "#_-" for c in value), 1)
            self.assertTrue(value[0].isalpha())
            self.assertNotIn("APP_USER", value.upper())
            self.assertFalse(set(value) & set("OI0ol1\"'\\"))

    def test_rejects_quotes_in_special_chars(self):
        with self.assertRaises(v.OpsError):
            v.password_from_policy({"password_policy": {"special_chars": '#"'}}, "U")

    def test_rejects_inconsistent_policy(self):
        with self.assertRaises(v.OpsError):
            v.password_from_policy({"password_policy": {"length": 4}}, "U")


class MappingTests(unittest.TestCase):
    def test_admin_and_user_resolution(self):
        self.assertEqual(v.resolve_target(helpers.cfg(), "stage", "demo-admin-pwd")[2], "ADMIN")
        self.assertEqual(v.resolve_target(helpers.cfg(), "stage", "demo-app_user-pwd")[2], "APP_USER")

    def test_unmapped_secret_is_not_rotatable(self):
        with self.assertRaises(v.OpsError):
            v.resolve_target(helpers.cfg(), "stage", "some-app-jwt-key")

    def test_secret_mapped_twice_is_rejected(self):
        cfg = helpers.cfg()
        cfg["environments"]["stage"]["databases"]["other"] = {"user_secrets": {"demo-app_user-pwd": "X"}}
        with self.assertRaises(v.OpsError):
            v.resolve_target(cfg, "stage", "demo-app_user-pwd")

    def test_unsafe_username_is_rejected(self):
        cfg = helpers.cfg(user_secrets={"demo-app_user-pwd": 'x" IDENTIFIED BY y --'})
        with self.assertRaises(v.OpsError):
            v.resolve_target(cfg, "stage", "demo-app_user-pwd")

    def test_unknown_environment(self):
        with self.assertRaises(v.OpsError):
            v.environment(helpers.cfg(), "prod")

    def test_tag_reading(self):
        cfg = helpers.cfg()
        tag = lambda m: v.tag_of(SimpleNamespace(metadata=m), cfg)
        self.assertEqual(tag(None), "UNTAGGED")
        self.assertEqual(tag({"rotationTag": "bogus"}), "UNRECOGNIZED")
        self.assertEqual(tag({"rotationTag": "P2:ADB:JWT"}), "P2:ADB:JWT")
        # The legacy key is not read: a secret tagged only under rotationClass is untagged.
        self.assertEqual(tag({"rotationClass": "ADB"}), "UNTAGGED")

    def test_tag_grammar(self):
        for good in ("P1", "P2", "P2:ADB", "P2:ADB:JWT", "P2:JNR_APP", "EXEMPT", "MANUAL"):
            self.assertTrue(v.valid_tag(good), good)
        for bad in ("P3", "p1", "P2:", "P2::ADB", "P2:adb", "P1:ADB", "ADB", "P2: ADB", ""):
            self.assertFalse(v.valid_tag(bad), bad)
        self.assertEqual(v.tag_handlers("P2:ADB:JWT"), ["ADB", "JWT"])
        self.assertEqual(v.tag_handlers("P1"), [])


class RouteCheckTests(unittest.TestCase):
    def status(self, tag, handlers):
        return v.route_check(tag, handlers).status

    def test_adb_runner_accepts_only_exactly_p2_adb(self):
        self.assertEqual(self.status("P2:ADB", ["ADB"]), "PASS")
        for tag in ("P1", "P2", "P2:ADB:JWT", "P2:JWT", "EXEMPT", "MANUAL", "UNTAGGED", "UNRECOGNIZED"):
            self.assertEqual(self.status(tag, ["ADB"]), "FAIL", tag)

    def test_unimplemented_handler_blocks_instead_of_partial_rotation(self):
        check = v.route_check("P2:ADB:JWT", ["ADB"])
        self.assertEqual(check.status, "FAIL")
        self.assertIn("JWT", check.detail)
        self.assertIn("partial", check.detail)

    def test_vault_only_runner_accepts_only_p1(self):
        self.assertEqual(self.status("P1", []), "PASS")
        for tag in ("P2", "P2:ADB", "EXEMPT", "MANUAL", "UNTAGGED"):
            self.assertEqual(self.status(tag, []), "FAIL", tag)

    def test_password_with_empty_username_terminates(self):
        self.assertEqual(len(v.password_from_policy({}, "")), 20)


class EventTests(unittest.TestCase):
    def test_a_field_may_be_called_name(self):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            v.event("preflight_check", name="wallet_directory", status="FAIL", detail="/x")
        record = json.loads(out.getvalue())
        self.assertEqual((record["event"], record["name"]), ("preflight_check", "wallet_directory"))


class ConfigTests(unittest.TestCase):
    def test_local_override_merges_runtime_values_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp, "config.json")
            local = Path(tmp, "local.json")
            shared.write_text(json.dumps(helpers.cfg()))
            local.write_text(json.dumps({"runtime_overrides": {
                "environments": {"stage": {"databases": {"demo": {"wallet_dir": "/mine"}}}}}}))
            with patch.dict(os.environ, {"OCI_VAULT_OPS_LOCAL": str(local)}):
                merged = v.load_config(str(shared))
            db = merged["environments"]["stage"]["databases"]["demo"]
            self.assertEqual(db["wallet_dir"], "/mine")
            self.assertEqual(db["admin_secret"], "demo-admin-pwd")

    def test_missing_config_is_a_clear_error(self):
        with self.assertRaises(v.OpsError):
            v.load_config("/nonexistent/config.json")

    def test_profile_is_never_assumed(self):
        with self.assertRaises(v.OpsError):
            v.sdk_config({"oci": {}})


class WalletParsingTests(unittest.TestCase):
    TNS = """demodb_high = (description= (retry_count=20)(address=(protocol=tcps)(port=1522)(host=adb.us-ashburn-1.oraclecloud.com))(connect_data=(service_name=abc_demodb_high.adb.oraclecloud.com)))

demodb_low = (description= (address=(protocol=tcps)(port=1522)(host=adb.us-ashburn-1.oraclecloud.com))(connect_data=(service_name=abc_demodb_low.adb.oraclecloud.com)))
"""

    def test_alias_and_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "tnsnames.ora").write_text(self.TNS)
            entry = v.tns_entry(Path(tmp), "demodb_low")
            self.assertEqual(v.tns_field(entry, "service_name"), "abc_demodb_low.adb.oraclecloud.com")
            self.assertEqual(v.tns_field(entry, "port"), "1522")
            self.assertIsNone(v.tns_entry(Path(tmp), "missing_alias"))

    def test_encrypted_wallet_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Header assembled at runtime so secret scanners don't flag a fixture with no key material.
            header = "-----BEGIN {}PRIVATE KEY-----\nnot-a-key\n"
            Path(tmp, "ewallet.pem").write_text(header.format("ENCRYPTED "))
            self.assertTrue(v.wallet_key_encrypted(Path(tmp)))
            Path(tmp, "ewallet.pem").write_text(header.format(""))
            self.assertFalse(v.wallet_key_encrypted(Path(tmp)))

    def test_ssh_forward_parsing(self):
        out = "hostname jump\nlocalforward 1522 [10.0.1.5]:1522\nlocalforward 8080 web:80\nuser opc\n"
        self.assertEqual(v.parse_ssh_forwards(out), [(1522, "10.0.1.5", 1522), (8080, "web", 80)])

    def test_warn_does_not_block(self):
        self.assertTrue(v.all_pass([v.Check("a", "PASS", ""), v.Check("b", "WARN", "")]))
        self.assertFalse(v.all_pass([v.Check("a", "PASS", ""), v.Check("b", "FAIL", "")]))


class VaultStepTests(unittest.TestCase):
    def active_client(self, current=5):
        client = MagicMock()
        client.get_secret.return_value.data.lifecycle_state = "ACTIVE"
        client.get_secret.return_value.data.current_version_number = current
        return client

    def test_plain_409_incorrect_state_is_retried(self):
        client = self.active_client(current=4)
        busy = oci.exceptions.ServiceError(409, "IncorrectState", {}, "secret is UPDATING")
        client.update_secret.side_effect = [busy, None]
        states = iter([4, 5])  # read after the 409, then after the successful update
        type(client.get_secret.return_value.data).current_version_number = property(lambda _self: next(states, 5))
        with patch.object(v, "event"), patch.object(v.time, "sleep"):
            self.assertEqual(v.promote_pending_version(client, "id", 5), 5)
        self.assertEqual(client.update_secret.call_count, 2)

    def test_non_retryable_error_is_raised_immediately(self):
        client = self.active_client(current=4)
        client.update_secret.side_effect = oci.exceptions.ServiceError(404, "NotAuthorizedOrNotFound", {}, "m")
        with self.assertRaises(oci.exceptions.ServiceError):
            v.promote_pending_version(client, "id", 5)
        self.assertEqual(client.update_secret.call_count, 1)

    def test_wait_for_active_polls_through_updating(self):
        client = MagicMock()
        seq = iter(["UPDATING", "UPDATING", "ACTIVE"])
        client.get_secret.side_effect = lambda _id: SimpleNamespace(data=SimpleNamespace(lifecycle_state=next(seq)))
        with patch.object(v.time, "sleep"):
            self.assertEqual(v.wait_for_active(client, "id").lifecycle_state, "ACTIVE")

    def test_wait_for_active_rejects_unexpected_state(self):
        client = MagicMock()
        client.get_secret.return_value.data.lifecycle_state = "PENDING_DELETION"
        with self.assertRaises(v.OpsError):
            v.wait_for_active(client, "id")

    def test_promotion_confirms_after_transient_error(self):
        client = self.active_client()
        client.update_secret.side_effect = oci.exceptions.TransientServiceError(503, "x", {}, "m")
        with patch.object(v, "event"):
            self.assertEqual(v.promote_pending_version(client, "id", 5), 5)
        client.update_secret.assert_called_once()

    def test_promotion_that_selects_wrong_version_raises(self):
        client = self.active_client(current=4)
        with self.assertRaises(v.OpsError):
            v.promote_pending_version(client, "id", 5)

    def test_stage_requires_exactly_one_pending(self):
        client = self.active_client()
        with patch.object(v, "pending_versions", return_value=[5, 6]), self.assertRaises(v.OpsError):
            v.stage_pending(client, "id", "value")


if __name__ == "__main__":
    unittest.main()
