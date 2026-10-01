from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import helpers  # noqa: F401
import hostexec
import vaultlib as v
from handlers import build, REGISTRY
from handlers.base import HandlerError

VALUE = "Rotated-Value-Never-In-Argv-7"
CFG = {"hosts": {"box": {"ssh": "ubuntu@box.example"}}}
PG = {"host": "box", "container": "app-db", "role": "app_user", "database": "appdb"}
COMPOSE = {"host": "box", "project_dir": "/srv/app", "env_var": "DB_PASSWORD", "services": ["db", "api"]}


class FakeHost:
    """Records every remote call; answers from a small script of rules."""

    def __init__(self, rules):
        self.calls, self.rules = [], rules

    def __call__(self, cfg, host, argv, stdin=None, timeout=180):
        self.calls.append((argv, stdin))
        for match, result in self.rules:
            if match(argv, stdin):
                return result(argv, stdin) if callable(result) else result
        return hostexec.Result(0, "", "")

    def assert_value_never_in_argv(self, test):
        for argv, _ in self.calls:
            test.assertFalse(any(VALUE in a for a in argv), f"value leaked into argv: {argv[:3]}")


def ok(out=""):
    return hostexec.Result(0, out, "")


class PgHandlerTests(unittest.TestCase):
    def test_apply_sends_sql_on_stdin_only(self):
        fake = FakeHost([])
        with patch.object(hostexec, "run", fake):
            build("PG", CFG, "stage", "s", PG).apply(VALUE)
        argv, stdin = fake.calls[0]
        self.assertIn("ALTER ROLE", stdin)
        self.assertIn(VALUE, stdin)
        fake.assert_value_never_in_argv(self)

    def test_probe_is_a_real_login_with_password_on_stdin(self):
        fake = FakeHost([(lambda a, s: "sh" in a, ok("1\n"))])
        with patch.object(hostexec, "run", fake):
            self.assertTrue(build("PG", CFG, "stage", "s", PG).probe(VALUE))
        self.assertEqual(fake.calls[0][1], VALUE + "\n")
        fake.assert_value_never_in_argv(self)

    def test_failed_login_probe_is_false(self):
        fake = FakeHost([(lambda a, s: "sh" in a, hostexec.Result(2, "", "auth failed"))])
        with patch.object(hostexec, "run", fake):
            self.assertFalse(build("PG", CFG, "stage", "s", PG).probe(VALUE))

    def test_preflight_fails_when_any_password_is_accepted(self):
        fake = FakeHost([(lambda a, s: "inspect" in a, ok("true")),
                         (lambda a, s: "sh" in a, ok("1")),            # wrong password accepted
                         (lambda a, s: "psql" in a, ok("1"))])
        with patch.object(hostexec, "run", fake):
            checks = {c.name: c.status for c in build("PG", CFG, "stage", "s", PG).preflight()}
        self.assertEqual(checks["pg_password_auth_enforced"], "FAIL")

    def test_rejects_quotes_and_bad_identifiers(self):
        with patch.object(hostexec, "run", FakeHost([])), self.assertRaises(HandlerError):
            build("PG", CFG, "stage", "s", PG).apply("abc'; drop role x; --")
        with self.assertRaises(v.OpsError):
            build("PG", CFG, "stage", "s", {**PG, "role": 'x"; drop'})


class ComposeHandlerTests(unittest.TestCase):
    def rules(self, recreated=True, healthy=True, match=True):
        ids = iter(["old-db", "old-api", "new-db" if recreated else "old-db", "new-api" if recreated else "old-api"] * 3)
        return [
            (lambda a, s: a[:2] == ["python3", "-c"] and a[2] == hostexec.ENV_WRITE, ok("WRITTEN")),
            (lambda a, s: a[:2] == ["python3", "-c"] and a[2] == hostexec.ENV_COMPARE, ok("MATCH" if match else "DIFFERENT")),
            (lambda a, s: "ps" in a and "-q" in a, lambda a, s: ok(next(ids))),
            (lambda a, s: "ps" in a and "json" in a,
             ok("\n".join(json.dumps({"Service": x, "State": "running", "Health": "healthy" if healthy else "starting"})
                          for x in ("db", "api")))),
        ]

    def test_apply_writes_env_on_stdin_and_recreates_only_named_services(self):
        fake = FakeHost(self.rules())
        with patch.object(hostexec, "run", fake):
            h = build("COMPOSE", CFG, "stage", "s", COMPOSE)
            h.apply(VALUE)
            h.verify(VALUE)
        up = next(a for a, _ in fake.calls if "up" in a)
        self.assertEqual(up[-7:], ["up", "-d", "--no-deps", "--pull", "never", "db", "api"])
        self.assertEqual(up[-2:], ["db", "api"])
        write = next(s for a, s in fake.calls if a[:3] == ["python3", "-c", hostexec.ENV_WRITE])
        self.assertEqual(write, VALUE)
        fake.assert_value_never_in_argv(self)

    def test_verify_fails_if_containers_were_not_recreated(self):
        fake = FakeHost(self.rules(recreated=False))
        with patch.object(hostexec, "run", fake), self.assertRaises(HandlerError):
            h = build("COMPOSE", CFG, "stage", "s", COMPOSE)
            h.apply(VALUE)
            h.verify(VALUE)

    def test_url_embedded_forbids_reserved_characters(self):
        h = build("COMPOSE", CFG, "stage", "s", {**COMPOSE, "url_embedded": True})
        for bad in ("a@b", "a:b", "a/b", "a#b", "a$b", "a b"):
            with patch.object(hostexec, "run", FakeHost([])), self.assertRaises(HandlerError):
                h.apply(bad)

    def test_unhealthy_service_fails_apply(self):
        fake = FakeHost(self.rules(healthy=False))
        with patch.object(hostexec, "run", fake), patch("handlers.compose.time.sleep"), \
             patch("handlers.compose.time.monotonic", side_effect=[0, 0, 999, 999]), self.assertRaises(HandlerError):
            build("COMPOSE", CFG, "stage", "s", COMPOSE).apply(VALUE)

    def test_bad_binding_is_rejected(self):
        for bad in ({**COMPOSE, "env_var": "lower"}, {**COMPOSE, "services": ["x; rm -rf /"]},
                    {**COMPOSE, "project_dir": "relative"}, {k: val for k, val in COMPOSE.items() if k != "services"}):
            with self.assertRaises(v.OpsError):
                build("COMPOSE", CFG, "stage", "s", bad)


class RecoveryPreflightTests(unittest.TestCase):
    """Found live: a broken consumer is the normal state mid-rotation, so it must not block recovery."""

    def checks(self, recovery):
        fake = FakeHost([
            (lambda a, s: a[:3] == ["python3", "-c", hostexec.ENV_COMPARE], ok("DIFFERENT")),
            (lambda a, s: "config" in a, ok("db\napi")),
            (lambda a, s: "ps" in a and "json" in a,
             ok("\n".join(json.dumps({"Service": x, "State": "running", "Health": ""}) for x in ("db", "api")))),
            (lambda a, s: a[:2] == ["docker", "exec"], hostexec.Result(2, "", "")),   # verify_command fails
        ])
        with patch.object(hostexec, "run", fake):
            h = build("COMPOSE", CFG, "stage", "s", {**COMPOSE, "verify_command": ["docker", "exec", "api", "check"]})
            return {c.name: c.status for c in h.preflight(recovery=recovery)}

    def test_broken_consumer_blocks_a_new_rotation(self):
        self.assertEqual(self.checks(recovery=False)["compose_verify_command"], "FAIL")

    def test_broken_consumer_only_warns_during_recovery(self):
        self.assertEqual(self.checks(recovery=True)["compose_verify_command"], "WARN")


class RegistryTests(unittest.TestCase):
    def test_every_registered_handler_counts_as_implemented(self):
        self.assertTrue(set(REGISTRY) <= v.IMPLEMENTED_HANDLERS)

    def test_ssh_target_validation(self):
        self.assertEqual(hostexec.ssh_target(CFG, "box"), "ubuntu@box.example")
        with self.assertRaises(v.OpsError):
            hostexec.ssh_target({"hosts": {"b": {"ssh": "x; rm -rf /"}}}, "b")
        with self.assertRaises(v.OpsError):
            hostexec.ssh_target(CFG, "missing")


if __name__ == "__main__":
    unittest.main()
