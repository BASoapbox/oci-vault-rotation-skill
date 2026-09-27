"""Shared fakes for the test suite. No test touches OCI or a database."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

CURRENT_SECRET = "Current-Value-Should-Never-Print-7"
NEW_SECRET = "New-Value-Should-Never-Print-9"
PENDING_SECRET = "Pending-Value-Should-Never-Print-3"


def cfg(**db_overrides):
    vault_only = db_overrides.pop("_vault_only", ["demo-webhook-token"])
    db = {
        "ocid": "ocid1.autonomousdatabase.oc1..example",
        "connection": "public",
        "service_alias": "demodb_low",
        "wallet_dir": "/wallet",
        "admin_secret": "demo-admin-pwd",
        "user_secrets": {"demo-app_user-pwd": "APP_USER"},
    }

    db.update(db_overrides)
    return {
        "oci": {"profile": "EXAMPLE"},
        "environments": {"stage": {"secret_compartments": ["ocid1.compartment.oc1..example"],
                                   "vault_only_secrets": vault_only, "databases": {"demo": db}}},
    }


def secret_detail(version=4, autogen=False, metadata=None, name="demo-app_user-pwd"):
    return SimpleNamespace(id="secret-id", secret_name=name, lifecycle_state="ACTIVE",
                           current_version_number=version, is_auto_generation_enabled=autogen,
                           secret_generation_context="ctx" if autogen else None,
                           metadata=metadata if metadata is not None else {"rotationTag": "P2:ADB"})


def args(**kw):
    base = dict(env="stage", secret="demo-app_user-pwd", execute=False, confirm=None,
                recover_pending=False, resume_pending=False)
    base.update(kw)
    return SimpleNamespace(**base)


class Cursor:
    def __init__(self, events):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, statement):
        self.events.append("alter")


class Connection:
    def __init__(self, events):
        self.events = events

    def cursor(self):
        return Cursor(self.events)

    def commit(self):
        self.events.append("commit")

    def close(self):
        pass
