"""Downstream handlers for P2 rotations.

A handler applies a new secret value to one downstream system and proves the
system accepts it. Tags name handlers in order: P2:PG:COMPOSE changes the
Postgres role's password, then updates the Compose .env and recreates the
services that read it. P2:MDB:FILE changes a MongoDB user's password, then the
files its clients read it from.

ADB is implemented separately by rotate_adb_user.py / rotate_adb_admin.py.
"""

from __future__ import annotations

from .base import Handler
from .compose import ComposeHandler
from .file import FileHandler
from .mdb import MdbHandler
from .pg import PgHandler

REGISTRY: dict[str, type[Handler]] = {
    "PG": PgHandler,
    "COMPOSE": ComposeHandler,
    "MDB": MdbHandler,
    "FILE": FileHandler,
}


def build(name: str, cfg, env: str, secret: str, binding: dict) -> Handler:
    if name not in REGISTRY:
        raise KeyError(name)
    return REGISTRY[name](cfg, env, secret, binding)
