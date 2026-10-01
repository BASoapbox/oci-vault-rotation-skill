"""Handler contract.

  preflight(recovery=False)
                  read-only checks; never reads or sends a secret value. With
                  recovery=True, checks that a half-finished rotation is expected
                  to break (consumer health) report WARN instead of FAIL, so they
                  cannot block the tool that repairs it.
  apply(value)    make the downstream system use the new value
  verify(value)   raise unless the system now accepts/holds the value
  probe(value)    read-only: does the system currently accept/hold the value?

Handlers never emit a value, and never emit remote output from a command that
was given a value on stdin.
"""

from __future__ import annotations

from typing import Any

import vaultlib as v


class HandlerError(v.OpsError):
    """A handler step failed. Messages are authored here and never carry values."""


class Handler:
    name = ""
    # Characters a generated value must not contain for this handler to use it safely.
    forbidden_chars = ""
    required_keys: tuple[str, ...] = ()

    def __init__(self, cfg: dict[str, Any], env: str, secret: str, binding: dict[str, Any]):
        missing = [k for k in self.required_keys if not binding.get(k)]
        if missing:
            raise v.OpsError(f"{self.name} binding for {secret} is missing: {', '.join(missing)}")
        self.cfg, self.env, self.secret, self.binding = cfg, env, secret, binding

    @property
    def host(self) -> str:
        return self.binding["host"]

    def describe(self) -> dict[str, Any]:
        """Safe metadata for plans and reports."""
        return {"handler": self.name}

    def preflight(self, recovery: bool = False) -> list[v.Check]:
        raise NotImplementedError

    def apply(self, value: str) -> None:
        raise NotImplementedError

    def verify(self, value: str) -> None:
        if not self.probe(value):
            raise HandlerError(f"{self.name} does not accept the new value")

    def probe(self, value: str) -> bool:
        raise NotImplementedError
