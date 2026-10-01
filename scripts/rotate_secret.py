#!/usr/bin/env python3
"""Confirmation-gated P2 rotation through downstream handlers (PG, COMPOSE, ...).

The tag names the handlers in order: P2:PG:COMPOSE changes the Postgres role's
password, then updates the Compose env file and recreates its services. Gates:
the tag in Vault, and environments.<env>.secret_bindings.<secret>.handlers in
the reviewed config must cover every handler the tag names. ADB has its own
runners (rotate_adb_user.py / rotate_adb_admin.py).

Transaction:
  1. read Vault CURRENT and prove every handler holds/accepts it (consumers in
     sync with Vault; otherwise stop: import the live value first)
  2. disable auto-generation if enabled; stage a generated value as PENDING;
     read it back and compare in memory
  3. for each handler in tag order: apply the value, then verify it
  4. promote PENDING to CURRENT; restore auto-generation

  (default)          rotate:<env>:<secret>:v<current>:<H1+H2>
  --recover-pending  recover:<env>:<secret>:current-v<c>:pending-v<p>
                     promotes PENDING only if every handler already holds it
  --resume-pending   resume:<env>:<secret>:current-v<c>:pending-v<p>
                     applies PENDING to each handler still on CURRENT, in order,
                     verifies all, promotes. Never generates another value.
"""

from __future__ import annotations

import argparse
import hmac
import sys
from typing import Any

import handlers as hreg
import vaultlib as v


def confirmation(env, secret, version, names):
    return f"rotate:{env}:{secret}:v{version}:{'+'.join(names)}"


def recovery_confirmation(env, secret, current, pending):
    return f"recover:{env}:{secret}:current-v{current}:pending-v{pending}"


def resume_confirmation(env, secret, current, pending):
    return f"resume:{env}:{secret}:current-v{current}:pending-v{pending}"


def route(cfg: dict[str, Any], env: str, secret: str, *, allow_pending: bool = False):
    client, detail = v.find_secret(cfg, env, secret)
    tag = v.tag_of(detail, cfg)
    names = v.tag_handlers(tag)
    if not names:
        checks = [v.route_check(tag, ["ADB"]) if tag != "P1" else
                  v.Check("rotation_tag", "FAIL", "P1; use rotate_vault_only.py")]
    elif "ADB" in names:
        checks = [v.Check("rotation_tag", "FAIL", f"{tag}; ADB rotations use rotate_adb_user.py / rotate_adb_admin.py")]
    else:
        checks = [v.route_check(tag, names)]
    built: list = []
    binding = v.secret_binding(cfg, env, secret) or {}
    if checks[0].status == "PASS":
        bound = binding.get("handlers") or {}
        for name in names:
            if name not in bound:
                checks.append(v.Check(f"binding_{name}", "FAIL", f"no {name} binding in environments.{env}.secret_bindings"))
                continue
            try:
                handler = hreg.build(name, cfg, env, secret, bound[name])
            except v.OpsError as exc:
                checks.append(v.Check(f"binding_{name}", "FAIL", str(exc)))
                continue
            checks.append(v.Check(f"binding_{name}", "PASS", "configured"))
            built.append(handler)
        for handler in built:
            checks.extend(handler.preflight(recovery=allow_pending))
    pending = v.pending_versions(client, detail.id)
    if not allow_pending:
        checks.append(v.Check("no_pending_version", "PASS" if not pending else "FAIL",
                              "none" if not pending else f"pending v{pending}; use --recover-pending or --resume-pending"))
    if not v.all_pass(checks):
        for check in checks:
            v.event("preflight_check", name=check.name, status=check.status, detail=check.detail)
        raise v.OpsError("Preflight is blocked; no mutation was made")
    return client, detail, tag, built, binding.get("value") or {}, pending


def probe_all(handlers, value) -> dict[str, bool]:
    return {h.name: h.probe(value) for h in handlers}


def run_rotation(cfg: dict[str, Any], args: argparse.Namespace) -> int:
    client, target, tag, handlers, value_spec, _ = route(cfg, args.env, args.secret)
    names = [h.name for h in handlers]
    current_version = int(target.current_version_number)
    phrase = confirmation(args.env, args.secret, current_version, names)
    v.event("p2_rotation_plan_ready", environment=args.env, secret=args.secret, rotation_tag=tag,
            current_version=current_version, handlers=[h.describe() for h in handlers],
            value_format=value_spec.get("format", "password"),
            auto_generation_enabled=bool(target.is_auto_generation_enabled), confirmation=phrase)
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current version and handlers; no mutation was made")

    current = new_value = staged = None
    applied: list[str] = []
    stage_attempted = auto_generation_disabled = False
    promoted: int | None = None
    original_auto_generation = bool(target.is_auto_generation_enabled)
    original_context = target.secret_generation_context
    try:
        current = v.read_secret_value(cfg, args.env, target.id, current_version)
        in_sync = probe_all(handlers, current)
        v.event("consumer_sync", handlers=in_sync)
        if not all(in_sync.values()):
            raise v.OpsError("A consumer does not hold Vault CURRENT; import the live value first "
                             "(import_secret.py) so Vault is the source of truth")

        exclude = "".join(sorted({c for h in handlers for c in h.forbidden_chars}))
        new_value = v.generate_value(cfg, value_spec, exclude)
        if any(c in new_value for c in exclude):
            raise v.OpsError("Generated value violates a handler's character constraints")
        if original_auto_generation:
            v.set_auto_generation(client, target.id, False)
            auto_generation_disabled = True
            v.event("vault_auto_generation_temporarily_disabled", secret=args.secret)

        fresh = v.wait_for_active(client, target.id)
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, target.id):
            raise v.OpsError("Secret state changed before staging; nothing was changed")

        stage_attempted = True
        pending_version = v.stage_pending(client, target.id, new_value)
        staged = v.read_secret_value(cfg, args.env, target.id, pending_version)
        if not hmac.compare_digest(staged, new_value):
            raise v.OpsError("Staged version does not match the generated value; no handler was run")
        v.event("vault_version_staged", secret=args.secret, pending_version=pending_version)

        for handler in handlers:
            handler.apply(new_value)
            applied.append(handler.name)
            v.event("handler_applied", handler=handler.name)
            handler.verify(new_value)
            v.event("handler_verified", handler=handler.name)

        promoted = v.promote_pending_version(client, target.id, pending_version)
        v.event("vault_version_promoted", secret=args.secret, previous_version=current_version, current_version=promoted)
        if auto_generation_disabled:
            v.set_auto_generation(client, target.id, True, original_context)
            auto_generation_disabled = False
            v.event("vault_auto_generation_restored", secret=args.secret)
        v.event("p2_rotation_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                handlers=names, current_version=promoted)
        return 0
    except Exception as exc:
        if promoted is not None:
            result, state = "POLICY_RESTORE_REQUIRED", "ALL_HANDLERS_AND_VAULT_MATCH"
        elif applied:
            result, state = "MANUAL_RECOVERY_REQUIRED", "SOME_HANDLERS_ON_PENDING"
        elif stage_attempted:
            result, state = "RESUME_AVAILABLE", "HANDLERS_EXPECTED_ON_CURRENT"
        else:
            result, state = "NO_MUTATION", "VAULT_AND_HANDLERS_UNCHANGED"
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("p2_rotation_stopped", result=result, state=state, handlers_applied=applied,
                next_step="verify.py --check recovery-scan, then --resume-pending" if stage_attempted and promoted is None else None,
                secret=args.secret, **fields)
        return 2
    finally:
        if auto_generation_disabled:
            try:
                v.set_auto_generation(client, target.id, True, original_context)
                v.event("vault_auto_generation_restored_after_stop", secret=args.secret)
            except Exception as restore_exc:
                v.event("vault_auto_generation_restore_failed", secret=args.secret, **v.safe_error_fields(restore_exc))
        current = new_value = staged = None


def _pending_plan(cfg, args, kind):
    client, detail, tag, handlers, _, pending = route(cfg, args.env, args.secret, allow_pending=True)
    if len(pending) != 1:
        raise v.OpsError(f"{kind.capitalize()} requires exactly one pending version; found {len(pending)}")
    current_version, pending_version = int(detail.current_version_number), pending[0]
    maker = recovery_confirmation if kind == "recovery" else resume_confirmation
    phrase = maker(args.env, args.secret, current_version, pending_version)
    v.event(f"{kind}_plan_ready", environment=args.env, secret=args.secret, rotation_tag=tag,
            handlers=[h.name for h in handlers], current_version=current_version,
            pending_version=pending_version, confirmation=phrase)
    return client, detail, handlers, current_version, pending_version, phrase


def _state(cfg, args, detail, handlers, current_version, pending_version):
    current = v.read_secret_value(cfg, args.env, detail.id, current_version)
    pending = v.read_secret_value(cfg, args.env, detail.id, pending_version)
    state = {h.name: {"current": h.probe(current), "pending": h.probe(pending)} for h in handlers}
    return current, pending, state


def run_recovery(cfg, args) -> int:
    client, detail, handlers, current_version, pending_version, phrase = _pending_plan(cfg, args, "recovery")
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending versions")
    current = pending = None
    try:
        current, pending, state = _state(cfg, args, detail, handlers, current_version, pending_version)
        v.event("recovery_handler_state", handlers=state)
        if all(s["pending"] and not s["current"] for s in state.values()):
            promoted = v.promote_pending_version(client, detail.id, pending_version)
            v.event("recovery_complete", result="SUCCESS", secret=args.secret, current_version=promoted)
            return 0
        resumable = all(s["pending"] != s["current"] for s in state.values())
        v.event("recovery_stopped", result="NO_MUTATION",
                state="SOME_HANDLERS_ON_CURRENT" if resumable else "AMBIGUOUS_HANDLER_STATE",
                next_step="--resume-pending applies the staged value to the rest" if resumable
                else "A handler accepts both or neither value; resolve it by hand, then re-run")
        return 2
    finally:
        current = pending = None


def run_resume(cfg, args) -> int:
    client, detail, handlers, current_version, pending_version, phrase = _pending_plan(cfg, args, "resume")
    if not args.execute:
        v.event("dry_run_complete", result="NO_MUTATION")
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation phrase does not match the current and pending versions")
    current = pending = None
    applied: list[str] = []
    try:
        current, pending, state = _state(cfg, args, detail, handlers, current_version, pending_version)
        v.event("resume_handler_state", handlers=state)
        if any(s["pending"] == s["current"] for s in state.values()):
            v.event("resume_stopped", result="NO_MUTATION", state="AMBIGUOUS_HANDLER_STATE",
                    next_step="A handler accepts both or neither value; resolve it by hand, then re-run")
            return 2
        fresh = v.wait_for_active(client, detail.id)
        if int(fresh.current_version_number) != current_version or v.pending_versions(client, detail.id) != [pending_version]:
            raise v.OpsError("Vault state changed before resume; nothing was changed")
        for handler in handlers:
            if state[handler.name]["current"]:
                handler.apply(pending)
                applied.append(handler.name)
                v.event("handler_applied", handler=handler.name)
            handler.verify(pending)
            v.event("handler_verified", handler=handler.name)
        promoted = v.promote_pending_version(client, detail.id, pending_version)
        v.event("resume_complete", result="SUCCESS", secret=args.secret, handlers_applied=applied,
                current_version=promoted)
        return 0
    except Exception as exc:
        fields = {"reason": str(exc)} if isinstance(exc, v.OpsError) else v.safe_error_fields(exc)
        v.event("resume_stopped", result="MANUAL_RECOVERY_REQUIRED" if applied else "NO_MUTATION",
                handlers_applied=applied, **fields)
        return 2
    finally:
        current = pending = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Confirmation-gated P2 rotation through downstream handlers")
    parser.add_argument("--config", help=f"default: $OCI_VAULT_OPS_CONFIG or {v.DEFAULT_CONFIG}")
    parser.add_argument("--env", required=True)
    parser.add_argument("--secret", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--recover-pending", action="store_true", help="promote if every handler already holds PENDING")
    mode.add_argument("--resume-pending", action="store_true", help="apply PENDING to handlers still on CURRENT")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        cfg = v.load_config(args.config)
        if args.recover_pending:
            return run_recovery(cfg, args)
        if args.resume_pending:
            return run_resume(cfg, args)
        return run_rotation(cfg, args)
    except v.OpsError as exc:
        v.event("p2_rotation_blocked", result="NO_MUTATION", reason=str(exc))
        return 2


if __name__ == "__main__":
    sys.exit(main())
