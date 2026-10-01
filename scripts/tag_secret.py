#!/usr/bin/env python3
"""Confirmation-gated rotation tag for one secret (metadata only).

Tags:
  P1               Vault-only rotation (rotate_vault_only.py); nothing downstream
  P2               has downstream consumers; add a handler before it can rotate
  P2:<H>[:<H>...]  Vault plus each named downstream handler, in order.
                   Implemented handlers: ADB (rotate_adb_user.py / rotate_adb_admin.py)
  EXEMPT           does not require rotation
  MANUAL           rotates, but this skill cannot perform it

Updates only the tag key (and removes a legacy tag key if present), preserves
every other metadata entry, uses the secret's ETag so a concurrent change fails
instead of being overwritten, and verifies the result. Never creates a version.
"""

from __future__ import annotations

import argparse
import sys

import oci

import vaultlib as v


def confirmation(env: str, secret: str, version: int, tag: str) -> str:
    return f"tag:{env}:{secret}:v{version}:{tag}"


def warnings_for(cfg, env: str, secret: str, tag: str) -> list[str]:
    warnings = []
    try:
        mapped = v.resolve_target(cfg, env, secret)[2]
    except v.OpsError:
        mapped = None
    handlers = v.tag_handlers(tag)
    missing = [h for h in handlers if h not in v.IMPLEMENTED_HANDLERS]
    if tag == "P2":
        warnings.append("P2 without a handler cannot rotate; name one, e.g. P2:ADB")
    if missing:
        warnings.append(f"No handler yet for {', '.join(missing)}; rotation stays blocked until one exists")
    other = [h for h in handlers if h != "ADB" and h in v.IMPLEMENTED_HANDLERS]
    bound = (v.secret_binding(cfg, env, secret) or {}).get("handlers") or {}
    unbound = [h for h in other if h not in bound]
    if unbound:
        warnings.append(f"{', '.join(unbound)} handler needs a binding in environments.<env>.secret_bindings before rotation")
    if "ADB" in handlers and other:
        warnings.append("ADB combined with other handlers is not supported yet; rotation stays blocked")
    if "ADB" in handlers and not mapped:
        warnings.append("ADB handler requires the secret to be mapped in config (admin_secret or user_secrets)")
    if tag == "P1" and secret not in v.vault_only_secrets(cfg, env):
        warnings.append("P1 rotation also requires the secret in environments.<env>.vault_only_secrets")
    if tag == "P1" and mapped:
        warnings.append(f"Secret is mapped to database user {mapped}; P1 would rotate Vault without the database")
    return warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Confirmation-gated secret rotation tag")
    parser.add_argument("--config")
    parser.add_argument("--env", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--tag", required=True, help="P1 | P2 | P2:<HANDLER>[:<HANDLER>...] | EXEMPT | MANUAL")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()

    tag = args.tag.strip().upper().replace(" ", "")
    if not v.valid_tag(tag):
        raise v.OpsError(f"'{args.tag}' is not a valid tag: use P1, P2, P2:<HANDLER>[:<HANDLER>...], EXEMPT, or MANUAL")

    cfg = v.load_config(args.config)
    key = v.tag_key(cfg)
    client, found = v.find_secret(cfg, args.env, args.secret, require_active=True)
    response = client.get_secret(found.id)
    detail = response.data
    metadata = dict(detail.metadata or {})
    current = v.tag_of(detail, cfg)
    legacy = [k for k in v.LEGACY_TAG_KEYS if k in metadata and k != key]
    version = int(detail.current_version_number)
    phrase = confirmation(args.env, args.secret, version, tag)

    v.event("tag_plan", environment=args.env, secret=args.secret, secret_version=version, metadata_key=key,
            current_tag=current, target_tag=tag, legacy_keys_removed=legacy,
            warnings=warnings_for(cfg, args.env, args.secret, tag), confirmation=phrase,
            mutation="NONE" if not args.execute else "APPROVED")
    if not args.execute:
        return 0
    if args.confirm != phrase:
        raise v.OpsError("Confirmation does not match the current secret version and target tag")
    if current == tag and not legacy:
        v.event("tag_unchanged", secret=args.secret, target_tag=tag, mutation="NONE")
        return 0

    metadata[key] = tag
    for k in legacy:
        metadata.pop(k)
    client.update_secret(detail.id, oci.vault.models.UpdateSecretDetails(metadata=metadata),
                         if_match=response.headers.get("etag"))
    verified = v.wait_for_active(client, detail.id)
    verified_meta = dict(verified.metadata or {})
    if verified_meta != metadata or int(verified.current_version_number) != version:
        raise v.OpsError("Post-update metadata verification failed")
    v.event("tag_updated", environment=args.env, secret=args.secret, secret_version=version,
            previous_tag=current, target_tag=tag, legacy_keys_removed=legacy,
            result="SUCCESS", mutation="METADATA_ONLY")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except v.OpsError as exc:
        v.event("tag_blocked", result="NO_MUTATION", reason=str(exc))
        sys.exit(2)
    except Exception as exc:
        v.event("tag_blocked", result="NO_MUTATION", **v.safe_error_fields(exc))
        sys.exit(2)
