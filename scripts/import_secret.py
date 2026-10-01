#!/usr/bin/env python3
"""Make Vault the source of truth by importing a value a system already uses.

Reads the live value from a host (a Compose env file entry, or a file) straight
into process memory, compares it with Vault in memory, and after confirmation
writes it to Vault. Never prints the value.

  existing secret, same value      -> nothing to do
  existing secret, different value -> new version, made CURRENT immediately
                                      (the live value is what consumers use)
  no such secret                   -> created beside --create-like (same
                                      compartment, vault and key), tagged --tag

  import:<env>:<secret>:v<current>   or   import:<env>:<secret>:new

Sources (on a host configured under hosts):
  --env-file PATH --env-var KEY          KEY=value line in an env file
  --file PATH [--file-key KEY --file-format env|yaml]
                                         whole file (trimmed), or one key in it
"""

from __future__ import annotations

import argparse
import base64
import hmac
import sys

import oci

import hostexec
import vaultlib as v


def read_source(cfg, args) -> str:
    if args.env_file:
        r = hostexec.run(cfg, args.host, ["python3", "-c", hostexec.ENV_READ, args.env_file, args.env_var])
    else:
        mode = args.file_format if args.file_key else "whole"
        r = hostexec.run(cfg, args.host, ["python3", "-c", hostexec.FILE_READ, args.file, args.file_key or "-", mode])
    if not r.ok or not r.stdout:
        raise v.OpsError(f"Could not read exactly one value from the source (exit {r.rc})")
    return r.stdout


def source_label(args) -> str:
    if args.env_file:
        return f"{args.host}:{args.env_file}#{args.env_var}"
    return f"{args.host}:{args.file}" + (f"#{args.file_key}" if args.file_key else "")


def content(value: str):
    return oci.vault.models.Base64SecretContentDetails(
        content_type="BASE64", content=base64.b64encode(value.encode("utf-8")).decode("ascii"), stage="CURRENT")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a live value into OCI Vault (Vault becomes the source of truth)")
    parser.add_argument("--config")
    parser.add_argument("--env", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--host", required=True, help="key under hosts")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--env-file")
    source.add_argument("--file")
    parser.add_argument("--env-var")
    parser.add_argument("--file-key")
    parser.add_argument("--file-format", choices=("env", "yaml"), default="env")
    parser.add_argument("--create-like", help="existing secret whose compartment, vault and key a new secret uses")
    parser.add_argument("--tag", help="rotation tag for a newly created secret")
    parser.add_argument("--description")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm")
    args = parser.parse_args()
    if args.env_file and not args.env_var:
        parser.error("--env-file needs --env-var")
    tag = args.tag.strip().upper().replace(" ", "") if args.tag else None
    if tag and not v.valid_tag(tag):
        raise v.OpsError(f"'{args.tag}' is not a valid tag")

    cfg = v.load_config(args.config)
    client = v.vault_client(cfg, args.env)
    matches = [s for s in v.list_env_secrets(cfg, args.env, client) if s.secret_name == args.secret]
    if len(matches) > 1:
        raise v.OpsError(f"More than one secret named {args.secret}")
    live = vault_value = None
    try:
        live = read_source(cfg, args)
        if matches:
            detail = client.get_secret(matches[0].id).data
            if detail.lifecycle_state != "ACTIVE":
                raise v.OpsError(f"Secret is {detail.lifecycle_state}")
            if detail.is_auto_generation_enabled:
                raise v.OpsError("Secret has Vault auto-generation enabled; importing a value would fight it")
            version = int(detail.current_version_number)
            vault_value = v.read_secret_value(cfg, args.env, detail.id, version)
            same = hmac.compare_digest(live.encode(), vault_value.encode())
            if same:
                v.event("import_not_needed", environment=args.env, secret=args.secret, source=source_label(args),
                        current_version=version, comparison="SAME", mutation="NONE")
                return 0
            phrase = f"import:{args.env}:{args.secret}:v{version}"
            v.event("import_plan", environment=args.env, secret=args.secret, source=source_label(args),
                    current_version=version, comparison="DIFFERENT",
                    action="new version from the live value, made CURRENT", confirmation=phrase, mutation="NONE")
        else:
            if not args.create_like:
                raise v.OpsError("Secret does not exist; pass --create-like to choose its compartment, vault and key")
            _, like = v.find_secret(cfg, args.env, args.create_like)
            phrase = f"import:{args.env}:{args.secret}:new"
            v.event("import_plan", environment=args.env, secret=args.secret, source=source_label(args),
                    comparison="NO_SECRET", action=f"create beside {args.create_like}", rotation_tag=tag,
                    confirmation=phrase, mutation="NONE")
        if not args.execute:
            v.event("dry_run_complete", result="NO_MUTATION")
            return 0
        if args.confirm != phrase:
            raise v.OpsError("Confirmation phrase does not match; no mutation was made")

        if matches:
            fresh = v.wait_for_active(client, detail.id)
            if int(fresh.current_version_number) != version:
                raise v.OpsError("Secret version changed since the plan; re-run")
            client.update_secret(detail.id, oci.vault.models.UpdateSecretDetails(secret_content=content(live)))
            secret_id = detail.id
        else:
            created = client.create_secret(oci.vault.models.CreateSecretDetails(
                compartment_id=like.compartment_id, vault_id=like.vault_id, key_id=like.key_id,
                secret_name=args.secret, description=args.description,
                metadata={v.tag_key(cfg): tag} if tag else None, secret_content=content(live))).data
            secret_id = created.id
        after = v.wait_for_active(client, secret_id)
        stored = v.read_secret_value(cfg, args.env, secret_id, int(after.current_version_number))
        if not hmac.compare_digest(stored.encode(), live.encode()):
            raise v.OpsError("Vault CURRENT does not match the imported value after writing")
        stored = None
        v.event("import_complete", result="SUCCESS", environment=args.env, secret=args.secret,
                current_version=int(after.current_version_number), rotation_tag=v.tag_of(after, cfg),
                mutation="VAULT_WRITE")
        return 0
    finally:
        live = vault_value = None


if __name__ == "__main__":
    try:
        sys.exit(main())
    except v.OpsError as exc:
        v.event("import_blocked", result="NO_MUTATION", reason=str(exc))
        sys.exit(2)
    except Exception as exc:
        v.event("import_failed", **v.safe_error_fields(exc))
        sys.exit(2)
