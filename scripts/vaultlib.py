#!/usr/bin/env python3
"""Shared helpers for the oci-vault-operations skill.

Every function here either reads metadata or is an explicitly named step of an
approved transaction. Nothing in this module prints, logs, or persists a secret
value. Functions that return a value (``read_secret_value``,
``password_from_policy``) are only called by executors after exact confirmation,
and callers must never emit their return value.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets as csprng
import socket
import string
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import oci

# Rotation tags
#   P1               Vault-only rotation; nothing downstream
#   P2               has downstream consumers; needs a handler before it can rotate
#   P2:<H>[:<H>...]  Vault plus each named downstream handler, in order
#   EXEMPT           does not require rotation
#   MANUAL           rotates, but the skill cannot perform it (e.g. provider-issued keys)
UNTAGGED = "UNTAGGED"
UNRECOGNIZED = "UNRECOGNIZED"
DEFAULT_TAG_KEY = "rotationTag"
LEGACY_TAG_KEYS = ("rotationClass",)
TAG_PATTERN = re.compile(r"^(P1|P2(?::[A-Z][A-Z0-9_]{0,29})*|EXEMPT|MANUAL)$")
# Downstream handlers this skill can execute. P2 rotation is refused unless
# every handler named in the tag is here, so a rotation never runs half its targets.
IMPLEMENTED_HANDLERS = frozenset({"ADB", "PG", "COMPOSE"})
DEFAULT_CONFIG = "~/.config/oci-vault-ops/config.json"
DEFAULT_LOCAL_OVERRIDE = "~/.config/oci-vault-ops/local.json"
SAFE_DB_USER = re.compile(r"^[A-Z][A-Z0-9_$#]{0,127}$")
SAFE_SSH_HOST = re.compile(r"^[A-Za-z0-9_.-]+$")


class OpsError(RuntimeError):
    """Expected operational failure. Messages are authored here and never contain secret material."""


@dataclass
class Check:
    name: str
    status: str  # PASS | FAIL | WARN
    detail: str


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def event(event_name: str, /, **fields: object) -> None:
    """Emit one redacted JSON event line.

    The event name is positional-only so a field may itself be called ``name``.
    """
    payload: dict[str, object] = {
        "time_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "event": event_name,
        **fields,
    }
    print(json.dumps(payload, sort_keys=True, default=str), flush=True)


def safe_error_fields(exc: BaseException) -> dict[str, object]:
    """Describe an exception without its message.

    Drivers and remote services can echo credentials or request details in
    exception text, so only the type and OCI status/code are ever reported.
    """
    fields: dict[str, object] = {"error_type": type(exc).__name__}
    if isinstance(exc, oci.exceptions.ServiceError):
        fields.update({"oci_http_status": exc.status, "oci_code": exc.code})
    return fields


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load the mapping config, then merge workstation-only runtime overrides.

    The override file lets a team share one mapping (OCIDs, secret names) while
    each operator keeps profiles and wallet paths local.
    """
    config_path = Path(path or os.environ.get("OCI_VAULT_OPS_CONFIG", DEFAULT_CONFIG)).expanduser()
    if not config_path.is_file():
        raise OpsError(f"Config not found: {config_path}. Copy config/vault-ops.example.json or run discover_config.py")
    cfg = json.loads(config_path.read_text())
    override_path = Path(os.environ.get("OCI_VAULT_OPS_LOCAL", DEFAULT_LOCAL_OVERRIDE)).expanduser()
    if override_path.is_file() and override_path.resolve() != config_path.resolve():
        runtime = json.loads(override_path.read_text()).get("runtime_overrides", {})
        if not isinstance(runtime, dict):
            raise OpsError("runtime_overrides in the local override file must be a JSON object")
        cfg = _deep_merge(cfg, runtime)
    return cfg


def environment(cfg: dict[str, Any], env: str) -> dict[str, Any]:
    envs = cfg.get("environments", {})
    if env not in envs:
        raise OpsError(f"Unknown environment '{env}'. Configured: {', '.join(sorted(envs)) or 'none'}")
    return envs[env]


def sdk_config(cfg: dict[str, Any], env: str | None = None) -> dict[str, Any]:
    oci_cfg = cfg.get("oci", {})
    profile = oci_cfg.get("profile")
    if not profile:
        raise OpsError("Config must name an explicit oci.profile; the DEFAULT profile is never assumed")
    kwargs: dict[str, Any] = {"profile_name": profile}
    if oci_cfg.get("config_file"):
        kwargs["file_location"] = str(Path(oci_cfg["config_file"]).expanduser())
    sdk = oci.config.from_file(**kwargs)
    region = (environment(cfg, env).get("region") if env else None) or oci_cfg.get("region")
    if region:
        sdk["region"] = region
    return sdk


def tag_key(cfg: dict[str, Any]) -> str:
    return cfg.get("tag_key", DEFAULT_TAG_KEY)


def valid_tag(tag: str) -> bool:
    return bool(TAG_PATTERN.fullmatch(tag or ""))


def tag_of(detail: Any, cfg: dict[str, Any]) -> str:
    value = dict(detail.metadata or {}).get(tag_key(cfg))
    if value is None:
        return UNTAGGED
    return value if valid_tag(value) else UNRECOGNIZED


def tag_handlers(tag: str) -> list[str]:
    """Downstream handlers named by a P2 tag, in order. Empty for every other tag."""
    return tag.split(":")[1:] if tag.startswith("P2") else []


def route_check(tag: str, required_handlers: list[str]) -> Check:
    """PASS only when the tag names exactly these handlers and all of them are implemented."""
    if tag in (UNTAGGED, UNRECOGNIZED):
        return Check("rotation_tag", "FAIL", f"{tag}; tag the secret before rotating")
    if tag in ("EXEMPT", "MANUAL"):
        return Check("rotation_tag", "FAIL", f"{tag}; this skill does not rotate it")
    if not required_handlers:
        ok = tag == "P1"
        return Check("rotation_tag", "PASS" if ok else "FAIL",
                     tag if ok else f"{tag}; only P1 secrets rotate Vault-only")
    handlers = tag_handlers(tag)
    missing = [h for h in handlers if h not in IMPLEMENTED_HANDLERS]
    if tag == "P1":
        return Check("rotation_tag", "FAIL", "P1; use rotate_vault_only.py")
    if not handlers:
        return Check("rotation_tag", "FAIL", "P2 without a handler; name one, e.g. P2:ADB")
    if missing:
        return Check("rotation_tag", "FAIL",
                     f"{tag}; no handler yet for {', '.join(missing)}, refusing a partial rotation")
    if handlers != required_handlers:
        return Check("rotation_tag", "FAIL", f"{tag}; this runner handles {':'.join(required_handlers)} only")
    return Check("rotation_tag", "PASS", tag)


def vault_only_secrets(cfg: dict[str, Any], env: str) -> list[str]:
    return list(environment(cfg, env).get("vault_only_secrets") or [])


def secret_binding(cfg: dict[str, Any], env: str, secret: str) -> dict[str, Any] | None:
    """Config half of the gate for P2 handlers other than ADB:
    environments.<env>.secret_bindings.<secret> = {"value": {...}, "handlers": {"PG": {...}, ...}}"""
    return (environment(cfg, env).get("secret_bindings") or {}).get(secret)


# ---------------------------------------------------------------------------
# Vault lookups (metadata only)
# ---------------------------------------------------------------------------

def vault_client(cfg: dict[str, Any], env: str) -> oci.vault.VaultsClient:
    return oci.vault.VaultsClient(sdk_config(cfg, env))


def list_env_secrets(cfg: dict[str, Any], env: str, client: oci.vault.VaultsClient | None = None) -> list[Any]:
    """Secret summaries across the environment's configured compartments."""
    settings = environment(cfg, env)
    compartments = settings.get("secret_compartments") or []
    if not compartments:
        raise OpsError(f"Environment '{env}' has no secret_compartments configured")
    client = client or vault_client(cfg, env)
    allowed_vaults = set(settings.get("vault_ids") or [])
    rows: list[Any] = []
    for compartment in compartments:
        rows.extend(oci.pagination.list_call_get_all_results(
            client.list_secrets, compartment_id=compartment, sort_by="NAME", sort_order="ASC").data)
    rows = [row for row in rows if row.lifecycle_state != "DELETED"]
    if allowed_vaults:
        rows = [row for row in rows if row.vault_id in allowed_vaults]
    return rows


def find_secret(cfg: dict[str, Any], env: str, name: str, *, require_active: bool = True,
                client: oci.vault.VaultsClient | None = None) -> tuple[oci.vault.VaultsClient, Any]:
    client = client or vault_client(cfg, env)
    matches = [row for row in list_env_secrets(cfg, env, client) if row.secret_name == name]
    if len(matches) != 1:
        raise OpsError(f"Expected exactly one secret named {name} in {env}; found {len(matches)}")
    detail = client.get_secret(matches[0].id).data
    if require_active and detail.lifecycle_state != "ACTIVE":
        raise OpsError(f"Secret {name} is {detail.lifecycle_state}, not ACTIVE")
    return client, detail


def pending_versions(client: oci.vault.VaultsClient, secret_id: str) -> list[int]:
    versions = oci.pagination.list_call_get_all_results(client.list_secret_versions, secret_id=secret_id).data
    return sorted(int(v.version_number) for v in versions if "PENDING" in (v.stages or []))


def resolve_target(cfg: dict[str, Any], env: str, secret_name: str) -> tuple[str, dict[str, Any], str]:
    """Map a secret to exactly one configured database and user.

    Mapping is explicit by design: a secret is rotatable against a database only
    when the config names it as that database's admin_secret or in user_secrets.
    """
    found: list[tuple[str, dict[str, Any], str]] = []
    for db_key, db in (environment(cfg, env).get("databases") or {}).items():
        if db.get("admin_secret") == secret_name:
            found.append((db_key, db, "ADMIN"))
        user = (db.get("user_secrets") or {}).get(secret_name)
        if user:
            found.append((db_key, db, str(user).upper()))
    if len(found) != 1:
        raise OpsError(f"Secret {secret_name} must map to exactly one database user in {env}; found {len(found)}")
    db_key, db, username = found[0]
    if not SAFE_DB_USER.fullmatch(username):
        raise OpsError("Mapped database username does not meet the allowed identifier policy")
    return db_key, db, username


# ---------------------------------------------------------------------------
# Approved-transaction steps (these touch values or mutate Vault)
# ---------------------------------------------------------------------------

def read_secret_value(cfg: dict[str, Any], env: str, secret_id: str, version_number: int | None = None) -> str:
    """Read one secret version into memory. Callers must never emit the result."""
    client = oci.secrets.SecretsClient(sdk_config(cfg, env))
    kwargs = {"version_number": version_number} if version_number is not None else {}
    bundle = client.get_secret_bundle(secret_id, **kwargs).data
    return base64.b64decode(bundle.secret_bundle_content.content).decode("utf-8")


def password_from_policy(cfg: dict[str, Any], username: str, exclude: str = "") -> str:
    """Generate a password from the configured policy using the OS CSPRNG.

    Ambiguous characters (O/0, I/l/1) are removed. The special-character set
    must not contain a double quote, because the value is placed inside a
    quoted identifier in ALTER USER.
    """
    policy = cfg.get("password_policy", {})
    length = int(policy.get("length", 20))
    special = str(policy.get("special_chars", "#_-"))
    if '"' in special or "'" in special or "\\" in special:
        raise OpsError("password_policy.special_chars must not contain quotes or backslashes")
    drop = "".join(sorted(set(exclude)))
    classes = (
        string.ascii_uppercase.translate(str.maketrans("", "", "OI" + drop)),
        string.ascii_lowercase.translate(str.maketrans("", "", "ol" + drop)),
        string.digits.translate(str.maketrans("", "", "01" + drop)),
        special.translate(str.maketrans("", "", drop)),
    )
    minimums = (int(policy.get("min_upper", 2)), int(policy.get("min_lower", 2)),
                int(policy.get("min_digits", 2)), int(policy.get("min_special", 1)))
    if any(count and not charset for charset, count in zip(classes, minimums)):
        raise OpsError("After excluding characters the handlers cannot accept, a required character class is empty; "
                       "adjust password_policy.special_chars or min_special")
    if length < sum(minimums):
        raise OpsError("password_policy is inconsistent: length is below the required character minimums")
    alphabet = "".join(classes)
    while True:
        chars = [csprng.choice(charset) for charset, count in zip(classes, minimums) for _ in range(count)]
        chars.extend(csprng.choice(alphabet) for _ in range(length - sum(minimums)))
        csprng.SystemRandom().shuffle(chars)
        candidate = "".join(chars)
        # ADB rejects a password containing the username, and must start with a letter.
        if (not username or username.upper() not in candidate.upper()) and candidate[0].isalpha():
            return candidate


RETRYABLE_CONFLICTS = {"IncorrectState", "LockConflict"}


def is_retryable(exc: BaseException) -> bool:
    """True for errors that mean "the secret is busy", independent of SDK circuit-breaker settings.

    A secret sits in UPDATING for a few seconds after any change. Depending on
    configuration the SDK surfaces that as TransientServiceError or as a plain
    409 IncorrectState ServiceError.
    """
    if isinstance(exc, oci.exceptions.TransientServiceError):
        return True
    return isinstance(exc, oci.exceptions.ServiceError) and exc.status == 409 and exc.code in RETRYABLE_CONFLICTS


def wait_for_active(client: oci.vault.VaultsClient, secret_id: str, timeout_seconds: int = 120) -> Any:
    """Poll until the secret leaves UPDATING. Returns the ACTIVE detail."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        detail = client.get_secret(secret_id).data
        if detail.lifecycle_state == "ACTIVE":
            return detail
        if detail.lifecycle_state not in ("UPDATING", "CREATING"):
            raise OpsError(f"Secret entered unexpected state {detail.lifecycle_state}")
        if time.monotonic() >= deadline:
            raise OpsError("Timed out waiting for the secret to become ACTIVE")
        time.sleep(2)


def generate_value(cfg: dict[str, Any], spec: dict[str, Any] | None, exclude: str = "", username: str = "") -> str:
    """Generate a new value for a secret binding's value spec.

    {"format": "password"} (default) uses password_policy minus excluded characters.
    {"format": "hex", "bytes": 32} gives 64 hex characters, e.g. for signing keys.
    """
    spec = spec or {}
    fmt = spec.get("format", "password")
    if fmt == "hex":
        return csprng.token_hex(int(spec.get("bytes", 32)))
    if fmt == "password":
        return password_from_policy(cfg, username, exclude)
    raise OpsError(f"Unknown value format '{fmt}'")


def stage_pending(client: oci.vault.VaultsClient, secret_id: str, value: str) -> int:
    """Stage a new value as the sole PENDING version; CURRENT is untouched."""
    content = oci.vault.models.Base64SecretContentDetails(
        content_type=oci.vault.models.Base64SecretContentDetails.CONTENT_TYPE_BASE64,
        content=base64.b64encode(value.encode("utf-8")).decode("ascii"),
        stage=oci.vault.models.Base64SecretContentDetails.STAGE_PENDING,
    )
    client.update_secret(secret_id, oci.vault.models.UpdateSecretDetails(secret_content=content))
    wait_for_active(client, secret_id)
    pending = pending_versions(client, secret_id)
    if len(pending) != 1:
        raise OpsError("Vault did not produce exactly one pending version")
    return pending[0]


def promote_pending_version(client: oci.vault.VaultsClient, secret_id: str, pending_version: int,
                            max_attempts: int = 6) -> int:
    """Promote a verified PENDING version, inspecting state after every transient error.

    OCI can accept an update while the client sees a transient failure, so a
    retry happens only after confirming the promotion has not already landed.
    """
    for attempt in range(1, max_attempts + 1):
        wait_for_active(client, secret_id)
        try:
            client.update_secret(secret_id, oci.vault.models.UpdateSecretDetails(current_version_number=pending_version))
        except Exception as exc:
            if not is_retryable(exc):
                raise
            if int(client.get_secret(secret_id).data.current_version_number) == pending_version:
                event("vault_promotion_confirmed_after_transient", pending_version=pending_version, attempt=attempt)
                return pending_version
            if attempt == max_attempts:
                raise OpsError(f"Vault promotion remained transiently unavailable after {max_attempts} attempts")
            event("vault_promotion_retrying", pending_version=pending_version, attempt=attempt)
            time.sleep(min(2 ** attempt, 5))
            continue
        current = int(wait_for_active(client, secret_id).current_version_number)
        if current != pending_version:
            raise OpsError("Vault promotion did not select the staged version")
        return current
    raise OpsError("Vault promotion did not complete")


def set_auto_generation(client: oci.vault.VaultsClient, secret_id: str, enabled: bool,
                        generation_context: Any = None, timeout_seconds: int = 90) -> None:
    """Change Vault auto-generation and wait until the secret is ACTIVE in the requested state.

    Rotation disables auto-generation so Vault cannot generate a competing value
    mid-transaction, then restores the original policy.
    """
    details = oci.vault.models.UpdateSecretDetails(enable_auto_generation=enabled)
    if enabled:
        details.secret_generation_context = generation_context
    for attempt in range(1, 7):
        if client.get_secret(secret_id).data.lifecycle_state != "ACTIVE":
            time.sleep(min(2 ** attempt, 5))
            continue
        try:
            client.update_secret(secret_id, details)
        except Exception as exc:
            if not is_retryable(exc):
                raise
            event("auto_generation_update_retrying", attempt=attempt)
            time.sleep(min(2 ** attempt, 5))
            continue
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            detail = client.get_secret(secret_id).data
            if detail.lifecycle_state == "ACTIVE" and bool(detail.is_auto_generation_enabled) is enabled:
                return
            time.sleep(1)
        raise OpsError("Timed out waiting for the requested auto-generation state")
    raise OpsError("Vault auto-generation update remained unavailable after six attempts")


# ---------------------------------------------------------------------------
# Database connectivity
# ---------------------------------------------------------------------------

def tns_entry(wallet_dir: Path, alias: str) -> str | None:
    tns = wallet_dir / "tnsnames.ora"
    if not tns.is_file():
        return None
    text = tns.read_text(errors="replace")
    match = re.search(rf"(?ims)^\s*{re.escape(alias)}\s*=\s*(\(.*?)(?=^\s*[A-Za-z0-9_]+\s*=|\Z)", text)
    return match.group(1) if match else None


def tns_field(entry: str, field: str) -> str | None:
    match = re.search(rf"(?i)\(\s*{field}\s*=\s*([^)\s]+)\s*\)", entry)
    return match.group(1) if match else None


def wallet_key_encrypted(wallet_dir: Path) -> bool:
    pem = wallet_dir / "ewallet.pem"
    return pem.is_file() and "ENCRYPTED PRIVATE KEY" in pem.read_text(errors="replace")


def database_service_names(adb: Any) -> set[str]:
    names: set[str] = set()
    profiles = getattr(getattr(adb, "connection_strings", None), "profiles", None) or []
    for profile in profiles:
        found = tns_field(str(profile.value or ""), "service_name")
        if found:
            names.add(found.lower())
    return names


def ssh_forwards(host: str) -> list[tuple[int, str, int]]:
    if not SAFE_SSH_HOST.fullmatch(host):
        raise OpsError("ssh_host must contain only letters, digits, dots, dashes, or underscores")
    result = subprocess.run(["ssh", "-G", host], capture_output=True, text=True, check=True)
    return parse_ssh_forwards(result.stdout)


def parse_ssh_forwards(ssh_g_output: str) -> list[tuple[int, str, int]]:
    found: list[tuple[int, str, int]] = []
    for line in ssh_g_output.splitlines():
        fields = line.split()
        if len(fields) != 3 or fields[0] != "localforward" or not fields[1].isdigit():
            continue
        match = re.fullmatch(r"(?:\[(.+)\]|([^:]+)):(\d+)", fields[2])
        if match:
            found.append((int(fields[1]), match.group(1) or match.group(2), int(match.group(3))))
    return found


def local_port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            return True
    except OSError:
        return False


def has_oracledb() -> bool:
    try:
        import oracledb  # noqa: F401
        return True
    except ImportError:
        return False


def database(cfg: dict[str, Any], env: str, db_key: str) -> dict[str, Any]:
    db = (environment(cfg, env).get("databases") or {}).get(db_key)
    if not db:
        raise OpsError(f"No database '{db_key}' configured in {env}")
    return db


def connectivity(cfg: dict[str, Any], env: str, db_key: str) -> tuple[list[Check], dict[str, Any]]:
    """Read-only prerequisites for authenticating to one Autonomous Database."""
    db = database(cfg, env, db_key)
    mode = db.get("connection", "public")
    if mode not in ("public", "ssh_tunnel"):
        raise OpsError("database.connection must be 'public' or 'ssh_tunnel'")
    adb = oci.database.DatabaseClient(sdk_config(cfg, env)).get_autonomous_database(db["ocid"]).data
    wallet = Path(db.get("wallet_dir", "")).expanduser()
    alias = db.get("service_alias", "")
    entry = tns_entry(wallet, alias) if wallet.is_dir() else None
    endpoint = getattr(adb, "private_endpoint", None)

    checks = [
        Check("adb_lifecycle", "PASS" if adb.lifecycle_state == "AVAILABLE" else "FAIL", adb.lifecycle_state),
        Check("connection_mode", "PASS" if (mode == "public") == (not endpoint) else "FAIL",
              f"{mode}; private endpoint {'configured' if endpoint else 'not configured'}"),
        Check("wallet_directory", "PASS" if wallet.is_dir() else "FAIL", str(wallet)),
        Check("wallet_tns_alias", "PASS" if entry else "FAIL", alias or "service_alias not set"),
    ]
    if entry:
        service = (tns_field(entry, "service_name") or "").lower()
        checks.append(Check("wallet_matches_database",
                            "PASS" if service and service in database_service_names(adb) else "FAIL",
                            "wallet service name belongs to this database" if service else "no service_name in alias"))
    if wallet.is_dir():
        encrypted = wallet_key_encrypted(wallet)
        checks.append(Check("wallet_password_source",
                            "PASS" if (not encrypted or db.get("wallet_password_secret")) else "FAIL",
                            "wallet key encrypted; password read from Vault" if encrypted and db.get("wallet_password_secret")
                            else "wallet key encrypted; set wallet_password_secret" if encrypted
                            else "wallet key not encrypted"))
    checks.append(Check("oracledb_runtime", "PASS" if has_oracledb() else "FAIL", "python-oracledb import"))

    details: dict[str, Any] = {"connection": mode, "wallet_dir": str(wallet), "service_alias": alias}
    if mode == "ssh_tunnel":
        host = db.get("ssh_host", "")
        forward = next((f for f in (ssh_forwards(host) if host else [])
                        if endpoint and f[1].lower() == endpoint.lower() and f[2] == 1522), None)
        if not forward:
            checks.append(Check("ssh_forward", "FAIL", f"No {endpoint}:1522 LocalForward for ssh host '{host}'"))
        else:
            port = forward[0]
            tns_port = tns_field(entry or "", "port")
            tns_host = (tns_field(entry or "", "host") or "").lower()
            checks += [
                Check("ssh_forward", "PASS", f"{host}: 127.0.0.1:{port} -> {endpoint}:1522"),
                Check("local_tunnel", "PASS" if local_port_open(port) else "FAIL", f"127.0.0.1:{port}"),
                Check("alias_uses_tunnel", "PASS" if tns_port == str(port) and tns_host in ("127.0.0.1", "localhost") else "FAIL",
                      f"{alias} -> {tns_host}:{tns_port}"),
            ]
            details["local_port"] = port
    return checks, details


def all_pass(checks: list[Check]) -> bool:
    return all(check.status != "FAIL" for check in checks)


def wallet_password(cfg: dict[str, Any], env: str, db: dict[str, Any]) -> str | None:
    """Read the wallet password from Vault when configured. Never emit the result."""
    name = db.get("wallet_password_secret")
    if not name:
        return None
    _, detail = find_secret(cfg, env, name)
    return read_secret_value(cfg, env, detail.id)


def connect_kwargs(db: dict[str, Any], wallet_dir: str, user: str, password: str,
                   wallet_pw: str | None) -> dict[str, Any]:
    return {
        "user": user,
        "password": password,
        "dsn": db["service_alias"],
        "config_dir": wallet_dir,
        "wallet_location": wallet_dir,
        "wallet_password": wallet_pw,
    }


def connect(db: dict[str, Any], wallet_dir: str, user: str, password: str, wallet_pw: str | None):
    import oracledb
    return oracledb.connect(**connect_kwargs(db, wallet_dir, user, password, wallet_pw))


def verify_login(db: dict[str, Any], wallet_dir: str, user: str, password: str, wallet_pw: str | None) -> None:
    connection = connect(db, wallet_dir, user, password, wallet_pw)
    connection.close()


def can_login(db: dict[str, Any], wallet_dir: str, user: str, password: str, wallet_pw: str | None) -> bool:
    try:
        verify_login(db, wallet_dir, user, password, wallet_pw)
        return True
    except Exception:
        return False
