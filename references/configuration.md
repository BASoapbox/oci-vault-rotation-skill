# Configuration

The config maps environments to compartments, databases, and secrets. It holds
OCIDs and names, never secret values, but treat it as private: it describes
your tenancy's layout.

Default location: `~/.config/oci-vault-ops/config.json`. Override with
`--config` or `$OCI_VAULT_OPS_CONFIG`. Start from
`config/vault-ops.example.json`, or draft one with:

```bash
python scripts/discover_config.py --profile MYPROFILE \
  --wallet-root ~/wallets --output ~/.config/oci-vault-ops/config.json
```

Discovery is read-only against OCI and writes a mode-600 draft. **Review every
`admin_secret` and `user_secrets` entry**: the naming heuristic can be wrong, and
a wrong mapping points a rotation at the wrong account. Secrets it could not map
are listed under `_unmapped_secrets`.

## Keys

| Key | Purpose |
|---|---|
| `python` | Optional interpreter path for the agent to use |
| `oci.profile` | **Required.** Never defaults to DEFAULT |
| `oci.region`, `oci.config_file` | Optional |
| `tag_key` | Metadata key for the rotation tag (default `rotationTag`) |
| `password_policy` | Length and per-class minimums; `special_chars` must not contain quotes |
| `audit_journal`, `audit_actor` | Optional journal path and your name |
| `environments.<env>.region` | Optional per-environment region |
| `environments.<env>.secret_compartments` | Compartment OCIDs to search for secrets |
| `environments.<env>.vault_ids` | Optional: restrict to these vaults |
| `environments.<env>.vault_only_secrets` | Secret names allowed to rotate as `P1` (the config half of the two gates) |
| `environments.<env>.databases.<key>` | One entry per Autonomous Database |

### Database entry

| Key | Purpose |
|---|---|
| `ocid` | Autonomous Database OCID |
| `connection` | `public` (reachable endpoint + ACL) or `ssh_tunnel` (private endpoint) |
| `service_alias` | TNS alias from the wallet, e.g. `mydb_low` |
| `wallet_dir` | Unzipped wallet directory |
| `wallet_password_secret` | Vault secret holding the wallet password; required when `ewallet.pem` is encrypted |
| `ssh_host` | `ssh_tunnel` only: an `~/.ssh/config` host with a `LocalForward` to the private endpoint on 1522 |
| `admin_secret` | Vault secret name for ADMIN |
| `user_secrets` | `{ "secret-name": "DB_USERNAME" }` |

For `ssh_tunnel`, the wallet's alias must point at `127.0.0.1` and the forwarded
local port. `preflight.py` checks both.

## Team pattern: shared mapping, local paths

A team can keep one mapping in a private repository and let each operator hold
workstation-specific values in `~/.config/oci-vault-ops/local.json` (override
with `$OCI_VAULT_OPS_LOCAL`). Only its `runtime_overrides` object is merged:

```json
{
  "runtime_overrides": {
    "oci": { "profile": "MY_PROFILE" },
    "environments": { "stage": { "databases": { "appdb": { "wallet_dir": "~/wallets/Wallet_appdb" } } } }
  }
}
```

Never commit wallets, OCI API keys, the local override file, or the journal.
