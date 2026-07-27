# External credential-provider examples

These adapters implement Network Collector's `credentials.provider: command`
contract. The collector invokes the configured program once per selected
inventory device and supplies:

- `NET_TARGET_HOSTNAME`
- `NET_TARGET_IP`
- `NET_CREDENTIAL_PROFILE`

The adapter must write exactly one JSON object to stdout:

```json
{"username":"automation","password":"secret"}
```

Diagnostics belong on stderr. Never enable shell tracing because it can expose
retrieved passwords. The examples require `jq`; Vault and 1Password also
require their supported CLIs. CyberArk uses `curl`.

## HashiCorp Vault KV

Use [`vault.yaml`](vault.yaml) and export the Vault connection/authentication
variables accepted by your deployment plus:

```bash
export VAULT_KV_MOUNT=network
export VAULT_KV_PREFIX=devices
```

For `credential_profile: datacenter`, [`vault.sh`](vault.sh) runs:

```text
vault kv get -format=json -mount=network devices/datacenter
```

The KV record must contain string fields named `username` and `password`. Use a
read-only policy scoped to the required paths. Prefer workload identity,
AppRole, Kubernetes auth, or another short-lived machine identity over a
long-lived token in an environment file. The adapter follows HashiCorp's
[`vault kv get`](https://developer.hashicorp.com/vault/docs/commands/kv/get)
mount syntax.

## 1Password

Use [`onepassword.yaml`](onepassword.yaml), authenticate `op` with a
least-privilege service account or approved interactive session, and set:

```bash
export OP_VAULT='Network Automation'
export OP_ITEM_PREFIX='collector-'
```

For `credential_profile: datacenter`, [`onepassword.sh`](onepassword.sh)
reads `username` and `password` from `collector-datacenter`. Restrict the
service account to the named vault and required items.
This uses 1Password's documented
[`op read` secret-reference flow](https://developer.1password.com/docs/cli/secrets-scripts).

## CyberArk Central Credential Provider

Use [`cyberark.yaml`](cyberark.yaml) and configure:

```bash
export CYBERARK_CCP_URL='https://ccp.example/AIMWebService/api/Accounts'
export CYBERARK_APP_ID='NetworkCollector'
export CYBERARK_SAFE='Network-Automation'
export CYBERARK_OBJECT_PREFIX='collector-'
export CYBERARK_CA_FILE='/etc/network-collector/ca.pem'
export CYBERARK_CLIENT_CERT='/etc/network-collector/client.pem'
export CYBERARK_CLIENT_KEY='/etc/network-collector/client-key.pem'
# Optional when required by the account policy:
export CYBERARK_REASON='Network Collector automation'
```

For `credential_profile: datacenter`, [`cyberark.sh`](cyberark.sh) queries
`Safe=Network-Automation;Object=collector-datacenter` and maps CyberArk's
`UserName` and `Content` response fields to the provider contract. Client
certificate variables are optional but must be supplied as a pair. The
adapter deliberately has no insecure TLS option.
The request uses CyberArk Central Credential Provider's
`AIMWebService/api/Accounts` application/query pattern; confirm the application
authentication rules and query fields with the documentation for your deployed
CyberArk release.

## Inventory selection

Profiles keep secret-system object names independent of addresses:

```yaml
hosts:
  - name: core-01
    ip: 192.0.2.10
    type: cisco_iosxr
    credential_profile: datacenter
```

When `credential_profile` is absent, each adapter falls back to the inventory
hostname. Secret resolution occurs before device execution starts. A provider
failure stops the run before any network changes are attempted.
