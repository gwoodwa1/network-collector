# Enterprise credential-provider examples

Network Collector has first-class `hashicorp`, `1password`, and `cyberark`
providers. Non-secret connection and lookup settings can be placed in YAML or
supplied through environment variables. A non-empty YAML value takes
precedence over its environment fallback.

Keep authentication tokens out of YAML:

- HashiCorp authentication remains with `VAULT_TOKEN`, the Vault token helper,
  or another supported Vault CLI login method.
- 1Password authentication remains with `OP_SERVICE_ACCOUNT_TOKEN` or an
  approved signed-in CLI session.
- CyberArk CCP authorization remains in AppID restrictions and, when required,
  a client certificate whose path can be configured in YAML.

Credentials are resolved once per selected inventory device before network
execution begins.

## HashiCorp Vault KV

Use [`vault.yaml`](vault.yaml):

```yaml
credentials:
  provider: hashicorp
  hashicorp:
    address: https://vault.example:8200
    namespace: network
    mount: network
    path_prefix: devices
    ca_file: /etc/network-collector/vault-ca.pem
```

For `credential_profile: datacenter`, the provider runs:

```text
vault kv get -format=json -mount=network devices/datacenter
```

The KV record must contain `username` and `password` string fields unless
`username_field` or `password_field` overrides them. Use a read-only policy
scoped to the required paths. Prefer workload identity, AppRole, Kubernetes
auth, or another short-lived machine identity over a long-lived token in an
environment file. The provider follows HashiCorp's
[`vault kv get`](https://developer.hashicorp.com/vault/docs/commands/kv/get)
mount syntax and supports KV v1 and v2 JSON output.

YAML fields have these environment fallbacks: `VAULT_ADDR`,
`VAULT_NAMESPACE`, `VAULT_KV_MOUNT`, `VAULT_KV_PREFIX`, `VAULT_CACERT`,
`VAULT_CLIENT_CERT`, and `VAULT_CLIENT_KEY`.

## 1Password

Use [`onepassword.yaml`](onepassword.yaml):

```yaml
credentials:
  provider: 1password
  onepassword:
    account: automation.1password.com
    vault: Network Automation
    item_prefix: collector-
```

For `credential_profile: datacenter`, the provider reads `username` and
`password` from `collector-datacenter`. Restrict the service account to the
named vault and required items. `OP_ACCOUNT`, `OP_VAULT`, and `OP_ITEM_PREFIX`
are environment fallbacks. Authentication remains in the standard
`OP_SERVICE_ACCOUNT_TOKEN` variable or an approved signed-in session.

This uses 1Password's documented
[`op read` secret-reference flow](https://developer.1password.com/docs/cli/secrets-scripts).

## CyberArk Central Credential Provider

Use [`cyberark.yaml`](cyberark.yaml):

```yaml
credentials:
  provider: cyberark
  cyberark:
    url: https://ccp.example/AIMWebService/api/Accounts
    app_id: NetworkCollector
    safe: Network-Automation
    object_prefix: collector-
    folder: Root
    ca_file: /etc/network-collector/ca.pem
    cert_file: /etc/network-collector/client.pem
    key_file: /etc/network-collector/client-key.pem
```

For `credential_profile: datacenter`, the provider queries
`Safe=Network-Automation;Object=collector-datacenter` and maps CyberArk's
`UserName` and `Content` response fields to the collector credential contract.
Client certificate fields are optional but must be supplied as a pair. The
provider requires HTTPS with TLS 1.2 or newer and deliberately has no insecure
TLS option.

Every nested field has an environment fallback: `CYBERARK_CCP_URL`,
`CYBERARK_APP_ID`, `CYBERARK_SAFE`, `CYBERARK_OBJECT_PREFIX`,
`CYBERARK_FOLDER`, `CYBERARK_REASON`, `CYBERARK_CA_FILE`,
`CYBERARK_CLIENT_CERT`, and `CYBERARK_CLIENT_KEY`.

Confirm AppID authentication rules and query fields with the documentation for
your deployed CyberArk release.

## Inventory selection

Profiles keep secret-system object names independent of addresses:

```yaml
hosts:
  - name: core-01
    ip: 192.0.2.10
    type: cisco_iosxr
    credential_profile: datacenter
```

When `credential_profile` is absent, each provider falls back to the inventory
hostname. A provider failure stops the run before network changes are
attempted.

## Executable boundary

The generic `command`/`exec` credential provider is intentionally unsupported.
HashiCorp and 1Password use only the approved executable names `vault` and
`op`, with collector-owned arguments; YAML cannot select a binary or supply
arguments. CyberArk uses the built-in HTTPS client and does not launch `curl`.
Add other secret systems as reviewed Go providers rather than workbook
commands.
