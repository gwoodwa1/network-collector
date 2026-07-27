# Network Collector

Network Collector is a Go-based tool designed for flexible and efficient data collection from various network devices. It supports multiple protocols and drivers, allowing you to connect to and collect data from a wide range of network devices.

## Features

- **SSH**: Collect data using SSH for devices running various operating systems like Cisco NX-OS, Juniper Junos, etc.
- **HTTP**: Fetch data using HTTP from devices with REST APIs, such as Arista EOS.
- **Netconf**: Use Netconf to interact with devices supporting the Netconf protocol.
- **gNMI**: Collect data using the gNMI protocol.
- **RESTCONF**: Fetch data using RESTCONF from devices supporting this protocol.


<img width="1672" height="941" alt="info_graphic" src="https://github.com/user-attachments/assets/7a1fe8ff-9b94-4539-8314-24fcdc5220f7" />

## Installation

Download a platform archive from the [GitHub releases page](https://github.com/gwoodwa1/network-collector/releases), extract it, and run:

```bash
./network-collector --version
```

To build from source instead:

1. **Clone the repository:**

    ```bash
    git clone https://github.com/gwoodwa1/network-collector.git
    cd network-collector
    ```

2. **Install dependencies:**

    ```bash
    go mod tidy
    ```

3. **Build the CLI examples:**

    ```bash
    go build -o network-collector ./cmd/network-collector
    go build -o arista-http ./cmd/arista-http
    go build -o netconf-client ./cmd/netconf-client
    go build -o gnmi-client ./cmd/gnmi-client
    go build -o restconf-client ./cmd/restconf-client
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o xr-routing-monitor ./cmd/xr-routing-monitor
    ```

4. **Provide credentials:**

    Set credentials using environment variables:

    ```bash
    export NET_USER=<username>
    export NET_PASSWORD=<your password>
    ```

Alternatively, pass `--creds_input` to any of the built commands to be
    prompted for a username and password. Interactive input overrides any
    credentials already set in the environment, and password entry is hidden:

    ```bash
    ./network-collector --creds_input
    ```

For RSA SecurID authentication, use `--rsa-token` (or set
`credentials.rsa_token: true`). The collector prompts once at startup and
reuses that token while opening the selected devices, including devices
started in parallel. Each device then keeps one SSH session for its complete
workflow. If a workflow deliberately closes and reconnects the session, or a
later scheduled occurrence needs a new session, the collector pauses for a
fresh masked RSA passcode; it never silently retries with the old token.

```yaml
credentials:
  rsa_token: true
```

For unattended or mixed-credential estates, select a credential provider in the playbook. Existing environment behavior remains the default:

```yaml
credentials:
  provider: file
  file: /secure/network-credentials.yaml
```

Credential files must not be accessible by group or other users (`chmod 600`) and support a default plus named profiles:

```yaml
default: {username: automation, password: replace-me}
profiles:
  datacenter: {username: eos-automation, password: replace-me}
  edge: {username: junos-automation, password: replace-me}
```

Assign a profile to an inventory host with `credential_profile: datacenter`. The `command` provider executes an argument array and expects one JSON object on stdout containing `username` and `password`; it receives `NET_TARGET_HOSTNAME`, `NET_TARGET_IP`, and `NET_CREDENTIAL_PROFILE` environment variables:

```yaml
credentials:
  provider: command
  command: [/usr/local/bin/read-network-secret, --format, json]
  timeout_seconds: 30
```

This command contract can wrap Vault, AWS Secrets Manager, an OS keyring, or another organization-specific secret broker without storing secrets in playbooks. Provider commands time out after 30 seconds. Never commit populated credential files or print secrets from provider commands.

`timeout_seconds` can be set from 1 to 300 seconds. The helper receives
`NET_TARGET_HOSTNAME`, `NET_TARGET_IP`, and `NET_CREDENTIAL_PROFILE`; only its
stdout is decoded, so diagnostics should go to stderr. First-class provider
configurations and optional command adapters are included for
[HashiCorp Vault](examples/credential-providers/vault.yaml),
[1Password](examples/credential-providers/onepassword.yaml), and
[CyberArk CCP](examples/credential-providers/cyberark.yaml). See the
[credential-provider guide](examples/credential-providers/README.md) for
least-privilege setup and required variables.

Native provider names are `hashicorp` (aliases `vault` and
`hashicorp-vault`), `1password` (aliases `onepassword` and `op`), and
`cyberark` (aliases `cyberark-ccp` and `ccp`). Put non-secret endpoints,
lookup paths, field names, and certificate paths in their nested YAML block;
the corresponding vendor environment variables are fallbacks. Vault and
1Password authentication tokens are intentionally not accepted as YAML
fields.

### Docker

Build the multi-stage image. The final Alpine image runs as a non-root user and includes only the collector, CA roots, timezone data, OpenSSH client, and the default configuration/parser assets:

```bash
docker build --build-arg VERSION=dev -t network-collector:local .
```

Run with credentials supplied through the environment and mount configuration read-only. Mount `/workspace/artifacts` and `/workspace/session_logs` when the output must persist:

```bash
docker run --rm \
  -e NET_USER \
  -e NET_PASSWORD \
  -v "$PWD/config.yaml:/workspace/config.yaml:ro" \
  -v "$PWD/inventory.yaml:/workspace/inventory.yaml:ro" \
  -v "$PWD/parsers.yaml:/workspace/parsers.yaml:ro" \
  -v "$PWD/artifacts:/workspace/artifacts" \
  -v "$PWD/session_logs:/workspace/session_logs" \
  network-collector:local --fail-on-fail
```

The container uses `/workspace` as its working directory. Local workflow steps can execute only programs installed in the image; build a derived runtime image when additional local tools are required.

## Package usage

Import the SSH module into your Go program:

```go
import "github.com/gwoodwa1/network-collector/pkg/drivers/ssh"
```

Import the Arista HTTP driver:

```go
import "github.com/gwoodwa1/network-collector/pkg/drivers/aristahttp"
```

Import the NETCONF driver:

```go
import "github.com/gwoodwa1/network-collector/pkg/drivers/netconf"
```

Import the gNMI driver:

```go
import "github.com/gwoodwa1/network-collector/pkg/drivers/gnmi"
```

Import the RESTCONF driver:

```go
import "github.com/gwoodwa1/network-collector/pkg/drivers/restconf"
```

Example usage for SSH:

```go
client := ssh.NewClient()
if err := client.Connect("192.0.2.1", "admin", "password", "cisco_nxos"); err != nil {
    log.Fatal(err)
}
output, err := client.Execute("show version")
if err != nil {
    log.Fatal(err)
}
fmt.Println(output)
if err := client.Close(); err != nil {
    log.Fatal(err)
}
```

### Separate command examples

- `cmd/network-collector`: SSH example using `pkg/drivers/ssh`
- `cmd/arista-http`: HTTP example using `pkg/drivers/aristahttp`
- `cmd/netconf-client`: NETCONF example using `pkg/drivers/netconf`
- `cmd/gnmi-client`: gNMI example using `pkg/drivers/gnmi`
- `cmd/restconf-client`: RESTCONF example using `pkg/drivers/restconf`
- `cmd/xr-routing-monitor`: standalone Cisco IOS-XR change-window monitor

## CLI validation and output

The `cmd/network-collector` SSH example supports validation configured in `config.yaml` and these CLI flags:

- `--json`: emit consolidated machine-readable JSON for all validation results (suppresses raw command output)
- `--fail-on-fail`: exit with non-zero status if any validation returns `fail` or `error`, or if a device/step cannot run successfully
- `--creds_input`: securely prompt for credentials instead of using `NET_USER` and `NET_PASSWORD`
- `--rsa-token`: recognize RSA `PASSCODE:` challenges, cache the startup token across devices, and require fresh human input before reconnecting
- `--check` / `--dry-run`: discover declarative state and preview changes without applying configuration

`fail-on-fail` can also be configured with `fail_on_fail: true` in `config.yaml` or the `FAIL_ON_FAIL=true` environment variable. The CLI flag takes precedence when provided.

Example: run validations and emit only JSON

```bash
./network-collector --json
```

Example: run validations and exit non-zero if any check fails

```bash
./network-collector --fail-on-fail
```

Example: preview a workbook without applying changes

```bash
./network-collector --config change.yaml --check
```

Check mode never sends generic SSH commands, local commands, gNMI subscriptions,
SSH probes, approval gates, waits, facts collection, or mutating NETCONF
operations. A supported SSH `ensure` adapter may run only its predefined
read-only discovery command and emits exact apply and rollback command lists;
arbitrary SSH commands remain skipped. NETCONF RPC payloads whose top-level
operation is `get` or `get-config` still run because they are unambiguously
read-only; arbitrary vendor RPCs are previewed but skipped. Native `get-config`
and `validate` steps also run; lock, unlock, edit, commit, copy, delete,
discard, and cancel-commit are previewed only. NETCONF `ensure` steps perform
their discovery read and emit a JSON current/desired diff plus the exact
OpenConfig XML that would be applied.
This intentionally treats arbitrary imperative commands as unsafe instead of
guessing whether a vendor command is read-only. A separate post-change RPC in
an imperative workbook can still validate the current state and fail; use an
`ensure` step when the preview needs state-aware change planning.

## XR Routing Monitor

`cmd/xr-routing-monitor` is a standalone IOS-XR operational tool for live change windows. It opens persistent SSH sessions to a small set of routers, polls BGP, route, and interface health on an interval, and captures before/after BGP snapshots for later comparison.

It is separate from the playbook-driven `network-collector` CLI and has its own embedded TextFSM parser set. Build it as a static binary for jump hosts:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o xr-routing-monitor ./cmd/xr-routing-monitor
```

See [`cmd/xr-routing-monitor/README.md`](cmd/xr-routing-monitor/README.md) for devices-file examples, RSA passcode reuse behavior, VRF auto-detection, snapshot output, and live status formatting.
     
## Configuration

The configuration is done through a `config.yaml` file Here’s an example of the `config.yaml`:
```
fail_on_fail: false

restconf:
  - hostname: device-eos-02
    ip: 192.0.2.2
    port: 3333
    skip_tls: true
    method: GET
    endpoint: data/openconfig-interfaces:interfaces/interface

gnmi:
  - hostname: device-eos-01
    ip: 192.0.2.3:6030
    skip_tls: true
    path: /interfaces/interface/subinterfaces/subinterface/state/description

ssh:
  - hostname: device-nxos-01
    ip: 192.0.2.4
    type: cisco_nxos
    cmd: show ip route
  - hostname: device-qfx-01
    ip: 192.0.2.4
    type: juniper_junos
    cmd: show route

http:
  - hostname: device-eos-08
    ip: 192.0.2.5
    type: arista_eos
    cmd: show version
    skip_tls: true
  - hostname: device-eos-03
    ip: 192.0.2.6
    type: arista_eos
    cmd: show ip route
    skip_tls: true

netconf:
  - hostname: device-eos-05
    ip: 192.0.2.7
    type: arista_eos
    rpc: |
      <get>
        <filter type="subtree">
          <interfaces>
            <interface>
            </interface>
          </interfaces>
        </filter>
      </get>
  - hostname: device-eos
    ip: 192.0.2.8
    type: arista_eos
    rpc: |
      <get>
        <filter type="subtree">
          <interfaces>
            <interface>
            </interface>
          </interfaces>
        </filter>
      </get>
```

### SSH step-based commands with retry

The `cmd/network-collector` example supports `ssh.steps`, which lets you run multiple commands over the same SSH connection for a single device. Each step can include `validation` and optional retry behavior.

### Inventory-based SSH targets

You can keep connection details in `inventory.yaml` and reference them from `config.yaml`, which avoids repeating hostnames, IP addresses, and device types across playbook entries.

Example `inventory.yaml`:

```yaml
hosts:
  - name: router-01
    ip: 192.0.2.10
    type: cisco_ios
  - name: router-02
    ip: 192.0.2.11
    type: cisco_ios

groups:
  ios:
    hosts:
      - router-01
      - router-02
```

Example `config.yaml`:

```yaml
inventory_file: inventory.yaml
parsers_file: parsers.yaml

ssh:
  - host: router-01
    cmd: show version

  - group: ios
    steps:
      - name: show-version
        cmd: show version
```

Use `host` for one inventory host, `hosts` for a list of inventory hosts, `group` for one inventory group, or `groups` for multiple groups. Inventory hosts can define `name`, `hostname`, `ip` or `address`, `type`, `timeout`, and `operation_timeout`. Values in `config.yaml` override inventory values, so you can set a common `type` or timeout at the playbook entry if needed. Existing single-node entries with inline `hostname`, `ip`, and `type` continue to work without an inventory file.

### NETCONF workflow targets

Use a top-level `netconf` target when every executable device step should run
through NETCONF rather than a CLI SSH session. Targets use the same inventory,
credential providers, selectors, scheduling, workflow controls, validation,
retry, registration, drift, and artifact handling as `ssh` targets. NETCONF
connects to port 830 and uses `operation_timeout` for RPC operations.

```yaml
inventory_file: inventory.yaml

netconf:
  - host: junos-pe-01
    steps:
      - name: load-candidate
        netconf:
          operation: edit-config
          target: candidate
          payload_file: payloads/system-hostname.xml

      - name: commit-candidate
        netconf:
          operation: commit

      - name: verify-interface
        netconf:
          operation: rpc
          payload: |
            <get-interface-information>
              <interface-name>ge-0/0/0</interface-name>
              <terse/>
            </get-interface-information>
        validation:
          extractor: regex
          pattern: '<oper-status[^>]*>\s*(up)\s*</oper-status>'
          condition: eq
          expected: up
```

Supported step operations are:

- `rpc`: send the supplied operation element as a bare NETCONF RPC payload.
- `edit-config`: merge the supplied configuration into `candidate` (the
  default) or `running`.
- `commit`: commit the candidate configuration; optional `confirmed: true`
  and `confirm_timeout_seconds` enable confirmed commit. `persist` starts a
  persistent confirmed commit; a later commit with `persist_id` confirms it.
- `discard-changes` (`discard` or `rollback`): discard uncommitted candidate
  changes.
- `lock` / `unlock`: lock or release `candidate`, `running`, or `startup`
  (default `candidate`).
- `validate`: validate `candidate`, `running`, or `startup` (default
  `candidate`) when the target advertises `:validate`.
- `get-config`: read `running` (default), `candidate`, or `startup`, with an
  optional subtree filter in `payload` or `payload_file`.
- `copy-config`: copy between named `running`, `candidate`, and `startup`
  datastores.
- `delete-config`: delete only the `startup` datastore. Running configuration
  deletion is rejected.
- `cancel-commit`: cancel a confirmed commit, optionally using `persist_id`.

The target must advertise the corresponding NETCONF capability. Unsupported
operations fail with the returned RPC error rather than being approximated.
Mutating operations are rendered but not sent under `--check`.

Use either inline `payload` or `payload_file`, but not both. Relative payload
paths are resolved from the directory containing the main playbook. File
contents are loaded and then rendered with the same `{{variable}}` values as
inline payloads, which keeps large XML artifacts separate without losing
workflow parameterization.

### Declarative desired state

Use `ensure` when the workbook should express the desired state rather than an
imperative command followed by a regular-expression check. OpenConfig
interfaces are supported over NETCONF:

```yaml
netconf:
  - host: eos-netconf-01
    steps:
      - name: ensure-customer-handoff
        ensure:
          resource: interface
          name: "{{interface}}"
          state: enabled
          description: "{{interface_description}}"
          transport: netconf
          target: running
```

For NETCONF interfaces, `state` accepts `enabled` or `disabled` (`up` and
`down` are aliases). `transport` defaults to `netconf`, and `target` defaults
to `running`; candidate-datastore commits are rejected rather than silently
approximated. `description` is optional, so omitting it leaves the existing
description unmanaged.

The step reads the interface's OpenConfig `config` state, changes it only when
the requested fields differ, and reads it again after `edit-config` to verify
the desired state. It therefore reports success without a write when the
device is already compliant. With `--check`, the discovery still runs but the
edit and verification write path do not. See
[`35-declarative-interface-ensure.yaml`](examples/workflow-operations/multivendor/35-declarative-interface-ensure.yaml).

IOS XR and Arista EOS support state-aware SSH `ensure` adapters for interfaces
and exact static routes:

```yaml
ssh:
  - host: xr-lab-01
    steps:
      - name: ensure-uplink
        ensure:
          resource: interface
          name: HundredGigE0/0/0/0
          state: enabled
          require_state: disabled
          description: Customer path
          transport: ssh
          rollback_on_failure: true

      - name: ensure-customer-route
        ensure:
          resource: static_route
          prefix: 203.0.113.0/24
          next_hop: 192.0.2.1
          vrf: CUSTOMER-A
          state: present
          transport: ssh
          rollback_on_failure: true
```

The interface adapter discovers state with `show interfaces`, changes only
managed fields, and verifies after applying. `require_state: disabled` is a
precondition whenever a mutation is required: selecting an active port with
different desired configuration fails before any write. An already compliant
interface remains idempotent and sends no configuration. IOS XR uses commit
semantics; EOS exits configuration mode and saves with `write memory`. See
[`38-arista-eos-declarative-interface.yaml`](examples/workflow-operations/arista/38-arista-eos-declarative-interface.yaml)
for the EOS form.

The static-route adapters discover native configuration (`router static` on
IOS XR and global `ip route` statements on EOS) and treat `vrf`, `prefix`, and
`next_hop` as the resource identity. `state` is `present` or `absent`;
removing one tuple preserves other next-hops for intentional ECMP. IPv4 is
supported in this first adapter release. The EOS commands follow Arista's
documented `ip route [vrf NAME] PREFIX NEXT_HOP` form; see
[`39-arista-eos-declarative-static-route.yaml`](examples/workflow-operations/arista/39-arista-eos-declarative-static-route.yaml).

Under `--check`, these adapters open SSH only for their fixed read-only
discovery commands. The JSON plan contains `current`, `desired`, `changed`,
`commands`, and `rollback_commands`; no configuration is sent. Normal mode
applies the planned command block and performs the same discovery again for
verification. Set `rollback_on_failure: true` to execute the generated inverse
command block if apply returns an error or post-apply verification fails.
Rollback is best-effort because a transport failure can leave device state
uncertain. A successfully rolled-back ensure step deliberately remains failed:
the requested desired state was not achieved, and the plan records
`action: rolled-back` plus `rollback_status: succeeded`. A rollback error
records `action: rollback-failed`. Declarative execution errors are hard gates
and stop later device steps. See
[`37-declarative-ssh-path.yaml`](examples/workflow-operations/iosxr/37-declarative-ssh-path.yaml).

Do not include the outer `<rpc>` element in either payload form; the NETCONF
driver adds the protocol envelope and message ID. Junos accepts either native
Junos configuration XML or `<config-text>` within `edit-config`. Use `block`
with NETCONF edit and commit steps in `rollback` for transactional recovery.
[`36-junos-netconf-transaction.yaml`](examples/workflow-operations/junos/36-junos-netconf-transaction.yaml)
demonstrates filtered running/candidate reads, candidate locking, edit,
validation, confirmed commit, immediate cancellation or automatic timed
rollback, discard recovery, and guaranteed unlock.

The rollback policy is declarative at the block and verification step:

```yaml
- name: guarded-change
  block:
    steps:
      - name: apply-change
        netconf:
          operation: edit-config
          target: candidate
          payload_file: payloads/change.xml

      - name: verify-change
        netconf:
          operation: rpc
          payload: <get-system-information/>
        validation:
          extractor: regex
          pattern: '<status>(up)</status>'
          condition: eq
          expected: up
        on_fail:
          action: fail

    rollback:                 # Include this for automatic rollback.
      - netconf:
          operation: discard-changes

    always:
      - netconf:
          operation: unlock
          target: candidate
```

`on_fail: {action: fail}` makes the verification a gate: later change steps
are not executed. If the enclosing block contains `rollback`, any command,
parser, or validation failure runs those recovery steps automatically. Omit
`rollback` to stop and report the failure without changing the configuration
again. `always` runs in both cases, so cleanup such as `unlock` belongs there.
A successful rollback marks the failed block as recovered; if rollback itself
fails, the workbook remains failed and `--fail-on-fail` returns a non-zero
exit status.

### Configuration-management scope

Network Collector provides useful configuration orchestration: templated
multi-line CLI, native or OpenConfig NETCONF payload files, datastore
transactions, reusable workflows, approval gates, rollback blocks, validation,
and a growing declarative `ensure` model. It is not yet a full
configuration-management platform: there is no broad catalogue of rich,
idempotent resource modules or service models comparable to Ansible
collections or Cisco NSO. Use it for focused network workflows and assurance,
or compose it with a larger source-of-truth and service-orchestration system.

Inventory hosts may also carry arbitrary labels for runtime targeting:

```yaml
hosts:
  - name: core-lon-01
    address: 192.0.2.10
    type: cisco_iosxr
    labels:
      site: london
      role: core
      environment: production
```

Use `--limit` and `--exclude` to select resolved SSH or NETCONF device targets. Expressions support `and`, `or`, `not`, parentheses, `=` and `!=`; label names and the built-in fields `hostname`, `name`, `ip`, `address`, `type`, and `platform` are case-insensitive. Quote values containing spaces.

```bash
network-collector --limit 'site=london and (role=core or role=edge)'
network-collector --limit 'environment=production' --exclude 'maintenance=true'
```

When structured output includes `results.json`, each result records whether its device failed. Use `--rerun-failed artifacts/run-.../results.json` to select only those failed devices on a subsequent run. It may be combined with `--limit` and `--exclude`. Older summaries without device outcomes fall back to hosts with failed or errored validations; connection-only failures require a newly generated summary.

### SSH security profiles

Existing configurations remain compatible. When `ssh_security` is omitted, Network Collector uses the previous behavior: the `compatibility` algorithm profile with host-key verification disabled. This avoids breaking legacy device estates. At startup, one inventory-wide security summary reports profile and host-key-policy counts instead of repeating warnings for every connection.

```yaml
ssh_security:
  profile: compatibility
  host_key_policy: insecure
```

Available profiles:

- `compatibility`: preserves the previous cipher and key-exchange behavior.
- `auto`: tries the SSH library's standard algorithm set first, then retries with legacy compatibility algorithms only after a recognizable algorithm-negotiation failure.
- `modern`: uses only the SSH library's standard algorithm set and never falls back.
- `legacy`: explicitly enables the compatibility algorithm set and appears in the startup warning summary.

Auto fallback never occurs for authentication failures, host-key failures, timeouts, DNS errors, or refused connections.

Enable known-host verification with either an explicit OpenSSH file or the normal system/user locations:

```yaml
ssh_security:
  profile: auto
  host_key_policy: known_hosts
  known_hosts_file: ~/.ssh/known_hosts # optional
```

If `known_hosts_file` is omitted, ScrapliGo checks its supported user and system defaults. A device entry or inventory host can override individual settings for mixed estates:

```yaml
ssh:
  - host: old-router
    ssh_security:
      profile: legacy
      host_key_policy: insecure
    cmd: show version
```

Legacy fallback and host identity are independent. Where possible, use `known_hosts` even for devices that require old key exchange or cipher algorithms.

### Custom SSH platform definitions

SSH platform definitions and command-output parsers solve different problems:

- A ScrapliGo platform definition teaches the SSH driver how to recognise prompts, move between privilege levels, disable paging, and identify command errors.
- `parsers.yaml` and TextFSM templates transform the output returned by a command into structured data.

The device `type` is passed directly to ScrapliGo. It can be a bundled platform name such as `cisco_iosxe`, `cisco_iosxr`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `nokia_srl`, `nokia_sros`, `huawei_vrp`, or `hp_comware`. For Ericsson, another vendor, or a non-network appliance with a recognisable CLI prompt, set `type` to a custom ScrapliGo YAML file:

```yaml
hosts:
  - name: ericsson-router-01
    ip: 192.0.2.40
    type: ./platforms/ericsson_generic.yaml
```

A minimal network-driver platform definition looks like this:

```yaml
platform-type: ericsson_generic
default:
  driver-type: network
  privilege-levels:
    exec:
      name: exec
      pattern: '(?m)^[A-Za-z0-9_.@:/-]{1,80}[>#]\s?$'
      not-contains: []
      previous-priv: ''
      deescalate: ''
      escalate: ''
      escalate-auth: false
      escalate-prompt: ''
  default-desired-privilege-level: exec
  failed-when-contains:
    - Error
    - Invalid command
    - Unknown command
  network-on-open:
    - operation: acquire-priv
  network-on-close:
    - operation: channel.write
      input: exit
    - operation: channel.return
```

Tune the prompt expression and open/close operations against captured sessions from the target system. Custom definitions must use `driver-type: network` because Network Collector requests ScrapliGo's network driver. Relative `type` paths currently resolve from the directory where `network-collector` is launched, not from `inventory.yaml`; use an absolute path when the working directory is uncertain.

### Modular playbook imports

A master config can compose reusable partial YAML files with `imports`:

```yaml
imports:
  - roles/10-platform-health.yaml
  - roles/20-ntp-monitor.yaml
  # Globs are supported and expanded in lexical order:
  # - roles/*.yaml

name_playbook: Modular IOS-XR collection
inventory_file: inventory.yaml
parsers_file: ../../parsers.yaml

execution:
  max_parallel: 2
```

Each imported file is an ordinary partial config. A reusable role commonly contains only SSH workflows:

```yaml
ssh:
  - group: xr
    steps:
      - name: ntp-status
        cmd: show ntp status
        parser: xr_show_ntp_status
```

Imports are recursive and paths are relative to the file containing the import. Imported files are merged in declared order, then the importing file is applied. Maps merge recursively, lists such as `ssh` append, and later scalar values override earlier ones. Keep shared settings such as `inventory_file`, `parsers_file`, credentials policy, execution, and output in the master config; put reusable workflows in role files.

The loader rejects import cycles, duplicate inclusion, unmatched glob patterns, invalid entries, and nesting deeper than 20 files. This prevents the same upgrade role from silently running twice. See [`examples/modular`](examples/modular) for a complete master, inventory, and role layout. The [`workflow operation examples`](examples/workflow-operations) provide full playbooks for every control operation described below.

### Staged and concurrent SSH execution

Use the top-level `execution` settings to run inventory devices concurrently while staggering when each device starts. This is useful for long-running software upgrades where devices should overlap without all beginning at once.

```yaml
inventory_file: inventory.yaml

execution:
  max_parallel: 3
  start_interval_seconds: 120
  canary_count: 1
  failure_threshold: 2

ssh:
  - group: ios_upgrade
    steps:
      - name: perform-upgrade
        cmd: install replace harddisk:/8000-x64.iso
        return_to_prompt: false
      - name: wait-for-router
        ssh_probe:
          port: 22
          interval_seconds: 30
          max_attempts: 40
          post_wait_seconds: 120
```

- `max_parallel` is the maximum number of active SSH device runs. `0` or an omitted value preserves the default of one device at a time.
- `start_interval_seconds` is the minimum delay between device starts. The first device starts immediately, and a free concurrency slot does not bypass the delay.
- `canary_count` runs that many devices from the resolved inventory order as a separate first stage. All canaries must succeed before remaining devices are started.
- `failure_threshold` stops launching new devices after that many device runs have failed. Devices already running are allowed to finish. `0` disables the threshold.

### Bounded recurring schedules

Use a finite top-level schedule when collection must recur within one invocation:

```yaml
schedule:
  count: 4
  interval_seconds: 900
```

`count` defaults to one and is limited to 1000. Multiple occurrences require an interval of at least one second. The first starts immediately; registered per-device variables persist between occurrences, artifacts are uniquely prefixed, and `local_steps` run once after the schedule. A stopped occurrence ends the schedule. Continue using cron, systemd, CI, or Kubernetes CronJobs for indefinite calendar scheduling.

For the example above, the canary runs first. If it succeeds, another device may start immediately when the canary took longer than two minutes; subsequent starts remain two minutes apart, with no more than three active devices. A failed canary stops the main stage regardless of `failure_threshold`.

Validation failures, connection errors, step errors, and session setup or shutdown errors count as device failures. Results are aggregated in inventory order even though devices may complete in a different order. Each device continues to write its own session log; live terminal output from simultaneously active devices may be interleaved.

Separate SSH entries targeting the same hostname/IP remain serialized and share their registered variables. This preserves playbooks that capture a value in one entry and consume it in a later entry.

For fleet sizing, nested-session calculations, serial and wave patterns,
secret-provider pressure, host limits, and gNMI monitoring guidance, see
[Scaling Network Collector across large fleets](docs/scaling.md).

### Pluggable parser modules

You can define reusable parser modules in `parsers.yaml`, reference them from a step with `parser`, and validate the generated JSON with the existing `gjson` extractor. Parser definitions are data files: adding a regex parser or custom TextFSM template does not require recompiling Network Collector.

Example `parsers.yaml`:

```yaml
parsers:
  xr_install_active_summary:
    type: regex
    fields:
      active_packages:
        pattern: '(?m)^\s+(disk0:\S+)'
        group: 1
        repeated: true
      profile:
        pattern: '(?m)^(.+ Profile):'
        group: 1
```

Example `config.yaml`:

```yaml
parsers_file: parsers.yaml

ssh:
  - host: xr-router-1
    steps:
      - name: parse-active-packages
        cmd: show install active summary
        parser: xr_install_active_summary
        validations:
          - extractor: gjson
            json_path: active_packages.#
            condition: gte
            expected: 1
            expected_type: int
          - extractor: gjson
            json_path: profile
            condition: contains
            expected: Default
            expected_type: string
```

Parser fields support `pattern`, optional capture `group` (defaults to the first capture group when present), `repeated: true` for arrays, and `type: int` for numeric coercion. Parsed JSON is written to the session log before validation.

The original `regex` parser is best for independent scalar values and simple arrays. Use `regex_records` when each CLI row should become one JSON object, which preserves the relationship between columns:

```yaml
parsers:
  xr_show_interfaces_brief_records:
    type: regex_records
    root: interfaces
    pattern: '(?m)^(\S+)\s+(up|down|administratively down)\s+(up|down)\s+(.+)$'
    fields:
      interface: {group: 1}
      status: {group: 2}
      protocol: {group: 3}
      description: {group: 4}
```

This produces:

```json
{"interfaces":[{"interface":"GigabitEthernet0/0/0/0","status":"up","protocol":"up","description":"Core uplink"}]}
```

Use `textfsm` for stateful, multi-line, or multi-section CLI output. Templates are completely user supplied and their paths are resolved relative to `parsers.yaml`:

```yaml
parsers:
  xr_show_interfaces_brief_textfsm:
    type: textfsm
    template: parser_templates/cisco_xr/show_interfaces_brief.textfsm
    root: interfaces
```

TextFSM value names are preserved as JSON keys. For example, `Value INTERFACE ...` produces an `INTERFACE` key. The `root` setting defaults to `records` for both record-oriented parser types.

#### User-defined JSON enrichment

Attach `enrich` to a step to transform JSON output with an embedded, pure-Go jq engine. Enrichment runs after parsing and before registration, validation, drift checks, and parsed artifact storage. This lets playbooks turn counters and measurements into deterministic summaries without adding vendor rules to Network Collector:

```yaml
- name: summarize-interface-errors
  cmd: show interfaces HundredGigE0/0/0/0
  parser: xr_interface_error_counters
  enrich:
    engine: gojq
    expression_file: enrich/interface-errors.jq
    variables:
      error_threshold: 0
  register: interface_health
  validation:
    extractor: gjson
    json_path: _summary.has_issues
    condition: eq
    expected: false
    expected_type: bool
```

Expressions can be supplied with `expression` or `expression_file`; the two settings are mutually exclusive. Relative expression paths are resolved from the main configuration file. Values under `variables` are available to the expression as `$params`, preserving YAML number, boolean, string, list, and object types. An expression must produce exactly one JSON value.

The evaluator defaults to a two-second timeout and a 1 MiB result limit. Override these per step with `timeout_seconds` and `max_output_bytes`. It does not expose environment variables, filesystem functions, or jq module loading. The enriched document should preserve useful source data and add evidence-backed fields such as `_summary` for downstream playbooks and agents. See `examples/workflow-operations/enrich/interface-errors.jq` for a complete rule.

Common expression patterns include:

```jq
# Add a count while preserving the source document.
. + {"_summary": {"interface_count": ((.interfaces // []) | length)}}

# Select evidence with a playbook-supplied threshold.
. as $source
| [.records[] | select((.utilization // 0) > $params.threshold)] as $busy
| $source + {"_summary": {
    "has_issues": (($busy | length) > 0),
    "issue_count": ($busy | length),
    "issues": $busy
  }}

# Normalize an optional value without discarding the original data.
. + {"normalized": {"hostname": (.HOSTNAME // .hostname // "unknown")}}
```

An expression does not require a separate tool or service: it is ordinary gojq stored inline or in a `.jq` file. Prefer a file for multi-line policy, keep tunable thresholds under `variables`, use `//` for optional input fields, and wrap streams in arrays so the expression returns one result. A dedicated expression-authoring skill is useful only when a team maintains a larger rule catalogue with shared schemas, fixtures, and golden-output tests; `skills.md` contains the built-in authoring guidance for normal playbooks.

#### Included IOS-XR TextFSM parsers

The parser pack includes custom TextFSM coverage for:

- `show platform` → `xr_show_platform`, rooted at `nodes`
- `show route summary` → `xr_show_route_summary`, rooted at `routes`
- `show interfaces brief` → `xr_show_interfaces_brief_textfsm`, rooted at `interfaces`
- `show ntp associations` → `xr_show_ntp_associations`, rooted at `associations`
- `show ntp status` → `xr_show_ntp_status`, rooted at `status`
- `show running-config ntp` → `xr_show_running_config_ntp`, rooted at `ntp`

```yaml
ssh:
  - group: xr
    steps:
      - name: collect-ntp-associations
        cmd: show ntp associations
        parser: xr_show_ntp_associations
      - name: collect-ntp-status
        cmd: show ntp status
        parser: xr_show_ntp_status
      - name: collect-ntp-config
        cmd: show running-config ntp
        parser: xr_show_running_config_ntp
```

The association template handles IPv4, IPv6, configured peers, selection markers, VRFs, and continuation rows. The status template handles synchronized and unsynchronized clocks, including `never updated`. Numeric TextFSM values remain JSON strings; use `expected_type` in validations when a typed comparison is required.

### Vendor-neutral facts

Use a `facts` step to gather operational state without spelling out each device command. Collection is performed per subset: OpenConfig NETCONF is tried first, then SSH with the platform's TextFSM parser. A failure or unsupported model in one subset does not force successfully collected subsets onto the fallback transport.

```yaml
facts:
  default_format: both
  default_subsets: [system, platform, interfaces, lldp, bgp, isis, ldp]
  default_transports: [netconf, ssh]

ssh:
  - group: xr
    steps:
      - name: gather-facts
        facts: {}
        register: device_facts
```

`format` accepts `openconfig`, `native`, or `both` (the default). OpenConfig data uses RFC 7951-style module-qualified top-level names. Native data is the JSON emitted by NETCONF XML decoding or TextFSM and retains vendor-specific fields. Metadata records the transport, command/parser, normalization completeness, unmapped fields, and recoverable fallback errors for every subset. Step values override the top-level defaults:

```yaml
- name: routing-native-facts
  facts:
    format: native
    subsets: [bgp, isis, ldp]
    transports: [ssh]
  register: routing_facts
```

The bundled SSH facts registry covers IOS-XR (`system`, `platform`, `interfaces`, `lldp`, `bgp`, `isis`, and `ldp`) plus Arista EOS and Juniper Junos (`system`, `platform`, `interfaces`, `lldp`, and `bgp`). Unsupported subsets can still use OpenConfig NETCONF; SSH fallback deliberately requires a tested command and parser mapping rather than guessing CLI syntax.

`facts` steps currently register and store their collected JSON through a dedicated execution path. They do not currently apply `enrich` or step validation, so do not attach `enrich` to a `facts` step. To derive a summary today, enrich JSON from a command/parser step or a local JSON-producing step. A future facts integration should apply enrichment before registration, drift checks, and parsed artifact storage, matching normal structured steps.

### Structured drift detection

Attach `drift` to a command or local step that produces JSON directly or through a parser:

```yaml
- name: platform-drift
  cmd: show platform
  parser: xr_show_platform
  drift:
    baseline: previous
    ignore: [nodes.*.uptime]
    fail_on_change: true
```

`baseline: previous` stores rolling per-device/per-step state under the output directory's `.baselines` folder. A file path instead compares against an explicitly approved JSON baseline; `{{hostname}}` and `{{ip}}` are available in the path. `update_baseline: true` creates or refreshes file baselines. Comparisons are structural, ignore JSON object key ordering, identify added/removed/changed paths, and always write a `drift.json` artifact. With `fail_on_change: false`, changes remain visible without failing the run.

### Offline parser fixture tests

Parser and validation changes can be tested without logging into a network device. Add captured command output as plain text under `cmd/network-collector/testdata/cli/`, then add a case to `cmd/network-collector/testdata/parser-fixtures.yaml`.

Fixture cases can define `parser` and `validations` directly, or reference a parser-bearing step from `cmd/network-collector/testdata/offline-config.yaml`:

```yaml
cases:
  - name: xr-show-alarms-brief-system-active
    input: cli/xr_show_alarms_brief_system_active.txt
    config_ref:
      ssh_index: 0
      step: parse-active-alarms
```

Run the offline parser suite with:

```bash
go test ./cmd/network-collector -run TestParserFixtures
```

The fixture runner loads `parsers.yaml`, parses the CLI text file, applies the referenced config step's `validation` or `validations`, and fails the test if parsing or validation does not pass.

Fixtures support `regex`, `regex_records`, and `textfsm`, so custom templates can be tested against captured CLI text without connecting to a router.

For baseline/final comparisons, provide both `baseline_input` and `input`. The baseline output is parsed, registered into the variable named by the baseline config step's `register`, and then the final output is parsed and validated.

```yaml
cases:
  - name: xr-active-alarms-unchanged
    baseline_input: cli/xr_show_alarms_before.txt
    input: cli/xr_show_alarms_after_unchanged.txt
    baseline_config_ref:
      ssh_index: 0
      step: capture-baseline-alarms
    config_ref:
      ssh_index: 0
      step: compare-final-alarms

  - name: xr-active-alarms-changed
    baseline_input: cli/xr_show_alarms_before.txt
    input: cli/xr_show_alarms_after_changed.txt
    baseline_config_ref:
      ssh_index: 0
      step: capture-baseline-alarms
    config_ref:
      ssh_index: 0
      step: compare-final-alarms
    expect_pass: false
```

Use `expect_pass: false` for negative fixtures that should detect a changed parser result.

Example:

```yaml
name_playbook: Software Upgrade on Cisco IOS
inventory_file: inventory.yaml
parsers_file: parsers.yaml

ssh:
  - host: device-ios-03
    timeout: 20
    operation_timeout: 120
    steps:
      - name: show-version
        message: checking currently running image
        cmd: show version
        validation:
          extractor: regex
          pattern: "System image file is \"(.+)\""
          condition: contains
          expected: flash
          expected_type: string

      - name: capture-install-id
        cmd: 'show install active | include "Install ID"'
        validation:
          extractor: regex
          pattern: 'Install ID:\s+(\\d+)'
          condition: eq
          expected: 14
          expected_type: int
        register: install_id

      - name: wait-for-install-state
        wait_seconds: 30

      - name: confirm-reload
        cmd: yes
        return_to_prompt: false

      - name: wait-for-reboot
        wait_seconds: 600
        ssh_probe:
          port: 22
          interval_seconds: 30
          max_attempts: 40
          timeout_seconds: 5
          post_wait_seconds: 120

      - name: show-install-by-id
        cmd: 'show install active {{install_id}}'
        retry:
          until_pass: true
          interval_seconds: 60
          max_attempts: 5
        validation:
          extractor: regex
          pattern: 'Package ID:\s+{{install_id}}'
          condition: contains
          expected: '{{install_id}}'
          expected_type: string
```

The retry step keeps rerunning the command until validation passes, with the configured interval and attempt limit.

Validation steps can also run conditional actions after the final validation result:

```yaml
      - name: check-current-image
        cmd: show version
        validation:
          extractor: regex
          pattern: "System image file is \"(.+)\""
          condition: contains
          expected: iosxe-17.09.04
          expected_type: string
        on_pass:
          action: exit
          message: target image is already active; stopping this device
        on_fail:
          message: target image is not active; running upgrade path
          steps:
            - name: collect-install-state
              cmd: show install summary
              validation:
                extractor: regex
                pattern: 'State:\s+(\S+)'
                condition: eq
                expected: READY
                expected_type: string
            - name: perform-upgrade
              cmd: install add file flash:iosxe-17.09.04.bin activate commit
```

Use `on_pass` or `on_fail` on a step with `validation`. Supported actions are `exit`/`stop` to stop the remaining steps for the current device without failing, `fail` to stop and mark the run failed, `cmd` to run another SSH command, `steps` to run a nested list of normal SSH steps, and `none`/`noop` to take no control-flow action. If an action block contains only `message`, the collector logs the message and continues. If it contains only `cmd`, `action: cmd` is implied. If it contains only `steps`, `action: steps` is implied. Nested steps support the same fields as top-level steps, including `validation`, `retry`, `register`, `ssh_probe`, `return_to_prompt`, and their own `on_pass` / `on_fail` actions. Action `message` and `cmd` values support registered variables such as `{{install_id}}`.

### Workflow control operations

Use `when` to skip a step without running a validation command. It compares a registered variable using the same conditions as validation (`eq`, `neq`, `contains`, `not_contains`, `matches`, `gt`, `gte`, `lt`, or `lte`):

```yaml
- name: collect-xr-state
  when:
    variable: platform
    condition: eq
    expected: iosxr
  cmd: show platform
```

The variable must exist. `condition` defaults to `eq`; set `expected_type: int` for numeric comparisons.

Use `foreach` for a literal list or a registered JSON array. The item and zero-based index variables exist only inside the nested steps:

```yaml
- name: collect-interfaces
  foreach:
    items: [GigabitEthernet0/0, GigabitEthernet0/1]
    item: interface
    index: interface_index
    stop_on_failure: true
    steps:
      - cmd: show interfaces {{interface}}

- name: collect-discovered-interfaces
  foreach:
    from: discovered_interfaces
    steps:
      - cmd: show interfaces {{item}}
```

`stop_on_failure` defaults to `true`. Set it to `false` to continue later items after a failed iteration. `from` must name a variable containing a JSON array, such as parser output registered from a JSON array.

Reusable parameterized workflows are defined at the top level and invoked with `use` and `with`. Parameters are required, unknown arguments are rejected, and parameter values are restored after the call:

```yaml
workflows:
  inspect-interface:
    parameters: [interface, expected_state]
    steps:
      - name: inspect
        cmd: show interfaces {{interface}}
        validation:
          extractor: regex
          pattern: 'line protocol is (\S+)'
          condition: eq
          expected: '{{expected_state}}'

ssh:
  - host: router-01
    steps:
      - name: inspect-uplink
        use: inspect-interface
        with:
          interface: GigabitEthernet0/0
          expected_state: up
```

Workflow definitions can live in imported YAML files. Recursive calls are stopped after 20 nested control levels.

Use `block`, `rollback`, and `always` for an automatically reverted SSH
change. The verification must use `on_fail.action: fail` so it is a hard gate
and no later change step can run:

```yaml
- name: guarded-change
  block:
    steps:
      - name: apply-change
        cmd: configure replace disk0:/candidate.cfg
      - name: verify
        cmd: show configuration commit changes last 1
        validation:
          extractor: regex
          pattern: '(change-id 123)'
          condition: eq
          expected: change-id 123
        on_fail:
          action: fail
          message: SSH verification failed; restoring the previous configuration
    rollback:
      - name: restore-previous-configuration
        cmd: rollback configuration last 1
    always:
      - name: collect-final-state
        cmd: show configuration commit list 1
```

This is the same policy used by NETCONF blocks: `rollback` is the automatic
rollback knob. Omit the entire `rollback` list for fail-only behavior:

```yaml
- name: verify-without-rollback
  cmd: show interfaces HundredGigE0/0/0/0
  validation:
    extractor: regex
    pattern: 'line protocol is (up)'
    condition: eq
    expected: up
  on_fail:
    action: fail
```

`rollback` runs automatically after a command, parser, output, or validation
failure. A successful rollback marks failed validations as recovered; a
failed rollback keeps the workbook failed. `always` runs after either path and
can itself fail the run. Explicit stop actions still propagate after recovery,
and the failure log retains the original event for auditability.

Use `rescue` instead of `rollback` for non-reverting recovery such as recording
that an optional command is unsupported. They are mutually exclusive. A
successful rescue also recovers the block for the overall run.

Manual approval gates fail closed for non-interactive stdin, denial, EOF, or timeout. Use `--approve-all` only for an explicitly authorized unattended run:

```yaml
- name: authorize-change
  approval:
    message: Apply the software upgrade?
    timeout_seconds: 300
```

Use `parallel` for independent same-device branches. Each branch gets a separate SSH session and isolated variables. Results merge in declared order; conflicting registered values fail the run. `max_parallel` defaults to the branch count and is capped at 16:

```yaml
- name: independent-collection
  parallel:
    max_parallel: 3
    steps:
      - {name: routes, cmd: show route, register: routes}
      - {name: interfaces, cmd: show interfaces, register: interfaces}
      - {name: alarms, cmd: show alarms, register: alarms}
```

A control step may define one of `repeat`, `foreach`, `use`, `block`, or `parallel`; executable fields belong in its nested steps. An `approval` gate is a standalone step. `when` may guard any normal or control step.

Use `gnmi_subscribe` for finite telemetry collection and event-driven actions. `once` completes when the target sends its synchronization response. A `stream` must set `duration_seconds` or `max_updates`; subscriptions without an explicit duration remain bounded by `timeout_seconds` (30 seconds by default), so an ordinary playbook can never wait forever. The resulting JSON array supports `register`, `validations`, `drift`, retries, and structured output like other step output.

Keep reusable connection and TLS settings on the inventory host:

```yaml
hosts:
  - name: router-01
    ip: 192.0.2.10
    type: cisco_iosxr
    gnmi:
      port: 57400
      ca_file: certs/gnmi-ca.pem
      server_name: router-01.example.net
      timeout_seconds: 30
```

Certificate paths are relative to the inventory file. The supported security modes are:

- Production server TLS: set `ca_file` and, when the certificate name differs from the inventory address, `server_name`.
- Mutual TLS: also set both `cert_file` and `key_file`. They must be configured together.
- TLS without certificate verification: set `skip_verify: true`. Traffic remains encrypted, but this is suitable only for controlled migration or lab use.
- Plaintext gRPC: set `insecure: true`. Use this only when the target is explicitly configured without TLS on a trusted lab network.

For a small lab CA and mutual-TLS client certificate, create a private directory and issue the files before starting the collector:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout certs/gnmi-ca-key.pem -out certs/gnmi-ca.pem \
  -subj "/CN=network-collector-lab-ca"
openssl req -newkey rsa:3072 -nodes \
  -keyout certs/collector-key.pem -out certs/collector.csr \
  -subj "/CN=network-collector"
openssl x509 -req -days 365 -in certs/collector.csr \
  -CA certs/gnmi-ca.pem -CAkey certs/gnmi-ca-key.pem -CAcreateserial \
  -out certs/collector.pem
chmod 600 certs/collector-key.pem certs/gnmi-ca-key.pem
```

Install the CA/server certificate and enable gNMI on the router using the platform procedure, then use:

```yaml
gnmi:
  port: 57400
  ca_file: certs/gnmi-ca.pem
  cert_file: certs/collector.pem
  key_file: certs/collector-key.pem
  server_name: router-01.example.net
```

The older per-step `skip_tls: true` remains compatible and means plaintext gRPC; new inventories should use `gnmi.insecure` so the security choice is explicit.

Add `triggers` to react immediately to individual updates or deletes while the subscription is open:

```yaml
- name: collect-interface-changes
  gnmi_subscribe:
    paths:
      - /interfaces/interface/state/oper-status
    port: 57400
    mode: stream
    stream_mode: on_change
    duration_seconds: 30
    max_updates: 20
    triggers:
      - name: interface-became-up
        event: update
        path_regex: '^/interfaces/interface\[name=.*\]/state/oper-status$'
        value: UP
        steps:
          - name: collect-interface-detail
            cmd: show interfaces brief

      - name: route-disappeared
        event: delete
        path_regex: '/afts/(ipv4|ipv6)-unicast/.*entry'
        steps:
          - name: verify-routes-over-netconf
            netconf:
              operation: get
              payload: |
                <filter type="subtree">
                  <network-instances xmlns="http://openconfig.net/yang/network-instance"/>
                </filter>
  register: interface_changes
```

Trigger `event` is `update` (the default) or `delete`. Match an exact canonical path with `path`, or use `path_regex`; updates may also match an exact `value` or `value_regex`. Initial values sent before the first gNMI sync response are ignored by default, preventing an already-UP interface from looking like a new transition. Set `include_initial: true` when the initial state should trigger, and `once: true` when a rule should run only on its first match.

Trigger actions receive `{{gnmi_event_type}}`, `{{gnmi_event_path}}`, `{{gnmi_event_value}}`, and the complete JSON event in `{{gnmi_event}}`. Their nested `steps` use the normal executor, so SSH commands, NETCONF operations, local commands, workflows, blocks, and other controls can be mixed without opening duplicate top-level inventory entries. A `gnmi.triggered` lifecycle event is also emitted.

For numeric telemetry such as CPU, add `condition` and `threshold`. Supported conditions are `gt`, `gte`, `lt`, `lte`, `eq`, and `neq`:

```yaml
- name: cpu-high
  event: update
  path: /components/component[name=CPU0]/cpu/utilization/state/instant
  condition: gte
  threshold: 80
  once: true
  fail: true
  steps:
    - name: collect-cpu-detail
      cmd: show processes cpu
```

Interface octet values are counters rather than utilization rates. Set `counter_rate: true` to calculate the change per second from consecutive gNMI timestamps. `baseline_samples` then averages the first rates, and `max_drop_percent` fires when a later rate falls below that baseline by more than the configured percentage:

```yaml
- name: ingress-dropped-more-than-10-percent
  event: update
  path: /interfaces/interface[name=FourHundredGigE0/0/0/0]/state/counters/in-octets
  counter_rate: true
  baseline_samples: 3
  max_drop_percent: 10
  once: true
  fail: true
  steps:
    - name: capture-interface
      message: "Rate {{gnmi_metric_value}} octets/s is below {{gnmi_threshold_value}}; baseline {{gnmi_baseline_value}}."
      cmd: show interfaces FourHundredGigE0/0/0/0
```

The first counter sample establishes the starting counter; the following `baseline_samples` rates establish the baseline. Counter resets are ignored and restart rate measurement. Every canonical event path has independent rate, baseline, and `once` state, whether selected with an exact path or regular expression. Setting `fail: true` records the alarm as a workbook failure while still running its diagnostic steps. Numeric actions additionally receive `{{gnmi_metric_value}}`, `{{gnmi_baseline_value}}`, and `{{gnmi_threshold_value}}`.

For optical power in dBm, use `max_drop` rather than `max_drop_percent`. dBm is logarithmic and commonly negative, so this example fires when any matched channel falls more than 1 dB below its own three-sample baseline:

```yaml
- name: receive-light-dropped
  event: update
  path_regex: '^/components/component\[name=.*\]/transceiver/physical-channels/channel\[index=.*\]/state/input-power/instant$'
  baseline_samples: 3
  max_drop: 1.0
  once: true
  fail: true
  steps:
    - name: collect-optics
      message: "{{gnmi_event_path}} is {{gnmi_metric_value}} dBm; baseline {{gnmi_baseline_value}} dBm."
      cmd: show controllers optics
```

Baselines and `once` state are maintained independently for every canonical event path. A regular-expression trigger can therefore cover all returned interfaces and channels without combining their readings.

Streaming modes are `target_defined`, `on_change`, and `sample`. For `sample`, also set `sample_interval_seconds`. Use `mode: once` for a synchronized snapshot without a duration. See [`examples/workflow-operations/multivendor/27-gnmi-event-actions.yaml`](examples/workflow-operations/multivendor/27-gnmi-event-actions.yaml) for a complete mixed-transport example.

Additional monitoring examples:

- [`28-gnmi-new-path-turnup.yaml`](examples/workflow-operations/multivendor/28-gnmi-new-path-turnup.yaml) waits for a new uplink and expected route, then verifies them over SSH and NETCONF.
- [`29-gnmi-interface-traffic-guard.yaml`](examples/workflow-operations/multivendor/29-gnmi-interface-traffic-guard.yaml) protects ingress and egress traffic against a 10% rate drop.
- [`30-gnmi-cpu-monitor.yaml`](examples/workflow-operations/multivendor/30-gnmi-cpu-monitor.yaml) alarms on an 80% CPU threshold.
- [`31-gnmi-combined-change-monitor.yaml`](examples/workflow-operations/multivendor/31-gnmi-combined-change-monitor.yaml) monitors interface state, traffic, and CPU together during one bounded change window.
- [`32-gnmi-guarded-new-path-provision.yaml`](examples/workflow-operations/multivendor/32-gnmi-guarded-new-path-provision.yaml) provisions interface `0/0/0/10` in parallel while protecting existing interfaces `0/0/0/0` and `0/0/0/1`, and immediately disables the new interface if a guard fires.
- [`33-gnmi-all-interface-light-level-guard.yaml`](examples/workflow-operations/multivendor/33-gnmi-all-interface-light-level-guard.yaml) establishes independent RX/TX light baselines for every returned optical channel and alarms on a 1 dB drop.
- [`34-gnmi-change-health-monitor.yaml`](examples/workflow-operations/multivendor/34-gnmi-change-health-monitor.yaml) combines all-channel optics, packet discards, interface errors, and IS-IS/LDP/BGP neighbor state as a standalone monitor for a separate routine-change run.

To monitor an unrelated routine-change workbook, use two collector processes. Start the monitor first:

```bash
go run ./cmd/network-collector \
  --config examples/workflow-operations/multivendor/34-gnmi-change-health-monitor.yaml \
  --fail-on-fail
```

Allow approximately 40 seconds for the first counters and three optical baseline samples, then start the normal change from another terminal:

```bash
go run ./cmd/network-collector --config path/to/routine-change.yaml
```

The monitor runs for its configured `duration_seconds` independently of the change process. Its sampled branch fails if any RX/TX channel falls more than `max_drop` dB, any interface discard counter increases, or any interface error counter increases. A parallel `on_change` branch requires IS-IS adjacency state `UP`, LDP session state `OPERATIONAL`, and BGP session state `ESTABLISHED`; it checks initial state and fails on later state changes or neighbor-path deletion. Each canonical path alarms independently and writes its own diagnostic event and session output.

Use `value_not` for inverse string-state matching. The trigger fires for any value other than the configured healthy value:

```yaml
- name: bgp-session-not-established
  event: update
  path_regex: '/protocol\[identifier=BGP\].*/neighbor\[neighbor-address=.*\]/state/session-state$'
  value_not: ESTABLISHED
  include_initial: true
  once: true
  fail: true
  steps:
    - name: collect-bgp
      cmd: show bgp summary
```

The example paths and healthy values follow the OpenConfig models. Platform support and protocol instance keys vary, so verify them against the target’s gNMI capabilities.

Each SSH device run is recorded under `session_logs/` using the hostname and start timestamp in the filename. Set top-level `name_playbook` to include a playbook title in the ASCII banner at the start of each session log.

### Structured output files

Session logs remain the human-readable transcript. To additionally save command output and JSON as machine-readable artifacts, configure:

```yaml
output:
  directory: artifacts
  save_raw: true
  save_parsed: true
  summary_file: results.json
  events_file: events.jsonl
  event_sinks:
    - type: webhook
      url: https://automation.example.net/network-events
      timeout_seconds: 5
      queue_size: 256
      headers:
        X-Collector-Site: london
      hmac_secret_env: EVENT_WEBHOOK_SECRET
    - type: syslog
      network: udp
      address: syslog.example.net:514
      app_name: network-collector
      queue_size: 256
```

Each invocation creates a timestamped run directory. Raw and parsed output is stored per inventory entry, step, and attempt, so concurrent devices and retries never overwrite one another. `results.json` contains run timestamps, overall failure state, validations, and the paths of all saved artifacts. Files are written atomically.

When `events_file` is set, lifecycle events are appended as JSON Lines. Relative paths are placed in the run directory. Events include `run.started`, `device.started`, `step.started`, `validation.completed`, `artifact.written`, `device.completed`, and `run.completed`. Event-sink errors are logged as warnings and do not interrupt device work. `--events-jsonl PATH` overrides the configured event file for one invocation.

`event_sinks` sends the same payload to webhooks or RFC 5424 syslog over UDP/TCP. Network sinks use bounded asynchronous queues; delivery failures and full queues are warnings rather than device failures. Webhook HMAC signing uses the named environment variable and sends `X-Network-Collector-Signature: sha256=<hex>`. Keep secrets out of YAML.

### Reusable orchestration package

The CLI's inventory targeting and device scheduling are available to other Go programs through `pkg/orchestrator`. The package provides:

- Generic bounded execution with canary staging, start intervals, failure thresholds, and context cancellation
- Compiled inventory selectors over standard target fields and arbitrary labels
- Lifecycle `Event` and `EventSink` contracts plus JSONL, asynchronous webhook, and RFC 5424 syslog sinks
- Shared target and device-outcome types

The scheduler is generic, so an embedding application keeps its own task and result types:

```go
policy := orchestrator.Policy{
    MaxParallel:      5,
    CanaryCount:      1,
    FailureThreshold: 2,
}

results, stopped := orchestrator.Run(ctx, devices, policy,
    func(ctx context.Context, index int, device Device) orchestrator.Outcome[Result] {
        result, err := collect(ctx, device)
        return orchestrator.Outcome[Result]{
            Index: index,
            Value: result,
            Failed: err != nil,
        }
    },
)
```

The package deliberately owns orchestration policy rather than transport or workflow syntax. Embedders can use Network Collector's drivers, their own device clients, or test executors without coupling the scheduler to the CLI configuration model.

Sensitive steps can override the global raw or parsed setting:

```yaml
- name: sensitive-command
  cmd: show sensitive-data
  output:
    save_raw: false
    save_parsed: true
```

Omit `output`, or leave all its settings disabled, to retain the previous session-log-only behaviour. `--json` continues to emit validation results to stdout and can be used independently of artifact output.

### Bounded repeated step groups

Use `repeat` to run a finite group of steps at a fixed interval. The first iteration runs immediately; the interval is applied only between iterations.

```yaml
ssh:
  - host: xr-router-01
    steps:
      - name: monitor-ntp
        repeat:
          count: 10
          interval_seconds: 120
          stop_on_failure: true
          steps:
            - name: ntp-associations
              cmd: show ntp associations
              parser: xr_show_ntp_associations
            - name: ntp-status
              cmd: show ntp status
              parser: xr_show_ntp_status
```

Safety constraints are enforced: `count` is required and limited to 1–1000, an interval of at least one second is required when `count` is greater than one, repeat nesting is limited to three levels, and an invalid repeat stops that device. Retries inside a repeat must set a positive `max_attempts`; an unbounded `until_pass` retry is rejected. `stop_on_failure` defaults to `true`; set it to `false` only when later iterations should continue after a failed command, parser, validation, or output write. A repeat step cannot also define its own command, wait, probe, or validation—those belong under its nested `steps`.

Use `operation_timeout` on an SSH device to increase the scrapligo operation timeout for long-running commands. The value is seconds; for example, `operation_timeout: 120` gives commands up to two minutes to return to the prompt.

Use `wait_seconds` on a step to pause while keeping the SSH connection open. A wait-only step does not require `cmd`; if both `wait_seconds` and `cmd` are set, the collector waits first and then runs the command.

Use `message` on a step to write an operator note to stdout and the session log. Message-only steps are allowed, and messages can use registered variables such as `{{install_id}}`. Action messages under `on_pass` and `on_fail` are logged the same way.

Use `ssh_probe` after software upgrades or reloads. The collector closes the stale SSH session, probes the configured TCP port until it responds, waits `post_wait_seconds` after the first successful probe, reconnects SSH, and then continues with the following steps. This helps cover the gap where port 22 is accepting connections but the device is still booting.

Use `return_to_prompt: false` for commands that intentionally reboot or disconnect the device before a normal CLI prompt can return, such as a `yes` confirmation. Timeout/error from that command is treated as expected, the stale SSH client is closed, and the next wait/probe step can handle reconnecting. The collector also accepts `no` as a compatibility alias.

You can also register a value from a step using `register: <name>` and reuse it in later steps with `{{<name>}}` in `cmd`, `pattern`, `json_path`, or string `expected` values.

Define custom variables inline or import variable maps relative to the file that declares them:

```yaml
vars_files:
  - vars/common.yaml
  - vars/site.yaml

vars:
  change_reference: CHG-2026-0042
```

Earlier variable files are overridden by later files, inline `vars` override file values, and values registered during execution override both for that device. Variable files may contain a bare map or a single top-level `vars:` map. Lists and objects are exposed as compact JSON, allowing an imported list to be used directly by `foreach.from`. Variable names must match `[A-Za-z_][A-Za-z0-9_]*`. Files declared inside imported configs resolve relative to that imported config.

### Running local tools

A step can run an installed local CLI with `local`. Commands are executed directly as an argument list, without a shell. This avoids shell expansion and quoting surprises. Local commands default to a 30-second timeout, and their output can be registered, parsed, validated, and saved like SSH command output.

This example captures Junos routing XML before and after a change, materializes both registered values as temporary files, and passes those files to [route-compare](https://github.com/gwoodwa1/route-compare):

```yaml
ssh:
  - host: junos-router-01
    steps:
      - name: routes-before
        cmd: show route | display xml
        register: routes_before

      # Perform and validate the network change here.

      - name: routes-after
        cmd: show route | display xml
        register: routes_after

      - name: compare-routes
        local:
          command: routecompare
          args:
            - -pre
            - "{{pre_file}}"
            - -post
            - "{{post_file}}"
            - -vrf
            - ALL
          inputs:
            pre_file: "{{routes_before}}"
            post_file: "{{routes_after}}"
          timeout_seconds: 60
        register: route_comparison
        output:
          save_raw: true
```

Each `inputs` key becomes a template variable containing the path to a private temporary file. Its value is the file content. Temporary inputs are removed when the program exits. The executable must already be installed and discoverable through `PATH`, or `command` must contain its path. A missing executable, timeout, or non-zero exit marks the device run as failed. Shell operators such as pipes and redirects are intentionally unsupported; call a script explicitly when orchestration is needed.

For commands that should run once after every device workflow has completed, use the top-level `local_steps` phase:

```yaml
local_steps:
  - name: summarize-results
    local:
      command: jq
      args:
        - .
        - "{{results_file}}"
      inputs:
        results_file: '{"status":"complete"}'
      timeout_seconds: 10
    register: summary
    validation:
      extractor: gjson
      json_path: status
      condition: eq
      expected: complete
      expected_type: string
```

Top-level local steps execute sequentially and share registered variables with later top-level local steps. They run once per playbook, even when the playbook contains many devices, and also work in local-only playbooks without SSH credentials. Per-device registered variables are deliberately not merged into this phase because concurrent devices may use the same variable names; pass data through saved artifacts or a purpose-built local command instead. Top-level entries support `local`, `register`, `parser`, `validation`/`validations`, `retry`, and `output`.

### Validation semantics

Validation steps in `config.yaml` support extractors and typed comparisons. Use `extractor: regex` for CLI text output and `extractor: gjson` for JSON payloads, including parser output. Use `validation` for one rule, or `validations` for multiple rules. When multiple validations are configured, all rules must pass for the step to trigger `on_pass`; any failed or errored rule triggers `on_fail`.

- `pattern` / `json_path`: the extraction pattern or JSON path. Regex extraction uses the first capture group when present; otherwise it uses the whole regex match.
- `condition`: `eq`, `neq`, `contains`, `not_contains`, `matches`, `gt`, `gte`, `lt`, or `lte`.
- `expected`: the expected value to compare against
- `expected_type` (optional): `string`, `int`, `bool`, or `length` — when provided the extracted value will be coerced to that type before comparison. This prevents accidental string vs numeric mismatches (for example, the string "100" is distinct from the integer 100 when `expected_type` is `int`). With `length`, regex values use string length and GJSON arrays/objects use item count.

Example equality checks added in `config.yaml`:

- String equality (exact match): `condition: eq`, `expected: "RUNNING"`, `expected_type: string`
- Integer equality: `condition: eq`, `expected: 100`, `expected_type: int`
- Boolean equality: `condition: eq`, `expected: true`, `expected_type: bool`
- Regex match against an extracted value: `condition: matches`, `expected: '^\d+\.\d+\.\d+$'`
- Length check: `condition: gte`, `expected: 3`, `expected_type: length`
