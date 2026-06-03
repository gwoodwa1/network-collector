# Network Collector

Network Collector is a Go-based tool designed for flexible and efficient data collection from various network devices. It supports multiple protocols and drivers, allowing you to connect to and collect data from a wide range of network devices.

## Features

- **SSH**: Collect data using SSH for devices running various operating systems like Cisco NX-OS, Juniper Junos, etc.
- **HTTP**: Fetch data using HTTP from devices with REST APIs, such as Arista EOS.
- **Netconf**: Use Netconf to interact with devices supporting the Netconf protocol.
- **gNMI**: Collect data using the gNMI protocol.
- **RESTCONF**: Fetch data using RESTCONF from devices supporting this protocol.

## Installation

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
    ```

4. **Set credentials:**

    ```bash
    export NET_USER=<username>
    export NET_PASSWORD=<your password>
    ```

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
if err := client.Connect("192.168.1.10", "admin", "password", "cisco_nxos"); err != nil {
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

## CLI validation and output

The `cmd/network-collector` SSH example supports validation configured in `config.yaml` and two useful CLI flags:

- `--json`: emit consolidated machine-readable JSON for all validation results (suppresses raw command output)
- `--fail-on-fail`: exit with non-zero status if any validation returns `fail` or `error`, or if a device/step cannot run successfully

`fail-on-fail` can also be configured with `fail_on_fail: true` in `config.yaml` or the `FAIL_ON_FAIL=true` environment variable. The CLI flag takes precedence when provided.

Example: run validations and emit only JSON

```bash
./network-collector --json
```

Example: run validations and exit non-zero if any check fails

```bash
./network-collector --fail-on-fail
```
     
## Configuration

The configuration is done through a `config.yaml` file Here’s an example of the `config.yaml`:
```
fail_on_fail: false

restconf:
  - hostname: device-eos-02
    ip: 192.168.15.7
    port: 3333
    skip_tls: true
    method: GET
    endpoint: data/openconfig-interfaces:interfaces/interface

gnmi:
  - hostname: device-eos-01
    ip: 192.168.16.10:6030
    skip_tls: true
    path: /interfaces/interface/subinterfaces/subinterface/state/description

ssh:
  - hostname: device-nxos-01
    ip: 192.168.16.1
    type: cisco_nxos
    cmd: show ip route
  - hostname: device-qfx-01
    ip: 192.168.16.1
    type: juniper_junos
    cmd: show route

http:
  - hostname: device-eos-08
    ip: 192.168.16.8
    type: arista_eos
    cmd: show version
    skip_tls: true
  - hostname: device-eos-03
    ip: 192.168.16.9
    type: arista_eos
    cmd: show ip route
    skip_tls: true

netconf:
  - hostname: device-eos-05
    ip: 192.168.16.7
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
    ip: 192.168.15.8
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

Example:

```yaml
name_playbook: Software Upgrade on Cisco IOS

ssh:
  - hostname: device-ios-03
    ip: 192.168.16.13
    type: cisco_ios
    timeout: 20
    operation_timeout: 120
    steps:
      - name: show-version
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
          cmd: show install summary
```

Use `on_pass` or `on_fail` on a step with `validation`. Supported actions are `exit`/`stop` to stop the remaining steps for the current device without failing, `fail` to stop and mark the run failed, and `cmd` to run another SSH command. If an action contains only `cmd`, `action: cmd` is implied. Action `message` and `cmd` values support registered variables such as `{{install_id}}`.

Each SSH device run is recorded under `session_logs/` using the hostname and start timestamp in the filename. Set top-level `name_playbook` to include a playbook title in the ASCII banner at the start of each session log.

Use `operation_timeout` on an SSH device to increase the scrapligo operation timeout for long-running commands. The value is seconds; for example, `operation_timeout: 120` gives commands up to two minutes to return to the prompt.

Use `wait_seconds` on a step to pause while keeping the SSH connection open. A wait-only step does not require `cmd`; if both `wait_seconds` and `cmd` are set, the collector waits first and then runs the command.

Use `ssh_probe` after software upgrades or reloads. The collector closes the stale SSH session, probes the configured TCP port until it responds, waits `post_wait_seconds` after the first successful probe, reconnects SSH, and then continues with the following steps. This helps cover the gap where port 22 is accepting connections but the device is still booting.

Use `return_to_prompt: false` for commands that intentionally reboot or disconnect the device before a normal CLI prompt can return, such as a `yes` confirmation. Timeout/error from that command is treated as expected, the stale SSH client is closed, and the next wait/probe step can handle reconnecting. The collector also accepts `no` as a compatibility alias.

You can also register a value from a step using `register: <name>` and reuse it in later steps with `{{<name>}}` in `cmd`, `pattern`, `json_path`, or string `expected` values.

### Validation semantics

Validation steps in `config.yaml` support extractors and typed comparisons. Use `extractor: regex` for CLI text output and `extractor: gjson` for JSON payloads (gNMI/RESTCONF responses).

- `pattern` / `json_path`: the extraction pattern or JSON path. Regex extraction uses the first capture group when present; otherwise it uses the whole regex match.
- `condition`: `eq`, `neq`, `contains`, `not_contains`, `matches`, `gt`, `gte`, `lt`, or `lte`.
- `expected`: the expected value to compare against
- `expected_type` (optional): `string`, `int`, or `length` — when provided the extracted value will be coerced to that type before comparison. This prevents accidental string vs numeric mismatches (for example, the string "100" is distinct from the integer 100 when `expected_type` is `int`). With `length`, regex values use string length and GJSON arrays/objects use item count.

Example equality checks added in `config.yaml`:

- String equality (exact match): `condition: eq`, `expected: "RUNNING"`, `expected_type: string`
- Integer equality: `condition: eq`, `expected: 100`, `expected_type: int`
- Regex match against an extracted value: `condition: matches`, `expected: '^\d+\.\d+\.\d+$'`
- Length check: `condition: gte`, `expected: 3`, `expected_type: length`
