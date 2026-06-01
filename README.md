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
    git clone https://github.com/kcajme/network-collector.git
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
import "github.com/kcajme/network-collector/pkg/drivers/ssh"
```

Import the Arista HTTP driver:

```go
import "github.com/kcajme/network-collector/pkg/drivers/aristahttp"
```

Import the NETCONF driver:

```go
import "github.com/kcajme/network-collector/pkg/drivers/netconf"
```

Import the gNMI driver:

```go
import "github.com/kcajme/network-collector/pkg/drivers/gnmi"
```

Import the RESTCONF driver:

```go
import "github.com/kcajme/network-collector/pkg/drivers/restconf"
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
- `--fail-on-fail`: exit with non-zero status if any validation returns `fail` or `error`

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

### Validation semantics

Validation steps in `config.yaml` support extractors and typed comparisons. Use `extractor: regex` for CLI text output and `extractor: gjson` for JSON payloads (gNMI/RESTCONF responses).

- `pattern` / `json_path`: the extraction pattern or JSON path
- `condition`: `eq`, `contains`, `gt`, `lt`, etc.
- `expected`: the expected value to compare against
- `expected_type` (optional): `string` or `int` — when provided the extracted value will be coerced to that type before comparison. This prevents accidental string vs numeric mismatches (for example, the string "100" is distinct from the integer 100 when `expected_type` is `int`).

Example equality checks added in `config.yaml`:

- String equality (exact match): `condition: eq`, `expected: "RUNNING"`, `expected_type: string`
- Integer equality: `condition: eq`, `expected: 100`, `expected_type: int`


