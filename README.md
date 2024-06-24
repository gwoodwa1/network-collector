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

3. **Build the project:**

    ```bash
    go build -o network-collector
    ```
4. **Environment Variables for credentials**
     ```
     export NET_USER=<username>
     export NET_PASSWORD=<your password>
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

