# Workflow operation examples

These playbooks demonstrate the workflow language as complete configurations.
They are grouped into `iosxr/`, `junos/`, `arista/`, `iosxe/`, `nxos/`,
`sros/`, and `multivendor/` directories. Shared inventories, parsers,
variables, and enrichment files remain in the top-level support directories.
Update addresses, interfaces, and platform types before running them.

Larger NETCONF configuration artifacts live in each vendor's `payloads/`
directory and are referenced with `netconf.payload_file`. Paths are relative
to the playbook, and variables inside XML files are rendered at execution
time. Short operational RPCs remain inline where that makes the workflow
easier to read.

| Playbook | Operations demonstrated |
| --- | --- |
| `iosxr/01-conditions-and-loops.yaml` | registration, `when`, literal and registered-list `foreach`, bounded `repeat` |
| `iosxr/02-reuse-and-recovery.yaml` | parameterized `workflows`, `use`/`with`, `block`, `rescue`, explicit `rollback`, `always` |
| `iosxr/03-approval-and-parallel.yaml` | manual `approval`, `--approve-all`, independent `parallel` branches |
| `iosxr/04-recurring-schedule.yaml` | finite `schedule`, device concurrency, retries, validation actions |
| `iosxr/05-pre-post-diff.yaml` | parallel pre-checks, health gate, approval, change hook, post-checks, unified diffs |
| `iosxr/06-custom-variables.yaml` | inline `vars`, imported `vars_files`, conditions, loops, workflow arguments, validations |
| `iosxr/07-interface-turnup.yaml` | approval, interface configuration, light levels, error counters, rollback |
| `iosxr/08-ssh-security-profiles.yaml` | global `auto` negotiation, inventory-level `legacy` override, host-key migration |
| `iosxr/09-openconfig-facts.yaml` | vendor-neutral OpenConfig facts, native facts, per-subset transport fallback |
| `iosxr/10-targeting-canary-and-replay.yaml` | inventory labels, Boolean selectors, exclusions, canaries, failure thresholds, JSONL events, failed-device replay |
| `iosxr/11-reload-and-reconnect.yaml` | approval, expected disconnect, SSH probing, post-boot delay, reconnect, nested validation actions |
| `multivendor/12-multivendor-facts.yaml` | EOS and Junos system, platform, interface, LLDP, and BGP facts with NETCONF-first fallback |
| `iosxr/13-structured-drift.yaml` | approved JSON baselines, rolling previous-state baselines, ignored paths, drift artifacts, optional enforcement |
| `iosxr/14-multidevice-vrf-provision.yaml` | reusable L3VPN provisioning across two PEs, endpoint-specific RDs and route policies, verification, rollback |
| `iosxr/15-layer2-mpls-service.yaml` | two-ended IOS XR VPWS service, VLAN attachment circuits, MPLS/LDP pseudowire, retry, verification, rollback |
| `junos/16-junos-netconf-l3-vrf.yaml` | two-PE Junos L3 VRF provisioning, per-PE RDs and access addressing, static route, routing-table RPC verification |
| `junos/17-junos-netconf-l2vpn.yaml` | two-site BGP-signalled Junos L2VPN, per-site identifiers and RDs, operational RPC retry, rollback |
| `junos/18-junos-netconf-port-turnup.yaml` | native Junos XML port enablement, candidate commit, interface-state RPC verification, rollback to disabled |
| `arista/19-arista-eos-cli-vlan.yaml` | EOS CLI VLAN and access-port provisioning, approval, verification, rollback |
| `arista/20-arista-eos-netconf-interface.yaml` | EOS OpenConfig NETCONF interface configuration against running, state query, rollback |
| `iosxe/21-cisco-iosxe-cli-loopback.yaml` | IOS-XE CLI loopback and static route, verification, rollback |
| `iosxe/22-cisco-iosxe-netconf-loopback.yaml` | IOS-XE native YANG loopback creation against running, filtered verification, rollback |
| `nxos/23-cisco-nxos-cli-trunk.yaml` | NX-OS CLI VLAN and trunk update, verification, rollback |
| `nxos/24-cisco-nxos-netconf-interface.yaml` | NX-OS OpenConfig NETCONF interface configuration, state query, rollback |
| `sros/25-nokia-sros-cli-port.yaml` | SR OS model-driven CLI port turn-up, commit, verification, rollback |
| `sros/26-nokia-sros-netconf-port.yaml` | SR OS native YANG candidate edit, commit, verification, rollback |
| `multivendor/27-gnmi-event-actions.yaml` | gNMI on-change update/delete triggers with immediate nested SSH and NETCONF actions |
| `multivendor/28-gnmi-new-path-turnup.yaml` | new-interface and route turn-up events with SSH and NETCONF verification |
| `multivendor/29-gnmi-interface-traffic-guard.yaml` | sampled interface counters converted to rates with a three-sample baseline and 10% drop guard |
| `multivendor/30-gnmi-cpu-monitor.yaml` | sampled CPU telemetry with a numeric alarm threshold and SSH diagnostics |
| `multivendor/31-gnmi-combined-change-monitor.yaml` | one bounded change-window monitor for link state, traffic-rate degradation, and CPU |
| `multivendor/32-gnmi-guarded-new-path-provision.yaml` | parallel new-path provisioning while two different production interfaces are baselined and protected, with immediate rollback |
| `multivendor/33-gnmi-all-interface-light-level-guard.yaml` | per-interface and per-channel RX/TX optical baselines with an absolute 1 dB drop guard |
| `multivendor/34-gnmi-change-health-monitor.yaml` | standalone second-process monitor combining optics, discards, errors, and IS-IS/LDP/BGP neighbor state |
| `multivendor/35-declarative-interface-ensure.yaml` | idempotent OpenConfig interface state with NETCONF discovery, diff, apply, verification, and `--check` preview |

Run one example from the repository root:

```bash
export NET_USER=<username>
export NET_PASSWORD=<password>
go run ./cmd/network-collector --config examples/workflow-operations/iosxr/01-conditions-and-loops.yaml
```

## Inventory targeting and replay

`10-targeting-canary-and-replay.yaml` expands the `all-lab` group and then lets CLI selectors choose the actual rollout set. Selector keys can be built-in fields or arbitrary inventory labels:

```bash
# London core devices only.
go run ./cmd/network-collector \
  --config examples/workflow-operations/iosxr/10-targeting-canary-and-replay.yaml \
  --limit 'site=london and role=core'

# All London lab devices except anything held for maintenance.
go run ./cmd/network-collector \
  --config examples/workflow-operations/iosxr/10-targeting-canary-and-replay.yaml \
  --limit 'site=london and environment=lab' \
  --exclude 'maintenance=true'

# A deliberately tiny canary-wave run.
go run ./cmd/network-collector \
  --config examples/workflow-operations/iosxr/10-targeting-canary-and-replay.yaml \
  --limit 'wave=canary'
```

The playbook writes `results.json` and `events.jsonl` inside its timestamped artifact directory. Replay only the failed devices from a previous run, optionally narrowing the set again:

```bash
go run ./cmd/network-collector \
  --config examples/workflow-operations/iosxr/10-targeting-canary-and-replay.yaml \
  --rerun-failed artifacts/run-YYYYMMDDTHHMMSS.NNNNNNNNN/results.json \
  --exclude 'maintenance=true'
```

Canaries use the first device remaining after group expansion and selector filtering. A failed canary prevents the main stage from starting; later failures stop new launches when `failure_threshold` is reached. Inspect `events.jsonl` for streaming run, device, step, validation, and artifact events.

The approval example requires an interactive terminal. For an already-authorized unattended test, use:

```bash
go run ./cmd/network-collector \
  --config examples/workflow-operations/iosxr/03-approval-and-parallel.yaml \
  --approve-all
```

`02-reuse-and-recovery.yaml` contains illustrative configuration and rollback commands. Treat it as a lab template: replace the commands with the transactional syntax supported by your platform and test rollback independently before use.

Schedules are deliberately finite. `04-recurring-schedule.yaml` runs three occurrences and exits; use an external scheduler for indefinite calendar-based execution.

`05-pre-post-diff.yaml` is the most complete change-window pattern. It captures six pre/post command outputs, parses platform and route summaries with bundled TextFSM modules, generates unified JSON diffs with a reusable local workflow, and fails when selected state changes. Raw output may contain counters or timestamps, so compare only commands stable on your platform or parse and compare stable fields.

`09-openconfig-facts.yaml` demonstrates vendor-neutral fact gathering. Each subset tries an OpenConfig NETCONF filter first and falls back independently to SSH plus TextFSM. Set `format` to `openconfig`, `native`, or `both`; native output preserves fields that OpenConfig does not model. The bundled SSH mappings currently cover IOS-XR system, platform, interfaces, LLDP, BGP, IS-IS, and LDP.

`06-custom-variables.yaml` imports shared values from `vars/common.yaml` and uses them throughout the workflow. This is a useful pattern for keeping site, environment, interface, expected-state, and change-window data separate from reusable workflow logic.

`07-interface-turnup.yaml` is a guarded interface activation pattern. It verifies the port exists, asks for approval, commits `no shutdown`, checks line protocol, parses Rx/Tx optical power and alarm flags, verifies zero input/CRC/output errors, and returns the interface to shutdown if a post-check fails. Its multiline IOS-XR configuration commands are a lab template and must be tested against the target driver and commit policy.

`08-ssh-security-profiles.yaml` demonstrates a mixed customer estate. The playbook defaults to modern-first `auto`, while `inventory/security-profiles.yaml` explicitly assigns `legacy` to an older router. It retains the previous insecure host-key behavior to avoid surprising existing users and includes the two-line migration to `known_hosts` as comments.

`11-reload-and-reconnect.yaml` is intentionally a lab-only template. It demonstrates a command that disconnects before returning to the prompt, bounded TCP/SSH probing, a post-port-open boot delay, reconnection, post-reload validation, and nested `on_pass` steps. Replace and independently test the reload command before using it on real equipment.

`12-multivendor-facts.yaml` uses a separate EOS/Junos inventory. The same five fact subsets are normalized into the existing OpenConfig-shaped result while preserving the complete native TextFSM records. NETCONF remains first in the transport order and each unsupported or absent model falls back independently to the vendor CLI parser.

The gNMI monitoring examples use OpenConfig-style paths and documentation-only targets. Start the traffic guard before the change and allow one counter interval plus all configured `baseline_samples` to complete before changing the network. With the supplied 10-second interval and three baseline rates, allow roughly 40 seconds. Numeric baselines are maintained independently for every canonical event path, allowing the optics example to use a regular expression across all returned components and channels. Example 32 makes the intended topology explicit: interfaces `0/0/0/0` and `0/0/0/1` are existing production paths being protected while the distinct interface `0/0/0/10` is provisioned. CPU component names, operational and optical paths, CLI diagnostics, and the spelling/case of interface status values vary by platform and must be adjusted for the target.

Example 34 is deliberately independent of the change itself. Start it in one terminal, allow about 40 seconds for optical baselines and counter starting values, then run any routine-change workbook in another terminal. A parallel `on_change` branch checks initial and subsequent IS-IS, LDP, and BGP session state while the sampled branch handles optics and counters. The monitoring process exits non-zero when `--fail-on-fail` is used or `fail_on_fail: true` remains configured and any optical, discard, error, adjacency, or session guard fires.

`13-structured-drift.yaml` shows both baseline modes. `baseline: previous` maintains rolling state automatically; a normal path points to an explicitly approved JSON baseline. Drift compares parsed JSON rather than unstable CLI formatting and always writes a `drift.json` artifact. `fail_on_change` decides whether detected changes fail the device run.

`14-multidevice-vrf-provision.yaml` calls one workflow for two PEs. Both
endpoints share the customer VRF and route target, but each `with` block
supplies a different route distinguisher, prefix-set, route-policy, customer
prefix, and access address. IOS XR calls this construct a `route-policy`;
IOS/IOS-XE uses the related `route-map` terminology. The example filters
connected routes at the BGP redistribution attach point and verifies the RD,
RT, policy, and access interface before declaring success.

`15-layer2-mpls-service.yaml` provisions the two ends of an Ethernet private
line using IOS XR `l2transport` subinterfaces and an MPLS/LDP pseudowire. The
PW ID and xconnect identity remain constant, while each endpoint supplies its
own access attachment and the opposite PE loopback. The workflow refuses the
change when the parent interface is down, waits for signalling, retries the
operational check, and removes dedicated service configuration if validation
fails.

Both provisioning examples are lab templates. Replace the documentation
addresses and interface names, confirm the required parent bundles and MPLS
control plane already exist, review generated configuration, and test the
explicit rollback commands against the exact IOS XR release before production
use. The command structure follows Cisco's IOS XR
[L3VPN configuration](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5500/vpn/25xx/configuration/guide/b-l3vpn-cg-ncs5500-25xx/implementing-mpls-layer-3-VPNs.html)
and [point-to-point L2VPN configuration](https://www.cisco.com/c/en/us/td/docs/iosxr/ncs5xx/l2vpn/25xx/b-l2vpn-cg-25xx-ncs540/config-point-to-point-layer2-services.html)
guides.

The three Junos examples use top-level `netconf` targets, so Network Collector
does not open a CLI SSH session. Configuration changes are expressed as native
Junos configuration XML and loaded into the candidate datastore with
`edit-config`; no CLI `set` or `delete` commands are sent. Changes are made
active with `commit`, verified with structured Junos operational RPCs, and
reversed with NETCONF `operation="remove"` edits and commits when a guarded
block fails.

`16-junos-netconf-l3-vrf.yaml` invokes one parameterized workflow for two PEs.
It assigns a distinct RD, logical interface, address, static prefix, and next
hop to each endpoint. The final `get-route-information` RPC selects the
customer table and validates the exact prefix, `Static` protocol, and next hop.

`17-junos-netconf-l2vpn.yaml` provisions a BGP-signalled Layer 2 VPN with
unique RDs and site identifiers. It assumes MPLS transport and BGP
`l2vpn-signaling` already exist. Confirm the operational RPC tag on the target
release with `show l2vpn connections | display xml rpc`, as Junos XML tags can
vary by release.

`18-junos-netconf-port-turnup.yaml` uses NETCONF `operation="remove"` to clear
the Junos `disable` leaf, commits, then retries
`get-interface-information` until both administrative and operational status
are up. Its rollback restores the `disable` leaf.

## EOS, IOS-XE, NX-OS, and SR OS

Examples 19 through 26 provide one CLI and one NETCONF workflow for each
platform. They deliberately use separate documentation hosts so a user can
select and adapt one transport without accidentally running the equivalent
change twice on the same device.

The EOS and NX-OS NETCONF examples use the OpenConfig interfaces hierarchy
against the writable running datastore. EOS requires its NETCONF API and
OpenConfig models to be enabled. NX-OS requires `feature netconf` and
`feature openconfig`; model availability and deviations depend on the exact
release. See the Arista [NETCONF feature documentation](https://www.arista.com/en/support/toi/tag/netconf)
and Cisco's [NX-OS OpenConfig interface examples](https://developer.cisco.com/docs/openconfig-yang/latest/oc-interfaces/).

The IOS-XE NETCONF example uses the native
`Cisco-IOS-XE-native` interface hierarchy to create a loopback directly in
the running datastore. The SR OS example uses the native
`urn:nokia.com:sros:ns:yang:sr:conf` hierarchy, where configuration is edited
in the candidate datastore and committed. Nokia documents that native SR OS
YANG edits target candidate rather than running; see
[SR OS NETCONF](https://documentation.nokia.com/sr/25-7/7x50-shared/system-management/netconf-intro.html).

All eight files are lab templates. Use dedicated interfaces, VLANs, loopbacks,
and ports; check the advertised NETCONF capabilities and YANG library first;
and compare modelled XML with the target release before a production change.
CLI rollback removes only the example's named resources where practical.

The transaction pattern follows Juniper's documentation for
[NETCONF edit-config](https://www.juniper.net/documentation/us/en/software/junos/netconf/topics/task/netconf-configuration-editing.html),
[candidate commits](https://www.juniper.net/documentation/us/en/software/junos/junos-xml-protocol/topics/task/junos-xml-protocol-configuration-committing.html),
and [Junos operational RPC mapping](https://www.juniper.net/documentation/us/en/software/junos/junos-xml-protocol/topics/task/junos-xml-protocol-rpcs-and-xml-mapping.html).
