# Workflow operation examples

These playbooks demonstrate the workflow language as complete configurations. They target the example IOS-XR lab device in `inventory.yaml`; update its address and platform type before running them.

| Playbook | Operations demonstrated |
| --- | --- |
| `01-conditions-and-loops.yaml` | registration, `when`, literal and registered-list `foreach`, bounded `repeat` |
| `02-reuse-and-recovery.yaml` | parameterized `workflows`, `use`/`with`, `block`, `rescue`, explicit `rollback`, `always` |
| `03-approval-and-parallel.yaml` | manual `approval`, `--approve-all`, independent `parallel` branches |
| `04-recurring-schedule.yaml` | finite `schedule`, device concurrency, retries, validation actions |
| `05-pre-post-diff.yaml` | parallel pre-checks, health gate, approval, change hook, post-checks, unified diffs |
| `06-custom-variables.yaml` | inline `vars`, imported `vars_files`, conditions, loops, workflow arguments, validations |
| `07-interface-turnup.yaml` | approval, interface configuration, light levels, error counters, rollback |
| `08-ssh-security-profiles.yaml` | global `auto` negotiation, inventory-level `legacy` override, host-key migration |

Run one example from the repository root:

```bash
export NET_USER=<username>
export NET_PASSWORD=<password>
go run ./cmd/network-collector --config examples/workflow-operations/01-conditions-and-loops.yaml
```

The approval example requires an interactive terminal. For an already-authorized unattended test, use:

```bash
go run ./cmd/network-collector \
  --config examples/workflow-operations/03-approval-and-parallel.yaml \
  --approve-all
```

`02-reuse-and-recovery.yaml` contains illustrative configuration and rollback commands. Treat it as a lab template: replace the commands with the transactional syntax supported by your platform and test rollback independently before use.

Schedules are deliberately finite. `04-recurring-schedule.yaml` runs three occurrences and exits; use an external scheduler for indefinite calendar-based execution.

`05-pre-post-diff.yaml` is the most complete change-window pattern. It captures six pre/post command outputs, parses platform and route summaries with bundled TextFSM modules, generates unified JSON diffs with a reusable local workflow, and fails when selected state changes. Raw output may contain counters or timestamps, so compare only commands stable on your platform or parse and compare stable fields.

`09-openconfig-facts.yaml` demonstrates vendor-neutral fact gathering. Each subset tries an OpenConfig NETCONF filter first and falls back independently to SSH plus TextFSM. Set `format` to `openconfig`, `native`, or `both`; native output preserves fields that OpenConfig does not model. The bundled SSH mappings currently cover IOS-XR system, platform, interfaces, LLDP, BGP, IS-IS, and LDP.

`06-custom-variables.yaml` imports shared values from `vars/common.yaml` and uses them throughout the workflow. This is a useful pattern for keeping site, environment, interface, expected-state, and change-window data separate from reusable workflow logic.

`07-interface-turnup.yaml` is a guarded interface activation pattern. It verifies the port exists, asks for approval, commits `no shutdown`, checks line protocol, parses Rx/Tx optical power and alarm flags, verifies zero input/CRC/output errors, and returns the interface to shutdown if a post-check fails. Its multiline IOS-XR configuration commands are a lab template and must be tested against the target driver and commit policy.

`08-ssh-security-profiles.yaml` demonstrates a mixed customer estate. The playbook defaults to modern-first `auto`, while `inventory/security-profiles.yaml` explicitly assigns `legacy` to an older router. It retains the previous insecure host-key behavior to avoid surprising existing users and includes the two-line migration to `known_hosts` as comments.
