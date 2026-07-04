# Workflow operation examples

These playbooks demonstrate the workflow language as complete configurations. They target documentation-only IOS-XR devices in `inventory.yaml`; update their addresses and platform types before running them. The inventory includes labels for site, role, environment, maintenance state, and rollout wave.

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
| `09-openconfig-facts.yaml` | vendor-neutral OpenConfig facts, native facts, per-subset transport fallback |
| `10-targeting-canary-and-replay.yaml` | inventory labels, Boolean selectors, exclusions, canaries, failure thresholds, JSONL events, failed-device replay |
| `11-reload-and-reconnect.yaml` | approval, expected disconnect, SSH probing, post-boot delay, reconnect, nested validation actions |

Run one example from the repository root:

```bash
export NET_USER=<username>
export NET_PASSWORD=<password>
go run ./cmd/network-collector --config examples/workflow-operations/01-conditions-and-loops.yaml
```

## Inventory targeting and replay

`10-targeting-canary-and-replay.yaml` expands the `all-lab` group and then lets CLI selectors choose the actual rollout set. Selector keys can be built-in fields or arbitrary inventory labels:

```bash
# London core devices only.
go run ./cmd/network-collector \
  --config examples/workflow-operations/10-targeting-canary-and-replay.yaml \
  --limit 'site=london and role=core'

# All London lab devices except anything held for maintenance.
go run ./cmd/network-collector \
  --config examples/workflow-operations/10-targeting-canary-and-replay.yaml \
  --limit 'site=london and environment=lab' \
  --exclude 'maintenance=true'

# A deliberately tiny canary-wave run.
go run ./cmd/network-collector \
  --config examples/workflow-operations/10-targeting-canary-and-replay.yaml \
  --limit 'wave=canary'
```

The playbook writes `results.json` and `events.jsonl` inside its timestamped artifact directory. Replay only the failed devices from a previous run, optionally narrowing the set again:

```bash
go run ./cmd/network-collector \
  --config examples/workflow-operations/10-targeting-canary-and-replay.yaml \
  --rerun-failed artifacts/run-YYYYMMDDTHHMMSS.NNNNNNNNN/results.json \
  --exclude 'maintenance=true'
```

Canaries use the first device remaining after group expansion and selector filtering. A failed canary prevents the main stage from starting; later failures stop new launches when `failure_threshold` is reached. Inspect `events.jsonl` for streaming run, device, step, validation, and artifact events.

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

`11-reload-and-reconnect.yaml` is intentionally a lab-only template. It demonstrates a command that disconnects before returning to the prompt, bounded TCP/SSH probing, a post-port-open boot delay, reconnection, post-reload validation, and nested `on_pass` steps. Replace and independently test the reload command before using it on real equipment.
