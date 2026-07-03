# Workflow operation examples

These playbooks demonstrate the workflow language as complete configurations. They target the example IOS-XR lab device in `inventory.yaml`; update its address and platform type before running them.

| Playbook | Operations demonstrated |
| --- | --- |
| `01-conditions-and-loops.yaml` | registration, `when`, literal and registered-list `foreach`, bounded `repeat` |
| `02-reuse-and-recovery.yaml` | parameterized `workflows`, `use`/`with`, `block`, `rescue`, explicit `rollback`, `always` |
| `03-approval-and-parallel.yaml` | manual `approval`, `--approve-all`, independent `parallel` branches |
| `04-recurring-schedule.yaml` | finite `schedule`, device concurrency, retries, validation actions |

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

