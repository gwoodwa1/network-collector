# Scaling Network Collector across large fleets

Network Collector has two concurrency levels:

1. `execution.max_parallel` limits active device runs across the inventory.
2. A workflow `parallel.max_parallel` limits simultaneous branches inside one
   device run.

This differs from Ansible's `forks`: a device slot can contain several
transport sessions when its workflow has parallel branches or gNMI
subscriptions. Size the run from sessions and device control-plane capacity,
not only from device count.

## Starting values

For a routine read-only collection:

```yaml
execution:
  max_parallel: 20
  start_interval_seconds: 1
  canary_count: 2
  failure_threshold: 5
```

For configuration changes:

```yaml
execution:
  max_parallel: 4
  start_interval_seconds: 15
  canary_count: 1
  failure_threshold: 1
```

These are starting points, not universal defaults. Begin lower when devices
share a console server, TACACS/RADIUS service, NETCONF gateway, telemetry
collector, or secret manager.

## Estimate peak sessions

For a conservative upper bound:

```text
peak sessions =
  execution.max_parallel
  × (root SSH + root NETCONF + parallel SSH + parallel NETCONF + gNMI streams)
```

Count each term as the maximum simultaneously live for one device:

- A normal SSH workbook generally holds one root SSH session for the device.
- NETCONF is opened lazily and then retained until that device run finishes.
- Each `parallel` branch opens its own SSH and NETCONF clients when required.
- Every active `gnmi_subscribe` step owns a gNMI connection for its duration.
- A parallel gNMI monitor plus a configuration branch can therefore hold the
  monitor connection and the change transport at the same time.

Example: `execution.max_parallel: 10` with one root SSH session and three
SSH-using parallel branches can reach roughly 40 SSH sessions. A two-branch
workflow containing one gNMI monitor and one NETCONF change can reach roughly
20 active transport connections at ten device slots, before accounting for a
root connection retained by surrounding steps.

## Serial, canary, and wave patterns

Use `max_parallel: 1` for strict serial execution. Use `canary_count` when the
first inventory entries form an explicit safety stage. Canaries complete
before the main stage begins.

For controlled waves, label inventory entries:

```yaml
labels: {site: london, role: core, wave: "1"}
```

Then run successive selectors:

```bash
network-collector --config change.yaml --limit 'wave=1' --check
network-collector --config change.yaml --limit 'wave=1'
network-collector --config change.yaml --limit 'wave=2'
```

Use `--rerun-failed` with a previous `results.json` rather than rerunning an
entire successful wave.

## Start-rate and failure controls

- `start_interval_seconds` rate-limits new device starts even when a
  concurrency slot is free. Use it to protect AAA, secret managers, bastions,
  NETCONF gateways, and control planes from login bursts.
- `failure_threshold` stops launching new non-canary devices after the
  configured number of failed device runs. Already active devices finish.
- `canary_count` is stricter: any failed canary prevents the main stage.
- Top-level scheduled occurrences do not overlap. The next occurrence starts
  only after the previous occurrence finishes and the interval elapses.

Credential-provider commands currently resolve sequentially before device
execution. This avoids a secret-manager login burst, but it also means 5,000
devices with a 500 ms provider lookup add about 42 minutes before network work
starts. Prefer shared `credential_profile` records only when the account is
truly shared, and use the secret manager's local agent/cache where supported.
Do not add a plaintext cache inside the workbook.

## Host and service limits

Before increasing concurrency, check:

- process file-descriptor limits;
- SSH/NETCONF/gNMI session limits on each device;
- AAA authentication and accounting throughput;
- bastion and NAT connection limits;
- secret-manager quotas and token lease duration;
- artifact storage IOPS and capacity;
- JSONL/webhook sink queue pressure;
- CPU and memory while parsing large responses.

Test at 1, 5, 10, and 20 device slots while recording connection failures,
device CPU, AAA latency, secret lookup latency, run duration, open file
descriptors, and artifact volume. Increase only while error rates and latency
remain stable.

## Monitoring at scale

Long-lived gNMI subscriptions consume a device slot for their full duration.
For a fleet-wide monitoring window, use a dedicated monitor invocation and
set `execution.max_parallel` high enough for the intended simultaneous
coverage. Stagger starts to avoid synchronized subscriptions.

If a change workbook and monitor workbook run as separate processes, add their
session estimates together. They do not share a global concurrency limiter.
For very large continuous telemetry estates, use a dedicated telemetry
collector and reserve workbook gNMI subscriptions for bounded change windows.
