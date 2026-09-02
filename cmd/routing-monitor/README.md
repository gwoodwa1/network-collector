# routing-monitor

The mixed-fleet front-end for [`cmd/xr-routing-monitor`](../xr-routing-monitor/README.md)
and [`cmd/junos-routing-monitor`](../junos-routing-monitor/README.md). If you monitor
Cisco IOS-XR and Juniper Junos devices in the same change window today, this is what
gives you **one output folder and one `--devices` YAML file** instead of two separate
runs of the two platform-specific tools.

It doesn't reimplement anything: all collection/parsing/diffing logic still lives in
`internal/xrmonitor` and `internal/junosmonitor` (the same code the two standalone
binaries use — they still work exactly as before, unchanged). This tool just shares
their onboarding/output-folder/reporting infrastructure across both platforms in one
process.

## Why one process, not two

A simpler-looking design — spawn `xr-routing-monitor` and `junos-routing-monitor` as
subprocesses pointed at the same output directory — doesn't work: both tools read
credentials interactively from `os.Stdin`, one device at a time. Running them as
concurrent subprocesses so both platforms' change windows genuinely overlap means their
credential prompts would race on the same terminal input.

So this tool onboards **sequentially, platform by platform**: every Cisco IOS-XR device
in your `--devices` file onboards fully (its own one-prompt-at-a-time credential flow,
exactly like the standalone tool) before the Juniper Junos section starts. Once
onboarding finishes, every device — both platforms — polls **concurrently** for the
rest of the run, same as always.

One side effect worth knowing: onboarding shares one passcode-reuse cache and one
hostname registry across both platforms. A passcode just entered for an IOS-XR device
can be offered for reuse on the very next Junos device too (if your fleet's one-time
token backend is shared), and the same hostname can't be claimed under both sections by
accident.

## Build

```bash
CGO_ENABLED=0 go build -trimpath -o routing-monitor ./cmd/routing-monitor
```

## Run

```bash
./routing-monitor --devices CRQXXX.yaml
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--devices` | *(none)* | **Required.** Combined YAML file — see below. |
| `--interval` | `60s` | Polling interval, both platforms. Overridden by the file's top-level `interval:`, which is itself overridden by a section's own `interval:` (see [The combined --devices file](#the-combined---devices-file)) — unless `--interval` is passed explicitly, which always wins for both platforms. |
| `--output-dir` | `artifacts` | Parent directory for the shared output folder, named after `--devices` (same convention as the two standalone tools). |
| `--passcode-reuse-window` | `45s` | How long a just-entered passcode may be offered for reuse on the *next* device, across both platforms. `0` disables reuse. |
| `--capture-running-config` | `false` | Also capture the running configuration before/after, on every device, both platforms. |
| `--netconf-snapshot` | `false` | **Junos devices only.** Also dial NETCONF for extra before/after snapshot sections — see [junos-routing-monitor's README](../junos-routing-monitor/README.md#netconf-snapshot-capture-optional). No effect on IOS-XR devices. |
| `--report-only` | `false` | Regenerate the HTML report from this run's existing output folder and exit — no onboarding, no polling, no device contacted. Use with the same `--devices`/`--output-dir` as the live run. See [Watching interface traffic while it's still running](#watching-interface-traffic-while-its-still-running). |
| `--since` | *(none, meaning every tick on disk)* | Only used with `--report-only`. RFC3339 timestamp; only plot ticks at or after this time. |
| `--report-output` | `interface-traffic.html` | HTML report filename. |
| `--report-title` | `Change Monitoring Report` | Report title. |
| `--change-reference` | *(none)* | Change/ticket reference shown in the report. |
| `--logo-folder`, `--header-logo`, `--footer-logo` | *(none)* | Optional PNG report branding. |
| `--version` | | Print the build version and exit. |

Unlike the two standalone tools, there is **no `--type` flag** — each device's platform
is already known from which section of the YAML file it's listed under, so the correct
scrapligo platform name (`cisco_iosxr`/`juniper_junos`) is always used automatically.

There is also **no interactive (no-`--devices`) onboarding** in this first pass, and
**no `-diff-before`/`-diff-after` replay flags** — a captured snapshot pair is
self-contained per hostname regardless of which binary captured it, so use the matching
standalone tool (`xr-routing-monitor -diff-before ... -diff-after ...` or the Junos
equivalent) to replay a diff after the fact.

### The combined `--devices` file

One shared top-level `interval:`, plus a `cisco_iosxr:` and/or `juniper_junos:`
section — each using **exactly** the same schema as that platform's own standalone
`--devices` file (see [xr-routing-monitor's](../xr-routing-monitor/README.md#providing-devices-via-a-yaml-file-optional)
and [junos-routing-monitor's](../junos-routing-monitor/README.md#providing-devices-via-a-yaml-file-optional)
own documentation for every per-device field, including each section's own `interval:`).
At least one of the two sections must be present; either can be omitted if that run is
single-platform.

```yaml
interval: 30s

cisco_iosxr:
  interval: 15s
  customer_gateway_prefix: 192.0.2.
  hub_top_interfaces: 2
  devices:
    - hostname: xr-router-1
      vrfs: [CUSTOMER-A]
      interfaces: [BE45, BE46]
    - hostname: xr-router-2
      auto_detect_vrf: true
      interfaces: [BE10]

juniper_junos:
  netconf_snapshot: true
  devices:
    - hostname: pe-router-1
      tables: [CUSTOMER-A.inet.0]
      interfaces: [ae0, ae1]
```

The two sections are nested under their own keys rather than flattened into one device
list, deliberately: both platforms' `commands:` override block already uses the same
YAML key with **completely different, incompatible sub-fields** (IOS-XR's
`route_command`/`default_route_command`/etc. vs. Junos's own set) — nesting keeps them
apart without any renaming.

A section's own `interval:` overrides the shared top-level one for just that platform —
in the example above, IOS-XR devices poll every 15s while Junos devices poll every 30s
(the shared default). Useful when one platform's devices need a tighter or looser
cadence than the other in the same run. The `--interval` CLI flag, if passed explicitly,
still wins over both for every device regardless of platform.

Credentials are, as always, never part of this file — prompted interactively per device,
per platform, in section order.

## What gets collected, and where

Identical to what each standalone tool already writes — the same `<hostname>.jsonl`
tick files, before/after snapshots, and (if enabled) running-config captures — just all
landing in the **same** `<output-dir>/<devices-file-basename>/` folder and the same
`session.log`, regardless of which platform a given device belongs to. At the end of the
run, **one** HTML report covers every device on both platforms — see
[`internal/monitorreport`](../../internal/monitorreport), which reads generic
per-tick fields (`hostname`, `interfaces`, `default_route_next_hops`) both platforms'
tick records already produce identically, with no platform-specific code needed to
combine them.

## Watching interface traffic while it's still running

The HTML report is only written once, when the run stops (Ctrl+C or natural
end) — nothing regenerates it automatically while devices are still being
polled. To see the traffic plotted from a *live* run without stopping it, run
`routing-monitor -report-only` from a second terminal, with the same
`-devices`/`-output-dir` as the live run so it resolves to the same output
folder:

```bash
./routing-monitor -report-only -devices CRQXXX.yaml
```

It only reads the `.jsonl` tick files already on disk and (over)writes the
HTML report — no onboarding, no polling, no device contacted, and it never
touches the actual running `routing-monitor` process, so it's safe to run as
often as you like, e.g. on a loop:

```bash
watch -n 30 ./routing-monitor -report-only -devices CRQXXX.yaml
```

For an existing folder written by the standalone `xr-routing-monitor`/
`junos-routing-monitor` tools instead, use
[`cmd/monitor-report`](../monitor-report) the same way — it takes the output
folder directly rather than `-devices`/`-output-dir`, so it works regardless
of which binary wrote the ticks it's reading.

## Relationship to the standalone tools

`cmd/xr-routing-monitor` and `cmd/junos-routing-monitor` are unaffected by this tool's
existence — they're thin wrappers over the exact same `internal/xrmonitor`/
`internal/junosmonitor` packages this tool imports, so a single-platform run with either
standalone binary behaves exactly as it always has. Use this tool specifically when a
change window touches both platforms at once.
