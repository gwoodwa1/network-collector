# junos-routing-monitor

A standalone binary for watching a set of Juniper Junos routers during a
change window — BGP session health, routing-table health, and interface
traffic — plus a before/after snapshot of monitored route tables and BGP
neighbor routes so you can confirm nothing moved except what you meant to
change.

It is self-contained: this directory's `parsers.yaml` and `templates/` are
compiled into the binary via `go:embed`, so `go build` produces a single
file with nothing else to copy to the jumphost. It does not use or modify
anything under `cmd/network-collector`.

This tool is a sibling to [`cmd/xr-routing-monitor`](../xr-routing-monitor/README.md)
(same change-window workflow, retargeted at Junos CLI syntax) — see
[Not yet ported from xr-routing-monitor](#not-yet-ported-from-xr-routing-monitor)
for what's deliberately out of scope in this first pass.

## Why this exists

- Authentication on these routers is assumed to be a one-time passcode
  (RSA SecurID or similar), so **every device is connected and
  authenticated individually**, and the tool **never reconnects
  automatically** — a dropped session needs a human to type a fresh
  passcode. Each device's SSH session is opened once and kept open for the
  whole run; the periodic polling below reuses that same session instead of
  reconnecting, so you're never prompted for credentials more than once per
  device per run (see [Passcode reuse](#passcode-reuse) for reusing one
  passcode across several devices within its cache window). If your fleet
  instead uses reusable password/key auth, this still works fine — you'll
  just never be offered a reuse prompt beyond the first entry, since nothing
  ever expires.
- You can watch **multiple devices at once**, each on its own independent
  polling loop, so one device dropping doesn't stop monitoring the others.

## Build

```bash
CGO_ENABLED=0 go build -o junos-routing-monitor ./cmd/junos-routing-monitor
```

**`CGO_ENABLED=0` is required**, not optional. A plain `go build` on a machine with cgo
enabled (the default whenever gcc is present) dynamically links against the build host's
`libc.so.6`. Copying that binary to an older jumphost fails at runtime with
`GLIBC_2.34 not found` / `GLIBC_2.32 not found`, even though `file` still reports what
looks like a normal ELF binary — the giveaway is `file` reporting `dynamically linked`
instead of `statically linked`. `CGO_ENABLED=0` produces a fully static binary with no
runtime glibc dependency at all.

Copy the resulting `junos-routing-monitor` binary to the jumphost. No other
files are required.

## Run

```bash
./junos-routing-monitor [flags]
```

### Flags

| Flag                      | Default         | Meaning                                                                                                                          |
|---------------------------|-----------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `--interval`               | `60s`           | How often each device is polled (Go duration syntax, e.g. `30s`, `2m`).                                                          |
| `--output-dir`             | `artifacts`     | Parent directory for output files. Every run creates and writes into its own subfolder underneath it, named after `--devices` (or a start timestamp without one) — see below. |
| `--parsers`                | *(embedded)*    | Path to an external `parsers.yaml` to use instead of the binary's built-in parser set.                                           |
| `--type`                   | `juniper_junos` | scrapligo platform/driver name used for every device you onboard.                                                                |
| `--devices`                | *(none)*        | Optional YAML file pre-listing hostname/tables/interfaces/neighbors per device. See [below](#providing-devices-via-a-yaml-file-optional). |
| `--passcode-reuse-window`  | `45s`           | How long a just-entered passcode may be offered for reuse on the next device. `0` disables reuse. See [below](#passcode-reuse).  |
| `--report-output`          | `interface-traffic.html` | Professional HTML report filename inside the run artifact folder. |
| `--report-title`           | `Junos Change Monitoring Report` | Title shown in the report header. |
| `--change-reference`       | *(none)*        | Optional change or ticket reference shown in the report. |
| `--logo-folder`            | *(none)*        | Folder containing optional PNG report branding. |
| `--header-logo`, `--footer-logo` | *(automatic)* | PNG filenames inside `--logo-folder`; defaults to `header.png` and `footer.png` when present. |
| `--diff-before`, `--diff-after` | *(none)*   | Paths to a captured before/after `.json` snapshot pair. When both are set, prints a route-level diff and exits instead of connecting to any device. See [below](#once-at-the-start-and-once-at-the-end). |

### Onboarding (once at startup)

If `--devices` was given, the tool connects to each listed device first
(prompting only for credentials — see below), then always falls through to
interactive onboarding, prompting once per device for as many additional
devices as you want to add. Leave the hostname blank to finish onboarding
and start polling:

1. **Router hostname/IP** — blank ends onboarding.
2. **Routing table(s)** for route-summary polling, the default route's BGP
   protocol next hop, and the before/after route snapshot — comma-separated,
   e.g. `CUSTOMER-A.inet.0,CUSTOMER-B.inet.0`, or `inet.0` for the
   default/master table — blank skips route polling for this device. This is
   the full table name Junos itself uses (not a bare routing-instance name):
   a routing-instance can carry more than one address-family table, so
   there's no safe instance-name-to-table-name translation this tool could
   invent — see [Not yet ported](#not-yet-ported-from-xr-routing-monitor) for
   the auto-detection xr-routing-monitor has that this tool doesn't (yet).
3. **Interface(s)** — comma-separated (e.g. `ae0,ae1`) — blank skips
   interface polling for this device. Physical interfaces, aggregated
   Ethernet, and logical sub-interfaces (e.g. `ae0.100`) all poll the same
   way.
4. **BGP neighbor IP(s)** to snapshot routes for, before and after the
   change — comma-separated — blank skips the snapshot for this device.
5. **Username / passcode** — standard interactive prompt, unless a still-valid
   passcode is available to reuse (see [Passcode reuse](#passcode-reuse)).
   **A failed connection is not retried** — see below — the device is
   skipped and reported, and you'd need a fresh onboarding attempt
   (re-enter its hostname) to try it again.

A hostname already connected (whether from `--devices` or entered
interactively, case-insensitively) is refused a second time — two sessions
for the same device would otherwise race on the same output files. You'll
see `already connected to <host>, skipping duplicate`; connecting the same
hostname again requires stopping and re-running the tool.

Once you finish onboarding (blank hostname), polling starts immediately on
every device that connected successfully.

Stop the tool with **Ctrl+C**. It shuts down all devices' sessions
cleanly and exits once every polling loop has stopped.

### Providing devices via a YAML file (optional)

Instead of typing hostname/table/interfaces/neighbors interactively for
every device, list them once in a file and pass `--devices path/to/file.yaml`:

```yaml
interval: 30s

devices:
  - hostname: pe-router-1
    tables: [CUSTOMER-A.inet.0, CUSTOMER-B.inet.0]
    interfaces: [ae0, ae1]
    neighbors: [198.51.100.101]
  - hostname: pe-router-2
    tables: [inet.0]
    interfaces: [ae10]
```

Only `hostname` is required. `tables`/`interfaces`/`neighbors` are each
optional exactly like their interactive-prompt equivalents (`table:` —
singular — also works as an alias for a one-item `tables:` list; both may
be set and are merged). **Credentials are never part of this file** — a
one-time passcode is single-use/time-limited, so the tool always prompts
for them interactively (with reuse offered per [Passcode
reuse](#passcode-reuse)) regardless of `--devices`. After the file is
processed you're dropped into the normal interactive prompt to add any
further ad hoc devices, or just hit Enter immediately to start polling.

The document's optional top-level `interval` field sets the default polling
interval for the run (same duration syntax as `--interval`), so it can live
alongside the device list instead of being retyped on the command line each
time. Passing `--interval` explicitly always overrides it.

A `commands:` block overrides the show-commands/parser modules this tool
polls every tick, if your fleet needs something different (e.g. a Junos
version whose `show route summary table` output differs, or a fleet-specific
match filter on the interface command):

```yaml
commands:
  bgp_command: show bgp summary
  bgp_parser: junos_bgp_summary
  route_command: show route summary table %s
  route_parser: junos_route_table_summary
  default_route_command: 'show route table %s 0/0 exact extensive | match "Protocol next hop:"'
  default_route_parser: junos_default_route_nexthop
  interface_command: 'show interfaces %s extensive | match "Description:|Input|Output"'
  interface_parser: junos_interface_stats
```

Every field is optional; only the ones you set are overridden.
`route_command`, `default_route_command`, and `interface_command` must each
contain exactly one `%s` placeholder for the table or interface name.

### Passcode reuse

A one-time passcode is typically cached server-side for a short window
after entry, during which the same passcode can authenticate more than one
device. When a still-valid passcode is available, you're asked before every
connection:

```
Reuse cached passcode for automation (~32s left in the cache window)? [Y/n]:
```

Answering **Enter/`y`** reuses it (no re-prompt); answering **`n`/`no`** asks
for a fresh username/passcode instead. This is always an explicit per-device
choice, never automatic — you're expected to know whether you're still
inside your environment's actual cache window. A failed connection attempt
immediately invalidates the cache (a rejected passcode isn't trustworthy to
offer again). Set `--passcode-reuse-window 0` to disable the prompt
entirely and always require fresh credentials.

**No automatic retry.** A failed connection (bad passcode, network issue,
anything) is never retried inline — the tool reports it and moves on. If a
device fails, take a breath, confirm your credentials, and deliberately
re-enter that hostname at the next onboarding prompt (or re-run the tool)
rather than immediately hammering it again.

## What gets collected

Every run creates one subfolder under `--output-dir` and writes everything
below into it: `<output-dir>/<devices-file>/` when run with `--devices
CRQXXX.yaml` (named after that file's basename, without extension), or
`<output-dir>/<start-timestamp>-<pid>/` for a purely interactive run with no
`--devices` file. Re-running against the *same* `--devices` file
deliberately reuses the same folder (it's named for the change, not the
run) — every file inside it still has its own capture timestamp, so a
second run's captures don't overwrite the first's; only the per-device
`.jsonl` accumulates across repeat runs against the same file. The paths
below all omit the `<output-dir>/<change>/` prefix for brevity.

### Every `--interval`, per device (written to `<hostname>.jsonl`, one JSON line per tick)

| Data point                   | Command                                              | Condition                  |
|-------------------------------|-------------------------------------------------------|-----------------------------|
| BGP session health            | `show bgp summary`                                    | always                      |
| Route table health            | `show route summary table <table>`                    | once per monitored table   |
| Default route protocol next hop | `show route table <table> 0/0 exact extensive \| match "Protocol next hop:"` | once per monitored table |
| Interface traffic             | `show interfaces <iface> extensive \| match "Description:\|Input\|Output"` | once per configured interface |

BGP is collected on every tick and doubles as a liveness check: if the BGP
command itself fails to execute, that device's session is assumed to have
dropped and polling for that device stops (the other devices keep going).
Everything else falls back to raw text in the same JSON line if its parser
lookup fails, so a tick is never silently lost.

After Ctrl+C, the tool reads this run's samples from the `.jsonl` files and
writes the shared Network Collector professional report
(`interface-traffic.html` by default) in the same artifact folder when it
finds parseable interface-rate data. The responsive, print-friendly report is
self-contained and includes the run outcome, optional change reference,
embedded PNG branding, and input/output bps charts for every
device/interface. The time scale uses minute-aligned gridlines, automatically
coarsening on longer windows. Any tick where a monitored table's default-route
protocol next hop changed is marked as a labeled vertical line so the traffic
shift around a migration can be read in context. Older samples already present
in an accumulated `.jsonl` from a previous run are ignored.

Branding images must be PNG files directly inside `--logo-folder`; absolute
paths and parent traversal are rejected. For example:

```bash
./junos-routing-monitor \
  --devices CHG-2026-0042.yaml \
  --report-title "Junos core path migration" \
  --change-reference CHG-2026-0042 \
  --logo-folder ./branding
```

The interface command covers both statistics formats Junos produces: the
compact `Input :`/`Output:` table that ae/physical units print, and `irb`
units' section-based `extensive` output, where the rates come from the
**Transit statistics** lines (the only section carrying a trailing
`N bps`/`N pps` rate — the Traffic and Local statistics sections are totals
only and are deliberately ignored). Both formats have been validated
against real captured output; if your Junos release prints something
different, override `interface_command`/`interface_parser` via the
`commands:` block rather than patching and rebuilding.

The default route's **protocol** next hop (the originating PE/route
reflector, as opposed to the resolved forwarding next hop/interface+MPLS
label — which changes with the underlay and isn't the useful signal here)
is tracked specifically because it's a stable indicator that the route
still comes from where it should. Junos repeats `Protocol next hop: <ip>`
once per route reflector that advertised the path (a fleet with 3 RRs
commonly shows the same value 3 times, each with a second, more detailed
line too) — this tool dedupes to the distinct next-hop value(s) before
displaying or logging them, so a "before" of `192.0.2.9` (however many
times it was repeated in the raw output) reads clearly against an "after"
of `192.0.2.10` if the default route ever moves to a different upstream.

#### Status line output

Each tick also prints its status to stdout (and `session.log` — see below)
as one header line plus an indented interface table, e.g.:

```
22:07:26 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A.inet.0 routes 383, nexthop 192.0.2.9
  | Interface | Inbound | Outbound |
  | ae0       | 6.2Gbps |  4.1Gbps |
  | ae1.100   | 1.0Gbps |  0.8Gbps |
```

The `nexthop` clause always appears for a monitored table, so a collection
problem is visible on the status line instead of silently missing:
`nexthop <ip>` is the parsed value (comma-joined if a genuine ECMP default
route has several); `nexthop none` means the command ran and parsed cleanly
but found no protocol next hop — that node's table genuinely has no
(BGP-learned) default route at that moment; `nexthop ?` means the command
failed to execute or its output didn't parse — check that tick's `errors`
field in the device's `.jsonl` for the reason.

Only interfaces with non-zero inbound or outbound rates are expanded into
rows; idle 0/0 interfaces are counted in a summary line instead
(`+N zero-rate interfaces not shown`). Lines are only ever appended, never
overwritten, so the full history of the change window stays visible whether
you're watching live or the output is redirected to a file. A dropped
session prints `SESSION DROPPED` instead of a status line for that tick and
stops appearing afterward.

### Once at the start and once at the end

If routing table(s) and/or neighbor IP(s) were given during onboarding:

| Command                                          | Purpose                                     |
|----------------------------------------------------|----------------------------------------------|
| `show route table <table>`                          | full route table, once per monitored table   |
| `show route receive-protocol bgp <neighbor>`         | per-neighbor received routes, per neighbor    |
| `show route advertising-protocol bgp <neighbor>`     | per-neighbor advertised routes, per neighbor  |

"Before" is captured right after onboarding finishes (right before your
change starts); "after" is captured when you hit Ctrl+C (right when your
change is done). Immediately after the "after" capture, the tool
automatically diffs the before/after pair itself and prints the report to
the terminal and `session.log`. You only need the standalone `-diff-*`
flags later — to re-diff, or to diff a pair from a past run.

Each snapshot's filename is `[<devices-file>-]<hostname>-<capture-timestamp>-<label>`,
written twice:
- `<base>.txt` — raw command output, for a quick manual diff.
- `<base>.json` — the same data parsed into structured records (network,
  next hop, protocol) for a programmatic diff.

For a route-level diff instead of a raw text diff, pass the two `.json`
snapshots to `-diff-before`/`-diff-after` — this runs entirely offline (no
SSH session, no credential prompt) and exits after printing the report:

```sh
before=$(ls -t CRQXXX-pe-router-1-*-before.json | head -1)
after=$(ls -t CRQXXX-pe-router-1-*-after.json | head -1)
./junos-routing-monitor -diff-before "$before" -diff-after "$after"
```

```
snapshot diff for pe-router-1: 2026-07-10T08:00:00Z -> 2026-07-10T09:00:00Z

table CUSTOMER-A.inet.0:
  + added (1): [192.0.2.11/24]
  ~ changed (1): [192.0.2.12/24 (192.0.2.1 -> 192.0.2.9)]

neighbor 198.51.100.1 routes:
  no changes

1 of 2 section(s) changed
```

Each routing table and each neighbor's received/advertised routes gets its
own section, diffed by prefix (`NETWORK`) rather than by position — route
tables can reorder between two captures with no real change, so only a
genuinely new/withdrawn prefix, or one whose next hop changed, is reported.
A section that failed to parse into structured records on either side
(rare; falls back to `{"raw": "..."}`) is reported as
`(raw output only, skipped)` instead of a misleading full add/remove — fall
back to `jq -S` against the raw JSON, or `diff` against the `.txt` pair, for
that section.

### `session.log`

Every scrolling status line, plus every operational log event (device
connected, session dropped, snapshot write failures), is mirrored to a log
file in `<output-dir>` in addition to your terminal. Interactive prompts and
credentials are never written to it. The filename is
`[<devices-file>-]<start-timestamp>-session.log`.

## Things to know before a live change window

- **CLI session timeout**: if `--interval` is set longer than the device's
  configured idle-timeout, the router — not this tool — will drop the
  session for inactivity between ticks. Keep the interval comfortably below
  whatever timeout is configured on these boxes.
- **A dropped session is not recovered automatically.** If a device's
  polling stops early, re-run the tool for that device.
- Run it somewhere that survives you being disconnected (`tmux`/`screen` on
  the jumphost), since it's a long-running foreground process for the
  duration of the change window.
- The TextFSM templates under `templates/juniper_junos/` have been validated
  against real captured output for `show bgp summary`, `show route summary
  table`, `show route table`, `show route ... extensive | match "Protocol
  next hop:"`, and `show interfaces ... | match "Description:|Input
  :|Output:"` (see the sanitized fixtures in `parser_fixture_test.go` —
  peer IPs/interface names are real-shaped, AS numbers/public prefixes/
  routing-instance names are replaced with documentation-safe values).
  Three real bugs were caught this way and fixed: a trailing MPLS label
  annotation (`, Push <label>`) on nearly every VPN-learned route's
  next-hop line; `Local` routes reading `Local via <iface>` rather than a
  bare `via <iface>`; and the interface command/format itself was wrong
  from the start — real (non-`extensive`) Junos interface statistics are a
  `Packets/pps/Bytes/bps` table under `Input :`/`Output:` labels, not the
  `N second input rate X bits/sec` text originally assumed.
  `show route receive-protocol/advertising-protocol bgp` (the neighbor
  before/after snapshot) is still unvalidated against real output — if a
  command's real output differs from what's here (a different Junos
  release, etc.), a parser lookup failure falls back to raw
  text rather than crashing (see collectTick/parseOrRaw), but the
  structured fields — and the automatic snapshot diff, which depends on
  them — won't be populated until the template is corrected against real
  output.

## Not yet ported from xr-routing-monitor

This is a first pass scoped to the core change-window workflow. The
following features exist in `cmd/xr-routing-monitor` and are deliberately
not (yet) in this tool:

- **Auto-detection of customer routing-instances.** xr-routing-monitor can
  discover "the" customer VRF on a device from its default-route gateway and
  auto-populate its interfaces. This tool requires routing tables and
  interfaces to be entered manually (or listed in `--devices`).
- **Hub-instance interface sampling.** xr-routing-monitor ranks a shared
  hub VRF's interfaces by current utilization and samples the busiest few.
  Not present here.
- **Running-config capture and diff** (`--capture-running-config`,
  `-diff-before-config`/`-diff-after-config`). Not present here.

Porting any of these should follow the same pattern already used for the
BGP/route/interface polling and snapshot diff: reuse `discover.go`'s
approach from xr-routing-monitor as a starting point, translating IOS-XR's
`show route vrf all`/`show vrf <vrf> ipv4 detail` to Junos's `show route
instance detail`/equivalent, and validate the resulting TextFSM templates
against real device output before relying on them operationally.
