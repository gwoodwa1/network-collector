# xr-routing-monitor

A standalone binary for watching a set of Cisco IOS-XR routers during a
change window — BGP session health, route table health, and traffic on
core-facing Bundle-Ether interfaces — plus a before/after snapshot of the
full BGP route table so you can confirm nothing moved except what you meant
to change.

It is self-contained: `internal/xrmonitor`'s `parsers.yaml` and `templates/` are
compiled into the binary via `go:embed`, so `go build` produces a single
file with nothing else to copy to the jumphost. It does not use or modify
anything under `cmd/network-collector`.

This binary is a thin wrapper over `internal/xrmonitor` — the same package
[`cmd/routing-monitor`](../routing-monitor/README.md) uses for mixed
Cisco IOS-XR/Juniper Junos fleets. Use this tool directly for an IOS-XR-only
run; use `routing-monitor` when a change window touches both platforms.

## Why this exists

- Authentication on these routers is RSA SecurID (one-time passcode), so
  **every device is connected and authenticated individually**, and the tool
  **never reconnects automatically** — a dropped session needs a human to
  type a fresh passcode. Each device's SSH session is opened once and kept
  open for the whole run; the periodic polling below reuses that same
  session instead of reconnecting, so you're never prompted for a passcode
  more than once per device per run (see [Passcode reuse](#passcode-reuse)
  for reusing one passcode across several devices within its cache window).
- You can watch **multiple devices at once**, each on its own independent
  polling loop, so one device dropping doesn't stop monitoring the others.

## Build

```bash
CGO_ENABLED=0 go build -o xr-routing-monitor ./cmd/xr-routing-monitor
```

**`CGO_ENABLED=0` is required**, not optional. A plain `go build` on a machine with cgo
enabled (the default whenever gcc is present) dynamically links against the build host's
`libc.so.6`. Copying that binary to an older jumphost fails at runtime with
`GLIBC_2.34 not found` / `GLIBC_2.32 not found`, even though `file` still reports what
looks like a normal ELF binary — the giveaway is `file` reporting `dynamically linked`
instead of `statically linked`. `CGO_ENABLED=0` produces a fully static binary with no
runtime glibc dependency at all. There's no automated release build for this binary yet
(`.goreleaser.yaml` doesn't cover it), so it must be built manually with the flag every
time.

Copy the resulting `xr-routing-monitor` binary to the jumphost. No other
files are required.

## Run

```bash
./xr-routing-monitor [flags]
```

### Flags

| Flag                      | Default       | Meaning                                                                                                                          |
|---------------------------|---------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `--interval`               | `60s`         | How often each device is polled (Go duration syntax, e.g. `30s`, `2m`).                                                          |
| `--output-dir`             | `artifacts`   | Parent directory for output files. Every run creates and writes into its own subfolder underneath it, named after `--devices` (or a start timestamp without one) — see below. |
| `--parsers`                | *(embedded)*  | Path to an external `parsers.yaml` to use instead of the binary's built-in parser set.                                           |
| `--type`                   | `cisco_iosxr` | scrapligo platform/driver name used for every device you onboard.                                                                |
| `--devices`                | *(none)*      | Optional YAML file pre-listing hostname/vrf/interfaces/neighbors per device. See [below](#providing-devices-via-a-yaml-file-optional). |
| `--passcode-reuse-window`  | `45s`         | How long a just-entered passcode may be offered for reuse on the next device. `0` disables reuse. See [below](#passcode-reuse).  |
| `--report-output`          | `interface-traffic.html` | HTML report filename inside the run artifact folder. |
| `--report-title`           | `IOS XR Change Monitoring Report` | Title shown in the report header. |
| `--change-reference`       | *(none)*      | Optional change or ticket reference shown in the report. |
| `--logo-folder`            | *(none)*      | Folder containing optional PNG report branding. |
| `--header-logo`, `--footer-logo` | *(automatic)* | PNG filenames inside `--logo-folder`; defaults to `header.png` and `footer.png` when present. |
| `--diff-before`, `--diff-after` | *(none)* | Paths to a captured before/after `.json` snapshot pair. When both are set, prints a route-level diff and exits instead of connecting to any device. See [below](#once-at-the-start-and-once-at-the-end-written-to-output-dirdevices-file-hostname-timestamp-labeltxtjson). |
| `--capture-running-config` | `false`       | Also capture `show running-config` before and after the change window, as a separate `<base>-running-config.txt` file per label. See [below](#running-config-optional). |
| `--diff-before-config`, `--diff-after-config` | *(none)* | Paths to a captured before/after running-config `.txt` pair. When both are set, prints a unified line diff and exits instead of connecting to any device. See [below](#running-config-optional). |
| `--version` | `false` | Print the build version and exit, instead of connecting to any device. |

### Onboarding (once at startup)

If `--devices` was given, the tool connects to each listed device first
(prompting only for credentials — see below), then always falls through to
interactive onboarding, prompting once per device for as many additional
devices as you want to add. Leave the hostname blank to finish onboarding
and start polling:

1. **Router hostname/IP** — blank ends onboarding.
2. **Auto-detect customer VRF(s)? [y/N]** — see [Auto-detecting a customer
   VRF](#auto-detecting-a-customer-vrf) below. Answering **y** replaces step 3
   with a prompt for the gateway prefix (skipped if one was already supplied
   via `--devices`), and the VRF(s) are discovered after connecting instead
   of typed by hand. The default (**N**/Enter) keeps the next step as-is.
3. **VRF name** for the route-summary check — blank skips route polling for
   this device. (Skipped if you answered **y** above.)
4. **Core-facing Bundle-Ether interface(s)** — comma-separated (e.g.
   `BE45,BE46`) — blank skips interface polling for this device. Any
   interface name works here, not just Bundle-Ether — physical interfaces
   and sub-interfaces (e.g. `TenGigE0/0/0/2.200`) poll exactly the
   same way. If auto-detect found customer-facing interfaces too, they're
   added to whatever you type here, not instead of it.
5. **BGP neighbor IP(s)** to snapshot routes for, before and after the
   change — comma-separated — blank skips the snapshot for this device.
6. **Username / RSA passcode** — standard interactive prompt, unless a
   still-valid passcode is available to reuse (see [Passcode
   reuse](#passcode-reuse)). **A failed connection is not retried** — see
   below — the device is skipped and reported, and you'd need a fresh
   onboarding attempt (re-enter its hostname) to try it again.

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

Instead of typing hostname/VRF/interfaces/neighbors interactively for every
device, list them once in a file and pass `--devices path/to/file.yaml`:

```yaml
interval: 30s
customer_gateway_prefix: 192.0.2.

devices:
  - hostname: pe-router-1
    vrfs: [CUSTOMER-A-INTERNET]
    interfaces: [BE45, BE46]
    neighbors: [198.51.100.101]
  - hostname: pe-router-2
    auto_detect_vrf: true
    interfaces: [BE10]
```

Only `hostname` is required. `vrfs`/`interfaces`/`neighbors` are each
optional exactly like their interactive-prompt equivalents (`vrf:` — singular
— also still works as an alias for a one-item `vrfs:` list, for files written
before multi-VRF support existed; both may be set and are merged). Setting
`auto_detect_vrf: true` instead of `vrfs:` runs the same discovery as the
interactive "Auto-detect customer VRF(s)..." prompt — see [Auto-detecting a
customer VRF](#auto-detecting-a-customer-vrf) — using the document's
top-level `customer_gateway_prefix`, which `loadDeviceSpecs` requires to be
set whenever any device has `auto_detect_vrf: true`. **Credentials are never
part of this file** — RSA passcodes are single-use/time-limited, so the tool
always prompts for them interactively (with reuse offered per [Passcode
reuse](#passcode-reuse)) regardless of `--devices`. After the file is
processed you're dropped into the normal interactive prompt to add any
further ad hoc devices, or just hit Enter immediately to start polling.

A few more top-level, fleet-wide settings are optional:

```yaml
exclude_interface_prefixes: [loopback]
hub_top_interfaces: 2

commands:
  bgp_command: show bgp vpnv4 unicast summary
  bgp_parser: xr_bgp_vpnv4_summary
  route_command: show route vrf %s summary
  route_parser: xr_route_vrf_summary
  default_route_command: show route vrf %s 0.0.0.0/0 detail
  default_route_parser: xr_route_vrf_default_nexthop
  interface_command: 'show int %s | inc "rate|Description:"'
  interface_parser: xr_bundle_interface_stats
```

- `exclude_interface_prefixes` overrides which (lowercase) interface-name
  prefixes are excluded from auto-detected polling targets — the default
  above is applied automatically if omitted. Set this if your fleet's
  customer VRFs carry connected routes on some other non-core virtual
  interface type (e.g. `tunnel-ip`) that should also be excluded.
- `hub_top_interfaces` caps how many of a hub VRF's interfaces get sampled,
  *per hub VRF* (a device matching two hub VRFs samples up to
  `hub_top_interfaces` from each, not `hub_top_interfaces` total), for any
  device with `auto_detect_vrf: true` — see [Auto-detecting a customer
  VRF](#auto-detecting-a-customer-vrf). Defaults to 2 if omitted; set it to
  `0` to disable hub-VRF interface sampling entirely; must not be negative.
- `commands` overrides the show-commands/parser modules this tool polls
  every tick (see `defaultSpec` in `poll.go`). Every field is optional; only
  the ones you set are overridden. Use this if your fleet needs a different
  command — e.g. a code variant without `show bgp vpnv4 unicast summary`, or
  a `... detail` variant — without patching Go source and rebuilding.
  `route_command`, `default_route_command`, and `interface_command` must
  each contain exactly one `%s` placeholder for the VRF or interface name.

### Auto-detecting a customer VRF

On a fleet where each router carries many VRFs (customer VRFs, system VRFs
like `**eint`/`**iid`, VRFs with no default route at all), typing the right
VRF name by hand for every device in every change is error-prone and doesn't
scale. Auto-detect instead identifies "the" customer VRF(s) the same way an
operator eyeballing `show route vrf all` would: **a VRF whose default route
(`0.0.0.0/0`) is sourced from a gateway starting with a known prefix** (e.g.
`192.0.2.` on this fleet) is treated as customer-facing; everything else
on the box is ignored.

The matched default-route gateway is only ever used to identify *which VRF*
is customer-facing — it's never used again after that. For each matched
VRF, the tool then adds every interface actually **assigned to that VRF**
(from `show vrf <vrf> ipv4 detail`'s `Interfaces:` section) to polling,
alongside whatever core-facing interfaces you specified manually (typically
the core Bundle-Ether). This is deliberately not based on the VRF's routing
table: a VRF can import a route-target that's also exported by other,
unrelated VRFs (e.g. a shared "internet access" RT), and an imported
connected route still displays as `C ... is directly connected` in the
importing VRF's table — indistinguishable from the VRF's own genuine
interfaces. `show vrf <vrf> ipv4 detail` comes from VRF configuration
instead, so it isn't affected by that. If more than one *customer* VRF
matches (real fleets often have more than one), all of them are monitored,
and their interfaces are combined and deduplicated. `Loopback*` interfaces
are still ignored by auto-discovery (they're never customer traffic); `BVI*`
interfaces are not — a BVI is a customer-facing bridge-group interface and
can carry real traffic worth polling. Add `bvi` to `exclude_interface_prefixes`
if your fleet's BVIs shouldn't be auto-discovered.

A shared internet-breakout/hub VRF (e.g. `RI-INTERNET-ENTERPRISE`) can
independently peer with the same route-reflector range and match the
gateway heuristic too — but it isn't a single customer's circuit, and
legitimately carries dozens of unrelated customers' interfaces and BGP
sessions. To avoid pulling all of that into per-tick polling, matches are
further filtered to this fleet's customer-VRF naming conventions: a purely
numeric circuit/account ID (`1115679`), or a `V<circuit-id>:<SERVICE>` tag
(`V10:CDN`, `V100:SDN`). A match that doesn't fit either style is treated as
a hub VRF instead of a customer VRF. If your fleet uses yet another
customer-VRF naming style, that VRF will show up as a hub VRF instead of
being picked up as a customer's own — the match rule (`customerVRFName` in
`discover.go`) needs extending for it.

A customer's own designated interface doesn't always carry traffic during a
change window — the traffic that matters may be flowing over the hub VRF
instead. Polling *every* interface on a hub VRF isn't viable (one real
device showed ~33 distinct connected subnets on it), so instead each hub
VRF's own interfaces are ranked by current utilization (input+output
bits/sec) independently, and only the busiest `hub_top_interfaces` (default
2, see above) *of that hub VRF* are added to polling — a device matching
two hub VRFs samples up to `hub_top_interfaces` from each, so one
especially busy hub VRF can't crowd out visibility into a second, unrelated
one. Selected interfaces are sampled the same way as any other interface on
every subsequent tick and labeled `hub` on the status line. The hub VRF's
own route table is never polled — only a small, ranked sample of its
interfaces is. What was found/selected is reported per hub VRF in a
`hub VRFs: ...` line after connecting, e.g.
`RI-INTERNET-ENTERPRISE (41 interfaces, sampling top 2: Gi0/0/0/1,
Gi0/0/0/7)`, so it's visible rather than silently dropped.

This runs at least two read-only commands per device once, right after
connecting, not on every poll tick — plus one more per hub VRF interface
being ranked:

```
show route vrf all | inc "Gateway of last resort|VRF:"
show vrf <matched-vrf> ipv4 detail
show int <hub-vrf-interface> | inc "rate|Description:"
```

If discovery finds no matching VRF, or a follow-up interface lookup fails
for one of several matched VRFs, onboarding still proceeds with whatever was
found (or nothing) rather than aborting — check the "auto-detected VRF(s)
... with interface(s) ..." line printed after connecting to confirm what was
actually picked up. Long discovered lists are summarized on screen; the
configured device session still uses the full discovered set.

The optional top-level `interval` field sets the default polling interval
for the run (same duration syntax as `--interval`, e.g. `30s`, `2m`), so it
can live alongside the device list instead of being retyped on the command
line each time. Passing `--interval` explicitly always overrides it.

### Passcode reuse

RSA SecurID passcodes are typically cached server-side (e.g. by ISE) for a
short window after entry — commonly around 60 seconds — during which the
same passcode can authenticate more than one device. When a still-valid
passcode is available, you're asked before every connection:

```
Reuse cached passcode for automation (~32s left in the ISE cache window)? [Y/n]:
```

Answering **Enter/`y`** reuses it (no re-prompt); answering **`n`/`no`** asks
for a fresh username/passcode instead. This is always an explicit per-device
choice, never automatic — you're expected to know whether you're still
inside your environment's actual cache window. A failed connection attempt
immediately invalidates the cache (a rejected passcode isn't trustworthy to
offer again). Set `--passcode-reuse-window 0` to disable the prompt
entirely and always require a fresh passcode.

**No automatic retry.** A failed connection (bad passcode, network issue,
anything) is never retried inline — the tool reports it and moves on. RSA/
ISE commonly locks the account after 3 consecutive bad attempts, and an
easy "retry?" prompt is a real way to hit that under pressure during a
change window, especially combined with passcode reuse across devices. If a
device fails, take a breath, confirm you have a good passcode, and
deliberately re-enter that hostname at the next onboarding prompt (or
re-run the tool) rather than immediately hammering it again.

**A wrong passcode can still cost 2 of your 3 attempts, not 1.** This
fleet's devices re-display `Enter PASSCODE:` in-band on a bad entry rather
than dropping the connection outright. The underlying SSH library
(scrapligo) automatically resends the *same* passcode once more if it sees
that identical prompt reappear, before finally giving up — a behavior
that's hardcoded in that library and not configurable from here. So a
single wrong entry can silently consume 2 of your environment's 3 allowed
attempts before this tool ever reports a failure. Double-check the passcode
before hitting Enter; there's no way for this tool to intercept that second
automatic resend.

## What gets collected

Every run creates one subfolder under `--output-dir` and writes everything
below into it: `<output-dir>/<devices-file>/` when run with `--devices
CRQXXX.yaml` (named after that file's basename, without extension), or
`<output-dir>/<start-timestamp>-<pid>/` for a purely interactive run with no
`--devices` file (the PID guards against two such processes launched within
the same second, e.g. a wrapper script starting one instance per node,
landing on the same folder name). This keeps one change window's artifacts
— the per-device JSONL, before/after snapshots, running-config captures,
and `session.log` — together in one clearly-named folder instead of a flat
directory of similarly-prefixed files. Re-running against the *same*
`--devices` file deliberately reuses the same folder (it's named for the
change, not the run) — that's fine, since every file inside it still has
its own capture timestamp (see below), so a second run's captures don't
overwrite the first's; only the per-device `.jsonl` accumulates across
repeat runs against the same file, same as it always has. The paths below
all omit the `<output-dir>/<change>/` prefix for brevity.

The run artifact directory is owner-only (`0700`), and JSONL, session logs,
snapshots, running configurations, and reports are owner-only (`0600`).
Existing reused artifacts are tightened before writing, and symlink artifact
targets are rejected.

On Unix, artifact paths use descriptor-relative no-follow operations through
the final open or replacement. Secure artifact writing fails closed on
non-Unix platforms, so production artifact output is supported only on Unix
deployments.

### Every `--interval`, per device (written to `<hostname>.jsonl`, one JSON line per tick)

| Data point                   | Command                                              | Condition                  |
|-------------------------------|-------------------------------------------------------|-----------------------------|
| BGP session health            | `show bgp vpnv4 unicast summary`                      | always                      |
| Route table health            | `show route vrf <vrf> summary`                        | once per monitored VRF (manually specified, auto-detected, or both) |
| Default route BGP next hop    | `show route vrf <vrf> 0.0.0.0/0 detail`               | once per monitored VRF |
| Interface traffic             | `show int <iface> \| inc "rate\|Description:"`        | once per configured interface (Bundle-Ether, physical, or sub-interface — any interface name works) |

BGP is collected on every tick and doubles as a liveness check: if the BGP
command itself fails to execute, that device's session is assumed to have
dropped and polling for that device stops (the other devices keep going).
Everything else falls back to raw text in the same JSON line if its parser
lookup fails, so a tick is never silently lost.

After Ctrl+C, the tool reads this run's samples from the `.jsonl` files and
writes a professional `interface-traffic.html` report in the same artifact
folder when it finds parseable interface-rate data. It uses the same
self-contained reporting style and branding support as `cmd/reporter`, with
summary cards, responsive input/output traffic charts, a route-transition
table, and print styling. Any tick where a monitored VRF's default-route next
hop changed — e.g. the moment an internet-facing VRF is repointed at a
different peering router mid-change — is marked on that device's charts as a
vertical dashed line, so the traffic shift around the migration can be read
in context. Older samples already present in an accumulated `.jsonl` from a
previous run against the same `--devices` file are ignored.

Branding images must be PNG files directly inside `--logo-folder`; absolute
logo filenames and `..` traversal are refused. When explicit filenames are
omitted, `header.png` and `footer.png` are used if present. For example:

```bash
./xr-routing-monitor \
  --devices change-42.yaml \
  --report-title "Core path migration" \
  --change-reference CHG-2026-0042 \
  --logo-folder ./branding
```

The `nexthop` clause on the status line always appears for a monitored VRF:
`nexthop <ip>` is the parsed value, `nexthop none` means the command ran
and parsed cleanly but the VRF has no default route right now, and
`nexthop ?` means the command failed or its output didn't parse — check
that tick's `errors` field in the device's `.jsonl` for the reason.

The default route's BGP next hop (the originating PE, from the "Routing
Descriptor Blocks" section of `show route vrf ... detail`) is tracked
specifically to catch it moving to a different upstream during a change
window. Unlike Junos's "extensive" output (which repeats the next hop once
per route reflector that advertised the path — see
[cmd/junos-routing-monitor](../junos-routing-monitor/README.md)), IOS-XR's
`detail` output normally shows only the single installed/best path, so no
route-reflector-count dedup is usually needed here — though a genuine ECMP
default route with multiple `Routing Descriptor Blocks` entries is still
deduped down to its distinct next-hop value(s) before being displayed or
logged.

#### Status line output

Each tick also prints its status to stdout (and `session.log` — see below)
as one header line plus an indented interface table, e.g.:

```
22:07:26 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A-INTERNET routes 383, nexthop 192.0.2.23
  | VRF                 | Interface             | Inbound |  Outbound |
  | core                | BE45                  | 6.2Gbps |   4.1Gbps |
  | CUSTOMER-A-INTERNET | GigabitEthernet0/0/0/8 |    0bps | 272.0Kbps |
```

Interfaces are never packed onto the header line — a device with many
interfaces would otherwise produce a single line far longer than a typical
terminal's column limit (a shared VRF can easily have 40+ interfaces; see
[Auto-detecting a customer VRF](#auto-detecting-a-customer-vrf)). The table's
`VRF` column shows `core` for manually specified core-facing interfaces
(e.g. Bundle-Ether uplinks) and the customer VRF for auto-detected
customer-facing interfaces when there is exactly one monitored VRF. A
device monitoring more than one VRF gets one `<vrf> routes <N>` segment per
VRF on the header line, sorted by VRF name. To keep the terminal readable,
the table shows every interface whose inbound or outbound rate is non-zero
and summarizes idle interfaces with a `+N zero-rate interfaces not shown`
line; the JSONL output still contains every interface result for that tick.

Lines are only ever appended, never overwritten, so the full history of the
change window stays visible in the terminal and looks the same whether
you're watching live or the output is redirected to a file. A dropped
session prints `SESSION DROPPED` instead of a status line for that tick and
stops appearing afterward.

### Once at the start and once at the end (written to `<output-dir>/[<devices-file>-]<hostname>-<timestamp>-<label>.{txt,json}`)

If VRF(s) and/or neighbor IP(s) were given during onboarding (manually,
auto-detected, or both):

| Command                                                            | Purpose                                   |
|----------------------------------------------------------------------|--------------------------------------------|
| `show bgp vrf <vrf>`                                                  | full VRF route table, once per monitored VRF |
| `show bgp vpnv4 unicast neighbors <ip> routes`                        | per-neighbor received routes, per neighbor |
| `show bgp vpnv4 unicast neighbors <ip> advertised-routes`             | per-neighbor advertised routes, per neighbor |

"Before" is captured right after onboarding finishes (right before your
change starts); "after" is captured when you hit Ctrl+C (right when your
change is done) — no extra interaction needed mid-run. Immediately after the
"after" capture, the tool automatically diffs the before/after pair itself
(the same route-level diff `-diff-before`/`-diff-after` produces, described
further down in this section) and prints the report to the terminal and
`session.log`, right there in the same run. If
`--capture-running-config` was set, the running-config before/after pair is
diffed the same way immediately after. You only need to reach for the
standalone `-diff-*` flags later — to re-diff, or to diff a pair from a past
run.

Each snapshot's filename is `[<devices-file>-]<hostname>-<capture-timestamp>-<label>`,
e.g. `CRQXXX-pe-router-1-20260709-143022-before.txt` when run as
`--devices CRQXXX.yaml`, or just `xr1-20260709-143022-before.txt` for a
device onboarded interactively (no `--devices` file). The `<devices-file>`
prefix is that file's basename without extension — keeping a dedicated YAML
file per change means that change's snapshots are identifiable by name in a
shared `--output-dir`, and the timestamp means re-running against the same
devices file never overwrites a previous change window's snapshots.

Each snapshot is written twice:
- `<base>.txt` — raw command output, for a quick manual diff.
- `<base>.json` — the same data parsed into structured records (network,
  next hop, best-path flag, AS path, etc.) for a programmatic diff, e.g.
  with `jq -S` to normalize key ordering first so the diff isn't full of
  false positives.

Since the filename now includes a timestamp, more than one before/after
pair for the same hostname can legitimately exist in one `--output-dir`
(e.g. after re-running the tool against the same `--devices` file). Don't
glob and pass the result straight to `diff` — with more than one match it
either fails (`diff: extra operand`) or silently diffs the wrong pair.
Pick the most recent pair with `ls -t | head -1` instead:

```sh
before=$(ls -t CRQXXX-pe-router-1-*-before.txt | head -1)
after=$(ls -t CRQXXX-pe-router-1-*-after.txt | head -1)
diff "$before" "$after"
```

For a route-level diff instead of a raw text diff, pass the two `.json`
snapshots to `-diff-before`/`-diff-after` — this runs entirely offline (no
SSH session, no credential prompt) and exits after printing the report:

```sh
before_json=$(ls -t CRQXXX-pe-router-1-*-before.json | head -1)
after_json=$(ls -t CRQXXX-pe-router-1-*-after.json | head -1)
./xr-routing-monitor -diff-before "$before_json" -diff-after "$after_json"
```

```
snapshot diff for pe-router-1: 2026-07-10T08:00:00Z -> 2026-07-10T09:00:00Z

vrf 1115679:
  + added (1): [192.0.2.11/24]
  ~ changed (1): [192.0.2.12/24 (192.0.2.1 -> 192.0.2.9)]

neighbor 198.51.100.1 routes:
  no changes

1 of 2 section(s) changed
```

Each VRF table and each neighbor's received/advertised routes gets its own
section, diffed by prefix (`NETWORK`) rather than by position — BGP route
tables can reorder between two captures with no real change, so only a
genuinely new/withdrawn prefix, or one whose next hop changed, is reported.
A section that failed to parse into structured records on either side (rare;
falls back to `{"raw": "..."}`) is reported as `(raw output only, skipped)`
instead of a misleading full add/remove — fall back to `jq -S` against the
raw JSON, or `diff` against the `.txt` pair, for that section:

```sh
diff <(jq -S . "$before_json") <(jq -S . "$after_json")
```

### Running config (optional)

Pass `--capture-running-config` to also capture the full `show
running-config` before and after the change window. This is a heavier
capture (one extra SSH round trip per label, and a potentially large file
on a big router) so it's off by default — the BGP/route snapshot above
captures regardless of this flag.

Each capture is written as its own raw text file, `<base>-running-config.txt`,
where `<base>` is the exact same `[<devices-file>-]<hostname>-<capture-timestamp>-<label>`
that the BGP snapshot for that same moment uses (see
[above](#once-at-the-start-and-once-at-the-end-written-to-output-dirdevices-file-hostname-timestamp-labeltxtjson)) —
a separate file, correlated by name, not merged into the BGP snapshot's
`.txt`/`.json` pair.

Diff a captured before/after config pair with `-diff-before-config`/
`-diff-after-config` — like `-diff-before`/`-diff-after`, this runs entirely
offline and exits after printing the report:

```sh
before_cfg=$(ls -t CRQXXX-pe-router-1-*-before-running-config.txt | head -1)
after_cfg=$(ls -t CRQXXX-pe-router-1-*-after-running-config.txt | head -1)
./xr-routing-monitor -diff-before-config "$before_cfg" -diff-after-config "$after_cfg"
```

Unlike the route-level snapshot diff (diffed by prefix, order-independent),
config text is diffed as an ordinary ordered unified diff — config needs
surrounding context and line order to stay readable, and there's no natural
key to diff it by. Both diff modes can be combined in one invocation by
passing all four `-diff-*` flags together.

### `session.log`

Every scrolling status line, plus every operational log event (device
connected, session dropped, snapshot write failures), is mirrored to a log
file in `<output-dir>` in addition to your terminal — so the terminal's
scrollback isn't the only record of what happened. Interactive prompts and
credentials are never written to it; only `os.Stderr` ever sees those, and
they're never duplicated anywhere else.

The filename is `[<devices-file>-]<start-timestamp>-session.log`, e.g.
`CRQ00004-20260709-220726-session.log` — not a fixed `session.log`. This
matters if you run one instance per device (recommended if you find several
devices' interleaved status lines on one terminal hard to follow) pointed at
a shared `--output-dir`: a fixed filename would have two processes appending
to the same file, and their writes can interleave line-by-line since the
in-process mutex that keeps one run's own output tidy can't coordinate
across separate processes. Each run's devices-file name plus start
timestamp keeps its log distinct, the same reasoning as the before/after
snapshot filenames above.

## Example

```
$ ./xr-routing-monitor --interval 30s --output-dir ./change-2026-07-08

Router hostname/IP (blank to finish onboarding): pe-router-1
Auto-detect customer VRF(s) via default-route gateway on pe-router-1? [y/N]: y
Customer-facing gateway prefix on pe-router-1 (e.g. 192.0.2.): 192.0.2.
Core-facing Bundle-Ether interface(s) on pe-router-1, comma-separated (blank to skip): BE45
BGP neighbor IP(s) on pe-router-1 to snapshot routes for before/after the change, comma-separated (blank to skip): 198.51.100.101
Username: automation
Password: ********
auto-detected VRF(s) [CUSTOMER-A-INTERNET] with interface(s) [GigabitEthernet0/0/0/1.100] on pe-router-1
connected to pe-router-1

Router hostname/IP (blank to finish onboarding): pe-router-2
Auto-detect customer VRF(s) via default-route gateway on pe-router-2? [y/N]:
VRF name for route summary on pe-router-2 (blank to skip):
Core-facing Bundle-Ether interface(s) on pe-router-2, comma-separated (blank to skip): BE10
BGP neighbor IP(s) on pe-router-2 to snapshot routes for before/after the change, comma-separated (blank to skip):
Reuse cached passcode for automation (~41s left in the ISE cache window)? [Y/n]:
connected to pe-router-2

Router hostname/IP (blank to finish onboarding):

2 device(s) connected; polling every 30s, writing to ./change-2026-07-08/. Press Ctrl+C to stop.

22:07:26 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A-INTERNET routes 383
  | VRF                 | Interface                 | Inbound | Outbound |
  | core                | BE45                      | 6.2Gbps |  4.1Gbps |
  | CUSTOMER-A-INTERNET | GigabitEthernet0/0/0/1.100 | 1.0Gbps |  0.8Gbps |
22:07:27 | pe-router-2    | BGP 4/4 up
  | VRF  | Interface | Inbound | Outbound |
  | core | BE10      | 1.1Gbps |  0.9Gbps |

22:07:56 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A-INTERNET routes 383
  | VRF                 | Interface                 | Inbound | Outbound |
  | core                | BE45                      | 6.3Gbps |  4.0Gbps |
  | CUSTOMER-A-INTERNET | GigabitEthernet0/0/0/1.100 | 1.0Gbps |  0.8Gbps |
22:07:57 | pe-router-2    | BGP 4/4 up
  | VRF  | Interface | Inbound | Outbound |
  | core | BE10      | 1.1Gbps |  0.9Gbps |
^C
all device sessions stopped, exiting
```

Resulting files:

```
change-2026-07-08/
  20260708-220555-session.log
  pe-router-1.jsonl
  pe-router-1-20260708-220555-before.txt
  pe-router-1-20260708-220555-before.json
  pe-router-1-20260708-223012-after.txt
  pe-router-1-20260708-223012-after.json
  pe-router-2.jsonl
```

(No `--devices` file was used here, so filenames have no name prefix — see
[filename format](#once-at-the-start-and-once-at-the-end-written-to-output-dirdevices-file-hostname-timestamp-labeltxtjson).)

## Things to know before a live change window

- **VTY `exec-timeout`**: if `--interval` is set longer than the device's
  configured exec-timeout, the router — not this tool — will drop the
  session for inactivity between ticks. Keep the interval comfortably below
  whatever exec-timeout is configured on these boxes.
- **A dropped session is not recovered automatically.** Since RSA SecurID
  needs a fresh human-entered passcode, there is no unattended reconnect.
  If a device's polling stops early, re-run the tool for that device.
- Run it somewhere that survives you being disconnected (`tmux`/`screen` on
  the jumphost), since it's a long-running foreground process for the
  duration of the change window.
