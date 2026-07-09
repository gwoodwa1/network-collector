# xr-routing-monitor

A standalone binary for watching a set of Cisco IOS-XR routers during a
change window — BGP session health, route table health, and traffic on
core-facing Bundle-Ether interfaces — plus a before/after snapshot of the
full BGP route table so you can confirm nothing moved except what you meant
to change.

It is self-contained: this directory's `parsers.yaml` and `templates/` are
compiled into the binary via `go:embed`, so `go build` produces a single
file with nothing else to copy to the jumphost. It does not use or modify
anything under `cmd/network-collector`.

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
go build -o xr-routing-monitor ./cmd/xr-routing-monitor
```

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
| `--output-dir`             | `artifacts`   | Directory for all output files (created if missing).                                                                             |
| `--parsers`                | *(embedded)*  | Path to an external `parsers.yaml` to use instead of the binary's built-in parser set.                                           |
| `--type`                   | `cisco_iosxr` | scrapligo platform/driver name used for every device you onboard.                                                                |
| `--devices`                | *(none)*      | Optional YAML file pre-listing hostname/vrf/interfaces/neighbors per device. See [below](#providing-devices-via-a-yaml-file-optional). |
| `--passcode-reuse-window`  | `45s`         | How long a just-entered passcode may be offered for reuse on the next device. `0` disables reuse. See [below](#passcode-reuse).  |

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
customer_gateway_prefix: 10.99.99.

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

### Auto-detecting a customer VRF

On a fleet where each router carries many VRFs (customer VRFs, system VRFs
like `**eint`/`**iid`, VRFs with no default route at all), typing the right
VRF name by hand for every device in every change is error-prone and doesn't
scale. Auto-detect instead identifies "the" customer VRF(s) the same way an
operator eyeballing `show route vrf all` would: **a VRF whose default route
(`0.0.0.0/0`) is sourced from a gateway starting with a known prefix** (e.g.
`10.99.99.` on this fleet) is treated as customer-facing; everything else
on the box is ignored.

For each such VRF, the tool then finds its physical/sub-interface uplinks —
the directly-connected routes in `show route vrf <vrf>` — and adds them to
interface polling alongside whatever core-facing interfaces you specified
manually (typically the core Bundle-Ether). If more than one VRF matches
(real fleets often have more than one), all of them are monitored, and their
interfaces are combined and deduplicated. `Loopback*` and `BVI*` directly
connected routes are ignored by auto-discovery so they don't flood the live
status output; add one manually under `interfaces:` if you explicitly want
to poll it.

This runs two read-only commands per device once, right after connecting,
not on every poll tick:

```
show route vrf all | inc "Gateway of last resort|VRF:"
show route vrf <matched-vrf> | inc "is directly connected"
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

Answering **Enter/`y`** reuses it (no re-prompt); answering **`n`** asks for
a fresh username/passcode instead. This is always an explicit per-device
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

### Every `--interval`, per device (written to `<output-dir>/<hostname>.jsonl`, one JSON line per tick)

| Data point         | Command                                              | Condition                  |
|---------------------|-------------------------------------------------------|-----------------------------|
| BGP session health  | `show bgp vpnv4 unicast summary`                      | always                      |
| Route table health  | `show route vrf <vrf> summary`                        | once per monitored VRF (manually specified, auto-detected, or both) |
| Interface traffic   | `show int <iface> \| inc "rate\|Description:"`        | once per configured interface (Bundle-Ether, physical, or sub-interface — any interface name works) |

BGP is collected on every tick and doubles as a liveness check: if the BGP
command itself fails to execute, that device's session is assumed to have
dropped and polling for that device stops (the other devices keep going).
Everything else falls back to raw text in the same JSON line if its parser
lookup fails, so a tick is never silently lost.

Each tick also prints one scrolling status line to stdout (and
`session.log` — see below), e.g.:

```
22:07:26 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A-INTERNET routes 383 | BE45 in 6.2Gbps/out 4.1Gbps
```

A device monitoring more than one VRF gets one `<vrf> routes <N>` segment
per VRF, sorted by VRF name, the same way multiple interfaces each get their
own segment. To keep the terminal readable, only the first few interface
segments are shown on the live status line followed by `+N interfaces` when
more are being polled; the JSONL output still contains every interface
result for that tick.

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
change is done) — no extra interaction needed mid-run.

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

# structured diff, same pattern:
before_json=$(ls -t CRQXXX-pe-router-1-*-before.json | head -1)
after_json=$(ls -t CRQXXX-pe-router-1-*-after.json | head -1)
diff <(jq -S . "$before_json") <(jq -S . "$after_json")
```

### `session.log`

Every scrolling status line, plus every operational log event (device
connected, session dropped, snapshot write failures), is mirrored to
`<output-dir>/session.log` in addition to your terminal — so the terminal's
scrollback isn't the only record of what happened. Interactive prompts and
credentials are never written to it; only `os.Stderr` ever sees those, and
they're never duplicated anywhere else.

## Example

```
$ ./xr-routing-monitor --interval 30s --output-dir ./change-2026-07-08

Router hostname/IP (blank to finish onboarding): pe-router-1
Auto-detect customer VRF(s) via default-route gateway on pe-router-1? [y/N]: y
Customer-facing gateway prefix on pe-router-1 (e.g. 10.99.99.): 10.99.99.
Core-facing Bundle-Ether interface(s) on pe-router-1, comma-separated (blank to skip): BE45
BGP neighbor IP(s) on pe-router-1 to snapshot routes for before/after the change, comma-separated (blank to skip): 198.51.100.101
Username: automation
Password: ********
auto-detected VRF(s) [CUSTOMER-A-INTERNET] with interface(s) [TenGigE0/0/0/2.200] on pe-router-1
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

22:07:26 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A-INTERNET routes 383 | BE45 in 6.2Gbps/out 4.1Gbps | TenGigE0/0/0/2.200 in 1.0Gbps/out 0.8Gbps
22:07:27 | pe-router-2    | BGP 4/4 up  | BE10 in 1.1Gbps/out 0.9Gbps

22:07:56 | pe-router-1    | BGP 6/6 up  | CUSTOMER-A-INTERNET routes 383 | BE45 in 6.3Gbps/out 4.0Gbps | TenGigE0/0/0/2.200 in 1.0Gbps/out 0.8Gbps
22:07:57 | pe-router-2    | BGP 4/4 up  | BE10 in 1.1Gbps/out 0.9Gbps
^C
all device sessions stopped, exiting
```

Resulting files:

```
change-2026-07-08/
  session.log
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
