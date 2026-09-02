# monitor-report

Renders (or re-renders) the professional HTML interface report from an
existing `routing-monitor` / `xr-routing-monitor` / `junos-routing-monitor`
output folder, without touching whatever process is still writing into it.

## Why this exists

Every monitor tool writes its HTML report exactly once, at the very end of
the run (after every device session stops). If a change window is long and
you want to see the traffic plotted while it's still in progress — without
stopping the run — there was previously no way to do that. This tool fills
that gap: it reads whatever `.jsonl` tick files already exist in an output
folder and writes the report from them, at any point, as many times as you
like.

It's safe to run from a second terminal or session against a folder a live
monitor process is still appending ticks into: it only ever reads `*.jsonl`
files and writes the report file via an atomic write-then-rename
(`internal/secureartifact.WriteFile`). It never signals, locks, or otherwise
interferes with the running process.

## Build

```bash
CGO_ENABLED=0 go build -trimpath -o monitor-report ./cmd/monitor-report
```

## Run

```bash
./monitor-report -output-dir artifacts/CRQXXX
```

Or on a loop, to keep a browser tab refreshing against the latest data while
a monitor keeps running elsewhere:

```bash
watch -n 30 ./monitor-report -output-dir artifacts/CRQXXX
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--output-dir` | *(none)* | **Required.** An existing run's output folder — the same directory `routing-monitor`/`xr-routing-monitor`/`junos-routing-monitor` were pointed at via their own `--output-dir`/`--devices` combination. |
| `--since` | *(none, meaning every tick on disk)* | RFC3339 timestamp; only plot ticks at or after this time. Per-device `.jsonl` files are never truncated on re-run against the same `--devices` file, so omitting `--since` includes every prior run's ticks too — pass the run's actual start time to scope the plot to just the current change window. |
| `--report-output` | `interface-traffic.html` | HTML report filename, written into `--output-dir`. |
| `--report-title` | `Change Monitoring Report` | Report title. |
| `--change-reference` | *(none)* | Change/ticket reference shown in the report. |
| `--logo-folder`, `--header-logo`, `--footer-logo` | *(none)* | Optional PNG report branding. |
| `--version` | | Print the build version and exit. |

If no interface samples are found yet (a run that just started, or an empty
`--since` window), it prints a message to stderr and exits without writing a
file — safe to call from a loop before any ticks have landed.
