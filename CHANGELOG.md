# Changelog

All notable changes to Network Collector are documented here.

## Unreleased

- Add `cmd/junos-routing-monitor`, a self-contained binary for watching Junos routers during a change window (BGP/routing-table/interface polling, per-table default-route BGP protocol-next-hop tracking, plus a before/after route snapshot diff), mirroring `cmd/xr-routing-monitor`'s workflow with Junos-native commands and parsers, validated against real `show bgp summary`/`show route summary table`/`show route table`/`show interfaces` output.
- Add end-of-run `interface-traffic.html` reports for Junos and IOS-XR routing monitors, generated from current-run JSONL interface samples.

## [1.1.0] - 2026-07-12

- Added the standalone IOS-XR routing observability monitor with interactive onboarding, route and interface polling, snapshots, running-configuration capture, and shutdown diffs.
- Added RSA SecurID mode to Network Collector, including `PASSCODE:` challenge recognition, startup-token reuse across devices, persistent workflow sessions, and fresh human-in-the-loop passcode prompts before reconnecting.
- Add bounded gNMI `once` and `stream` subscriptions with `target_defined`, `on_change`, and `sample` modes, available in playbook steps and the gNMI client.
- Add asynchronous webhook and RFC 5424 syslog lifecycle-event sinks, including optional webhook HMAC signing.

- Added Arista EOS and Juniper Junos SSH/TextFSM fact coverage for system, platform, interfaces, LLDP, and BGP with the existing NETCONF-first fallback model.
- Added structural JSON drift detection with approved or rolling previous-state baselines, ignored paths, machine-readable drift artifacts, and optional enforcement.
- Added pluggable environment, interactive, permission-checked file, and external-command credential providers with per-device inventory profiles.

## [1.0.2] - 2026-07-04

- Added inventory labels with Boolean `--limit` and `--exclude` selectors, plus `--rerun-failed` targeting from previous structured run summaries.
- Added non-fatal JSONL lifecycle events for runs, devices, steps, validations, and artifacts.
- Extracted a reusable Go orchestration package with bounded concurrency, canary staging, start intervals, failure thresholds, context cancellation, selectors, event contracts, and shared result types.
- Added a multi-stage, non-root Alpine container image with a minimal runtime, OpenSSH support, bundled parser assets, and persistent output mount guidance.
- Expanded the workflow cookbook with labelled inventories, selector recipes, canary rollout, failed-device replay, lifecycle events, guarded reload/reconnect handling, and stronger example validation.
- Added NETCONF-first, SSH/TextFSM-fallback facts gathering with OpenConfig, native, and combined JSON formats; IOS-XR coverage includes system, platform, interfaces, LLDP, BGP, IS-IS, and LDP.
- Added a local gNMI server integration test, parser fuzzing, NETCONF lifecycle tests, and full SSH auto-fallback control-flow tests.
- Added local TLS-server integration tests for Arista eAPI and RESTCONF, enforced race testing in CI/release workflows, and published CI coverage profiles.
- Added cross-feature regression tests for approval scheduling, recurring artifacts, rollback recovery metadata, and parallel variable scope/merging.
- Began decomposing the CLI monolith by extracting configuration/security loading and output/logging, and consolidated repetitive SSH compatibility warnings into one startup policy summary.
- Added backwards-compatible SSH security profiles with modern-first negotiation fallback, per-device overrides, optional known-host verification, and explicit legacy/insecure warnings.
- Added a guarded interface turn-up example with approval, optical telemetry parsing, error-counter validation, and rollback.
- Added inline custom variables and relative variable-file imports with deterministic precedence and support throughout templates and workflow logic.
- Added direct conditions, list iteration, parameterized workflows, recovery and rollback, approval gates, isolated parallel branches, and bounded recurring schedules for SSH workflows.
- Migrated the application to the maintained `go-viper/mapstructure/v2` configuration decoder.
- Added weekly dependency update pull requests with automatic dependency-file and test verification.
- Added safe local CLI steps with templated arguments, temporary file inputs, timeouts, output registration, and validation support.
- Added a top-level `local_steps` phase for running local tools once after all device workflows.

## [1.0.1] - 2026-07-03

- Added custom TextFSM parser templates and row-oriented regex record parsers.
- Added IOS-XR NTP association, status, and running-configuration parser templates.
- Added safe bounded repeat blocks for running step groups a finite number of times at a configured interval.
- Added atomic raw, parsed JSON, and run-summary output artifacts with per-step overrides.
- Added recursive modular YAML imports with deterministic merging, glob support, and cycle and duplicate protection.

## [1.0.0] - 2026-07-03

First stable release.

### Highlights

- Multi-vendor SSH, RESTCONF, NETCONF, gNMI, and Arista HTTP drivers.
- Inventory hosts and groups with reusable YAML playbooks.
- Step-based SSH workflows with parsing, validation, retries, variables, conditional actions, waits, and reconnect probes.
- Staged concurrent execution with start intervals, canary devices, concurrency limits, and failure thresholds.
- Per-device session logs, consolidated JSON output, and failure logging.
- Environment-based or interactive credential input.

[1.0.0]: https://github.com/gwoodwa1/network-collector/releases/tag/v1.0.0
[1.0.1]: https://github.com/gwoodwa1/network-collector/releases/tag/v1.0.1
[1.0.2]: https://github.com/gwoodwa1/network-collector/releases/tag/v1.0.2
[1.1.0]: https://github.com/gwoodwa1/network-collector/releases/tag/v1.1.0
