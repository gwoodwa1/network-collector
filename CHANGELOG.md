# Changelog

All notable changes to Network Collector are documented here.

## Unreleased

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
