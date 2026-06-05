# Network Collector Playbook Authoring Skill

Use this guide when generating `config.yaml`, `inventory.yaml`, or `parsers.yaml` for this repository. The output must be valid YAML and must match the schema and runtime behavior described here.

## Goal

Generate playbooks for `cmd/network-collector`, a network automation CLI that runs SSH commands, optionally parses command output into JSON, validates results, registers variables, retries checks, and runs conditional follow-up actions.

The primary generated files are:

- `config.yaml`: playbook, SSH targets, commands, parsers, validations, variables, retries, and conditionals.
- `parsers.yaml`: reusable regex parser modules that convert CLI text into JSON for `gjson` validation.
- `inventory.yaml`: optional host and group inventory used by `config.yaml`.

Prefer generating concise, explicit YAML. Do not invent unsupported keys.

## Top-Level `config.yaml`

Supported top-level keys for `network-collector`:

```yaml
name_playbook: Human readable playbook title
inventory_file: inventory.yaml
parsers_file: parsers.yaml
fail_on_fail: false
ssh: []
```

Rules:

- `name_playbook` is optional and appears in session logs.
- `inventory_file` is optional; default behavior is to look for `inventory.yaml`.
- `parsers_file` is optional; default behavior is to look for `parsers.yaml`.
- `fail_on_fail` is optional. Use `true` when the process should exit non-zero if any validation fails or errors.
- For this CLI, generate SSH playbooks under `ssh`. Other protocols may appear in sample configs, but the step engine, parsers, variables, retries, and actions described here apply to SSH.

## SSH Device Entries

Each item under `ssh` targets either inline connection details or inventory references.

Inline device:

```yaml
ssh:
  - hostname: router-01
    ip: 192.0.2.10
    type: cisco_ios
    timeout: 20
    operation_timeout: 120
    steps: []
```

Inventory device:

```yaml
ssh:
  - host: router-01
    steps: []
```

Inventory group:

```yaml
ssh:
  - group: core
    steps: []
```

Supported SSH device keys:

- `hostname`: inline hostname or display name.
- `ip`: inline management IP or DNS name.
- `type`: SSH device type passed to the driver, for example `cisco_ios`, `cisco_nxos`, `juniper_junos`.
- `host`: one inventory host name.
- `hosts`: list of inventory host names.
- `group`: one inventory group name.
- `groups`: list of inventory group names.
- `timeout`: SSH connection timeout in seconds.
- `operation_timeout`: command execution timeout in seconds; use for long-running commands.
- `cmd`: single command shortcut when `steps` is not needed.
- `parser`: parser module for single-command shortcut output.
- `validation`: one validation rule for single-command shortcut output.
- `validations`: multiple validation rules for single-command shortcut output.
- `steps`: ordered list of step objects.

Rules:

- Prefer `steps` for anything with more than one command, waits, retries, variables, conditionals, or probes.
- If using `cmd` at device level, do not also generate unrelated `steps`.
- Inventory values may be overridden by the SSH device entry.
- Variables are scoped per hostname/IP and can be reused by later SSH entries for the same device.

## `inventory.yaml`

Inventory format:

```yaml
hosts:
  - name: router-01
    hostname: router-01
    ip: 192.0.2.10
    type: cisco_ios
    timeout: 20
    operation_timeout: 120

groups:
  core:
    hosts:
      - router-01
```

Host keys:

- `name`: inventory key. Use stable lowercase or hyphenated names.
- `hostname`: optional display hostname.
- `ip`: management address.
- `address`: alternate management address key if `ip` is not used.
- `type`: SSH platform type.
- `timeout`: default connection timeout.
- `operation_timeout`: default command timeout.

Rules:

- Every inventory host needs `name` or `hostname`.
- Every inventory host needs `ip` or `address`.
- Use groups for repeated workflows across multiple devices.

## SSH Steps

Step format:

```yaml
steps:
  - name: check-version
    message: checking current software
    cmd: show version
    parser: optional_parser_name
    validation: {}
    validations: []
    register: variable_name
    retry: {}
    on_pass: {}
    on_fail: {}
```

Supported step keys:

- `name`: required in generated playbooks. Use short kebab-case names.
- `message`: optional operator note logged before the step. Supports variables.
- `cmd`: command to send over SSH. Supports variables.
- `parser`: parser module name from `parsers.yaml`.
- `validation`: one validation rule.
- `validations`: multiple validation rules. All must pass.
- `register`: variable name to store extracted or parsed data.
- `retry`: retry policy for failed validation.
- `wait_seconds`: wait before running the command, or wait-only if no `cmd`.
- `ssh_probe`: close stale SSH, probe TCP, reconnect, then continue.
- `return_to_prompt`: set `false` for commands expected to disconnect or reboot before returning a prompt.
- `on_pass`: conditional action after validation passes.
- `on_fail`: conditional action after validation fails or errors.

Rules:

- Use `validation` for one rule and `validations` for multiple rules.
- If a step has `parser`, validations run against the parsed JSON, not raw CLI text.
- If a step has `parser` and `register`, the parsed JSON is registered as the variable value.
- If a step has `register` and validation results have `raw_extract`, the first non-empty `raw_extract` can be registered.
- Use `wait_seconds` alone for pauses.
- Use `return_to_prompt: false` for reboot/confirmation commands that intentionally lose the prompt.

## Variables

Variable syntax:

```yaml
cmd: show install active {{install_id}}
pattern: 'Package ID:\s+{{install_id}}'
json_path: '{{dynamic_path}}'
expected: '{{baseline_alarms}}'
message: install id is {{install_id}}
```

Rules:

- Variables use `{{variable_name}}`.
- Variable names must match `[a-zA-Z_][a-zA-Z0-9_]*`.
- Variables can be used in `cmd`, `pattern`, `json_path`, string `expected` values, `message`, and action `cmd` or `message`.
- Variables must be registered before use.
- For parsed JSON baselines, use `register` on the parser step and compare later with `expected: '{{variable_name}}'`.

Regex extraction variable example:

```yaml
- name: capture-install-id
  cmd: 'show install active | include "Install ID"'
  validation:
    extractor: regex
    pattern: 'Install ID:\s+(\d+)'
    condition: matches
    expected: '^\d+$'
    expected_type: string
  register: install_id
```

Parsed JSON variable example:

```yaml
- name: capture-baseline-alarms
  cmd: show alarms brief system active
  parser: xr_show_alarms_brief_system_active
  register: baseline_alarms
```

## Validation Rules

Validation rule format:

```yaml
extractor: regex
pattern: 'State:\s+(\S+)'
condition: eq
expected: READY
expected_type: string
```

or:

```yaml
extractor: gjson
json_path: active_packages.#
condition: gte
expected: 1
expected_type: int
```

Supported validation keys:

- `extractor`: required. Use `regex` or `gjson`.
- `pattern`: required for `regex`.
- `json_path`: required for `gjson`.
- `condition`: required. One of `eq`, `neq`, `contains`, `not_contains`, `matches`, `gt`, `gte`, `lt`, `lte`.
- `expected`: required for comparisons.
- `expected_type`: optional. One of `string`, `int`, `length`.

Extractor behavior:

- `regex` runs against raw command output unless a parser is configured.
- `regex` uses the first capture group if present; otherwise it uses the whole match.
- `gjson` runs against JSON output, including parser output.
- Missing extraction normally fails the validation.
- Missing extraction with `condition: not_contains` passes.

Condition behavior:

- `eq`: extracted value equals expected.
- `neq`: extracted value does not equal expected.
- `contains`: extracted string contains expected string.
- `not_contains`: extracted string does not contain expected string, or the extraction path/pattern is absent.
- `matches`: extracted string matches the regex in `expected`.
- `gt`: extracted integer is greater than expected.
- `gte`: extracted integer is greater than or equal to expected.
- `lt`: extracted integer is less than expected.
- `lte`: extracted integer is less than or equal to expected.

Type behavior:

- `expected_type: string`: compare as strings.
- `expected_type: int`: coerce extracted value to integer before comparison.
- `expected_type: length`: for regex, use extracted string length; for GJSON arrays/objects, use item count.
- If `expected_type` is omitted with `gt`, `gte`, `lt`, or `lte`, integer comparison is inferred.

Rules:

- Always set `expected_type` for `eq` when comparing numbers.
- Use `expected_type: length` for array/object count checks.
- Quote regex patterns and strings containing `:`, `{`, `}`, `\`, `#`, or leading special characters.
- Prefer single quotes for regex in YAML so backslashes do not need double escaping.

## GJSON Query Construction

Use `extractor: gjson` when validating parsed JSON or JSON API output.

Common paths:

```yaml
json_path: locations.#          # array length
json_path: locations.0          # first array item
json_path: severities.5         # sixth array item
json_path: descriptions.#       # number of descriptions
json_path: descriptions.0       # first description
json_path: '@this'              # entire JSON document
```

Parser output example:

```json
{
  "locations": ["0"],
  "severities": ["Major"],
  "groups": ["Environ"],
  "set_times": ["02/26/2026 15:05:05 GMT"],
  "descriptions": ["Power Group redundancy lost."]
}
```

Validations for that parser output:

```yaml
validations:
  - extractor: gjson
    json_path: locations.#
    condition: eq
    expected: 1
    expected_type: int
  - extractor: gjson
    json_path: severities.0
    condition: eq
    expected: Major
    expected_type: string
  - extractor: gjson
    json_path: descriptions.0
    condition: contains
    expected: Power Group redundancy
    expected_type: string
```

Compare full parsed JSON to a baseline variable:

```yaml
- name: capture-baseline-alarms
  cmd: show alarms brief system active
  parser: xr_show_alarms_brief_system_active
  register: baseline_alarms

- name: compare-final-alarms
  cmd: show alarms brief system active
  parser: xr_show_alarms_brief_system_active
  validation:
    extractor: gjson
    json_path: '@this'
    condition: eq
    expected: '{{baseline_alarms}}'
    expected_type: string
  on_fail:
    action: fail
    message: active alarms changed after the workflow
```

Rules for full-document comparison:

- Use `json_path: '@this'`.
- Use `expected: '{{baseline_variable}}'`.
- Use `expected_type: string`.
- This compares serialized JSON. It is strict: array order and field values must match.

## Regex Parser Modules

`parsers.yaml` format:

```yaml
parsers:
  parser_name:
    type: regex
    fields:
      field_name:
        pattern: '(?m)^regex with (capture)$'
        group: 1
        repeated: true
        type: string
```

Supported parser module keys:

- `type`: only `regex` is supported. Omit or set to `regex`.
- `fields`: map of output JSON field names.

Supported parser field keys:

- `pattern`: required regex.
- `group`: optional capture group number. Defaults to first capture group if present.
- `repeated`: optional boolean. Use `true` to produce an array from all matches.
- `type`: optional. Use `string` or `int`.

Parser behavior:

- Each field regex is run independently against the whole command output.
- `repeated: true` returns an array. Without `repeated`, the first match is returned.
- If no non-repeated match is found, the field value is an empty string.
- If no repeated matches are found, the field value is an empty array.
- Parser output is JSON and can be validated with `gjson`.

Rules:

- Include `(?m)` for line-oriented CLI output so `^` and `$` match each line.
- Anchor row parsers with `^` and `$` when possible.
- Use `\s+` for column spacing.
- Avoid parsing header and separator lines by requiring expected severity, status, date, or other row tokens.
- Repeat the same row regex across fields with different `group` values when splitting tabular CLI output into parallel arrays.
- Use stable field names in lowercase snake_case.

Example `parsers.yaml`:

```yaml
parsers:
  xr_show_alarms_brief_system_active:
    type: regex
    fields:
      locations:
        pattern: '(?m)^(\S+)\s+(Major|Minor|Critical)\s+(\S+)\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(.+)$'
        group: 1
        repeated: true
      severities:
        pattern: '(?m)^(\S+)\s+(Major|Minor|Critical)\s+(\S+)\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(.+)$'
        group: 2
        repeated: true
      groups:
        pattern: '(?m)^(\S+)\s+(Major|Minor|Critical)\s+(\S+)\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(.+)$'
        group: 3
        repeated: true
      set_times:
        pattern: '(?m)^(\S+)\s+(Major|Minor|Critical)\s+(\S+)\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(.+)$'
        group: 4
        repeated: true
      descriptions:
        pattern: '(?m)^(\S+)\s+(Major|Minor|Critical)\s+(\S+)\s+(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(.+)$'
        group: 5
        repeated: true
```

## Retry

Retry format:

```yaml
retry:
  until_pass: true
  interval_seconds: 60
  max_attempts: 5
```

Rules:

- Retry only applies when the step has validation.
- Retry repeats the command until validation passes.
- Retry is triggered by validation status `fail`, not by parser errors or command execution errors.
- If `interval_seconds` is missing or less than/equal to zero, default retry interval is 60 seconds.
- If `max_attempts` is omitted or zero, retry may continue without a configured attempt limit.

## Conditional Actions

Actions run after the final validation result for a step.

```yaml
on_pass:
  action: exit
  message: target state already present

on_fail:
  action: fail
  message: target state not reached
```

Supported action keys:

- `action`: `exit`, `stop`, `fail`, `cmd`, `command`, `run`, `steps`, `none`, `noop`, or `no_op`.
- `message`: optional text. Supports variables.
- `cmd`: command to run. Supports variables.
- `steps`: nested steps to run.

Action behavior:

- `exit` or `stop`: stop remaining steps for the current device without marking run failed.
- `fail`: stop remaining steps for current device and mark run failed.
- `cmd`, `command`, or `run`: run one command over the current SSH session.
- `steps`: run nested steps.
- `none`, `noop`, or `no_op`: take no control-flow action.
- If `action` is omitted and `cmd` exists, action is treated as `cmd`.
- If `action` is omitted and `steps` exists, action is treated as `steps`.
- A message-only action logs the message and continues.

Rules:

- Use `on_pass` to skip unnecessary work when the desired state already exists.
- Use `on_fail` with `action: fail` for guardrail checks that must stop the workflow.
- Nested steps support the same step keys as top-level steps.

## Waiting, Reboots, and SSH Probes

Wait-only step:

```yaml
- name: wait-before-check
  wait_seconds: 30
```

Command expected to disconnect:

```yaml
- name: confirm-reload
  cmd: yes
  return_to_prompt: false
```

SSH probe:

```yaml
- name: wait-for-reboot
  wait_seconds: 300
  ssh_probe:
    port: 22
    interval_seconds: 30
    max_attempts: 40
    timeout_seconds: 5
    post_wait_seconds: 120
```

`ssh_probe` keys:

- `port`: TCP port. Defaults to 22.
- `interval_seconds`: delay between attempts. Defaults to 30.
- `max_attempts`: number of attempts. Defaults to 20.
- `timeout_seconds`: per-attempt TCP timeout. Defaults to 5.
- `post_wait_seconds`: extra wait after the first successful TCP probe.

Rules:

- Use `return_to_prompt: false` before a reboot if the command is expected to timeout or disconnect.
- Use `ssh_probe` after a reboot or reload to reconnect before continuing.
- Use `post_wait_seconds` because TCP/22 can open before the CLI is fully ready.

## Baseline and Final Comparison Pattern

Use this pattern when a workflow must prove that state did not change.

```yaml
name_playbook: Alarm-safe workflow
inventory_file: inventory.yaml
parsers_file: parsers.yaml
fail_on_fail: true

ssh:
  - host: xr-router-1
    operation_timeout: 120
    steps:
      - name: capture-baseline-alarms
        cmd: show alarms brief system active
        parser: xr_show_alarms_brief_system_active
        register: baseline_alarms

      - name: make-change
        cmd: show version

      - name: compare-final-alarms
        cmd: show alarms brief system active
        parser: xr_show_alarms_brief_system_active
        validation:
          extractor: gjson
          json_path: '@this'
          condition: eq
          expected: '{{baseline_alarms}}'
          expected_type: string
        on_fail:
          action: fail
          message: active alarms changed after the workflow
```

Rules:

- The baseline step must run before the final comparison.
- The baseline step must use the same parser as the final comparison.
- Use the same device host/IP for baseline and final steps.
- If splitting baseline and final across separate `ssh` entries, use the same inventory host or same inline hostname/IP.
- Full JSON comparison is strict. If timestamps are expected to change, compare only stable fields such as `locations`, `severities`, `groups`, and `descriptions`.

Stable field comparison example:

```yaml
- name: capture-baseline-alarm-descriptions
  cmd: show alarms brief system active
  parser: xr_show_alarms_brief_system_active
  validation:
    extractor: gjson
    json_path: descriptions
    condition: matches
    expected: '.+'
    expected_type: string
  register: baseline_alarm_descriptions

- name: compare-final-alarm-descriptions
  cmd: show alarms brief system active
  parser: xr_show_alarms_brief_system_active
  validation:
    extractor: gjson
    json_path: descriptions
    condition: eq
    expected: '{{baseline_alarm_descriptions}}'
    expected_type: string
```

To use stable field comparison, register that specific field with a validation extraction instead of registering the entire parser output. Because parser output registration happens first and validation extraction registration happens after validation, `register` on a parser step with validation stores the validation `raw_extract` when the validation extracts a value.

## Generation Checklist

Before returning generated YAML:

- Ensure YAML indentation is valid.
- Use only supported keys.
- Quote regex strings with single quotes.
- Quote templated expected values like `'{{variable_name}}'`.
- Use `parser` only when the named parser exists in `parsers.yaml`.
- Use `gjson` only against JSON or parsed output.
- Use `regex` against raw CLI output.
- Include `expected_type` for numeric equality and full JSON string comparisons.
- Ensure every variable is registered before use.
- Ensure every `on_pass` or `on_fail` belongs to a step with validation.
- For multi-step workflows, prefer one SSH entry with ordered `steps`.
- For reload workflows, include `return_to_prompt: false`, `wait_seconds`, and `ssh_probe`.
- For baseline/final comparisons, register the baseline parser output and compare final parser output with `json_path: '@this'`.
