# Network Collector Playbook Authoring Skill

Use this guide when generating `config.yaml`, `inventory.yaml`, or `parsers.yaml` for this repository. The output must be valid YAML and must match the schema and runtime behavior described here.

## Goal

Generate playbooks for `cmd/network-collector`, a network automation CLI that runs SSH commands, optionally parses and enriches command output into JSON, validates results, registers variables, retries checks, and runs conditional follow-up actions.

The primary generated files are:

- `config.yaml`: playbook, SSH targets, commands, parsers, validations, variables, retries, and conditionals.
- `parsers.yaml`: reusable regex parser modules that convert CLI text into JSON for `gjson` validation.
- `inventory.yaml`: optional host and group inventory used by `config.yaml`.
- Custom ScrapliGo platform YAML: optional SSH prompt, privilege, paging, and command-error behaviour for platforms not bundled with ScrapliGo.

Prefer generating concise, explicit YAML. Do not invent unsupported keys.

## Top-Level `config.yaml`

Supported top-level keys for `network-collector`:

```yaml
imports:
  - roles/*.yaml
name_playbook: Human readable playbook title
security_mode: production
inventory_file: inventory.yaml
parsers_file: parsers.yaml
fail_on_fail: false
ssh_security:
  profile: modern
  host_key_policy: known_hosts
vars_files:
  - vars/common.yaml
vars:
  environment: production
execution:
  max_parallel: 3
  start_interval_seconds: 120
  canary_count: 1
  failure_threshold: 2
output:
  directory: artifacts
  save_raw: true
  save_parsed: true
  summary_file: results.json
ssh: []
```

Rules:

- `imports` is optional and accepts one path or a list of paths relative to the importing file. Globs are expanded lexically.
- Imports are recursive. Maps merge, lists append, and later/importing scalar values override earlier values.
- Cycles, duplicate files, unmatched globs, and import depth over 20 are errors.
- Keep shared inventory, parser, execution, and output settings in the master; imported role files should normally contain reusable `ssh` workflows.
- `name_playbook` is optional and appears in session logs.
- `inventory_file` is optional; default behavior is to look for `inventory.yaml`.
- `parsers_file` is optional; default behavior is to look for `parsers.yaml`.
- `fail_on_fail` is optional. Use `true` when the process should exit non-zero if any validation fails or errors.
- `security_mode` defaults to `production` when omitted. Production mode rejects legacy/automatic SSH fallback, disabled host-key verification, plaintext gNMI, skipped certificate verification, and per-step gNMI `skip_tls`.
- Use `security_mode: permissive` only for an explicitly approved lab or legacy migration. It restores access to insecure transport switches but emits a startup warning.
- `ssh_security` supports `compatibility`, `auto`, `modern`, and `legacy` profiles plus `insecure`, `known_hosts`, or `pinned` host-key policy. Production mode permits only `modern` with `known_hosts` or `pinned`.
- Omitting `ssh_security` securely defaults to `modern` algorithms and `known_hosts` verification.
- `auto` falls back only for algorithm negotiation errors, never authentication, identity, timeout, or connection failures.
- Device and inventory-host `ssh_security` maps override individual global settings.
- The CLI emits one startup SSH policy summary across the resolved inventory; only actual auto-mode downgrade retries produce per-connection warnings.
- `vars_files` imports variable maps relative to the declaring config; globs and multiple files are supported.
- `vars` defines inline values and overrides imported variable-file values.
- `execution` is optional. Without it, SSH devices run serially as before.
- `execution.max_parallel` limits active device runs; `0` means the serial default of one.
- `execution.start_interval_seconds` sets the minimum delay between device starts.
- `execution.canary_count` requires the first resolved devices to succeed before remaining devices start.
- `execution.failure_threshold` stops new starts after the configured number of observed device failures; `0` disables it.
- `output` is optional. It writes per-run raw, parsed JSON, and summary artifacts separately from session logs.
- `output.directory` defaults to `artifacts` when structured output is enabled.
- `output.save_raw` and `output.save_parsed` control per-step attempt artifacts.
- `output.summary_file` writes a run summary relative to the timestamped run directory unless it is absolute.
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
- `type`: ScrapliGo platform name or custom platform YAML path passed directly to the SSH driver, for example `cisco_iosxe`, `cisco_nxos`, `juniper_junos`, or `./platforms/ericsson_generic.yaml`.
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

## Custom ScrapliGo SSH Platforms

Do not confuse SSH platform definitions with output parsers:

- A ScrapliGo platform YAML recognises prompts, defines privilege levels, disables paging, runs connection open/close operations, and lists command-error strings.
- `parsers.yaml` and TextFSM templates parse the command output returned after SSH prompt handling succeeds.

Use a bundled ScrapliGo platform name when available. Common names include `cisco_iosxe`, `cisco_iosxr`, `cisco_nxos`, `arista_eos`, `juniper_junos`, `nokia_srl`, `nokia_sros`, `huawei_vrp`, and `hp_comware`.

For an unbundled vendor or appliance, generate a custom file and reference it through the inventory `type`:

```yaml
hosts:
  - name: ericsson-router-01
    ip: 192.0.2.40
    type: ./platforms/ericsson_generic.yaml
```

Minimal custom definition:

```yaml
platform-type: ericsson_generic
default:
  driver-type: network
  privilege-levels:
    exec:
      name: exec
      pattern: '(?m)^[A-Za-z0-9_.@:/-]{1,80}[>#]\s?$'
      not-contains: []
      previous-priv: ''
      deescalate: ''
      escalate: ''
      escalate-auth: false
      escalate-prompt: ''
  default-desired-privilege-level: exec
  failed-when-contains:
    - Error
    - Invalid command
    - Unknown command
  network-on-open:
    - operation: acquire-priv
  network-on-close:
    - operation: channel.write
      input: exit
    - operation: channel.return
```

Rules:

- Always use `driver-type: network`; Network Collector calls `GetNetworkDriver`.
- Derive prompt patterns from captured prompts and keep them anchored and narrow enough to avoid matching command output.
- Add vendor-specific paging-disable commands to `network-on-open` when required.
- Relative platform paths resolve from the process working directory, not from `inventory.yaml`. Prefer an absolute path if launch location is not controlled.
- Do not create an output parser merely to fix prompt detection; use a custom ScrapliGo platform definition.
- Do not put output extraction rules in the platform YAML; use `parsers.yaml` or TextFSM.

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
    enrich: {}
    validation: {}
    validations: []
    register: variable_name
    retry: {}
    repeat: {}
    when: {}
    foreach: {}
    use: workflow_name
    with: {}
    block: {}
    approval: {}
    parallel: {}
    output: {}
    on_pass: {}
    on_fail: {}
```

Supported step keys:

- `name`: required in generated playbooks. Use short kebab-case names.
- `message`: optional operator note logged before the step. Supports variables.
- `cmd`: command to send over SSH. Supports variables.
- `parser`: parser module name from `parsers.yaml`.
- `enrich`: optional gojq transformation applied to JSON after parsing and before registration, validation, drift checks, and parsed artifact storage.
- `validation`: one validation rule.
- `validations`: multiple validation rules. All must pass.
- `register`: variable name to store extracted or parsed data.
- `retry`: retry policy for failed validation.
- `wait_seconds`: wait before running the command, or wait-only if no `cmd`.
- `ssh_probe`: close stale SSH, probe TCP, reconnect, then continue.
- `return_to_prompt`: set `false` for commands expected to disconnect or reboot before returning a prompt.
- `output`: optional per-step `save_raw` / `save_parsed` overrides for structured artifacts.
- `repeat`: bounded repeated step group with `count`, `interval_seconds`, optional `stop_on_failure`, and nested `steps`.
- `when`: direct typed comparison against a registered variable; a false result skips the step.
- `foreach`: iterate over literal `items` or a registered JSON array named by `from`.
- `use` / `with`: call a named top-level workflow with scoped parameter values.
- `block`: run `steps` with optional `rescue` and `always` recovery lists.
- `approval`: fail-closed manual operator gate; `--approve-all` authorizes unattended continuation.
- `parallel`: independent branches using separate SSH sessions and isolated variables.
- `on_pass`: conditional action after validation passes.
- `on_fail`: conditional action after validation fails or errors.

Rules:

- Use `validation` for one rule and `validations` for multiple rules.
- If a step has `parser`, validations run against the parsed JSON, not raw CLI text.
- If a step has `enrich`, its input must be valid JSON. A device command
  normally needs a `parser`.
- Enrichment runs after parsing. Registration, validation, drift checks, and parsed artifacts use the enriched result.
- If a step has `parser` and `register`, the parsed JSON is registered as the variable value.
- If a step has `register` and validation results have `raw_extract`, the first non-empty `raw_extract` can be registered.

## JSON Enrichment and gojq Expressions

Use enrichment for user-owned policy and derived data: health summaries, threshold checks, normalization, counts, and evidence lists. Keep device output parsing in parser modules; do not use enrichment as a substitute for parsing unstructured CLI text.

```yaml
- name: summarize-interface-errors
  cmd: show interfaces HundredGigE0/0/0/0
  parser: xr_interface_error_counters
  enrich:
    engine: gojq
    expression_file: enrich/interface-errors.jq
    variables:
      error_threshold: 0
  register: interface_health
  validation:
    extractor: gjson
    json_path: _summary.has_issues
    condition: eq
    expected: false
    expected_type: bool
```

Supported enrichment keys:

- `engine`: optional; omit it or use `gojq`.
- `expression`: inline gojq expression.
- `expression_file`: gojq file resolved relative to the main configuration file.
- `variables`: typed YAML values exposed to the expression as `$params`.
- `timeout_seconds`: optional evaluation timeout; defaults to 2 seconds.
- `max_output_bytes`: optional encoded-result limit; defaults to 1 MiB.

Rules for generated expressions:

- Set exactly one of `expression` and `expression_file`.
- Produce exactly one JSON value. Wrap filtered streams in arrays, for example `[.records[] | select(...)]`.
- Preserve source evidence unless replacement is intentional. Prefer `. as $source | ... | $source + {"_summary": ...}`.
- Use `//` for missing counters, for example `(.crc_errors // 0)`.
- Put adjustable policy values in `variables`; refer to them through `$params`, not hard-coded thresholds.
- Keep `_summary.has_issues`, `_summary.issue_count`, and `_summary.issues` stable when producing health results. Each issue should include a rule, severity, message, and evidence where practical.
- Validate booleans with `expected_type: bool`.
- Enrichment has no environment, filesystem, or jq module access. It is a deterministic transformation of the input JSON and `$params`.
- `facts` steps currently use a separate execution path and do not apply
  `enrich` or validation. Do not generate `facts` plus `enrich` until runtime
  support is added; enrich a command/parser step instead.

A separate general-purpose skill is not required to write expressions. This authoring skill contains the runtime contract and preferred patterns. Consider a dedicated expression library or skill only when maintaining a sizeable catalogue of domain rules, vendor schema mappings, shared fixtures, and golden-output tests.
- Use `wait_seconds` alone for pauses.
- Use `return_to_prompt: false` for reboot/confirmation commands that intentionally lose the prompt.

## Variables

Variable syntax:

```yaml
vars_files:
  - vars/common.yaml
vars:
  change_reference: CHG-2026-0042

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
- Variables may come from top-level `vars`, relative `vars_files`, workflow parameters, loop scopes, or earlier `register` steps.
- Variable file precedence is earlier files, later files, inline `vars`, then runtime registration.
- Variable files contain either a bare map or one `vars:` map. Lists and objects become compact JSON and can feed `foreach.from`.
- `vars_files` in imported configs resolve relative to the config that declares them.
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

## Parser Modules

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

Supported parser types:

- `regex`: independent scalar fields and arrays; backward compatible with existing parsers.
- `regex_records`: one regex match becomes one object in an array.
- `textfsm`: records produced by a user-supplied TextFSM template.

Supported parser module keys:

- `type`: `regex`, `regex_records`, or `textfsm`. Omitted means `regex`.
- `fields`: map of output JSON field names.
- `pattern`: required at module level for `regex_records`.
- `template`: required for `textfsm`; relative paths resolve from `parsers.yaml`.
- `root`: JSON array key for `regex_records` and `textfsm`; defaults to `records`.

Bundled IOS-XR TextFSM modules include `xr_show_platform`, `xr_show_route_summary`, `xr_show_interfaces_brief_textfsm`, `xr_show_ntp_associations`, `xr_show_ntp_status`, `xr_show_running_config_ntp`, and facts modules for system, LLDP, BGP, IS-IS, and LDP.

Use `facts: {}` as a device step for NETCONF-first, SSH-fallback collection. Supported output formats are `openconfig`, `native`, and `both` (default). Facts subsets are `system`, `platform`, `interfaces`, `lldp`, `bgp`, `isis`, and `ldp`. Top-level `facts.default_format`, `facts.default_subsets`, and `facts.default_transports` define playbook defaults; step values override them.

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
- `regex_records` applies its module pattern once and maps each match's capture groups into a record object.
- `textfsm` preserves template value names as JSON keys and supports normal TextFSM state and value options.

Included IOS-XR NTP parser names are `xr_show_ntp_associations`, `xr_show_ntp_status`, and `xr_show_running_config_ntp`.

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

## Direct Conditions

```yaml
- name: platform-only-step
  when:
    variable: platform
    condition: eq
    expected: iosxr
  cmd: show platform
```

- `variable` must name an existing registered variable.
- `condition` defaults to `eq` and accepts `eq`, `neq`, `contains`, `not_contains`, `matches`, `gt`, `gte`, `lt`, or `lte`.
- Use `expected_type: int` for numeric comparisons.
- `expected` supports template variables.
- A false comparison skips the complete step, including its message or control operation. An invalid condition or missing variable fails the step.

## Foreach

```yaml
- name: inspect-vlans
  foreach:
    items: [10, 20, 30]
    item: vlan
    index: vlan_index
    stop_on_failure: true
    steps:
      - cmd: show vlan id {{vlan}}
```

- Define exactly one of `items` or `from`.
- `from` names a registered variable containing a JSON array.
- `item` defaults to `item`; `index` defaults to `index` and is zero-based.
- Item and index variables are scoped to each iteration and restored afterward.
- `stop_on_failure` defaults to `true`; false continues with later items while retaining the run failure.

## Parameterized Workflows

```yaml
workflows:
  inspect-interface:
    parameters: [interface]
    steps:
      - cmd: show interfaces {{interface}}

ssh:
  - host: router-01
    steps:
      - use: inspect-interface
        with:
          interface: GigabitEthernet0/0
```

- Every declared parameter is required and unknown `with` keys are errors.
- String argument values support variables from the caller.
- Parameters are scoped to the call and previous values are restored afterward.
- Workflow maps merge through normal modular imports, so definitions can live in role files.
- Nested workflow/control execution is limited to 20 levels.

## Recovery Blocks

```yaml
- name: guarded-change
  block:
    steps:
      - cmd: configure replace disk0:/candidate.cfg
    rescue:
      - cmd: rollback configuration last 1
    always:
      - cmd: show configuration commit list 1
```

- `rescue` runs only after a failure in `steps`.
- A successful rescue recovers the block failure; a rescue failure keeps the run failed.
- `always` runs after the normal or rescue path and can fail the run.
- Explicit stop actions propagate. Original failures remain in the failure log for auditability.
- Use `rollback` instead of `rescue` for explicit reversion steps. They are mutually exclusive.
- A control step defines only one of `repeat`, `foreach`, `use`, `block`, or `parallel`; put executable fields in nested steps.

## Approval Gates

```yaml
- name: authorize-change
  approval:
    message: Apply the change?
    timeout_seconds: 300
```

- Approval accepts `y` or `yes`; every other answer denies.
- Denial, timeout, EOF, and non-interactive stdin fail closed and stop the device.
- `timeout_seconds: 0` waits indefinitely. `--approve-all` approves and logs every gate.
- Approval is a standalone step.

## Parallel Branches

```yaml
- name: collect-independent-state
  parallel:
    max_parallel: 2
    steps:
      - {name: routes, cmd: show route, register: routes}
      - {name: interfaces, cmd: show interfaces, register: interfaces}
```

- Each branch uses a separate SSH session and isolated variables.
- Results merge in declaration order; conflicting values for one variable fail the run.
- `max_parallel` defaults to the branch count and must be between 1 and 16.
- Branch failure fails the parallel operation; explicit stop actions propagate.

## Bounded Scheduling

```yaml
schedule:
  count: 4
  interval_seconds: 900
```

- Omitted or zero `count` means one occurrence; the maximum is 1000.
- Multiple occurrences require an interval of at least one second.
- Per-device variables persist and artifacts are occurrence-prefixed.
- Use an external scheduler for indefinite or calendar-based operation.

## Bounded Repeat

```yaml
- name: monitor
  repeat:
    count: 10
    interval_seconds: 120
    stop_on_failure: true
    steps:
      - name: collect
        cmd: show command
```

Rules:

- `count` is required, finite, and must be between 1 and 1000.
- `interval_seconds` must be at least 1 when `count` is greater than 1.
- The first iteration starts immediately; waits occur only between iterations.
- `stop_on_failure` defaults to `true`.
- Nesting is limited to three repeat blocks.
- `retry.until_pass` inside a repeat must have a positive `max_attempts`.
- Put executable fields and validations on nested steps, not on the repeat container.

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
- When creating or changing a parser, also create or update an offline parser fixture under `cmd/network-collector/testdata/`.

## Offline Parser Fixture Tests

Use offline fixtures to test parsers and config validations without logging into network devices.

Files:

- `cmd/network-collector/testdata/parser-fixtures.yaml`: fixture manifest.
- `cmd/network-collector/testdata/offline-config.yaml`: config steps used by fixtures.
- `cmd/network-collector/testdata/cli/*.txt`: captured raw CLI outputs.

Manifest format:

```yaml
parsers_file: ../../../parsers.yaml
config_file: offline-config.yaml

cases:
  - name: xr-show-alarms-brief-system-active
    input: cli/xr_show_alarms_brief_system_active.txt
    config_ref:
      ssh_index: 0
      step: parse-active-alarms
```

Before/after change-detection fixture format:

```yaml
cases:
  - name: xr-active-alarms-unchanged
    baseline_input: cli/xr_show_alarms_before.txt
    input: cli/xr_show_alarms_after_unchanged.txt
    baseline_config_ref:
      ssh_index: 0
      step: capture-baseline-alarms
    config_ref:
      ssh_index: 0
      step: compare-final-alarms

  - name: xr-active-alarms-changed
    baseline_input: cli/xr_show_alarms_before.txt
    input: cli/xr_show_alarms_after_changed.txt
    baseline_config_ref:
      ssh_index: 0
      step: capture-baseline-alarms
    config_ref:
      ssh_index: 0
      step: compare-final-alarms
    expect_pass: false
```

Fixture behavior:

- The fixture runner reads the CLI text file.
- It resolves `config_ref` to a step in the fixture config.
- It uses that step's `parser`.
- It parses the CLI output with the parser from `parsers.yaml`.
- It applies that step's `validation` or `validations` to the parsed JSON.
- The test fails if parsing errors or any validation fails.
- If `baseline_input` is set, the fixture runner parses it first and stores it in the variable named by `baseline_register` or the `register` value on `baseline_config_ref`.
- If `expect_pass: false` is set, the fixture passes only when validation fails or errors.

Rules:

- Add one CLI text file per real command output shape.
- Add one fixture case per parser scenario.
- For change detection, add at least two paired fixtures: unchanged output with default pass behavior, and changed output with `expect_pass: false`.
- Prefer `config_ref` so the fixture tests the same parser and validations that a playbook step uses.
- Use direct `parser` plus `validations` in the manifest only for parser-only experiments.
- Run fixtures with `go test ./cmd/network-collector -run TestParserFixtures`.
