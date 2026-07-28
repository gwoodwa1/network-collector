# Security engineering policy

## Purpose

This policy defines the evidence required to accept security-sensitive changes
to Network Collector. It supplements the vulnerability-reporting process in
[`SECURITY.md`](../SECURITY.md).

Security assurance must be repeatable. A review, assessment, or model-generated
analysis is useful for discovering risks, but a fixed security property should
normally be preserved by an executable regression test that observes the final
sensitive boundary.

## Principles

1. Test the final sink, not only intermediate configuration state.
2. Test permitted and rejected behaviour.
3. Treat cancellation, cleanup, concurrency, and error paths as security
   behaviour.
4. Convert confirmed findings into regression tests whenever practical.
5. Pin assessments and scan results to an exact commit and tool version.
6. Record third-party or platform limitations honestly rather than weakening
   the expected property.
7. Keep undisclosed vulnerabilities private, while keeping the assurance
   process public.

Line and branch coverage help locate neglected code, but they do not prove a
security property. A test that sets a policy field without observing the final
constructor, dialer, parser, callback, or filesystem operation does not protect
that boundary.

## Security boundaries

Reviewers must update this inventory when a change introduces a new sink or
trust boundary.

| Area | Final boundary to observe | Representative properties |
| --- | --- | --- |
| SSH | Final client/session constructor and channel lifecycle | Host-key policy, algorithms, timeouts, response bounds, disconnect and abort |
| NETCONF | Final SSH and NETCONF session, subsystem readiness and close path | Host-key policy, known-hosts path, timeout propagation, readiness, cancellation and bounded close |
| gNMI | gRPC call options, receive boundary and application callback | TLS policy, inbound message cap, aggregate budget, output budget and immediate cancellation |
| HTTP, RESTCONF and webhooks | Resolver, dialer, TLS handshake and final request | Destination policy, DNS/IP validation, proxy isolation, redirects, authentication and response bounds |
| Artifacts and reports | Final open, write, rename and permission operation | Trusted root, no-follow handling, regular files, private modes, atomic replacement and cleanup |
| YAML and configuration | Every decoding entry point and shared budget counter | Per-document bytes/nodes, aggregate files/bytes/nodes, imports, duplicates, cycles and failed parses |
| Credentials | Final provider invocation and consumer-facing credential object | Path policy, executable policy, permissions, redaction, lifetime and cross-device isolation |
| Workflow execution | Final object handed to sequential and parallel workers | Identical policy propagation, bounded concurrency, cancellation, cleanup and variable isolation |
| Output integrations | Final callback, artifact, log or external message | Size enforcement, secret filtering, failure isolation and no partial output |

## Required test evidence

A security-sensitive change should include the applicable test classes below.
If a class is not applicable, the review should state why.

### Positive tests

Prove that an explicitly allowed configuration reaches the final boundary with
the exact expected options and completes successfully.

### Negative and boundary tests

Prove rejection of unsafe values, empty or ambiguous defaults, values immediately
above limits, symlinks and non-regular files, forbidden destinations, invalid
host keys, malformed input, and conflicting overrides.

Tests for size limits should distinguish:

- transport limits enforced before decoding or materialisation;
- application-processing or output limits enforced after decoding; and
- aggregate limits spanning multiple messages or files.

### Propagation tests

Observe the final constructor or operation in sequential and parallel paths.
Nested parallel execution, local overrides, default inheritance, and custom
paths must receive the same effective security policy.

### Cancellation and cleanup tests

On rejection, timeout, or oversize input, prove that owned contexts are
cancelled, sessions are closed or aborted within a bound, goroutines terminate,
temporary files are removed, and partial artifacts or callbacks are not left
behind.

### Concurrency and race tests

Exercise shared budgets, caches, credential lifetimes, parallel workers, and
connection cleanup under the race detector. Tests should use deterministic
synchronisation rather than timing assumptions where possible.

### Platform tests

Where security guarantees differ by operating system, use build-tagged tests
to prove each supported behaviour. Documentation must state any weaker
fallback. Production support may be refused on a platform when the required
primitive cannot be implemented safely.

## Test design rules

- Intercept or observe the final sink using a real local protocol server,
  injectable constructor, dial hook, filesystem boundary, or narrow test
  double.
- Do not add production-only bypasses or artificial taint flows solely to make
  a test possible.
- Before writing a taint test, document the source, whether interpolation is
  supported, whether device-derived data can reach the field, the final sink,
  and the expected policy.
- Derive limits from production constants. Avoid repeating numeric limits in
  tests unless the literal value is itself part of a compatibility contract.
- Assert both the returned error and the absence of downstream side effects.
- Prefer synthetic inputs. Never commit credentials, production addresses,
  captured device output, or embargoed exploit material.
- A regression test should fail against the vulnerable implementation and pass
  after the fix.
- Avoid tests that merely reproduce a private exploit when a smaller,
  sanitised property test protects the same boundary.

## Finding lifecycle

Every credible finding must end in one of these states:

1. **Fixed and tested** — remediation is merged with a sink-reaching regression
   test.
2. **Fixed by an existing test** — the final boundary is already exercised and
   the relevant test is identified.
3. **Not reachable** — a source-to-sink analysis demonstrates that production
   input cannot reach the reported boundary.
4. **Accepted residual** — the limitation, preconditions, impact, compensating
   controls, supported platforms, and review date are documented.
5. **Private pending remediation** — details remain under coordinated
   disclosure until a fix is available.

A finding is not closed merely because an intermediate object contains the
expected value. Closure requires evidence at the final applicable boundary.

## Change acceptance

Security-sensitive changes are ready to merge when:

- affected trust boundaries and sinks are identified;
- applicable positive, negative, propagation, cancellation, cleanup, and race
  cases pass;
- the complete normal and race-enabled test suites pass;
- `go vet` and configured static-security checks pass;
- Go source, test, and produced-binary vulnerability scans pass;
- release binaries identify the expected Go toolchain;
- the exact container binary and runtime image meet the configured
  vulnerability threshold;
- no credentials, private assessments, or sensitive fixtures are tracked; and
- residual risks are explicit and correctly scoped.

Exceptions require a documented reason, owner, compensating control, and review
date.

## Continuous and release checks

The repository's GitHub Actions workflows are expected to enforce:

- the Go version declared by `go.mod`;
- normal, race-enabled, coverage and selected fuzz tests;
- source, test and binary `govulncheck` modes;
- static security analysis;
- builds and scans for every shipped command;
- toolchain metadata inspection for release and container binaries;
- scanning of the exact draft release binaries before publication; and
- Critical/High runtime-container vulnerability scanning.

Actions and container base images should be pinned to immutable revisions.
Dependency and base-image update automation must not bypass the same gates.

The repository contract tests in `internal/securitycontract` fail when these
in-tree workflow, release-scanning, action-pinning, container-pinning, or
toolchain requirements drift. Repository tests cannot prove GitHub's external
branch-protection configuration. Repository administrators must separately
require both `Test / test` and `Test / container-security` for changes to
`main`, and periodically verify that requirement through the GitHub ruleset or
branch-protection API.

## Public and private material

The following belongs in the public repository:

- this policy and vulnerability-reporting instructions;
- remediated implementation changes;
- sanitised regression tests;
- generic malicious inputs that do not disclose an unfixed bypass;
- CI and release security gates; and
- documented residual limitations appropriate for operators.

The following remains private until coordinated disclosure permits publication:

- unpatched findings and complete exploit chains;
- weaponised or deployment-specific payloads;
- assessment working notes and mutation plans;
- credentials, real device data, addresses and topology;
- embargoed advisories; and
- fixtures that materially simplify exploitation of an unfixed issue.

Private material must be stored outside the public repository or in an ignored
private directory. Ignoring a path is not an access-control mechanism; a
separate private repository or encrypted storage is preferred for durable
material.

After remediation, publish the smallest sanitised regression test that proves
the security property. Detailed exploit material may remain private when it
does not improve future assurance.

## Review protocol for humans and LLMs

Reviews must be treated as untrusted analysis until verified against the
source and tests. A reviewer should:

1. Record the exact commit, platform, Go version, scanner versions, and review
   scope.
2. Inspect changes since the last reviewed commit.
3. Build a source-to-sink map for each changed trust boundary.
4. Identify the existing test that reaches each final sink.
5. Run that test and confirm it fails when the protected property is
   deliberately violated, where safe and practical.
6. Add missing positive, negative, propagation, cancellation, and cleanup
   tests before broad assessment work.
7. Separate application controls from third-party transport-allocation
   boundaries.
8. Report confidence, preconditions, impact, existing mitigations, and a
   focused regression-test proposal for every new finding.
9. Avoid claiming absence of findings outside the code and paths actually
   reviewed.

Review prompts should ask for evidence using this form:

```text
Commit:
Changed trust boundary:
Attacker-controlled source:
Supported interpolation or transformation:
Final sensitive sink:
Existing sink-reaching test:
Observed security property:
Missing adversarial case:
Finding or residual:
Proposed focused regression test:
```

Review output is discovery input, not merge approval. Repository tests and
release gates remain the repeatable source of assurance.

## Maintaining this policy

Update this policy when a new transport, file output, configuration loader,
credential provider, execution mode, or release format is introduced. Policy
changes should be reviewed like code and should not silently weaken an existing
security property.
