# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.0.x | Yes |
| Earlier than 2.0.0 | No |

Releases earlier than v2.0.0 are retired and must not be used or deployed.
They may contain known security weaknesses and do not receive security fixes.
Upgrade to the latest v2.0.x release before deployment.

Security fixes are applied to the latest v2.0.x release and the current `main`
branch.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/gwoodwa1/network-collector/security/advisories/new).
Include the affected version or commit, configuration assumptions, impact, and
the smallest reproducible example you can safely provide.

Do not open a public issue containing exploit details, credentials, device
addresses, captured network output, or other sensitive deployment data. If
private vulnerability reporting is unavailable, open a public issue containing
only a request for a private security contact.

You should receive an acknowledgement within three working days. The
maintainer will validate the report, agree on an embargo and disclosure
timeline when appropriate, prepare a fix and regression test, and credit the
reporter unless anonymity is requested. Please allow coordinated remediation
before publishing technical details.

## Security scope

High-value reports include authentication or host-identity bypass, credential
exposure, unsafe transport downgrade, workbook-to-host code execution,
cross-device or cross-run secret leakage, webhook destination-policy bypass,
artifact permission bypass, and ways to evade configured execution bounds.

The following are normally deployment risks rather than product
vulnerabilities unless a documented control can be bypassed:

- intentionally selecting `security_mode: permissive`;
- granting the collector broader device privileges than required;
- trusting a malicious workbook, parser, inventory, certificate authority, or
  known-hosts file;
- compromise of the host running the collector; and
- a device returning false but schema-valid operational data.

Never include live credentials or production device data in a report. Replace
them with synthetic values.
