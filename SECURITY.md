# Security Policy

## Supported Versions

DKIM2 follows active Internet-Drafts and publishes experimental `v0.x`
releases. Security fixes are made against the latest release and the canonical
development branch. Older `v0.x` releases may require an upgrade rather than a
backport.

## Reporting A Vulnerability

Report suspected vulnerabilities privately through the canonical repository's
[private vulnerability reporting form](https://github.com/croessner/dkim2/security/advisories/new).
Do not open a public issue for an undisclosed vulnerability and do not include
credentials, private keys, message contents, recipient data, or production
configuration in a report.

Include the affected version or commit, the relevant component, reproduction
conditions, impact, and any suggested mitigation that can be shared safely.
The maintainer will acknowledge the report, validate it against the applicable
DKIM2 draft baseline, and coordinate disclosure and release handling.

The public `github.com/go-dkim2/dkim2` repository is a read-only source mirror.
Security reports and advisories are owned exclusively by
`github.com/croessner/dkim2`.
