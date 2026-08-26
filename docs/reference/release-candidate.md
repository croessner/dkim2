# Preview Release Candidate

The prepared product candidate is exactly `v0.1.0-rc.1`. It is a local,
non-publishing candidate for the pinned Draft-05 and historical DNS-04
behavior. It is not a stable release and it does not make either draft final.
The Exim implementation is `unqualified_draft05`; the completed five-row,
43-case-per-row source-linked matrix remains historical Draft-04 evidence. The
database-provider work is implemented.

This document and `testdata/reference/release-plan.json` are retained as the
pre-publication snapshot for that preview candidate. The stable `v0.1.0`
GitHub release was separately created on 2026-08-11 under maintainer authority;
that later release does not rewrite this snapshot's deliberately false
publication-authority fields. Stable publication now requires the independent
`make release-guardrails` gate documented in the container supply-chain guide.

The future six-tag plan for one exact maintainer-approved commit is:

```text
v0.1.0-rc.1
lib/v0.1.0-rc.1
cmd/dkim2d/v0.1.0-rc.1
cmd/dkim2-milter/v0.1.0-rc.1
cmd/dkim2-exim/v0.1.0-rc.1
cmd/dkim2ctl/v0.1.0-rc.1
```

No tag is created by candidate preparation. RC paths do not create stable,
minor, major, or `latest` aliases and cannot enter the protected stable
container publication workflow. Public tags, releases, module versions,
registry objects, OIDC credentials, and trusted attestations require separate
maintainer authority.

The release plan is owned by
[`testdata/reference/release-plan.json`](../../testdata/reference/release-plan.json).
`make check-reference` validates the plan and module metadata.
`make reference-report` creates ignored candidate-bound machine and human
reports. `make release-candidate` is a local, non-publishing aggregate.

The prepared scope includes the standalone protocol library, daemon, Postfix
Milter adapter, generated-client test tool, conformance and security evidence,
and local multi-architecture packaging evidence. External implementation
agreement is observation only. Current comparison availability and open draft
issues are stated in the generated report and
[`draft-issues.md`](draft-issues.md).

Exim is exactly `unqualified_draft05` in the unpublished candidate report.
Portable and full Draft-05 conformance contain no Exim case and reject imported
evidence until a fresh separately authorized five-row run is bound to unchanged
Draft-05 candidate bytes.
LDAP, PostgreSQL, MySQL, and MariaDB providers plus the offline legacy migration are implemented.

The native-domain onboarding implementation is a later local closeout
candidate. It enters no RC scope, tag, image, or compatibility window until its
unchanged-snapshot gates, fresh independent review, and explicit maintainer
approval are complete. Its presence in a worktree is not release authorization.
