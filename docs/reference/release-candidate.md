# Preview Release Candidate

The prepared product candidate is exactly `v0.1.0-rc.1`. It is a local,
non-publishing candidate for the pinned Draft-04 and historical DNS-04
behavior. It is not a stable release and it does not make either draft final.
The Exim implementation is `qualified_linux` through the completed five-row,
43-case-per-row source-linked matrix; the database-provider work is implemented.

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

Exim is exactly `qualified_linux` in the unpublished candidate report. Portable
conformance remains truthful by recording the Linux-only case as not
applicable; the full report requires the separately verified evidence import.
LDAP, PostgreSQL, MySQL, and MariaDB providers plus the offline legacy migration are implemented.
