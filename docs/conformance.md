# DKIM2 Conformance Evidence

This repository tests the behavior baseline
`draft-ietf-dkim-dkim2-spec-04` and the DNS baseline
`draft-chuang-dkim2-dns-04`. Results are evidence for one exact Git base and
candidate-snapshot digest; historical reports do not establish the state of a
different checkout.

## Evidence classes

The manifest keeps the source of every claim visible:

- `draft_normative` covers rules stated by the pinned DKIM2 drafts.
- `rfc_normative` covers incorporated RFC 5321, RFC 5322, RFC 6531, RFC 8259,
  and RFC 8601 behavior.
- `documented_interpretation` covers a behavior needed where Draft-04 is
  ambiguous.
- `local_security_policy` covers restrictive implementation policy, including
  replay handling; it is not protocol verification.
- `openapi_contract` covers the generated daemon HTTP boundary.
- `adapter_contract` covers Milter, real Postfix, and source-linked real Exim
  integration behavior.

Draft-04 still marks architecture references, EAI considerations, IANA
considerations, and security considerations as `TBA`. The implementation does
not turn those sections into protocol claims. In particular, signing remains
ASCII-envelope-only, while inbound SMTPUTF8 handling is bounded by the
documented RFC 6531 interpretation.

## Capability status

| Surface | Status | Evidence boundary |
| --- | --- | --- |
| Library verification, origin signing, and authorized revision | supported | Draft-versioned public, negative, recipe, DNS, custody, and cryptographic vectors |
| `dkim2d` process, sign, and revise operations | supported | Generated OpenAPI clients and real daemon sockets |
| Milter inbound, originator, ordinary-transit, and Postfix DSN modes | partial | Public Milter-v6 socket fixtures; Postfix DSN covers the exact `internal` origin enum and dedicated daemon capability, but still requires the upstream Postfix patch and qualification harness |
| Postfix SMTP and local `sendmail(1)` intake | partial | Linux Docker profile with Postfix 3.11.6 and exact immutable image identities |
| Replay detection | supported local policy | Memory and Valkey evidence; replay outcome is deliberately separate from DKIM2 cryptographic verification |
| LDAP and PostgreSQL signing datasources | supported local policy | Exact schema/DDL, shared provider parity, verified-TLS loaders, immutable generation and protected-registry tests |
| Offline OpenDKIM migration | supported administrative policy | Bounded inventory, protected key import, fresh DNS proof, fenced publication, and higher-generation rollback tests |
| Exim | qualified on Linux | Source-linked module and strict imported five-row matrix: upstream 4.99.5, Debian 4.98.2 security revisions, and Ubuntu 4.99.1 updates/security revisions; 43 cases passed per row |

Exim rewrites the timestamp in its first generated `Received` field after
`local_scan()` returns. Exim fidelity evidence therefore requires that field
on both sides, excludes exactly that first field from the stable comparison,
and proves the remaining headers, header boundary, and body byte-for-byte.
Later `Received` fields are not removed. This matches DKIM2 canonicalization,
which excludes `Received`, while preserving the pre-acceptance Exim-observed
message sent to the daemon.

Postfix prepends its own `Received` field outside the bytes visible to Milters.
The final queued message therefore contains that field while the daemon input
does not. For `non_smtpd_milters`, Postfix simulates SMTP callbacks and emits
unbracketed envelope mailbox fields. The adapter validates and frames those
mailboxes as RFC 5321 paths without otherwise changing mailbox bytes. These
facts are adapter limitations, not original-wire fidelity claims.

The real profile fixes Milter connect, command, and content timeouts instead of
depending on mutable Postfix defaults. When the originator Milter is
unavailable, SMTP intake must receive code 451 without a queue mutation.
Local `sendmail(1)` intake is asynchronous: successful handoff to `postdrop(1)`
is followed by a bounded assertion that exactly one unsigned message remains
held in the `maildrop` queue because cleanup cannot reach the Milter.

No external DKIM2 corpus is authoritative for this Draft-04 implementation.
The positive values in this repository come from reviewed draft examples,
independent derivations, generated contract fixtures, and local synthetic
oracles as recorded in the manifest.

## Reproducing the reports

The portable profile requires Go 1.26 and `valkey-server` 9.1.0:

```text
make check-conformance
make conformance
```

The real Postfix profile additionally requires Docker with Compose. The full
profile also requires the absolute preserved Exim evidence root:

```text
make conformance-postfix
make conformance-all EXIM_EVIDENCE_ROOT=/absolute/path/to/exim-evidence
```

`make conformance-all` fails before report production when
`EXIM_EVIDENCE_ROOT` is empty. The Make target passes that absolute directory
to the conformance command as
`-exim-evidence /absolute/path/to/exim-evidence`; no implicit discovery or
portable-profile fallback is permitted.

Generated `report.json` and `report.md` files are written below ignored
`.artifacts/` directories. The machine report records the manifest digest, Git
base, candidate snapshot, platform/profile, exact producer hashes, ordered
cases, evidence classes, and the explicit release capability. Portable reports
record the Linux-only Exim case as `not_applicable` and never open or claim an
Exim evidence path. Full reports rerun the strict real-matrix verifier and
admit only a bounded import summary bound to the current manifest, Git base,
candidate snapshot, and verifier digest. Missing or stale evidence fails the
full profile closed. Source-matched matrix execution additionally verifies
each bounded build-input record against that base and snapshot, the
authenticated row source and patch digests, and the exact adapter, daemon, and
Exim binaries before any case runs.

The separate repository security profile consumes these reports without
reclassifying their claims. See `docs/security-testing.md` and run
`make check-security`, `make fuzz-security`, or `make security` as appropriate.
