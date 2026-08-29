# DKIM2 Conformance Evidence

This repository tests the behavior baseline
`draft-ietf-dkim-dkim2-spec-06` and the DNS baseline
`draft-chuang-dkim2-dns-04`. Results are evidence for one exact Git base and
candidate-snapshot digest; historical reports do not establish the state of a
different checkout.

## Evidence classes

The manifest keeps the source of every claim visible:

- `draft_normative` covers rules stated by the pinned DKIM2 drafts.
- `rfc_normative` covers incorporated RFC 5321, RFC 5322, RFC 6531, RFC 8259,
  and RFC 8601 behavior.
- `documented_interpretation` covers a behavior needed where Draft-06 is
  ambiguous.
- `local_security_policy` covers restrictive implementation policy, including
  replay handling; it is not protocol verification.
- `openapi_contract` covers the generated daemon HTTP boundary.
- `adapter_contract` covers Milter, real Postfix, and source-linked real Exim
  integration behavior.

Draft-06 still marks architecture references, EAI considerations, IANA
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
| Exim | `unqualified_draft06` | Source-linked implementation remains available, but the five-row Linux evidence is Draft-04-only and cannot qualify the Draft-06 candidate; active portable and full reports contain no Exim suite or evidence import |

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

No external DKIM2 corpus is authoritative for this Draft-06 implementation.
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
Draft-06 profile is evidence-free for Exim while the capability is
`unqualified_draft06`:

```text
make conformance-postfix
make conformance-all
```

`make conformance-all` rejects an Exim evidence argument before repository
access while `unqualified_draft06` is active. A full report must also reject an
Exim suite, Exim case, imported evidence, or `qualified_linux` capability.
Fresh evidence becomes admissible only after a separately authorized Draft-06
matrix run and the corresponding reviewed capability-state migration.

Generated `report.json` and `report.md` files are written below ignored
`.artifacts/` directories. The machine report records the manifest digest, Git
base, candidate snapshot, platform/profile, exact producer hashes, ordered
cases, evidence classes, and the explicit release capability. Portable and
full Draft-06 reports contain no Exim case and never open or claim an Exim
evidence path. The historical Draft-04 matrix remains a dated adapter record
only. A future qualified profile must rerun the strict real-matrix verifier and
bind its bounded import summary to the then-current manifest, Git base,
candidate snapshot, verifier digest, authenticated row sources and exact
adapter, daemon, and Exim binaries.

## Draft-06 compatibility boundaries

Draft-06 deliberately tightens duplicate Message-Instance hash names,
non-lowercase decoded Recipe header keys, selector uniqueness, and the limit of
two occurrences per signing algorithm. The four corresponding protocol
infractions are distinct PERMERROR reasons:
`duplicate_hash_algorithm`, `invalid_recipe_json`, `duplicate_selector`, and
`too_many_signatures`. They are verification results, not HTTP JSON-decode
errors, and do not become SMTP 4xx outcomes.

The verifier now accepts SHA-512-only and agreeing dual-hash
Message-Instances, a second same-algorithm signature with a distinct selector,
and a matching non-origin unchanged Message-Instance without a Recipe. Every
supported advertised hash and signature must agree. Public `signature_sets`
rows remain positional and retain wire occurrence order even when algorithms
repeat. The deterministic signer continues to emit SHA-256 Message-Instance
hashes as an explicit local MAY policy and can revise a valid SHA-512-only
history.

The Draft-06 unsigned-header set changes canonical bytes in both directions:
the eight added exact names and `Received-*` are excluded, while only the three
named ARC fields are excluded and an unknown `ARC-*` field is signed. The
manifest contains one executable incompatibility case in each direction.
Replay identity is a separate drain-only epoch rotation; see
[`replay-store-valkey.md`](replay-store-valkey.md) for the no-mixed-version
procedure and retention-bounded detection gap.

The separate repository security profile consumes these reports without
reclassifying their claims. See `docs/security-testing.md` and run
`make check-security`, `make fuzz-security`, or `make security` as appropriate.
