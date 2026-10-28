# DKIM2 Conformance Evidence

This repository tests the behavior baseline
`draft-ietf-dkim-dkim2-spec-08` and the DNS baseline
`draft-ietf-dkim-dkim2-dns-02`; the migration from Draft-07 and DNS-01 is in
progress (`docs/specs/draft-08-migration-disposition.md`), and until its work
packages are complete the tested protocol behavior is the Draft-07 behavior.
Results are evidence for one exact Git base and candidate-snapshot digest;
historical reports do not establish the state of a different checkout.

## Evidence classes

The manifest keeps the source of every claim visible:

- `draft_normative` covers rules stated by the pinned DKIM2 drafts.
- `rfc_normative` covers incorporated RFC 5321, RFC 5322, RFC 6531, RFC 8259,
  and RFC 8601 behavior.
- `documented_interpretation` covers a behavior needed where Draft-08 is
  ambiguous.
- `local_security_policy` covers restrictive implementation policy, including
  replay handling; it is not protocol verification.
- `openapi_contract` covers the generated daemon HTTP boundary.
- `adapter_contract` covers Milter, delivery-status propagation, real
  Postfix, and source-linked real Exim integration behavior.

Draft-08 still marks architecture references and IANA considerations as
`TBA`. The implementation does not turn those sections into protocol claims.
The library maps SMTPUTF8 envelope domains to A-labels as Draft-08 Section 18
requires, and the Milter and Exim adapters sign SMTPUTF8 envelopes through it;
a real-MTA SMTPUTF8 signing run is qualified separately.

## Capability status

| Surface | Status | Evidence boundary |
| --- | --- | --- |
| Library verification, origin signing, and authorized revision | supported | Draft-versioned public, negative, recipe, DNS, custody, and cryptographic vectors |
| `dkim2d` process, sign, and revise operations | supported | Generated OpenAPI clients and real daemon sockets |
| Milter inbound, originator, ordinary-transit, and Postfix DSN modes | partial | Public Milter-v6 socket fixtures; Postfix DSN covers the upstream `bounce` origin with EOH confirmation and dedicated daemon capability; real-Postfix qualification of the exact upstream implementation or approved backport remains required |
| Received delivery-status evaluation and Draft-08 Section 16.3 propagation | supported | Byte-exact received-DSN and propagation golden vectors, daemon route and two-phase replay tests, and the adapter fail-closed matrix; the opt-in real-Postfix profile qualifies the deployment path without any MTA patch |
| Postfix SMTP and local `sendmail(1)` intake | partial | Linux Docker profile with Postfix 3.11.7 and exact immutable image identities |
| Replay detection | supported local policy | Memory and Valkey evidence; replay outcome is deliberately separate from DKIM2 cryptographic verification |
| LDAP and PostgreSQL signing datasources | supported local policy | Exact schema/DDL, shared provider parity, verified-TLS loaders, immutable generation and protected-registry tests |
| Offline OpenDKIM migration | supported administrative policy | Bounded inventory, protected key import, fresh DNS proof, fenced publication, and higher-generation rollback tests |
| Exim | `unqualified_draft08` | Source-linked implementation remains available, but the five-row Linux evidence is Draft-04-only and cannot qualify the Draft-08 candidate; active portable and full reports contain no Exim suite or evidence import |

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

The real Postfix profile also qualifies delivery-status propagation without
any Postfix patch. It routes a reserved local return-path address class to
the propagation adapter's LMTP socket with one recipient per transaction, and
re-injects the rebuilt notification through a dedicated loopback listener that
carries no Milters and no content filter. It gives the previous hop and the
downstream destination their own tenant, so neither domain can be local for
the propagation tenant, and it sets the LMTP transport's minimum retry
interval above the daemon's reservation window so a deferred retry can never
land inside a live lease. Its lanes exercise the propagation route's
fail-closed matrix, and the portable adapter, daemon, and library suites carry
the exhaustive negative coverage for spoofed notifications, notifications for
messages this system did not sign, a foreign signature naming a local address,
a null previous sender, replay, and re-injection outages.

The real profile fixes Milter connect, command, and content timeouts instead of
depending on mutable Postfix defaults. When the originator Milter is
unavailable, SMTP intake must receive code 451 without a queue mutation.
Local `sendmail(1)` intake is asynchronous: successful handoff to `postdrop(1)`
is followed by a bounded assertion that exactly one unsigned message remains
held in the `maildrop` queue because cleanup cannot reach the Milter.

The manifest binds two byte-exact Draft-08 vector families for this path:
`received-dsn-golden.json` for Section 16.4 evaluation and
`dsn-propagation-golden.json` for the Section 16.3 rebuild, report
generation, and propagation signing, both under
`lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-08/`. Their cases are
`verification/received-dsn-evaluation` and `signing/dsn-propagation-rebuild`.

No external DKIM2 corpus is authoritative for this Draft-08 implementation.
The positive values in this repository come from reviewed draft examples,
independent derivations, generated contract fixtures, and local synthetic
oracles as recorded in the manifest.

## Reproducing the reports

The portable profile requires exact Go 1.27.3 with `GOEXPERIMENT=runtimesecret` and `valkey-server` 9.1.2:

```text
make check-conformance
make conformance
```

The real Postfix profile additionally requires Docker with Compose. The full
Draft-08 profile is evidence-free for Exim while the capability is
`unqualified_draft08`:

```text
make conformance-postfix
make conformance-all
```

`make conformance-all` rejects an Exim evidence argument before repository
access while `unqualified_draft08` is active. A full report must also reject an
Exim suite, Exim case, imported evidence, or `qualified_linux` capability.
Fresh evidence becomes admissible only after a separately authorized Draft-08
matrix run and the corresponding reviewed capability-state migration.

Generated `report.json` and `report.md` files are written below ignored
`.artifacts/` directories. The machine report records the manifest digest, Git
base, candidate snapshot, platform/profile, exact producer hashes, ordered
cases, evidence classes, and the explicit release capability. Portable and
full Draft-08 reports contain no Exim case and never open or claim an Exim
evidence path. The historical Draft-04 matrix remains a dated adapter record
only. A future qualified profile must rerun the strict real-matrix verifier and
bind its bounded import summary to the then-current manifest, Git base,
candidate snapshot, verifier digest, authenticated row sources and exact
adapter, daemon, and Exim binaries.

## Draft-08 compatibility boundaries

Draft-08 deliberately tightens duplicate Message-Instance hash names (across
every `h=` group), non-lowercase decoded Recipe header keys, and selector
uniqueness (across every `s=` group). The three corresponding protocol
infractions are distinct PERMERROR reasons:
`duplicate_hash_algorithm`, `invalid_recipe_json`, and `duplicate_selector`.
They are verification results, not HTTP JSON-decode errors, and do not become
SMTP 4xx outcomes. Draft-08 Section 10.9 removed the Draft-07 limit of two
occurrences per signing algorithm and with it the `too_many_signatures`
reason; only the local `max_signature_sets` and `max_hash_sets` bounds of 16,
counted across all groups, remain (`limit_exceeded`).

The verifier now accepts SHA-512-only and agreeing dual-hash
Message-Instances, a second same-algorithm signature with a distinct selector,
and a matching non-origin unchanged Message-Instance without a Recipe. Every
supported advertised hash and signature must agree. Public `signature_sets`
rows remain positional and retain wire occurrence order even when algorithms
repeat. The deterministic signer continues to emit SHA-256 Message-Instance
hashes as an explicit local MAY policy and can revise a valid SHA-512-only
history.

The Draft-08 unsigned-header set changes canonical bytes in both directions:
the eight added exact names and `Received-*` are excluded, while only the three
named ARC fields are excluded and an unknown `ARC-*` field is signed. The
manifest contains one executable incompatibility case in each direction.
Replay identity is draft-bound inside the replay HMAC frame, so a draft
upgrade runs in place with the same epoch and secret; see
[`replay-store-valkey.md`](replay-store-valkey.md) for the key separation
evidence and the retention-bounded loss of replay continuity.

The separate repository security profile consumes these reports without
reclassifying their claims. See `docs/security-testing.md` and run
`make check-security`, `make fuzz-security`, or `make security` as appropriate.
