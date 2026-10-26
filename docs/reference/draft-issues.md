# DKIM2 Draft Issue Log

This log binds the first preview to
`draft-ietf-dkim-dkim2-spec-07` and
`draft-ietf-dkim-dkim2-dns-01`. The strict machine source is
`testdata/reference/draft-issues.json`; stable issue IDs are never reused.
Local implementation status and upstream draft status are intentionally
separate. No entry records an upstream filing or resolution unless that event
is independently observed.

## Open upstream text

- `DKIM2-ISSUE-0001` and `DKIM2-ISSUE-0004` cover the Draft-07 `TBA` areas:
  architecture references and IANA. No protocol behavior is invented for
  these areas.
- `DKIM2-ISSUE-0002` and `DKIM2-ISSUE-0005` covered the Draft-06 `TBA`
  areas for full-chain policy guidance and Security Considerations. Both are
  superseded by the Draft-07 baseline: Section 13 assigns acceptance of a
  Validly Signed message to local policy, which the policy engine owns, and
  Section 20 publishes the security considerations (unsigned header fields,
  resource limits, null Recipes, RSA key size), which the bounded recipe and
  verifier limits already enforce.
- `DKIM2-ISSUE-0003` records the Draft-07 Section 18 U-label to A-label
  mapping and the known IDNA2008 category gap of the strict profile.
- `DKIM2-ISSUE-0006` records that uppercase header tag names are rejected
  under Draft-07 Sections 9 and 10 instead of being ignored under the lenient
  reading of Section 8. Earlier external observations predate this rule and
  require re-qualification.
- `DKIM2-ISSUE-0007` through `DKIM2-ISSUE-0010` own the byte model, recipe,
  policy-projection, and restricted-release interpretations exercised by the
  conformance manifest.
- `DKIM2-ISSUE-0011` and `DKIM2-ISSUE-0012` preserve the DNS ABNF and
  query-method discrepancies without silently rewriting either pinned draft.
- `DKIM2-ISSUE-0014` is superseded by the baseline: Draft-07 Section 14.5
  makes more than one key record an error, which matches the existing
  fail-closed `ambiguous_key` PERMERROR.
- `DKIM2-ISSUE-0013` (DNS strict-identity flag versus the numeric signature
  `i=` tag) is superseded by the baseline: DNS-01 Section 3.4.1 retires the
  key-record `t=` tag, which verifiers SHOULD ignore. The `t=` tag is now
  subject only to the generic tag-list rules and never yields testing or
  strict-identity semantics. The explicitly configured local policy testing
  mode is unrelated and unchanged.

## Adapter and preview limitations

- `DKIM2-ISSUE-0015` keeps Milter/SMTP fidelity in the adapter claim class.
- `DKIM2-ISSUE-0016` records that Exim is `unqualified_draft07`. Draft-04
  qualification evidence is historical only and the current control plane
  rejects every evidence import until a fresh Draft-07 five-row qualification
  is independently produced.
- `DKIM2-ISSUE-0017` owns the bounded recipe-less unchanged-history
  interpretation: every supported tuple is compared, a mismatch fails, and an
  unknown-only predecessor is unsupported rather than silently accepted.

- `DKIM2-ISSUE-0018` records the existing explicit trusted-route null-sender
  originator policy. `header_from` binds signing to the single canonical From
  mailbox domain while retaining `mf=<>`; the default remains rejection.
  Delivery-status reports, ambiguous MIME and existing DKIM2 protocol history
  stay off this route. DSNs retain their dedicated Section 16 path. This is
  an implemented local interpretation, not a draft requirement to enable it.
  The two public-facade conformance cases are bound to this entry; their
  earlier omission from this register was a documentation defect.

- `DKIM2-ISSUE-0019` records a deliberate deviation: Draft-07 Section 3.4
  names the post-quantum `mldsa44-ed25519-sha512` algorithm without spelling
  out its message representative, DNS-01 Section 3.3 cites the LAMPS composite
  construction for the matching key type, and the DKIM working group has not
  settled the DKIM2 post-quantum construction (the October 2026 list
  discussion weighs separate multiple signatures, the LAMPS composite, and
  plain ML-DSA-44; it is to be revisited at IETF 127). The implementation does
  not ship a construction that may not be standardized: the algorithm and the
  `k=mldsa44-ed25519-sha512` key type are not implemented and are handled
  exactly like any other unknown algorithm or key type, and signing
  credentials that declare it fail closed. The baseline stays
  `draft-ietf-dkim-dkim2-spec-07` plus `draft-ietf-dkim-dkim2-dns-01`.

The repository has not filed, commented on, or modified any upstream issue as
part of this release-candidate work.

## Stable ID index

`DKIM2-ISSUE-0001`, `DKIM2-ISSUE-0002`, `DKIM2-ISSUE-0003`,
`DKIM2-ISSUE-0004`, `DKIM2-ISSUE-0005`, `DKIM2-ISSUE-0006`,
`DKIM2-ISSUE-0007`, `DKIM2-ISSUE-0008`, `DKIM2-ISSUE-0009`,
`DKIM2-ISSUE-0010`, `DKIM2-ISSUE-0011`, `DKIM2-ISSUE-0012`,
`DKIM2-ISSUE-0013`, `DKIM2-ISSUE-0014`, `DKIM2-ISSUE-0015`,
`DKIM2-ISSUE-0016`, `DKIM2-ISSUE-0017`, `DKIM2-ISSUE-0018`, and
`DKIM2-ISSUE-0019`.
