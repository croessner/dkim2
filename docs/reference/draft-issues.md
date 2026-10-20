# DKIM2 Draft Issue Log

This log binds the first preview to
`draft-ietf-dkim-dkim2-spec-07` and
`draft-ietf-dkim-dkim2-dns-01`. The strict machine source is
`testdata/reference/draft-issues.json`; stable issue IDs are never reused.
Local implementation status and upstream draft status are intentionally
separate. No entry records an upstream filing or resolution unless that event
is independently observed.

## Open upstream text

- `DKIM2-ISSUE-0001`, `DKIM2-ISSUE-0002`, `DKIM2-ISSUE-0004`, and
  `DKIM2-ISSUE-0005` cover the Draft-06 `TBA` areas: architecture references,
  full-chain policy guidance, IANA, and Security Considerations. Draft-07
  keeps `TBA` only for architecture references and IANA; the remaining two
  entries are re-evaluated with the Draft-07 qualification. No protocol
  behavior is invented for these areas.
- `DKIM2-ISSUE-0003` records the Draft-07 Section 18 U-label to A-label
  mapping and the known IDNA2008 category gap of the strict profile.
- `DKIM2-ISSUE-0006` records that uppercase header tag names are rejected
  under Draft-07 Sections 9 and 10 instead of being ignored under the lenient
  reading of Section 8. Earlier external observations predate this rule and
  require re-qualification.
- `DKIM2-ISSUE-0007` through `DKIM2-ISSUE-0010` own the byte model, recipe,
  policy-projection, and restricted-release interpretations exercised by the
  conformance manifest.
- `DKIM2-ISSUE-0011`, `DKIM2-ISSUE-0012`, and `DKIM2-ISSUE-0014` preserve
  the DNS-04 ABNF, query-method, and multiple-record discrepancies without
  silently rewriting either pinned draft.
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
  stay off this route. DSNs retain their dedicated Section 12 path. This is
  an implemented local interpretation, not a draft requirement to enable it.
  The two public-facade conformance cases are bound to this entry; their
  earlier omission from this register was a documentation defect.

- `DKIM2-ISSUE-0019` records that Draft-07 Section 3.4 defines the
  `mldsa44-ed25519-sha512` signature input (SHA-512 of the canonical input,
  pure ML-DSA-44 with empty context, then PureEd25519) while DNS-01 cites the
  LAMPS composite construction, which uses a different message
  representative. Verification implements Section 3.4 only; composite
  signing and interoperability claims wait for working-group clarification.

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
