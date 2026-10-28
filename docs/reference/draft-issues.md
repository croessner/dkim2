# DKIM2 Draft Issue Log

This log binds the first preview to
`draft-ietf-dkim-dkim2-spec-08` and
`draft-ietf-dkim-dkim2-dns-02`. The strict machine source is
`testdata/reference/draft-issues.json`; stable issue IDs are never reused.
Local implementation status and upstream draft status are intentionally
separate. No entry records an upstream filing or resolution unless that event
is independently observed.

## Open upstream text

- `DKIM2-ISSUE-0001` and `DKIM2-ISSUE-0004` cover the Draft-08 `TBA` areas:
  architecture references and IANA. No protocol behavior is invented for
  these areas.
- `DKIM2-ISSUE-0002` and `DKIM2-ISSUE-0005` covered the Draft-06 `TBA`
  areas for full-chain policy guidance and Security Considerations. Both are
  superseded by the Draft-08 baseline: Section 13 assigns acceptance of a
  Fully Verified DKIM2 Message to local policy, which the policy engine owns, and
  Section 20 publishes the security considerations (unsigned header fields,
  resource limits, null Recipes, RSA key size), which the bounded recipe and
  verifier limits already enforce.
- `DKIM2-ISSUE-0003` records the Draft-08 Section 18 U-label to A-label
  mapping and the known IDNA2008 category gap of the strict profile.
- `DKIM2-ISSUE-0006` records that uppercase header tag names are rejected
  under Draft-08 Sections 9 and 10 instead of being ignored under the lenient
  reading of Section 8. Earlier external observations predate this rule and
  require re-qualification.
- `DKIM2-ISSUE-0007` through `DKIM2-ISSUE-0010` own the byte model, recipe,
  policy-projection, and restricted-release interpretations exercised by the
  conformance manifest.
- `DKIM2-ISSUE-0011` and `DKIM2-ISSUE-0012` preserve the DNS ABNF and
  query-method discrepancies without silently rewriting either pinned draft.
- `DKIM2-ISSUE-0014` is superseded by the baseline: Draft-08 Section 14.5
  makes more than one key record an error, which matches the existing
  fail-closed `ambiguous_key` PERMERROR.
- `DKIM2-ISSUE-0013` (DNS strict-identity flag versus the numeric signature
  `i=` tag) is superseded by the baseline: DNS-02 Section 3.4.1 retires the
  key-record `t=` tag, which verifiers SHOULD ignore. The `t=` tag is now
  subject only to the generic tag-list rules and never yields testing or
  strict-identity semantics. The explicitly configured local policy testing
  mode is unrelated and unchanged.

## Adapter and preview limitations

- `DKIM2-ISSUE-0015` keeps Milter/SMTP fidelity in the adapter claim class.
- `DKIM2-ISSUE-0016` records that Exim is `unqualified_draft08`. Draft-04
  qualification evidence is historical only and the current control plane
  rejects every evidence import until a fresh Draft-08 five-row qualification
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

- `DKIM2-ISSUE-0019` is superseded by the baseline. Draft-07 Section 3.4
  named the post-quantum composite `mldsa44-ed25519-sha512`; Draft-08
  Section 3.4 replaces it with pure ML-DSA-44 (`mldsa44`), which the
  implementation now verifies and signs. The composite algorithm and the
  `k=mldsa44-ed25519-sha512` key type stay unimplemented and are handled
  exactly like any other unknown algorithm or key type; signing credentials
  that declare it fail closed.

## DNS-02 and Draft-08 algorithm gaps

- `DKIM2-ISSUE-0020` records that DNS-02 defines no key type for pure
  ML-DSA-44. The implementation reads `k=mldsa44` (a valid hyphenated
  `x-key-k-tag-type` word equal to the Draft-08 Section 10.9 sig-name, as the
  key-type and algorithm match requires) with `p=` carrying the raw
  1312-octet FIPS 204 public key (1752 base64 characters); every other length
  is a malformed key (`invalid_key`, Draft-08 Section 14.5), and `h=` is
  ignored. `opendkim-manage-go` publishes exactly this form.
- `DKIM2-ISSUE-0021` records that DNS-02 Section 3.3 lists `rsa-sha512`,
  `ed25519-sha512`, and the composite as signing algorithms, while Draft-08
  defines only `rsa-sha256`, `ed25519-sha256`, and `mldsa44`. Draft-08 is
  authoritative for `s=` sig-names; the DNS-02-only names are unknown
  algorithms (a PERMERROR intermediate, no key lookup). They never verify, so
  the REST verifier projection (`VerifierHop.signature_algorithms`) never
  lists them, and its closed vocabulary is exactly the three Draft-08 names.
- `DKIM2-ISSUE-0022` records that DNS-02 names the composite key type
  `mldsa44-ed25519` in its Section 3.3 table but `mldsa44-ed25519-sha512` in
  the Section 3.4.1 ABNF. Both spellings are unsupported key types.

## Delivery-status identity

- `DKIM2-ISSUE-0023` records that Draft-08 Section 16.2 requires both
  "appropriate Message-Instance and DKIM2-Signature fields" on a DSN and a
  relaxed domain match between the DSN's `d=` and an `rt=` address of the
  reported message's highest DKIM2-Signature. For a sender-side bounce (the
  highest signature is this system's and its `rt=` is a remote recipient) no
  local domain can satisfy the match, so both MUSTs cannot hold at once. The
  implementation never signs with a non-matching `d=`: such a report leaves
  unsigned as a classic RFC 3464 notification with the reason
  `delivery_status_identity_unavailable`. The same outcome applies when no
  local `delivery_status` profile covers a recipient domain.

The repository has not filed, commented on, or modified any upstream issue as
part of this release-candidate work.

## Stable ID index

`DKIM2-ISSUE-0001`, `DKIM2-ISSUE-0002`, `DKIM2-ISSUE-0003`,
`DKIM2-ISSUE-0004`, `DKIM2-ISSUE-0005`, `DKIM2-ISSUE-0006`,
`DKIM2-ISSUE-0007`, `DKIM2-ISSUE-0008`, `DKIM2-ISSUE-0009`,
`DKIM2-ISSUE-0010`, `DKIM2-ISSUE-0011`, `DKIM2-ISSUE-0012`,
`DKIM2-ISSUE-0013`, `DKIM2-ISSUE-0014`, `DKIM2-ISSUE-0015`,
`DKIM2-ISSUE-0016`, `DKIM2-ISSUE-0017`, `DKIM2-ISSUE-0018`,
`DKIM2-ISSUE-0019`, `DKIM2-ISSUE-0020`, `DKIM2-ISSUE-0021`,
`DKIM2-ISSUE-0022`, and `DKIM2-ISSUE-0023`.
