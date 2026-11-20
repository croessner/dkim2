# DKIM2 Draft Issue Log

This log binds the first preview to
`draft-ietf-dkim-dkim2-spec-09` and
`draft-ietf-dkim-dkim2-dns-03`. The strict machine source is
`testdata/reference/draft-issues.json`; stable issue IDs are never reused.
Local implementation status and upstream draft status are intentionally
separate. No entry records an upstream filing or resolution unless that event
is independently observed.

## Open upstream text

- `DKIM2-ISSUE-0001` and `DKIM2-ISSUE-0004` cover the Draft-09 `TBA` areas:
  architecture references and IANA. No protocol behavior is invented for
  these areas.
- `DKIM2-ISSUE-0002` and `DKIM2-ISSUE-0005` covered the Draft-06 `TBA`
  areas for full-chain policy guidance and Security Considerations. Both are
  superseded by the Draft-09 baseline: Section 13 assigns acceptance of a
  Fully Verified DKIM2 Message to local policy, which the policy engine owns, and
  Section 20 publishes the security considerations (unsigned header fields,
  resource limits, null Recipes, RSA key size), which the bounded recipe and
  verifier limits already enforce.
- `DKIM2-ISSUE-0003` records the Draft-09 Section 18 U-label to A-label
  mapping and the known IDNA2008 category gap of the strict profile.
- `DKIM2-ISSUE-0006` records that uppercase header tag names are rejected
  under Draft-09 Sections 9 and 10 instead of being ignored under the lenient
  reading of Section 8. Earlier external observations predate this rule and
  require re-qualification.
- `DKIM2-ISSUE-0007` through `DKIM2-ISSUE-0010` own the byte model, recipe,
  policy-projection, and restricted-release interpretations exercised by the
  conformance manifest.
- `DKIM2-ISSUE-0011` and `DKIM2-ISSUE-0012` are superseded by the baseline:
  DNS-03 Section 4.2 writes the key-type tag as a case-sensitive lowercase
  `k`, and DNS-03 Section 3 names the TXT lookup without a query-method
  option. Both match the existing behavior.
- `DKIM2-ISSUE-0014` is superseded by the baseline: Draft-09 Section 14.5
  makes more than one key record an error, which matches the existing
  fail-closed `ambiguous_key` PERMERROR. Draft-09 Section 3.7 first ignores
  records whose `v=` is not `DKIM1`; the uniqueness check applies to the
  remaining records only.
- `DKIM2-ISSUE-0013` (DNS strict-identity flag versus the numeric signature
  `i=` tag) is superseded by the baseline: DNS-03 Section 4 deprecates the
  key-record `t=` tag, which DKIM2 ignores. The `t=` tag is now
  subject only to the generic tag-list rules and never yields testing or
  strict-identity semantics. The explicitly configured local policy testing
  mode is unrelated and unchanged.

## Adapter and preview limitations

- `DKIM2-ISSUE-0015` keeps Milter/SMTP fidelity in the adapter claim class.
- `DKIM2-ISSUE-0016` records that Exim is `unqualified_draft09`. Draft-04
  qualification evidence is historical only and the current control plane
  rejects every evidence import until a fresh Draft-09 five-row qualification
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
  named the post-quantum composite `mldsa44-ed25519-sha512`; Draft-09
  Section 3.4 replaces it with pure ML-DSA-44 (`mldsa44`), which the
  implementation now verifies and signs. The composite algorithm and the
  `k=mldsa44-ed25519-sha512` key type stay unimplemented and are handled
  exactly like any other unknown algorithm or key type; signing credentials
  that declare it fail closed.

## DNS key types and algorithm names

- `DKIM2-ISSUE-0020` is superseded by the baseline. An earlier DNS draft
  defined no key type for pure ML-DSA-44, so `k=mldsa44` was a local
  interpretation. DNS-03 Section 4.2 defines exactly that key type: `p=`
  carries the raw 1312-octet FIPS 204 public key (1752 base64 characters)
  with no wrapper, and DNS-03 Section 4.3 makes every other length a
  malformed key (`invalid_key`, Draft-09 Section 14.5). `h=` is ignored.
- `DKIM2-ISSUE-0021` is superseded by the baseline. An earlier DNS draft
  listed `rsa-sha512`, `ed25519-sha512`, and the composite as signing
  algorithms. DNS-03 Section 4 lists key types only, and Draft-09 defines
  `rsa-sha256`, `ed25519-sha256`, and `mldsa44`. The removed names stay
  unknown algorithms (a PERMERROR intermediate, no key lookup). They never
  verify, so the REST verifier projection
  (`VerifierHop.signature_algorithms`) never lists them, and its closed
  vocabulary is exactly the three Draft-09 names.
- `DKIM2-ISSUE-0022` is superseded by the baseline. An earlier DNS draft
  named the composite key type `mldsa44-ed25519` in a table but
  `mldsa44-ed25519-sha512` in its ABNF. DNS-03 defines no composite key
  type; both spellings are unsupported key types.

## DNS-03 Base64 padding

- `DKIM2-ISSUE-0027` records that DNS-03 Section 2.3 says a base64string
  "MUST be padded with zero bits and trailing = characters provided if
  needed", while its ABNF keeps the trailing `=` characters optional and
  RFC 6376 key records could omit them. Draft-09 Section 2.14 states the same
  rule for header fields. The implementation follows the prose for key
  records as well: a `p=` value that omits needed `=` characters is a
  malformed record (`invalid_key`, Draft-09 Section 14.5). Earlier releases
  accepted such records. A 2048-bit RSA key needs no padding; 3072-bit and
  4096-bit RSA keys, Ed25519 keys, and ML-DSA-44 keys need it, so a record
  affected by this change was published without the padding its key
  generator emitted.

## Draft-09 grammar and Domain Policy Records

- `DKIM2-ISSUE-0024` records that Draft-09 Section 2.14 removes leading and
  trailing FWS from `base64string`, so the `rt=` list `base64string *(","
  base64string)` no longer admits FWS after a comma, which every earlier
  signer of this implementation emitted and Draft-08 allowed. The renderer now
  folds inside the next recipient after its first character. The parser keeps
  accepting FWS after an `rt=` comma so that mail signed by earlier releases
  still verifies. FWS before an `rt=` comma, which no earlier signer
  emitted, is rejected, and so are leading FWS in `h=` and `s=` hash values
  and trailing FWS before the next `:`. The Section 8 tag-spec FWS around `=` for
  `r=`, `mf=`, and `rt=` stays accepted although the tag ABNF omits it.
- `DKIM2-ISSUE-0025` records that Draft-09 Section 11.1 lets a subdomain `d=`
  make a parent From domain Authentic unless the From domain publishes a
  Domain Policy Record with `f=strict`, so an absent record authorizes every
  subdomain signer. This was questioned on the working group list as
  fail-open. The library requires an explicit construction choice (a Domain
  Policy Record provider or the downward-only option) and never defaults.
  `dkim2d` follows the draft by default
  (`verification.domain_policy.allow_subdomain_from: true`); `false` keeps
  the Draft-08 downward-only rule. Signers stay downward only.
- `DKIM2-ISSUE-0026` records that Draft-09 Section 3.8 and DNS-03 Section 5
  say which records are Domain Policy Records and that more than one is an
  error, but not how a verifier treats an invalid record or a permanent
  lookup failure. The implementation fails closed: `domain_policy_ambiguous`
  and `domain_policy_invalid` are PERMERROR, and a temporary failure is
  TEMPERROR `domain_policy_temporary`. An unrecognized flag is ignored, as
  DNS-03 Section 5.2 requires; an `f=` value outside the DNS-03 Section 5.2
  grammar (an empty flag, a flag that is not a hyphenated word) makes the
  record invalid rather than authorizing subdomains.

## Delivery-status identity

- `DKIM2-ISSUE-0023` records that Draft-09 Section 16.2 requires both
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
`DKIM2-ISSUE-0022`, `DKIM2-ISSUE-0023`, `DKIM2-ISSUE-0024`,
`DKIM2-ISSUE-0025`, `DKIM2-ISSUE-0026`, and `DKIM2-ISSUE-0027`.
