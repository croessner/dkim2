# DKIM2 Draft-08 Migration Disposition

Status: implementation authority, migration in progress

Message specification: `draft-ietf-dkim-dkim2-spec-08`, 27 October 2026

DNS companion: `draft-ietf-dkim-dkim2-dns-02`, 21 October 2026

Previous baseline: `draft-ietf-dkim-dkim2-spec-07` plus
`draft-ietf-dkim-dkim2-dns-01` (`docs/specs/draft-07-migration-disposition.md`)

## 1. Authority and method

This document is the tracked authority for the migration from Draft-07/DNS-01
to Draft-08/DNS-02. It records every behavior change, the owning work package,
and every local interpretation. Historical audit records, reports, and earlier
migration dispositions keep their original identifiers.

The comparison used the IETF archive texts:

| Document | SHA-256 |
| --- | --- |
| `draft-ietf-dkim-dkim2-spec-07.txt` | `1b110382190c9729b6c46ab3bbc1541423c53b28841291dc6dcab90c214548bd` |
| `draft-ietf-dkim-dkim2-spec-08.txt` | `f562f73e2c48f7d170f41ba691bd5c6867de59caefece5b122a428d4e07b7d8c` |
| `draft-ietf-dkim-dkim2-dns-01.txt` | `3bd7fdb601efd5addc31946cf640768847e3f39b5b1208b00f41b9d2673c882e` |
| `draft-ietf-dkim-dkim2-dns-02.txt` | `18aa5de0d209e7d44c943857ee992fb11ac2f10ec2e57e70758b10745db1a121` |

Spec-08 cites `[DKIMKEYS]` as DNS-02, so the new baseline is the pair
spec-08 plus DNS-02. The spec-07 and DNS-01 digests match the Draft-07
disposition record.

Requirement strength is marked MUST/SHOULD/MAY (draft), descriptive (draft
prose), editorial (no behavior), or local (product policy that is stricter
than the draft).

The repository advertises the Draft-08 identifiers from the first work package
on. No release or conformance claim is made until every work package below is
complete.

## 2. Section renumbering

Draft-08 inserts two subsections. Every other section keeps its Draft-07
number. Active code comments, manifest authorities, and issue citations use
Draft-08 numbers.

| Draft-07 | Draft-08 |
| --- | --- |
| — | 13.1 Messages that are not Fully Verified DKIM2 Messages (new) |
| 13.1 Provisionally Verified messages | 13.2 |
| 13.2 SMTP return codes | 13.3 |
| 13.3 Further observations on verification | 13.4 |
| 16.1 DSN contents (MIME structure) | 16.1 |
| 16.1 DSN contents (DKIM2 fields, null MAIL FROM, Provisionally Verified report) | 16.2 DSN header and SMTP parameters (new) |
| 16.2 DSN propagation | 16.3 |
| 16.3 Authentication of inbound DSNs | 16.4 |

Draft-07 Section 16.1 was split: its MIME-structure paragraph stays in 16.1,
while the DKIM2-field, null `MAIL FROM`, and provisional-verification
paragraphs moved to the new 16.2. Citations were mapped by content, not only
by number.

## 3. DNS-01 to DNS-02

| # | Section | Change | Disposition | Package |
| --- | --- | --- | --- | --- |
| N1 | 2.9 | `LWSP` token removed | The parser uses FWS/WSP only; regression test | 2 |
| N2 | 3.3 | Lists five algorithms: `rsa-sha256`, `rsa-sha512`, `ed25519-sha256`, `ed25519-sha512`, `mldsa44-ed25519-sha512` (composite); RSA MUST, others SHOULD during bring-up and MUST later; `rsa-sha1` MUST NOT validate | Inconsistent with spec-08, which defines only `rsa-sha256`, `ed25519-sha256`, and `mldsa44` and dropped the composite. Spec-08 is authoritative for `s=` sig-names: `rsa-sha512`, `ed25519-sha512`, and the composite are unknown algorithms (PERMERROR intermediate). New draft issue | 6 |
| N3 | 3.3 table | Composite key type renamed `mldsa44-ed25519` in the table, while the 3.4.1 ABNF still reads `mldsa44-ed25519-sha512` | Both are unsupported key types (no composite). Draft issue | 6 |
| N4 | 3.4.1 | No key type for pure ML-DSA-44 | Local interpretation D1: `k=mldsa44`, raw 1312-octet `p=`. Draft issue and operator note | 6 |
| N5 | references | Spec reference moves to -07 | Editorial | — |

## 4. Draft-07 to Draft-08

| # | Section | Change | Strength | Disposition | Package |
| --- | --- | --- | --- | --- | --- |
| C1 | 3, 3.4 | Composite `mldsa44-ed25519-sha512` replaced by pure ML-DSA-44 `mldsa44` (FIPS 204 ML-DSA.Sign/Verify, no HashML-DSA, input is the full Section 12.8 byte string, context `DKIM2`, 3228-character base64 signature); Signers SHOULD use hedged signing; Verifiers MUST implement all algorithms | MUST (verify), MAY (sign) | D1 | 6 |
| C2 | 3.2 | RSA: Signers SHOULD use at least 2048 bits; Verifiers MUST validate 1024 to 4096, MAY larger, MUST NOT below 1024 | MUST/SHOULD | Verification bounds 1024 to 8192 already comply; signing floor D10 | 6 |
| C3 | 3.5 | "Unimplemented algorithm disregarded" removed; an unimplemented algorithm is a PERMERROR intermediate, never a pass | MUST | D4 | 4 |
| C4 | 4, 4.1 | `Auto-Submitted` and `VBR-Info` removed from the unsigned list and therefore hashed | MUST | Remove both from the unsigned set; recipe and DSN rebuild consequences | 2 |
| C5 | 5 | JSON key lowercase and uniqueness are not expressible in the schema; implementations enforce them | descriptive | Already enforced (Draft-07 package 2) | 9 |
| C6 | 6.2 | Header order is ascending octet order of lower-cased names; bullets merged | MUST (clarification) | Already byte order; regression test | 2 |
| C7 | 7.1 item 2 | `d=`/`mf=` relaxed match: highest DS for Provisional Verification, every DS for Fully Verified | MUST | Every DS is checked; documentation and test | 5 |
| C8 | 7.1 item 4, 16.2 | DSN creation MUST relaxed-match the DSN `d=` (Parameter2) against an `rt=` address (Parameter1) of the highest DS of the reported message | MUST | D8 | 7 |
| C9 | 7.2 item 2 | Pointer to RFC 5321/5322 for address syntax | descriptive | No change | — |
| C10 | 8 | `tval = 1*(%x21-3A / %x3C-7E)` | ABNF fix | Already read this way (Draft-07 D5) | 9 |
| C11 | 9, 10 | Message-Instance and DKIM2-Signature are trace header fields; IANA registers both as trace fields | descriptive/IANA | D9 | 8 |
| C12 | 9.1, 10.1 | Gaps or duplicates in `m=`/`i=` mean not Fully Verified | MUST | Already rejected; state stays PERMERROR (D5) | 5 |
| C13 | 9.3 | `h=` grammar with `hash-any`/`hash-all` (`\|` OR, `,` AND, `,` binds tighter); a hash algorithm MUST NOT repeat in one Message-Instance | MUST | D2, D4 | 3, 4 |
| C14 | 10 | DKIM2-Signature description wording | editorial | — | — |
| C15 | 10.9 | `s=` grammar with `sig-any`/`sig-all`; `mldsa44` sig-name; a selector MUST NOT repeat; several signatures with one algorithm MAY appear with distinct selectors (per-algorithm cap removed) | MUST | D2, D3, D4 | 3, 4 |
| C16 | 11 | A From with more than one address or a domain literal cannot be Fully Verified | MUST | Already enforced (`from_not_authentic`) | 5 |
| C17 | 12 | A Signer MUST NOT sign a non-initial message unless Fully Verified, now including the null-Recipe consequence | MUST | D7 | 5 |
| C18 | 12.1 | A null Recipe affects verification (Section 13) | descriptive | D7 | 5 |
| C19 | 12.2 | Signer MUST ensure the Section 14.4 envelope check will succeed | MUST | Already enforced; evidence | 9 |
| C20 | 12.3 | Extra-hop key is a key for the RCPT TO domain or a parent | clarification | Same semantics | — |
| C21 | 12.4 | No Signing Domain can make From Authentic, so the message is never Fully Verified | descriptive/MUST | Signer refuses; DSN From in D8 | 7 |
| C22 | 12.8 | Unsigned target: only signature values are null; selectors, algorithm names, and `:` `,` `\|` remain | MUST | D2 | 3 |
| C23 | 13 | Full verification: every MI hash against the message recreated by higher Recipes; every DS over MI up to its `m=` and DS below its `i=` | MUST | Implemented; algebra in history (D4) | 4 |
| C24 | 13 | Body hashes below a null Recipe cannot be checked, so not Fully Verified; acceptance is local policy | MUST | D7 | 5 |
| C25 | 13.1 | New subsection | editorial | — | — |
| C26 | 13.2 | Provisional Verification as five explicit checks; DSN to MAIL FROM; backscatter argument. The Draft-07 Section 13.1 "MUST NOT be generated thereafter" for a DSN of a message that is not Provisionally Verified is now descriptive | MAY/descriptive | No provisional subsystem; the product keeps refusing such DSNs (local, unchanged) | 5 |
| C27 | 13.4 | Wording | editorial | — | — |
| C28 | 14.1 | FAIL means verification completed but concluded not Fully Verified; a verifier MAY stop once the outcome is known | MUST | D5 | 5 |
| C29 | 14.2 | Error list adds "Recipe is invalid", drops "more selectors than allowed"; recipe errors SHOULD include the invalid step text | SHOULD | D6 | 5 |
| C30 | 14.3 | Timestamp errors become FAIL; the reference is SMTP acceptance time | MUST | D5 | 5 |
| C31 | 14.4 | Envelope, `mf=`/`d=`, `nd=`, and custody errors become FAIL | MUST | D5 | 5 |
| C32 | 14.5 | ML-DSA-44 key exactly 1312 octets, Ed25519 exactly 32; "public key is malformed"; DNS timeouts are TEMPERROR | MUST | D1 | 6 |
| C33 | 14.6 | Signature evaluation steps 1 to 8 with per-signature intermediates and `sig-all`/`sig-any` combination | MUST | D4 | 4 |
| C34 | 14.7 | Hash evaluation steps 1 to 6 with per-set intermediates and `hash-all`/`hash-any` combination | MUST | D4 | 4 |
| C35 | 14.8 | From check covers every From since the message was first signed; error becomes FAIL | MUST | Draft-07 D3 matches; D5 | 5 |
| C36 | 15.1 | Replay "same" means equal `m=1` header and body hashes | descriptive | Draft-07 D2 already uses both; replay goldens recomputed for the new draft identifier | 1, 9 |
| C37 | 16 | DSN to MAIL FROM, never to `<>` | MUST | Implemented | — |
| C38 | 16.2 | New subsection; DSN assurances depend on Provisional Verification only | descriptive | Full verification used (stricter, local) | 7 |
| C39 | 16.3 | Propagation goes to the MAIL FROM used to deliver to the Forwarder (highest DS) | MUST | Previous hop `mf=` (same); C8 check on propagation | 7 |
| C40 | 16.4 item 3 | Headers-only: `h=` evaluated per Section 14.7, a hash-set passes when its header hash matches | SHOULD | D4 | 4 |
| C41 | 16.4 | Returned message without DKIM2 fields: the specification does not apply | descriptive | Already `EmbeddedAbsent`, not propagated | — |
| C42 | 19 | IANA header registrations | IANA | Documentation | 9 |
| C43 | 20 | Auto-Submitted example removed from Security Considerations | editorial | Documentation | 9 |
| C44 | 1.1, 21 | DKIM2BCP, DKIMKEYS (DNS-02), RFC 8301 and 3864 references | editorial | Identifiers in package 1, documentation in package 9 | 1, 9 |
| C45 | 2.11 | "Validly Signed DKIM2 Message" renamed "Fully Verified DKIM2 Message" | terminology | Documentation and comments | 9 |
| C46 | 2.13 | Imported tokens reduced to RFC 5321 `Domain` | editorial | — | — |
| C47 | 10.6 | Bcc rule broadened from an address in a `Bcc:` header field to any blind carbon copy address, envelope-only bcc included | MUST | The signer takes `rt=` from the adapter; adapter and operator responsibility. The existing stricter Bcc isolation is kept | 9 |

## 5. Local interpretations

**D1 ML-DSA-44.** Verify (MUST) and sign (MAY) `mldsa44`. The key record is
`k=mldsa44` (a valid hyphenated `x-key-k-tag-type` word equal to the spec-08
sig-name, as Section 10.9 requires `k=` to match the algorithm) with a raw
1312-octet `p=`; any other length is `invalid_key`. Signatures are exactly
2420 octets. The context constant `DKIM2` is owned by `cryptodkim2`.
Production signing uses hedged `Sign` with `crypto/rand`; `SignDeterministic`
is never used. Under the FIPS 140-3 v1.0.0 module `crypto/mldsa` is
unavailable, so enabling `mldsa44` fails closed at startup. Custody keys are
PKCS#8 seed form. The composite stays unsupported; `DKIM2-ISSUE-0019` is
superseded because spec-08 removed it.

**D2 Combinators.** Parsed `h=` and `s=` keep their group structure (an
ordered list of groups, each an ordered list of sets). The Section 12.8
unsigned target is rendered from that structure with `,` and `|` exactly where
received. Empty groups and leading, trailing, or doubled separators are syntax
errors (PERMERROR `malformed_protocol`). Duplicate hash names and selectors are
checked across all groups. The per-algorithm cap of two and the
`too_many_signatures` reason are removed everywhere; the local DoS bounds
`max_signature_sets` and `max_hash_sets` of 16 stay (`limit_exceeded`). Until
package 4 enables the algebra, package 3 parsers are group-aware but fail
closed with PERMERROR `malformed_protocol` on more than one group.

**D3 Signer layout.** The signer uses a fixed layout without configuration:
the classical credentials (`rsa-sha256`, `ed25519-sha256`) form the first
`sig-all` group joined by `,`; an `mldsa44` credential, if the profile has
one, is a separate alternative group after `|` (`rsa,ed25519 | mldsa44`).
This is the Section 10.9 phased-deployment pattern: a verifier without ML-DSA
still passes through the classical group. Consequence: until the classical
group is removed, ML-DSA adds no forgery resistance, because a hybrid `,`
would break verifiers that lack ML-DSA. A profile with only `mldsa44` emits
one group. The Section 12.8 unsigned target keeps every selector, algorithm
name, and the `:` `,` `|` punctuation, so all signatures are computed over
the same unsigned DKIM2-Signature rendered from the final layout (no white
space, `|` between groups); the signer fixes the layout before computing any
value, and one shared renderer serves signer and verifier. Selectors must be
distinct across all groups; the profile loader rejects duplicates.

**D4 Evaluation.** One shared evaluator implements Section 14.6 steps 3 to 7
and Section 14.7 steps 1 to 5 and is the only owner used by the current
target, revision and inherited signatures, history Message-Instances, the
headers-only DSN embedded check (Section 16.4 item 3, body ignored), and
outbound DSN evidence. An unknown algorithm is a PERMERROR
`unsupported_algorithm` intermediate without key lookup; an algorithm known
but disabled by local policy is also PERMERROR `unsupported_algorithm`, after
a reproducer for the current `PolicyRejected` to `internal_contract` mapping,
with an observation label separating "disabled locally" from "unknown". Key
results keep their specific reasons. The public reason of a non-PASS overall
result is the reason of the first set in field order whose intermediate equals
the overall result. Hash combinations never yield TEMPERROR. The Section 14.6
step 8 selector text cannot be carried by the bounded Authentication-Results
comment vocabulary (documented deviation).

**D5 States.** FAIL (Section 14.1, completed but not Fully Verified):
`hash_mismatch`, `signature_mismatch`, `timestamp_invalid`,
`envelope_mismatch`, `domain_alignment_mismatch`, `custody_mismatch` (new
public reason, today collapsed into `malformed_protocol`),
`out_of_band_required`, `from_not_authentic`, and `body_history_unavailable`
(new, C24). PERMERROR stays for syntax, missing protocol, duplicates, sequence
gaps and duplicates (C12 is structural), unsupported algorithms, key errors,
invalid recipes, and limits. TEMPERROR is unchanged. Policy and adapter
dispositions stay byte-identical for every reason except deliberate changes,
proven by a table-driven test over every reason and policy mode.

**D6 Recipe errors.** New public reason `invalid_recipe` (Section 14.2 "Recipe
is invalid") for schema, semantic step, and application errors;
`invalid_recipe_json` only for JSON syntax and object-shape errors;
`limit_exceeded` for complexity. Deliberate deviation from the Section 14.2
SHOULD: recipe step text is never placed in errors, because raw message
content must not appear in logs, REST, or CLI output; diagnostics carry the
step index, member, and kind.

**D7 Null Recipe.** A history containing `"b":null` is FAIL
`body_history_unavailable` (not Fully Verified). Transit and revision signing
therefore refuse such messages (Section 12). The library generator option
`AllowUnavailableBody` remains (Section 12.1 MAY) with a documentation
warning. There is no acceptance knob in this migration; the operator
documentation and rollout preflight state the consequence.

**D8 DSN identity.** Package 7 implements the Section 16.2 identity resolver:
candidate signing domains are the local `delivery_status` profile domains
that relaxed-match an `rt=` address of the highest DS of the embedded reported
message (Parameter1 is the `rt=` address, Parameter2 the `d=`), RFC
3464-linked recipients first and the longest profile domain first;
`reporting_domain` is preferred only when it matches. The derived "embedded
highest `d=`" mode is removed. The DSN's own From domain must relaxed-match
the chosen `d=` (Sections 11 and 12.4). Otherwise the outcome is explicitly
"not DKIM2 signed" with the reasons `delivery_status_identity_unavailable` or
`delivery_status_from_not_authentic`, a metric, and operator documentation
(the Postfix `MAILER-DAEMON@$myorigin` must sit under the DSN signing domain).
There is no From replacement and no new action. A sender-side bounce (highest
DS ours, `rt=` remote) can never match Section 16.2 and stays unsigned; this
is recorded as a draft issue. Propagation (Section 16.3) gets the same
`d=`/`rt=` check. DSN evidence keeps the current-target PASS gate, which is
stricter than Section 16.2 Provisional Verification (local, unchanged by D5).

**D9 Trace placement.** Adopted at SHOULD level: adapters insert this hop's
Message-Instance and DKIM2-Signature at the top of the header block (Milter
INSHEADER index 0, Exim prepend), Message-Instance then DKIM2-Signature,
directly above the previous top field, with tests for top-placed,
bottom-placed, mixed, and headers-only previous hops.

**D10 RSA signing floor.** New signing credentials and loaded signing profiles
require RSA of at least 2048 bits (C2 SHOULD made a local MUST); verification
bounds stay 1024 to 8192, which cover the MUST range. Profiles below the
floor fail at load.

**D11 API.** The OpenAPI `DraftVersion` enum is exactly
`draft-ietf-dkim-dkim2-spec-08`; other drafts get HTTP 400
`unsupported_draft`. The daemon, adapters, `dkim2ctl`, the Rspamd contrib,
and external consumers move together. The replay identity space restarts,
because the draft identifier is bound into the replay frame.

## 6. Work packages

1. Baseline identifiers, generated contracts, versioned fixtures, draft-bound
   goldens, section citations, and this document (no behavior change).
2. Unsigned header list and header order (C4, C6, N1).
3. Combinator syntax (C13, C15, C22; D2).
4. Evaluation algebra (C3, C23, C33, C34, C40; D4).
5. States and reasons (C7, C12, C16 to C18, C24, C26, C28 to C31, C35; D5 to
   D7).
6. Algorithms and keys (C1, C2, C32, N2 to N4; D1, D10).
7. DSN identity and propagation (C8, C21, C38, C39; D8).
8. Trace placement (C11; D9).
9. Documentation and qualification (C5, C10, C19, C36, C42 to C45, C47),
   operator migration guide, draft issues, and final review.

## 7. Package 1 state

- Draft identifiers now name Draft-08 and DNS-02: the six library constants
  (`dkim2.DraftIdentifier`, `canonical.DraftBaseline`, `verify.DraftBaseline`,
  `replay.DraftIdentifier`, `service.DraftIdentifier`,
  `keyresolver.DNSDraftIdentifier`) with `lib/draft_baseline_test.go`, the
  daemon JSON preflight, the `X-DKIM2-Info` interoperability header
  (`draft=ietf-dkim-dkim2-spec-08`), build metadata, conformance, interop,
  reference, security, and qualification tooling, JSON schemas with a draft
  constant, the Rspamd contrib `DRAFT` and its tests, and the agent skills.
- The OpenAPI `DraftVersion` enum is `draft-ietf-dkim-dkim2-spec-08`; all
  generated server and client code was regenerated, and the hand-written Go
  references use `DraftIetfDkimDkim2Spec08`.
- Versioned vector and fixture directories and files were renamed in place.
  Before the rename, the Draft-07 and DNS-01 versions of every corpus whose
  meaning a later package changes (canonical and recipe goldens, signing,
  public, custody, received-DSN, and DSN propagation vectors, and the DNS
  golden) were copied to `lib/testdata/vectors/history/draft-ietf-dkim-dkim2-spec-07/`
  and `lib/testdata/vectors/history/draft-ietf-dkim-dkim2-dns-01/`, so earlier
  evidence is never silently overwritten.
- Draft-bound goldens (replay identity and origin-declaration digests, the
  verifier-projection binding, and the conformance manifest digests) were
  recomputed through the repository's own tests and generators.
- Section citations in active code, manifest authorities, issue entries, and
  documentation use the Draft-08 numbers of Section 2, and the citation
  validator pins the Draft-08 section set including 13.4 and 16.4.
- Kept with their original identifiers as historical records: earlier
  migration dispositions, `docs/operator/draft-07-migration.md`, reports, the
  architecture change log, the Draft-07 operator upgrade section in
  `docs/operator/postfix-compose.md`, issue resolution criteria, and every
  statement that Draft-07 removed the `donotmodify` and `donotexplode` flags
  or that DNS-01 retired the DNS `t=` tag, including the operator-facing
  configuration migration error.
- Protocol behavior is still the Draft-07 behavior until the following
  packages land. Interoperability and Exim qualification remain
  `unqualified_draft08`.

## 8. Package 2 state

- C4: `Auto-Submitted` and `VBR-Info` are signed. The exact unsigned set in
  `exactUnsignedHeaderName` (`lib/internal/canonical/header.go`) now holds
  the six names `Apparently-To`, `DL-Expansion-History`,
  `Original-Recipient`, `SIO-Label-History`, `X400-Received`, and
  `X400-Trace`; together with the `Received`/`Received-*`, `Return-Path`,
  `Delivered-To`, `Authentication-Results`, `X-*`, `DKIM-Signature`, and
  three ARC classes it matches the Section 4.1 summary exactly, and
  Section 6.2 adds `Message-Instance` and `DKIM2-Signature`. The canonical
  `HeaderRelevance` classifier remains the single table used by the recipe
  parser and generator, signing, verification, and the DSN rebuild.
- Recipe consequence: recipes for `Auto-Submitted` and `VBR-Info` are legal
  and are generated when a hop adds or changes either field; a recipe for a
  Section 4.1 field is still rejected (`unsigned_header_recipe`).
- DSN rebuild consequence: the Section 16.3 pruning rule removes only
  hash-excluded fields above the previous hop signature. A forwarder-added
  `Auto-Submitted` is now a signed field that the local Recipe must undo; the
  rebuild applies that Recipe, independent of the field position, and fails
  closed with `hash_mismatch` when the Recipe omits the addition. No
  production change was needed in `lib/internal/dsn/rebuild.go`, because the
  rebuild already delegates to the canonical classifier.
- The propagated DSN writes `Auto-Submitted: auto-replied` before its `m=1`
  header hash is computed; a test proves that the report verifies and that a
  changed or removed field fails with `hash_mismatch`. No other producer adds
  `Auto-Submitted` or `VBR-Info` after hashing.
- C6: a regression test pins Section 6.2 ordering by ascending octet value of
  the lower-cased names (`-`, digits, `_`, mixed case, and a name that is a
  prefix of another). The implementation already compared bytes.
- N1: DNS-01 defined LWSP for information only and used it in no
  production, so DNS-02 removing it has no behavioral effect. A regression
  test pins that a CRLF must be followed by WSP in a key record.
- The Draft-07 to Draft-08 boundary test now proves that a Draft-07 header
  hash over `Auto-Submitted` and `VBR-Info` FAILs under Draft-08 and that
  Draft-08 signs both again as Draft-04 did.
- Regenerated artifacts: the canonical header golden (inputs relabelled as
  signed, canonical bytes, digest, and counts recomputed with the production
  canonicalizer and checked against an independent SHA-256), the DSN
  propagation corpus through `DKIM2_WRITE_DSN_PROPAGATION_VECTORS=1` (only
  the signed report bytes changed, because each report carries the now
  hashed `Auto-Submitted`), and the conformance manifest digests through
  `make generate-conformance-manifest`. The Draft-07 copies stay under
  `lib/testdata/vectors/history/draft-ietf-dkim-dkim2-spec-07/`.
- Qualification and `dkim2ctl` fixtures compute hashes at run time through
  the library and carry no frozen digests over these fields.

## 9. Package 3 state

- C13, C15: the `h=` and `s=` parsers follow the exact Draft-08 Section 9.3
  and 10.9 ABNF. `lib/internal/combine` owns the group structure (`Layout`:
  ordered groups of sets in field order) and the separator split shared by
  both parsers; `MessageInstance.HashLayout` and `Signature.SignatureLayout`
  expose it next to the sets in field order. Values are unfolded, so FWS is
  WSP. Tests pin every white-space position: accepted after `=`, around `,`
  and `|`, around hash names, selectors, and sig-names, and before or inside
  base64string values; rejected inside a hash name, selector, or sig-name and
  between header-hash `=` padding and the second colon. Empty groups and
  leading, trailing, or doubled separators are `malformed_hash_set` /
  `malformed_signature_set` (PERMERROR `malformed_protocol`).
- Duplicate hash names and duplicate selectors are rejected across all
  groups. The per-algorithm cap of two and the `too_many_signatures` reason
  are removed from the parser, the signer, the verify, service, and policy
  vocabularies, the public `ReasonCode` set, the OpenAPI `VerificationReason`
  and `primary_reason` enums with every generated server and client, the
  daemon mapping, the Milter, Exim, and `dkim2ctl` tests, the Rspamd contrib,
  and the documentation. The local bounds `max_signature_sets` and
  `max_hash_sets` of 16 count sets across all groups (`limit_exceeded`).
- C22: `Signature.UnsignedSignatureValue` is the single Section 12.8 unsigned
  `s=` renderer. It renders from the parsed structure with the received
  selector spelling, the algorithm names, both colons, and the `,` and `|`
  separators, nulls only the signature values, and emits no white space. The
  verifier canonicalization (`canonical.renderIncompleteSignatureValue`) and
  the signer's completion proof (`RebuildUnsignedFromComplete`) both use it,
  and `NewUnsignedTarget` proves that the folded unsigned field the signer
  emits reduces to the same bytes.
- D3: the signer layout is derived from the canonically ordered credentials
  before any signature value is computed. Classical algorithms
  (`rsa-sha256`, `ed25519-sha256`) form the first `sig-all` group; any other
  algorithm (the `mldsa44` credential of package 6) starts a separate `|`
  group. With today's two algorithms the output stays one `,` group, and the
  Message-Instance `h=` emission stays one `sha256` set.
- Until package 4 enabled the Section 14.6/14.7 algebra, a value with more
  than one group failed closed (PERMERROR `malformed_protocol`); package 4
  lifted that rule.
- Fuzz targets: `FuzzSplit` (exact rejoin and layout invariants) and the
  existing parser fuzzers with group seeds and layout and unsigned-rendering
  invariants.

## 10. Package 4 state

- C3, C33, C34: `lib/internal/combine` owns the Section 14.6 steps 5 to 7
  and Section 14.7 steps 3 to 5 algebra (`combine.Signatures`,
  `combine.Hashes`). Signature intermediates are PASS, FAIL (mismatch),
  TEMPERROR (key temporarily unavailable), and PERMERROR (any permanent key
  or provider error, unknown algorithm, algorithm disabled by local policy).
  `sig-all`: every PASS is PASS; else every non-PASS TEMPERROR is TEMPERROR;
  else any FAIL is FAIL; else PERMERROR. `sig-any`: any PASS, else any
  TEMPERROR, else any FAIL, else PERMERROR. Hash-sets are PASS when header
  and body hash match, FAIL otherwise, PERMERROR for an unimplemented
  algorithm; `hash-all` all PASS, any FAIL, else PERMERROR; `hash-any` any
  PASS, any FAIL, else PERMERROR; a single set is its intermediate; hashes
  never yield TEMPERROR. The outcome names the decisive set: the first set in
  field order whose intermediate equals the overall result.
- Single owners in `verify`: `CombineSignatureSets` (per-set status to
  intermediate, then the algebra) and `evaluateInstanceHashes`. They serve
  the current target, inherited and revision signatures, historical
  targets and run members, every history Message-Instance (each lower `h=`
  against the message recreated by the higher Recipes; below a null Recipe
  only header hashes are compared), the run descent, the headers-only DSN
  check (C40, Section 16.4 item 3: a hash-set passes on its header hash), and
  through the verifier the DSN evidence. The Draft-07 bucket rules
  (`targetStatus` pass/fail/other counters, "every known hash must match,
  unknown skipped", `revisionSignatureOutcome` precedence) are removed.
- An unknown algorithm is a PERMERROR intermediate without a key lookup. A
  locally disabled algorithm is also decided without a lookup; the reproducer
  showed `ClassifyAlgorithm` returned `KeyStatusPolicyRejected`, which did
  not pair with `SignatureSetStatusDisabledAlgorithm` and surfaced as
  `internal_contract` (and as `provider_contract` through the static
  provider). It now returns `KeyStatusDisabledAlgorithm`; the public result
  is PERMERROR `unsupported_algorithm`, and the verification observation
  event carries the bounded reason `policy` instead of `protocol` so
  operators can separate "disabled locally" from "unknown". A disabled
  algorithm in an inherited field no longer rejects the whole field before
  lookups; it is a PERMERROR intermediate like any other.
- Public reason of a non-PASS signature combination: FAIL is
  `signature_mismatch`, TEMPERROR is `provider_temporary`, PERMERROR is the
  decisive set's specific reason. The service mapping records per-set facts
  without per-set severity and adds the one combined severity; per-set public
  and REST reporting is unchanged (unknown algorithms stay `ignored` facts).
  `verify.Result.SignatureLayout`, `policy.NewGroupedSelectedProjection`,
  and the sealed policy projection carry the layout, and policy validation
  recomputes the combination instead of the Draft-07 "PASS has no failing
  set" invariants.
- Inherited key errors: the collapse into `provider_permanent` was not a
  documented privacy rule, only a coarse vocabulary. The revision proof
  outcome gains `missing_key`, `invalid_key`, `revoked_key`,
  `ambiguous_key`, `unsupported_key_type`, and `key_algorithm_mismatch`; the
  service keeps these reasons, the signing revision capability maps them to
  `provider_rejected` as before, and the policy revision-failure projection
  admits them. Sealed revision facts gain `alternative_not_passed` (with the
  key-lookup marker); lookups are counted for policy-enabled sets.
- Package 3's fail-closed rule for more than one group is lifted; the
  parsers accept `|` groups.
- Section 14.6 step 8 (selectors in error text) cannot be carried by the
  bounded Authentication-Results and reason vocabulary; FAIL per-set facts
  carry the selector as before (documented deviation).
- Changed expectations, each justified by the Draft-08 text: a supported
  pass beside an unknown set in one `,` group is PERMERROR
  `unsupported_algorithm` (Section 14.6 step 4; public golden case
  `supported_pass_plus_unknown_signature_in_group_permerror` over the frozen
  `supported_unknown_pass` vector); a pass beside a fail or a key error in
  one group is FAIL respectively PERMERROR (the internal `mixed` status is no
  longer produced); the composite-beside-Ed25519 case now depends on the
  separator (`|` PASS, `,` PERMERROR `unsupported_algorithm`), and the
  composite key is never fetched in either form.
- Tests: combination tables and a decisive-set fuzz target
  (`FuzzSignatureCombination`), real-key reproducers for every listed
  signature case, separator byte-exactness (swapping `,` and `|` breaks
  every signature), hash reproducers including headers-only, history groups,
  revision alternatives and specific key reasons, the disabled-algorithm
  reproducer, service and observation mapping.
