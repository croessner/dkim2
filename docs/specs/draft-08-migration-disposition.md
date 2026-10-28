# DKIM2 Draft-08 Migration Disposition

Status: implementation authority, migration complete (see Section 16)

Message specification: `draft-ietf-dkim-dkim2-spec-08`, 27 October 2026

DNS companion: `draft-ietf-dkim-dkim2-dns-02`, 21 October 2026

Previous baseline: `draft-ietf-dkim-dkim2-spec-07` plus
`draft-ietf-dkim-dkim2-dns-01` (`docs/specs/draft-07-migration-disposition.md`)

## 1. Authority and method

This document is the tracked authority for the migration from Draft-07/DNS-01
to Draft-08/DNS-02. It records every behavior change, the owning change area,
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

The repository advertised the Draft-08 identifiers from the first change area
on and made no release or conformance claim until every change area below was
complete. Section 16 records the final state.

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

| # | Section | Change | Disposition | Area |
| --- | --- | --- | --- | --- |
| N1 | 2.9 | `LWSP` token removed | The parser uses FWS/WSP only; regression test | 2 |
| N2 | 3.3 | Lists five algorithms: `rsa-sha256`, `rsa-sha512`, `ed25519-sha256`, `ed25519-sha512`, `mldsa44-ed25519-sha512` (composite); RSA MUST, others SHOULD during bring-up and MUST later; `rsa-sha1` MUST NOT validate | Inconsistent with spec-08, which defines only `rsa-sha256`, `ed25519-sha256`, and `mldsa44` and dropped the composite. Spec-08 is authoritative for `s=` sig-names: `rsa-sha512`, `ed25519-sha512`, and the composite are unknown algorithms (PERMERROR intermediate). New draft issue | 6 |
| N3 | 3.3 table | Composite key type renamed `mldsa44-ed25519` in the table, while the 3.4.1 ABNF still reads `mldsa44-ed25519-sha512` | Both are unsupported key types (no composite). Draft issue | 6 |
| N4 | 3.4.1 | No key type for pure ML-DSA-44 | Local interpretation D1: `k=mldsa44`, raw 1312-octet `p=`. Draft issue and operator note | 6 |
| N5 | references | Spec reference moves to -07 | Editorial | — |

## 4. Draft-07 to Draft-08

| # | Section | Change | Strength | Disposition | Area |
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
| C44 | 1.1, 21 | DKIM2BCP, DKIMKEYS (DNS-02), RFC 8301 and 3864 references | editorial | Identifiers in area 1, documentation in area 9 | 1, 9 |
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
the evaluation algebra is enabled, the group-aware parsers fail
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
the overall result. Hash combinations never yield TEMPERROR. Section 14.6
step 8: non-passing per-set results name their selector; only the
Authentication-Results comment keeps its closed reason vocabulary (see
Section 12).

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

**D8 DSN identity.** The DSN identity change implements the Section 16.2 identity resolver:
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
stricter than Section 16.2 Provisional Verification (local, unchanged by D5). Implemented as recorded in Section 14.

**D9 Trace placement.** Adopted at SHOULD level: adapters insert this hop's
Message-Instance and DKIM2-Signature at the top of the header block (Milter
INSHEADER index 0, Exim prepend), Message-Instance then DKIM2-Signature,
directly above the previous top field, with tests for top-placed,
bottom-placed, mixed, and headers-only previous hops. Implemented as recorded
in Section 15.

**D10 RSA signing floor.** New signing credentials and loaded signing profiles
require RSA of at least 2048 bits (C2 SHOULD made a local MUST); verification
bounds stay 1024 to 8192, which cover the MUST range. Profiles below the
floor fail at load.

**D11 API.** The OpenAPI `DraftVersion` enum is exactly
`draft-ietf-dkim-dkim2-spec-08`; other drafts get HTTP 400
`unsupported_draft`. The daemon, adapters, `dkim2ctl`, the Rspamd contrib,
and external consumers move together. The replay identity space restarts,
because the draft identifier is bound into the replay frame.

## 6. Change areas

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

The `Area` columns of Sections 3 and 4 refer to this list.

## 7. Baseline identifiers state

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
  meaning a later change area changes (canonical and recipe goldens, signing,
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
- Protocol behavior stayed the Draft-07 behavior until the following change
  areas landed. Interoperability and Exim qualification remain
  `unqualified_draft08`.

## 8. Unsigned header list state

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

## 9. Combinator syntax state

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
  algorithm (the `mldsa44` credential, Section 13) starts a separate `|`
  group. With today's two algorithms the output stays one `,` group, and the
  Message-Instance `h=` emission stays one `sha256` set.
- Until the Section 14.6/14.7 algebra was enabled, a value with more than
  one group failed closed (PERMERROR `malformed_protocol`); the evaluation
  algebra (Section 10) lifted that rule.
- Fuzz targets: `FuzzSplit` (exact rejoin and layout invariants) and the
  existing parser fuzzers with group seeds and layout and unsigned-rendering
  invariants.

## 10. Evaluation algebra state

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
  through the verifier the DSN evidence. No caller gates on a group of
  implemented algorithms any more: the history walk, the run descent, the
  initial-state proofs, and the received-DSN eligibility check compute the
  implemented sets and give unknown sets a PERMERROR intermediate, so a
  mismatching set beside an unknown one in a `hash-all` group is FAIL on
  every path, as on the current target. The only precondition,
  `HashCombinationComputable`, skips digests when no set is implemented, in
  which case every intermediate and therefore the combination is PERMERROR.
  The combined outcome maps FAIL to the history `mismatch` dimension and the
  `hash_mismatch` stop (run descent and rebuild `hash_mismatch`), and
  PERMERROR to `unsupported` and `unsupported_hash`. The Draft-07 bucket rules
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
- The combinator syntax's fail-closed rule for more than one group is lifted; the
  parsers accept `|` groups.
- Section 14.6 step 8 (selectors in error text): superseded by Section 12;
  every non-passing per-set fact now carries its selector.
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

## 11. Verification states and reasons state

- C16 to C18, C26, C28 to C31, C35 (D5): `policy.ProtocolForVerificationReason`
  is the single owner of the Section 14.1 state of every verification reason.
  The service mapping (`service.StateForReason` and the check-fact severities),
  the revision-failure mapping, the service error mapping, the public
  `VerifyResult.Valid` invariant, and the policy projection invariants
  (`verificationReasonProtocolCoherent`, `revisionFailureProtocolReasonAllowed`)
  all derive from it. FAIL (completed, not Fully Verified): `hash_mismatch`,
  `signature_mismatch`, `timestamp_invalid`, `envelope_mismatch`,
  `domain_alignment_mismatch`, `next_domain_mismatch`, `custody_mismatch`,
  `out_of_band_required`, `from_not_authentic`, and `body_history_unavailable`.
  TEMPERROR is only `provider_temporary`. Every other reason is PERMERROR.
- C12: signature and instance sequence gaps and duplicates stay PERMERROR
  `sequence_invalid`. Section 14.2 calls such a message "not Fully Verified",
  but the condition is structural and no target can be selected (local
  interpretation, unchanged).
- Chain of Custody (Section 14.4): `validateCustodyChain` failures were raised
  without an instance number and therefore collapsed into the pre-target
  PERMERROR `malformed_protocol`. They are now bound to the already selected
  target (`verify.Error.SelectedTarget`) and reported as FAIL for that target:
  an `mf=` or `d=` that does not match the previous `rt=` is the new public
  reason `custody_mismatch`; an `nd=` that does not match the next `d=` or an
  unexpected `nd=` transition keeps the existing, more specific
  `next_domain_mismatch` (the plan grouped these under `custody_mismatch`;
  both are FAIL, and the existing reason would otherwise be unreachable); an
  inherited signature whose MAIL FROM and `d=` do not relaxed-match is
  `domain_alignment_mismatch`, the same reason the current target uses. The
  verifier stops before any key lookup, in the Section 14 order where custody
  precedes key retrieval, and seals `policy.NewChainFailureProjection`: a
  selected FAIL projection without signature facts or authenticated hops, so
  no flag-derived finding can come from unverified fields. A custody error
  without a selected target stays PERMERROR `malformed_protocol` (fail
  closed). The defensive custody-entry guards for forms the parser already
  rejects also report `custody_mismatch`; they are unreachable from parsed
  fields.
- A terminal `nd=` without an out-of-band arrangement is a failing target in
  the core (`TargetStatusFail`) and FAIL `out_of_band_required` in the
  service, also when a signature set is temporarily unavailable.
- Precedence: severity order stays PERMERROR over FAIL over TEMPERROR over
  PASS. A remapped check failure therefore no longer hides a supported
  signature failure behind PERMERROR, and a permanent key error still wins over
  a timestamp or custody failure.
- D6 Recipes: `verify` splits the history parse stop into
  `HistoryStopRecipeInvalid` (JSON syntax, duplicate member, non-object root,
  owned by `recipe.IsJSONSyntaxError`) and `HistoryStopRecipeSchemaInvalid`.
  Schema, step, range, literal, and application failures are the new
  PERMERROR reason `invalid_recipe` (`RevisionProofInvalidRecipe`); before,
  schema failures were `invalid_recipe_json` and application failures
  `malformed_protocol`, both PERMERROR. A non-lowercase decoded Recipe key is
  therefore `invalid_recipe`. Complexity stays `limit_exceeded`. Deliberate
  deviation from the Section 14.2 SHOULD: Recipe step text is never placed in
  errors, logs, REST, or CLI output; `recipe.Error` carries only the step
  index, member index, step kind, dimension, and code.
- D7 null Recipe: the all-hop proof refuses a history that crossed a `b:null`
  Recipe (`RevisionProofBodyHistoryUnavailable`), after every inherited
  signature passed (hash evaluation follows signatures in Section 14), and a
  copy from unavailable body state below the null Recipe maps to the same
  outcome. The service reports FAIL `body_history_unavailable` in current
  scope instead of PASS with `partial` content history; `attachRevisionProof`
  treats a verified proof that still carries the gap as an internal contract
  defect. The signing revision gate maps the outcome to `protocol_rejected`,
  so `Signer.VerifyForRevision` issues no capability and transit or revision
  signing (`dkim2d` revise, batch revision) refuses the message (Section 12).
  `AllowUnavailableBody` stays for a signer's own hop (Section 12.1 MAY) with
  a documentation warning. There is no acceptance knob. The `partial`
  historical content and `indeterminate` feedback coverage values remain in
  the closed vocabularies and OpenAPI but are no longer produced.
- Disposition proof: `lib/verification_disposition_test.go` derives, for every
  public reason and every policy mode, the only state the sealed result and
  projection invariants admit and the evaluated verdict, policy primary
  reason, and action. Against the table recorded before the change, verdicts
  and actions are byte-identical for every existing reason; the rows that
  changed deliberately are `timestamp_invalid`, `envelope_mismatch`,
  `domain_alignment_mismatch`, `next_domain_mismatch`, `out_of_band_required`,
  and `from_not_authentic` (state PERMERROR to FAIL, strict primary reason
  `protocol_permerror` to `protocol_fail`), plus the new rows
  `custody_mismatch` (FAIL), `invalid_recipe` (PERMERROR), and
  `body_history_unavailable` (FAIL). Message level: Chain of Custody
  adjacency failures move from PERMERROR `malformed_protocol` to FAIL
  `custody_mismatch` with the same verdicts; Recipe schema and application
  failures move between PERMERROR reasons; a null body Recipe history moves
  from PASS (strict accept) to FAIL (strict reject, permissive accept by
  override, testing continue), the one deliberate verdict change.
- Adapters: Milter and Exim SMTP outcomes depend only on the daemon
  disposition; `TestProcessSMTPOutcomeIsIndependentOfFailOrPermerror` in both
  adapters proves that every reason yields the same outcome, reply, and
  temporary-key flag as FAIL or PERMERROR in every mode. Authentication-Results
  admit the new reasons through `dkim2.ReasonCode.Known`.
- Vocabularies: the public `ReasonCode`, service and policy reasons, the
  OpenAPI `VerificationReason` and `AuthenticationResult.primary_reason`
  enums (`PolicyReason` is unchanged), the `VerificationState` and
  `historical_content` descriptions, every generated server and client, the
  daemon mapping, the Rspamd contrib vocabulary and its test, and the
  documentation carry `custody_mismatch`, `body_history_unavailable`, and
  `invalid_recipe`. `dkim2ctl` fixtures carry no reason or state that changed.
- Changed expectations, each required by Draft-08: public golden cases for
  timestamp, envelope, alignment, From-authenticity, and terminal `nd=`
  vectors expect FAIL (cases renamed from `_permerror` to `_fail`); the
  custody facade, service, and core tests expect FAIL `custody_mismatch` /
  `next_domain_mismatch` for the selected target; the null-body revision and
  replay tests expect the refusal instead of a verified proof.

## 12. Signature-set selectors state

- Section 14.6 step 8 ("human-readable text for any error SHOULD provide the
  relevant Selector values"): Section 14.6 step 8 is implemented through the per-set results: every
  non-passing signature set (fail, permerror including key errors and unknown or
  locally disabled algorithms, temperror, ignored) carries its parsed selector in
  the library `SignatureSetFact.Selector` and the REST `SignatureSetResult.selector`.
  The remaining, narrow deviation is that the Authentication-Results comment keeps
  its closed `(reason=<code>)` vocabulary, which downstream parsers (Rspamd,
  mailstack, dkim2-intelligence) depend on; selector values are not placed there.
- Owner: `verify` attaches the parsed selector (DNS-label syntax enforced by
  the signature parser, never raw header bytes) to every set result; the
  service per-set mapping (`signatureSetFact`) exposes it for every non-passing
  fact, and `service.SignatureSelectorCoherent` is the single presence rule
  (pass and `internal_contract` without selector, every other status with one
  bounded selector). The public `VerifyResult` invariant delegates to it; the
  daemon REST mapper, the Milter and Exim response admission, and `dkim2ctl`
  re-check the same rule at their boundaries. Formatting a
  `SignatureSetFact` is now redacted, so selectors leave the library only
  through the explicit accessor and the REST field.
- Selectors are never metric labels and never part of the
  Authentication-Results value. The OpenAPI `SignatureSetResult.selector`
  description changed; its pattern and length bounds are unchanged, and all
  generated servers and clients were regenerated.
- Tests: library per-set presence for pass, fail, missing key, temporary
  provider failure, and unknown algorithm; REST JSON goldens for pass,
  permerror, and temperror sets; boundary rule tests in Milter, Exim, and
  `dkim2ctl`.

## 13. ML-DSA-44 and key state

- C1, C32, N2 to N4: pure ML-DSA-44 (`mldsa44`) is verified and signed.
  Spec-08 Section 3.4: "the field values are input directly into the
  signature algorithm without being hashed first", and the five octets
  `DKIM2` are the context string for signing and verifying; this matches the
  plan. `lib/internal/cryptodkim2` is the single owner of the message
  representative (`MessageRepresentative`): SHA-256 of the Section 12.8 input
  for `rsa-sha256` and `ed25519-sha256`, the complete input for `mldsa44`.
  Signer (`signing`), verifier (`verify`, including revision and history
  paths), and the signer's completion self-check use it. `MLDSA44SignerOptions`
  owns the context string; custody signers call the hedged `crypto/mldsa`
  `Sign`, never `SignDeterministic`.
- Sizes are exact: a 1312-octet public key (any other length, an SPKI
  wrapper, or another parameter set is `invalid_key`, Section 14.5
  "malformed") and a 2420-octet signature (any other decoded length is
  `invalid_signature_length` at parse time, the same malformed-field
  classification as a wrong-length Ed25519 value). The single 1024-octet
  signature cap became per-algorithm bounds: RSA 1024 (8192-bit modulus),
  Ed25519 64, ML-DSA-44 2420; the generated-field and private-callback
  ceilings are 2420 and may not be narrowed below it.
- DNS: `k=mldsa44` with the raw key in `p=` is the local interpretation
  `DKIM2-ISSUE-0020`; `h=` is ignored; `k=`/algorithm disagreement in either
  direction is `key_algorithm_mismatch`. DNS-02's extra algorithm names
  (`DKIM2-ISSUE-0021`) and its inconsistent composite key-type spelling
  (`DKIM2-ISSUE-0022`) are recorded; both composite spellings are
  unsupported key types. `DKIM2-ISSUE-0019` is superseded by the baseline.
- Runtime guard: `cryptodkim2.MLDSA44Available` probes `crypto/mldsa`. Built
  against the FIPS 140-3 Go Cryptographic Module v1.0.0 (no ML-DSA), verifier
  policy validation rejects `mldsa44` (`unsupported_algorithm`), `mldsa44`
  credentials fail with `unsupported_algorithm`, and `dkim2d serve` and
  `dkim2d validate` refuse to start with a fixed diagnostic before loading
  configuration. `make test-fips140-mldsa44` runs these guards under
  `GOFIPS140=v1.0.0` as part of `make test`.
- Signer layout: the existing fixed layout puts `mldsa44` in a separate `|`
  group after the classical `sig-all` group; all values cover the same
  unsigned field. Proven end to end with real keys: all three algorithms
  pass; a verifier with `mldsa44` disabled by policy passes through the
  classical group; a verifier allowing only `mldsa44` passes through its
  group; an `mldsa44`-only profile emits one group. Profiles reject duplicate
  selectors across every group.
- Public API: `PrivateKeySignRequest.MessageRepresentative` (the deprecated
  `Digest` returns nil for `mldsa44`), mldsa44 credential, profile, and
  next-domain constructors, the sealed `SigningCredential` with
  `NewSigningProfile`, `FoundMLDSA44PublicKey`,
  `PublicKeyResult.MLDSA44PublicKey`, `MLDSA44SignerOptions`, and
  `MLDSA44Available`; observation, service, and policy algorithm vocabularies
  append `mldsa44` without renumbering. Breaking changes are listed in
  `docs/reference/compatibility.md`. OpenAPI `SignatureSetResult.algorithm`
  and `VerifierHop.signature_algorithms` gain `mldsa44`; every generated
  artifact and the Rspamd vocabulary were regenerated or updated.
  `VerifierHop.signature_algorithms` also drops the never-produced
  `rsa-sha512` and `ed25519-sha512` (a hop lists only verified Draft-08
  Section 3 algorithms; DNS-02 listing them is `DKIM2-ISSUE-0021`) and
  bounds the array at three items in OpenAPI, the daemon, dkim2ctl, and
  the Rspamd adapter.
- Custody: `cmd/dkim2d/internal/signingstore` loads the seed-only PKCS#8 form
  (exact `crypto/x509` re-marshal, ML-DSA-44 parameter set, nonzero seed),
  derives the SPKI and matches it against the stored credential, generates
  keys from a 32-byte seed of the injected reader, and signs hedged. The seed
  and expanded key live inside `crypto/mldsa` and cannot be zeroized; only
  owned DER and seed buffers are cleared (documented gap).
- Interop with `opendkim-manage-go` (commit f9148dc): a credential produced by
  its `dkim2model.GenerateKeyPair` code path (seed-only PKCS#8, PKIX SPKI,
  `v=DKIM1; k=mldsa44; p=...` without `h=`, the raw DER values it writes to
  `dkim2PrivateKeyPKCS8` and `dkim2PublicKeySPKI`) loads through the shared
  native custody codec, signs, and verifies against its DNS record through
  the DNS key provider; the dkim2d DNS export renders the identical record.
  LDAP needs no schema change.
- Datasource limits: three credentials per profile. Each credential needs
  its own key handle (providers reject a shared handle as ambiguous), so the
  handle ceilings are derived as `profiles * 3`: 3072 (default, previously
  2048) and 98304 (production, previously 65536); the previous values could
  not load a fully populated three-credential installation. Record ceilings
  `1024*3 + 1024 + 3072 + 4096 = 11264` and
  `32768*3 + 32768 + 98304 + 65536 = 294912`, both within the hard limits.
  The hard limits follow the same derivation: `131072*3 = 393216` handles
  (previously 262144, which could not hold three credentials for every hard
  profile) and `131072*3 + 131072 + 393216 + 262144 = 1179648` records
  (previously 1048576). A reproducer loads `MaxProfiles`
  three-algorithm profiles with distinct handles and `MaxPolicies` policies
  under both profiles.
  Memory, flat-file, LDAP, and the shared SQL snapshot mapper (PostgreSQL,
  MySQL, MariaDB) accept the same three-algorithm profile and reject it under
  a two-credential bound. Forward migration `010_mldsa44_algorithm.sql`
  (PostgreSQL, MySQL/MariaDB) widens the algorithm constraints and is wired
  into `scripts/test-datasource-services.sh`.
- Tools: `dkim2d datasource key generate --algorithm mldsa44`, the DNS
  export, onboarding selectors (`d2m-`), rotation campaign selectors (`m`),
  and the domain report (`mldsa44_credential_count`, additive within
  `dkim2-domain-report-v1`) handle the algorithm.
- Tests: a known-answer vector (fixed seed, deterministic signature with ctx
  `DKIM2` reproduced byte for byte by OpenSSL 4.0.3, plus an OpenSSL hedged
  signature verified by the shared verifier), wrong-length key and signature
  reproducers, a 3228-character `s=` headerfold round trip, fuzz seeds,
  phased-deployment and three-algorithm facade round trips, provider parity,
  the opendkim-manage-go interop proof, migration contracts, and the FIPS
  v1.0.0 fail-closed guards.
- C2: the RSA signing floor is 2048 bits (`cryptodkim2.MinSigningRSABits`,
  public `dkim2.MinSigningRSABits`). `signing.NewCredential`, used by the
  public RSA credential constructor and the datasource-to-signing projection,
  rejects smaller keys with `key_mismatch` and the detail
  `limit_name=min_rsa_bits limit=2048 actual=<bits>`; `Credential.Valid`
  re-checks it, so a profile holding such a key fails at load. `dkim2d`
  custody (native datasource key material, flat-file PEM keys, legacy
  import) and key generation enforce the same floor. Verification bounds stay
  1024 to 8192 bits, covering the Section 3.2 MUST range; tests prove both
  sides. Test fixtures that signed with 1024-bit keys moved to 2048 bits,
  including the public-facade RSA fixture and the candidate-digest golden.

## 14. Delivery-status signing identity state

- C8, C21, C38 to C40 and the reviewed DSN identity interpretation of
  Section 5: no From replacement and no new adapter action. The normative basis, quoted from
  spec-08:
  - Section 16.2: "When creating a DSN there MUST be a relaxed domain match
    between the Signing Domain (placed into the d= value of the
    DKIM2-Signature header field of the DSN) and a recipient address in the
    rt= value of the highest numbered DKIM2-Signature header field of the
    message being reported upon (see Section 7.1 Item 4)."
  - Section 7.1 item 4: "Signers of DSNs use this match when choosing d=" and
    "The (decoded) value from rt= is Parameter1 to the algorithm, the d=
    value is Parameter2." Section 7.2 steps 3 to 5 remove labels only from
    the left of Parameter1, so `d=` must equal the `rt=` domain or a parent.
  - Section 12.4: "the Signing Domain MUST be chosen so that the From header
    field in the message will be Authentic (see Section 11)" and "If no
    Signing Domain can make the From header field Authentic, the message
    cannot ever be a Fully Verified DKIM2 Message." Section 11: "A From
    header field is Authentic when there is a relaxed domain match (see
    Section 7) between the email address in the From header field and the
    Signing Domain found in the d= tag".
  - Section 16.3: "The resultant DSN is sent to the MAIL FROM address from
    the now highest numbered DKIM2-Signature header field. The DSN itself
    MUST have only one DKIM2-Signature field and only one Message-Instance
    header field: i.e. it is a new message."
- Owner: `Signer.ResolveDSNSigningIdentity` (`lib/delivery_status.go`) over
  `dsn.Evidence.SigningIdentityCandidates` (`lib/internal/dsn/identity.go`).
  Candidates are the `rt=` domains of the highest embedded DKIM2-Signature
  and their parents, each admitted by `signature.RelaxedDomainMatch`, the
  existing single owner of Section 7.2 (also used for custody, Section 14.4
  alignment, Section 16.4 item 1, and From authenticity). Order: candidates
  of RFC 3464-linked recipients (Final-Recipient or decoded
  Original-Recipient) first; within that tier `reporting_domain` first when it
  is itself a candidate; then more labels first; then ascending octet order.
  At most 64 candidates (`dsn.MaxSigningIdentityCandidates`). The first
  candidate with a local `delivery_status` profile whose domain makes the
  report From Authentic (`verify.FromAuthenticFor`) is bound; `SignDSN`
  accepts only bound evidence and the matching profile.
- Removed: the derived identity "embedded highest `d=`"
  (`DSNSigningEvidenceRequest.deriveIdentity`, `dsn.Evidence.SigningDomain`)
  and the reporting identity that signed regardless of `rt=`. The public
  constructors `NewDerivedDSNSigningEvidenceRequest`,
  `NewPostfixDerivedDSNSigningEvidenceRequest`, and
  `NewPostfixReportingDSNSigningEvidenceRequest` are gone;
  `NewDSNSigningEvidenceRequest` takes no identity,
  `NewPostfixDSNSigningEvidenceRequest` and `WithPreferredIdentity` are new.
- Outcome "not DKIM2 signed": no candidate with a profile is the library
  stage `identity_unavailable`; candidates with a profile but no Authentic
  From is `from_not_authentic`. `dkim2d` maps them to the unsigned
  assessment: `POST /v1/dsn/sign` answers 204 with the new required header
  `X-DKIM2-Unsigned-Reason` (`delivery_status_identity_unavailable`,
  `delivery_status_from_not_authentic`; the existing compatibility outcome is
  `unsigned_original`). The Milter `postfix_dsn` adapter and `dkim2ctl`
  require exactly one closed reason and continue without mutation (accept
  without signature); neither outcome tempfails or rejects mail. The Exim
  adapter has no DSN signing route, so nothing changes there. Provider
  not-found, inactive, or invalid-domain answers count as absence; malformed
  profile data or a profile for another domain is a permanent refusal; an
  unavailable or ambiguous provider is temporary.
- Metric: `dkim2d_dsn_unsigned_total{unsigned_reason}` and the log event
  `dsn.unsigned.completed`, emitted through the central observability
  runtime; the label is the closed three-value reason vocabulary only.
- Configuration: the stable path
  `signing.policy.delivery_status.reporting_domain` keeps its syntax and
  validation; its meaning changed from "signing identity" to "preferred
  candidate when matching". The behavior change and migration notes are in
  `cmd/dkim2d/README.md` and `docs/operator/postfix-compose.md` (Postfix
  `MAILER-DAEMON@$myorigin` must sit at or below the DSN signing domain;
  multi-domain hosts get signed DSNs only for recipient domains under a
  matching profile; expected unsigned share).
- Propagation (Section 16.3): the propagated report is signed by the
  completion `d=`, and the rebuilt report's highest signature is the
  previous hop, so that `d=` must relaxed-match the previous hop's `rt=`.
  `classifyPreviousHop` refuses otherwise with the new propagation value
  `forbidden_identity_misaligned` (library `ReceivedDSNPropagation`, OpenAPI
  `DeliveryStatusProjection.propagation`, Rspamd vocabulary, propagation
  matrix `pass`/`discard`, propagator outcome
  `discarded_identity_misaligned`). Fixtures whose run members used sibling
  domains were moved under the completion domain; the received-DSN and
  propagation golden corpora gained one misaligned case each and were
  regenerated.
- Sender-side bounce: the highest embedded signature is ours and its `rt=` is
  remote, so Section 16.2 can never be satisfied while Section 16.2 also
  requires "appropriate Message-Instance and DKIM2-Signature fields". The
  report leaves unsigned (`delivery_status_identity_unavailable`), recorded as
  `DKIM2-ISSUE-0023`.
- Kept local rule: DSN evidence still requires the embedded current target to
  PASS. Section 16.2 says "The assurances in this section depend on the
  message being reported upon having been Provisionally Verified", so this
  gate is stricter than the draft and stays local policy (pass/non-pass was
  not changed by the states and reasons remap).
- Postfix qualification: the core lane now bounces one message to a failing
  recipient under the local profile domain (`failed.origin.example.test`),
  whose report must be signed with `d=origin.example.test`, and one to a
  remote failing recipient, whose report must be delivered without
  Message-Instance or DKIM2-Signature (new case
  `postfix_sender_side_bounce_unsigned`).
- Tests: candidate order (relaxed-match direction, longest domain,
  RFC 3464-linked recipients, reporting domain only when matching,
  determinism and bound), the library resolver (rt=-matching profile A signs
  although `reporting_domain` is B, longest profile, linked recipient, no
  matching profile, From mismatch and multi-address From, sender-side bounce,
  profile source failures, unresolved evidence refused by `SignDSN`), the
  daemon route (unsigned reasons, observation, absent/inactive/malformed/
  ambiguous/unavailable profiles), REST 204 header mapping and OpenAPI
  contract, Milter and `dkim2ctl` reason admission, propagation refusal
  (internal, library, golden vectors, propagator outcome).

## 15. Header field placement state

- C11, D9. The normative basis, quoted from spec-08:
  - Section 9: "The Message-Instance header field is a trace header field
    (see Section 3.6.7 of [RFC5322])."
  - Section 10: "The DKIM2-Signature header field is a trace header field
    (see Section 3.6.7 of [RFC5322])."
  - The IANA registrations in Section 19 mark both fields "Trace: yes".
  - Spec-08 contains no placement sentence of its own: no "top", "prepend",
    or position rule for either field and no order between them. The
    placement rule is inherited from RFC 5322 Section 3.6: "the trace header
    fields and resent header fields MUST NOT be reordered, and SHOULD be kept
    in blocks prepended to the message." Top placement is therefore SHOULD;
    the MUST NOT applies to reordering existing trace fields, which no
    adapter does. RFC 5322 Section 4.5 leaves the interpretation of trace
    fields outside prepended blocks unspecified, so a bottom-placed field is
    still a valid field.
  - Placement is outside the signed input: Section 6.2 sorts header fields by
    lower-cased name before hashing, and Section 12.8 selects the target by
    `i=`. Verifiers must not depend on position, and this implementation's
    verifier does not.
- Final top-of-header order for one signing hop, top-down: this hop's
  Message-Instance (when one is added), this hop's DKIM2-Signature, any
  `X-DKIM2-Info` diagnostic field, then the previous top field. The daemon
  action plan already lists the fields in this order; it is the top-down order
  of the hop block. The block is one unit and is never interleaved. The
  Message-Instance above DKIM2-Signature order is a local choice (the draft
  orders neither); it matches the plan order and the existing adapter
  validators. `X-DKIM2-Info` moved into the block so a Section 16.3 rebuild
  removes it with the local hop's other unsigned fields.
- Postfix (Milter). Each field is sent with SMFIR_INSHEADER index 0, in
  reverse plan order, so the queued result is the block above in plan order.
  Postfix `cleanup_milter.c` maps Milter index `n` to its own one-based index
  `n + 1`. Index 0 lands above Postfix's own Received field, which Milters
  never see; index 1 lands directly below it. After the first insert above
  that field, Postfix treats it like any other field, so later index 0
  inserts also reach the top. Postfix-generated messages (bounces via
  `post_mail`, local `pickup`) start with the same hidden Received field.
  Resulting queued orders:
  - Milter-signed SMTP or local submission: `Message-Instance`,
    `DKIM2-Signature`, `Received` (Postfix), then the submitted fields.
  - Postfix bounce signed by `postfix_dsn`: `Message-Instance`,
    `DKIM2-Signature`, `Received` (Postfix bounce), then the report fields.
  - Inbound verification of that message at the next Postfix:
    `Authentication-Results`, `Received` (inbound Postfix), then the previous
    hop's block. Authentication-Results keeps its existing SMFIR_INSHEADER
    index 0 placement.
  SMFIF_ADDHDRS authorizes both SMFIR_ADDHEADER and SMFIR_INSHEADER. The
  adapter already required it, so the negotiation is unchanged; an MTA that
  withholds it is refused at negotiation, before any message data (fail
  closed). The observed Milter action label for signing changed from
  `add_header` to `insert_header`; both values were already on the closed
  label allowlist.
- Exim (transport filter). `filter.TransformLimited` prepends the block at
  byte offset 0 of the transport message, above Exim's own Received field,
  and copies every inherited byte unchanged after it. This also covers an
  empty header block and header-only messages. The `local_scan` inbound
  Authentication-Results placement (`header_add_at_position` at the top) is
  unchanged. The Exim real-matrix scripts check the Message-Instance then
  DKIM2-Signature order, which top placement keeps.
- Owner: the daemon action plan carries no position field and the
  `add_header` enum is unchanged; the generated `ActionPlan` schema now
  documents the top-down block order and the SHOULD-level top placement.
  Placement is applied by each adapter with its MTA primitive.
- Library complete-message outputs (resolved): `rawmsg.PrependValidatedFields`
  is the single library owner of whole-message placement. It writes the
  generated fields as one block at byte offset 0 in generated order
  (Message-Instance, then DKIM2-Signature) and proves that the block holds
  the leading field positions and that every inherited field, the framing,
  and the body follow byte for byte. This covers the unrestricted and
  released signing results' `Bytes()`, every daemon result that carries
  library bytes, and the propagated DSN that `dkim2-dsn-propagator` relays.
  `X-DKIM2-Info` is a daemon diagnostic action and is never part of a
  library message. The Exim filter keeps its own one-step prepend: it writes
  daemon action values (fold points restored, LF line ends) into an Exim
  transport stream and imports no library internals, so sharing the rawmsg
  owner would need a new public API for a single concatenation; the shared
  rule is the plan order, which the daemon owns.
- Completion proof: the signing self-check bound this hop's
  DKIM2-Signature to the last physical DKIM2-Signature occurrence and
  required the generated fields to follow every inherited protocol field.
  Both assumptions encoded bottom placement and failed top-placed output with
  `protocol_tampering`. `proveCompletedProtocolFields` now identifies this
  hop's fields by the plan's new `m=` and next `i=`, requires them to equal
  the generated fields byte for byte and in generated order, and requires
  every other protocol field to equal the source protocol fields byte for
  byte and in source order. The Section 12.8 target is located through its
  own header occurrence index. The header-field count, hash, custody,
  reference, and cryptographic checks are unchanged. A forged extra
  DKIM2-Signature or Message-Instance anywhere in the header, an altered or
  internally reordered generated block, and a reordered inherited chain all
  still fail with `protocol_tampering`; the proof accepts the block at the
  top, at the bottom, and between inherited fields.
- `/v1/revise/batch` (REST behavior change): `insertion_offset` is now always
  0 (`minimum: 0`, `maximum: 0`), the start of the current message. The
  field stays required, so the wire shape is unchanged. `header_fields_base64`
  lists the fields in top-down order; with a controlled intermediate hop the
  final hop's DKIM2-Signature precedes the intermediate hop's
  Message-Instance and DKIM2-Signature, and a Message-Instance may appear
  only directly before the final DKIM2-Signature (previously only at index
  0). The daemon's own response validation enforces both rules.
- DSN rebuild (Section 16.3). The rebuild removes the local hop's
  DKIM2-Signature fields by `i=`, its Message-Instance fields by `m=`, and
  every hash-excluded field above the previous hop's DKIM2-Signature. The
  logic is unchanged and does not depend on placement. Top placement of the
  previous hop keeps that hop's own Received fields, because only fields
  added after arrival sit above its signature. With a bottom-placed previous
  hop every unsigned field sits above it, so the rebuild also removes
  unsigned fields that were present on arrival. That is safe, because
  Section 4 excludes them from every hash, and within the Section 16.3
  "good faith effort SHOULD" removal.
- Postfix qualification: `validateTopTraceOrder` pins the queued top-of-header
  names for the SMTP origin, local submission, Milter-signed bounce, and
  inbound cases above, and for the propagated notice: the Milter-free
  re-injection listener's `Received`, then `Message-Instance`,
  `DKIM2-Signature`, and the rebuilt report's `From`. `run.sh` had a stale config identity for
  `golang:1.27.3-trixie@sha256:604106...`: the Go 1.27.3 move updated the
  index digest but kept the Go 1.27.2 config digest (`sha256:99668476...`).
  The registry index resolves to the linux/amd64 manifest
  `sha256:8aa28219...`, whose config is
  `sha256:8f320504681311625326bbcea73247b25857f43e74098ddcb4a589192c024e5d`.
  That is now the pinned identity. The digest, identity, and platform checks
  are unchanged. The harness also generated 1024-bit RSA signing keys, which
  the 2048-bit signing floor (Section 13, D10) made the daemon refuse; it now
  generates keys at `dkim2.MinSigningRSABits`. With both fixes the core lane
  passes on Postfix 3.11.7 with the placement pins.
- Tests: Milter reproducer for SMFIR_INSHEADER index 0 in reverse plan order
  for originator, reviser, forwarder, and delivery-status plans; negotiation
  refusal without SMFIF_ADDHDRS; the portable Milter fixtures and the
  public-socket matrix updated to inserts; Exim prepend tests for Received,
  header-only, empty header block, and binary body; library verification of
  library-placed, top-placed, bottom-placed, and mixed chains, with a Reviser
  signing over top-placed and bottom-placed predecessors; DSN rebuild with
  both hops top-placed, both bottom-placed, both mixed orders, and a
  headers-only rebuild; rawmsg prepend for normal, header-only, and folded
  internationalized messages; completion-proof placement independence and
  tamper rejection; the batch revision offset and top-down field order.
- Vectors: the two `signing-golden.json` insertion digests were re-derived
  independently as SHA-256 over generated fields followed by the inherited
  bytes, matching the `manual_derivation` provenance; the 20 signed reports
  of `dsn-propagation-golden.json` were regenerated with
  `DKIM2_WRITE_DSN_PROPAGATION_VECTORS=1`, and the corpus test now verifies
  every frozen report PASS under the published keys and checks its leading
  trace block. Inputs and the frozen history copies are unchanged.

## 16. Final state

Every change area of Section 6 is implemented; the repository behavior is
Draft-08 plus DNS-02. The operator upgrade, rollback, and the consumers that
move together are in `docs/operator/draft-08-migration.md`; the library API
delta and the reviewed API base are in `docs/reference/compatibility.md`.

Closeout corrections found by running every gate against the finished
migration:

- Postfix propagation lane (`propagation_not_local`): the harness's foreign
  notification reported a message addressed to the local final recipient,
  so the foreign delivery-status `d=` could not relaxed-match its `rt=` and
  the daemon correctly left it unsigned under Section 16.2. The fixture was
  wrong, not the product: the foreign message is now addressed under the
  foreign delivery-status profile domain, a unit test pins that topology,
  and the lane classifies the completion signature as `not_local` again.
- Conformance runner freeze: the portable evidence count is 100, because
  the two `mldsa44` manifest cases have real producers. The tools module
  tests were outside every gate; `make test-tools` now runs them in
  `make guardrails`.
- Rspamd Policy E2E fixtures: the verifier projection binding covers the
  draft identifier, so the Draft-07 bindings were stale. They were
  regenerated with the producer's binding functions for all three
  binding-bearing responses, and `make check-rspamd-projection-binding`
  locks them in `make guardrails`.
- Datasource hard limits follow the one-handle-per-credential derivation:
  393216 handles and 1179648 records for 131072 profiles (Section 13).
- `VerifierHop.signature_algorithms` lists only `rsa-sha256`,
  `ed25519-sha256`, and `mldsa44` (at most three); `rsa-sha512` and
  `ed25519-sha512` were never produced (Section 13).
- Live datasource integration (`make integration-datasources`), which runs
  migration 010 against the pinned LDAP, PostgreSQL, MySQL, and MariaDB
  servers: its SECURITY DEFINER allowlists predated the rotation campaign
  and terminal closure routines (`purge_generation`,
  `campaign_candidate_generation_is_forward`, `dkim2_v3_purge_generation`,
  `dkim2_v3_record_campaign_terminal`), and the report carried a fixed base
  revision that the reference validator, which requires the checked-out
  `HEAD`, rejects on every other commit. The allowlists now name those
  routines with their exact kind, arguments, and grants (one shared
  PostgreSQL list for the routine and ACL audits), and the report binds
  `git rev-parse HEAD`.
- Terminology: active documentation, code comments, and the agent skills use
  "Fully Verified DKIM2 Message"; historical records keep "Validly Signed".
- Reviewed library API base: `testdata/reference/go-api-base.json` and the
  checker's bound revision moved to the Draft-08 surface; every removed,
  added, or changed root declaration since the previous base is listed.

Draft issues: `DKIM2-ISSUE-0019` is superseded by the baseline;
`DKIM2-ISSUE-0020` (`k=mldsa44`), `DKIM2-ISSUE-0021` (DNS-02-only algorithm
names), `DKIM2-ISSUE-0022` (composite key-type spelling), and
`DKIM2-ISSUE-0023` (sender-side bounce) are implemented interpretations,
recorded identically in `testdata/reference/draft-issues.json` and
`docs/reference/draft-issues.md`.

Evidence on the final tree:

- `make release-guardrails` (guardrails including `make test-tools` and
  `make check-rspamd-projection-binding`, `govulncheck` with no called
  vulnerability, `make check-conformance`, and the portable `make
  conformance` report): pass.
- `make check-reference` with the moved API base: pass.
- `make integration-datasources` on the pinned LDAP, PostgreSQL, MySQL, and
  MariaDB images, migration 010 included: pass, report published.
- `contrib/qualification/postfix-milter/run.sh --lane all
  .artifacts/conformance-postfix` (core and propagation lanes, two
  identical runs): pass.
- `make test-valkey`, `make check-security`, `make test-exim-local-scan`,
  `make check-exim-matrix-prep`, `contrib/rspamd/tests/run.sh`, and the
  Policy E2E Python tests: pass.

Open points that remain outside this repository or this migration:

- Exim stays `unqualified_draft08` until a fresh five-row Draft-08 real-matrix
  run; external interoperability peers are not requalified.
- The full Rspamd Policy E2E lane (`contrib/rspamd/tests/run-policy-e2e.sh`)
  needs the external Nauthilus and `miltertest-go` checkouts; its
  repository-local parts (projection binding lock, Lua contract tests,
  Python observer and probe tests) pass.
- Rollout of the consumers that move together (mailstack Rspamd adapter and
  pins, `dkim2pub`, `dkim2-intelligence`) and ML-DSA-44 production keys
  follow the release.
