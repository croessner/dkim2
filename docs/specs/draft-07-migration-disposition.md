# DKIM2 Draft-07 Migration Disposition

Status: implementation authority, migration in progress

Message specification: `draft-ietf-dkim-dkim2-spec-07`, 18 October 2026

DNS companion: `draft-ietf-dkim-dkim2-dns-01`, 18 October 2026

Previous baseline: `draft-ietf-dkim-dkim2-spec-06` plus
`draft-ietf-dkim-dkim2-dns-00`

## 1. Authority and method

This document is the tracked authority for the migration from Draft-06/DNS-00
to Draft-07/DNS-01. It records every behavior change, the owning work package,
and every local interpretation. Historical audit records, reports, and earlier
migration dispositions keep their original identifiers.

The comparison used the IETF archive texts:

| Document | SHA-256 |
| --- | --- |
| `draft-ietf-dkim-dkim2-spec-06.txt` | `7b75d0ef14c6975870cff5fb1703283a798f2111e8631dd200a7c516af1a68c6` |
| `draft-ietf-dkim-dkim2-spec-07.txt` | `1b110382190c9729b6c46ab3bbc1541423c53b28841291dc6dcab90c214548bd` |
| `draft-ietf-dkim-dkim2-dns-00.txt` | `ee3e602ac2762b8f224973ebd7b350f25fba73314842281d1a4aab1b3c2d9a0f` |
| `draft-ietf-dkim-dkim2-dns-01.txt` | `3bd7fdb601efd5addc31946cf640768847e3f39b5b1208b00f41b9d2673c882e` |

Requirement strength is marked MUST/SHOULD (draft), descriptive (draft prose),
or local (product policy that is stricter than the draft).

The repository advertises the Draft-07 identifiers from the first work package
on. No release or conformance claim is made until every work package below is
complete.

## 2. Section renumbering

Draft-07 renumbers most sections. Active code comments, manifest authorities,
and issue citations use Draft-07 numbers.

| Draft-06 | Draft-07 |
| --- | --- |
| 3.4–3.6 | 3.5–3.7 (new 3.4 composite algorithm) |
| 7 Message-Instance | 9 |
| 8 DKIM2-Signature | 10 |
| 9.1–9.3 Signer actions | 12.1–12.3 |
| 9.4 Relaxed domain match | 7 |
| 9.5–9.6 | 12.7–12.8 |
| 10 Verification requirements | 13 |
| 11.1–11.7 Verifier actions | 14.1–14.7 |
| 11.8 donotmodify/donotexplode | removed (flags retired, 10.10) |
| 11.9 Unexpected replay | removed (replay is delivery policy, 15.1) |
| 12, 12.1, 12.1.1, 12.1.2 DSN | 16, 16.1, 16.2, 16.3 |
| 13 Transport conversions | 17 |
| 14 EAI | 18 |

New sections: 8 Tag=Value lists, 11 Authentic From, 12.4–12.6 signer From,
exploded and timestamp duties, 13.1–13.3 provisional verification and SMTP
codes, 14.8 From check, 15 replay.

## 3. DNS-00 to DNS-01

| Section | Change | Disposition | Package |
| --- | --- | --- | --- |
| 2.8, 3.1 | RFC 5321 `sub-domain` import; selector grammar unchanged | Selector tests for multi-label and invalid labels | 5 |
| 3.2 | Tag names case-sensitive; tval is `1*VALCHAR` | Shared tag-value audit; duplicate rejection kept | 2 |
| 3.3 | `mldsa44-ed25519-sha512` added; RSA signing MUST; rsa-sha1 MUST NOT validate | Composite key type; rsa-sha1-only never passes | 5 |
| 3.4.1 `k=`/`p=` | RSA as PKCS#1 or SPKI DER; composite raw key of 1344 bytes | Both RSA forms already parse; composite key parsing added | 5 |
| 3.4.1 `t=` | Retired; SHOULD be ignored | All `t=y`/`t=s` behavior and typed `t=` parsing removed | 6 |
| 3.4.2 | Selector is a component of `s=`; residual `q=` wording | No `q=` semantics | — |
| — | Multiple key TXT records undefined in DNS-01; PERMERROR in spec-07 §14.5 | Fail closed (existing) | 6 |

## 4. Draft-06 to Draft-07

| Section | Change | Strength | Disposition | Package |
| --- | --- | --- | --- | --- |
| 8 | Tag-list grammar: RFC 7405 case-sensitive ABNF, optional final `;`, at least one tag-spec, unknown tags ignored | MUST | Shared header tag-list scanner | 2 |
| 9, 10 | All Message-Instance and DKIM2-Signature tag names lowercase | MUST | Any uppercase tag name is PERMERROR (local interpretation, §5 D5) | 2 |
| 2.14, 9.3, 10.9, 10.10 | Hash, algorithm, and flag values case-sensitive | MUST | No case folding; uppercase spellings are unknown values | 2 |
| 5 | Recipe JSON strictness, `u` steps, decoded CR/LF ban, valid UTF-8 `d`, `c` range order, no recipes for unsigned fields, folded fields count once | MUST | Recipe parser, application, generation, and budgets | 2 |
| 3, 3.4 | Verifiers implement both hashes and all three algorithms, including `mldsa44-ed25519-sha512` | MUST | Composite verifier (§5 D1) | 5 |
| 3.2 | RSA exponent and size rules | unchanged | Regression coverage only | 5 |
| 4, 6 | Unsigned-field and hash wording | no change | Canonical inputs stay byte-identical | 2 |
| 7 | Directional relaxed domain match, null `mf` and `nd` custody, literals never match | MUST | Custody and alignment owners | 3 |
| 18 | U-label to A-label conversion before envelope recording and comparison | MUST | Shared IDNA owner (§5 D4) | 3 |
| 11, 12.4, 14.8 | Every From state from `m=1` on must be Authentic | MUST | From authenticity evaluator (§5 D3) | 4 |
| 10.6 | Bcc wording relaxed | — | Existing stricter Bcc isolation kept (local) | — |
| 10.10 | `donotmodify` and `donotexplode` removed; unknown flags have no effect | MUST | Protocol meaning and emission removed | 4 |
| 12.5 | Intermediary fanout MUST set `exploded`; `i=1` MUST NOT | MUST | Signing fanout and verifier check | 4 |
| 12–13 | No signing over invalid DKIM2; provisional versus full verification | MUST | Full synchronous verification only (§5 D8) | 4, 7 |
| 14.1–14.7 | New reasons; over-budget JSON is not malformed JSON | MUST | Error vocabulary and mappings | 6 |
| 10.4, 14.3 | Any signature older than 14 days or more than one day in the future invalidates the message; delivery time must be known | MUST | Fixed windows on every signature (§5 D6) | 6 |
| 15.1 | Replay is delivery policy | descriptive | §5 D2 | 6 |
| 16 | DSN eligibility, privacy rewrite, own-signature removal, outer `i=1` authority | MUST/SHOULD | §5 D8 | 7 |
| 17 | Network-normal form applies to the transmitted message | MUST | Adapter byte proofs | 7 |
| 13.1–13.2 | SMTP 451 4.7.5 for temporary DNS, 550 5.7.x for rejection | SHOULD | Milter and Exim mappings | 7 |
| 19–21 | IANA and security text | docs | Documentation only | 8 |

## 5. Local interpretations

**D1 Composite.** Verify per spec-07 §3.4: SHA-512 over the §12.8 canonical
input, pure ML-DSA-44 with empty context, then PureEd25519, both over the
64-byte digest. Signature is ML-DSA followed by Ed25519 (2484 bytes); DNS
`p=` is the raw ML-DSA public key followed by the raw Ed25519 public key (1344
bytes). Both halves must pass. DNS-01 references the LAMPS composite
construction, which differs; this conflict is a known external issue.
Composite signing and interoperability claims wait for working-group
clarification. RSA signing remains available.

**D2 Replay.** Equality stays at the `m=1` header and body, taken from the
`i=1`-signed `m=1` hash declarations (sha256 preferred, otherwise sha512)
instead of reconstructed bytes. A replay of one original always carries the
same declarations; the body-only description in §15.1 would additionally merge
distinct originals that share a body. Only messages with more than one
DKIM2-Signature are eligible. A detected replay is a delivery-policy result,
not a verification failure. The draft identifier change rotates the replay
epoch and secret through the existing drain procedure.

**D3 From.** The From hashed at `m=1` aligns with `i=1`; each later changed From
aligns with the lowest `i` whose `m` covers the change. A pre-entry From
restored by `r=` at `m=1` predates the DKIM2 history and receives no
authenticity assertion; a stricter reading of §2.11 exists. Exactly one From
field with exactly one mailbox; a one-mailbox RFC 6854 group is accepted.

**D4 IDNA.** `golang.org/x/net/idna` with an explicit registration-validation
profile, lowercase A-label output, no partial output, and unchanged local
parts. Known limitation: the library is not a complete strict IDNA2008
validator (it collapses the validNV8 and validXV8 categories).

**D5 Tag names.** Any uppercase tag name in DKIM2-Signature or
Message-Instance is PERMERROR, based on the §§9–10 lowercase MUST; a lenient
reading of §8 would ignore such tags. tval is read as the nonempty run
`1*(%x21-3A / %x3C-7E)` as in DNS-01 §3.2, correcting a printing defect in
spec-07 §8.

**D6 Compatibility and time.** DNS `t=` is ignored. The 14-day and +1-day
windows are protocol constants checked on every signature against a known
delivery instant. The ±5-minute revision skew is a separate fixed guard.
Configuration whose meaning disappears fails with migration guidance.

**D7 API.** The REST draft enum is exactly `draft-ietf-dkim-dkim2-spec-07`;
other drafts get HTTP 400 `unsupported_draft`. The daemon and all generated
clients ship together. Authentication-Results keep the current bounded
profile.

**D8 DSN.** Inbound outer chains are fully verified; returned-recipient
authority comes from the outer `i=1` signer. Propagation removes all own
signatures, applies the privacy rewrite, and originates a fresh singleton DSN.
No provisional-acceptance subsystem.

## 6. Work packages

1. Baseline identifiers, generated contracts, section citations, and this
   document.
2. Recipe and tag-list syntax.
3. IDNA and directional custody.
4. From authenticity and signing rules.
5. Composite verification.
6. Verification policy and replay.
7. DSN and adapters.
8. Qualification and operator documentation.

## 7. Package 1 state

Draft identifiers, versioned vector and fixture directories, the OpenAPI
`DraftVersion` enum, all generated server and client code, observability
draft values, conformance and reference tooling, and code citations now name
Draft-07 and DNS-01. Replay goldens bound to the draft identifier were
recomputed. Protocol behavior is still the Draft-06 behavior until the
following packages land.

Versioned fixture directories were renamed in place because package 1 keeps
behavior unchanged. Before a later package changes the semantics of a fixture,
it copies the Draft-06 version of that fixture to a history location named
for Draft-06, so earlier evidence is never silently overwritten.

Open follow-ups owned by later packages:

- `testdata/reference/draft-issues.json` entries whose substance changed in
  Draft-07/DNS-01 are updated by the owning package: EAI (`DKIM2-ISSUE-0003`,
  package 3), tag-name case (`0006`, package 2), DNS `k=` ABNF corrected in
  DNS-01 (`0011`, package 5), retired DNS `t=` (`0013`, package 6), multiple
  key records now PERMERROR via spec-07 §14.5 (`0014`, package 6). Stale
  `DNS-04` citations are replaced in package 8.
- Unprefixed section numbers in Markdown documentation and operator
  replay-epoch transition text are updated in package 8.

## 8. Package 2 state

- Header tag lists: the shared scanner has one header mode (`ScanHeader`) with
  an optional final semicolon and mandatory lowercase tag names, including
  unknown extensions (D5). The previous `missing_tag_terminator` code is
  removed. Canonical signature input keeps the presence or absence of the
  final semicolon of the target field exactly as received.
- Textstrings: hash, signature algorithm, and flag names are parsed through
  `tagvalue.ParseTextstring` without case folding. Uppercase spellings of
  supported names are unknown names; duplicates compare by exact spelling.
- tval needed no code change: the scanner already accepts a nonempty printable
  run with internal white space, which equals the D5 reading.
- Recipes: `u` steps (canonical base64, decoded CR/LF forbidden, valid UTF-8
  accepted), lowercase keys in every JSON object, and rejection of recipes
  for unsigned header fields. The recipe parser now requires a header
  relevance classifier. The generator emits `u` literals for body lines that
  are not valid UTF-8 instead of declaring the body unavailable.
- Test fixtures that used recipes for `X-` fields (DSN rebuild tests) now use
  signed field names. The verifier-projection encoding golden keeps its
  arbitrary header names through a permissive classifier because it locks the
  byte encoding, not recipe validity.
- Known follow-ups: interop evidence for `signature-mixed-case`
  (`tools/internal/interop/current.go`) still records the Draft-06 local
  acceptance and is re-qualified in package 8. Header `u` values that are not
  valid UTF-8 are rejected by the raw-message parser during reconstruction;
  this fail-closed limit is documented in package 8.
