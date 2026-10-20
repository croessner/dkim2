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

## 9. Package 3 state

- Custody: `signature.custodyTransitionAllowed` now applies Draft-07 Section
  7.1 in both directions. A null `mf=` hop and an `nd=` hop relaxed-match a
  previous `rt=` (Parameter1) against their own `d=` (Parameter2); before,
  null `mf=` hops were always rejected and `nd=` entry required an exact
  match. Ordinary hops and the exact continuation after `nd=` are unchanged.
  Domain literals never match.
- IDNA: the new `lib/internal/domainname` package owns U-label to A-label
  conversion (D4) on `golang.org/x/net/idna`, which is added to the library
  module as a reviewed dependency together with `golang.org/x/text`. Plain
  LDH ASCII names keep their previous handling; `xn--` labels and U-labels are
  validated by the strict registration profile.
- Envelopes: SMTP paths accept RFC 6531 UTF-8 local parts and U-label
  domains. Comparisons use A-labels (`CanonicalEnvelopePath`), signers record
  A-labels with otherwise unchanged bytes (`RecordableEnvelopePath`), and
  recorded `mf=`/`rt=` values containing U-labels fail closed.
- `DKIM2-ISSUE-0003` now records the Section 18 interpretation and the known
  NV8/XV8 validator gap. The Draft-06 `TBA` issues for policy guidance
  (`0002`) and Security Considerations (`0005`) are no longer `TBA` in
  Draft-07 and are re-evaluated in package 8.
- Package 7 item: `verify/local_hop_run.go` derives local-run membership
  through `CanonicalEnvelopeDomain(mf=)`, which rejects a null `mf=`. Such a
  hop is valid custody since this package, so a local run containing it must
  be handled explicitly in the DSN rebuild (D8).
- From-domain conversion is wired in package 4; adapter SMTPUTF8 signing
  policy (the Milter still rejects SMTPUTF8 originator envelopes) is reviewed
  in package 7.

## 10. Package 4 state

- From parser: `lib/internal/mailbox` is the single bounded RFC 5322 author
  parser (RFC 6854 groups, RFC 6532 UTF-8, comments, obsolete dotted phrases
  and local parts). Obsolete route syntax and empty list elements are
  rejected as unsupported. The library no longer uses `net/mail`; the
  null-sender `header_from` classifier layers its stricter profile (no
  group, ASCII addr-spec) over this parser.
- From authenticity (D3): the all-hop revision proof evaluates every From
  state of the authenticated history from `m=1` on. A state begins at `m=1`
  and wherever the From fields differ from the previous instance; each must
  be exactly one From field with one non-literal mailbox whose domain
  relaxed-matches the `d=` of the lowest `i=` whose `m=` covers that
  instance. Failure yields the new outcome `from_not_authentic`, mapped to
  PERMERROR and added to the public, policy, OpenAPI, daemon, and rspamd
  reason vocabularies. A pre-entry From restored by an `r=` at `m=1` is never
  reconstructed by the walk and receives no assertion. The golden vector
  `intermediate_nd` (From outside `i=1` `d=`) is now this negative case.
- Signing (Section 12.4): the signer refuses (`chain_failure`) when an
  originator, or a revision that replaced the From fields, would leave the
  outgoing From non-Authentic for the profile domain.
- Propagated DSNs (Section 16.2) are new messages, so their From is now
  `MAILER-DAEMON@<propagation signing domain>`; `Reporting-MTA` and the
  Message-ID host stay the configured reporting MTA. The DSN propagation
  corpus was regenerated; its Draft-06 version is kept under
  `lib/testdata/vectors/history/draft-ietf-dkim-dkim2-spec-06/`.
- `exploded` (Section 12.5): set only by intermediary purposes (revision,
  `nd=` hop) that fan out to more than one recipient; originator and
  delivery-status signatures (`i=1`) never carry it, and prior flags are not
  inherited. Draft-07 states no verifier rejection for an `i=1` `exploded`;
  replay policy treatment is decided in package 6.
- `donotmodify`/`donotexplode` (Section 10.10) are removed everywhere and
  parse as inert unknown flags; their daemon configuration keys fail with a
  migration error.
- Follow-up: without `donotmodify`, nothing produces the `local_only`
  restriction anymore. `LocalOnlySignedMessage` and its release path are
  unreachable and should be removed in a separate cleanup.
- Review follow-ups: Draft-07 Sections 2.11 and 13 make every Signer
  requirement part of a Validly Signed message, so an `i=1` signature carrying
  `exploded` is now rejected as `malformed_protocol` PERMERROR (fixtures that
  placed `exploded` on `i=1` were corrected). MTA-generated DSNs are new
  `i=1` messages: their From must relaxed-match the DSN signing domain
  (Postfix bounce From `MAILER-DAEMON@$myhostname` requires `$myhostname`
  equal to or below that domain) — an operator note for package 8. The
  verifier-projection binding stays `v1` but is draft-bound; its Draft-07 hop
  encoding change is documented in `openapi-daemon-foundation.md`.

## 11. Package 5 state

- `signature.AlgorithmMLDSA44Ed25519SHA512` is a known verification
  algorithm. `cryptodkim2` owns `CompositePublicKey` (raw ML-DSA-44 key
  followed by raw Ed25519 key, exactly 1344 bytes; SPKI wrappers, other
  parameter sets, and trailing bytes fail) and verifies the Section 3.4
  construction: SHA-512 over the Section 12.8 input, pure ML-DSA-44 with an
  empty context and PureEd25519 over that digest, signature exactly 2484
  bytes, both halves required, no alternate profile.
- Digests: `VerifyDigest` takes a 32-byte digest for `rsa-sha256` and
  `ed25519-sha256` and a 64-byte digest for the composite. The verifier
  derives both digests once from the same canonical input and selects per
  algorithm in the current, revision, and historical-target paths; the
  replay projection keeps the SHA-256 digest.
- DNS: `k=mldsa44-ed25519-sha512` is a supported key type mapped only to the
  composite algorithm. Existing PKCS#1 and SPKI RSA parsing is unchanged.
- The default verifier enables all three Draft-07 algorithms. A runtime
  without ML-DSA (Go FIPS 140-3 module v1.0.0) fails verifier construction.
- Signing: `signing.SignableAlgorithm` keeps signing to `rsa-sha256` and
  `ed25519-sha256`. Composite signing waits for resolution of the conflict
  between Section 3.4 and the LAMPS construction cited by DNS-01.
- Evidence: primitive round trips with deterministic keys, corrupted and
  swapped halves, truncation, trailing bytes, nonempty ML-DSA context,
  wrong-digest Ed25519 half, wrong digest sizes, wrong key types, and an
  end-to-end composite DKIM2 message through the verifier. `rsa-sha1`-only
  signature sets never PASS.

## 12. Package 6 state

- Time windows (Section 14.3): signature age (14 days) and future tolerance
  (one day) are protocol constants checked on every DKIM2-Signature against
  the request reference instant (explicit `ReferenceTime`, otherwise the
  verifier clock). A failure is attributed to the lowest offending `i=`. The
  former configurable `TimestampPolicy` is gone. The revision and signing
  instant skew is a separate fixed five-minute constant.
- DNS `t=` (DNS-01 Section 3.4.1): retired. Typed `t=y`/`t=s` parsing, cache
  admission rules, testing-only PASS overrides, the public `KeyPolicyMetadata`
  and DNS-testing APIs, and the OpenAPI `key_policy`/`dns_testing` members are
  removed. DKIM2-ISSUE-0013 is superseded. The separately configured local
  testing policy mode is unchanged.
- Section 14 reasons: a message without DKIM2 header fields is PERMERROR
  `missing_protocol` for explicit verification, while `/v1/process` keeps its
  no-op. More than one key TXT record is PERMERROR `ambiguous_key` (Section
  14.5). A Recipe the verifier will not process for complexity reports
  `limit_exceeded`, never `invalid_recipe_json`. Expired and future
  timestamps share `timestamp_invalid`, and the timestamp check carries the
  distinguishing status.
- Replay (Section 15.1, local policy): replay detection is delivery policy
  layered over validity. A detected replay sets the `AuthenticationResult` to
  `FAIL duplicate_message_without_exploded`, while the `VerifyResult` stays
  `PASS`.
  - Identity: the authenticated `m=1` hash declarations (SHA-256 pair,
    otherwise SHA-512 pair), framed as `dkim2-replay-origin-declaration-v1`,
    replace the reconstructed origin bytes. A `"b":null` Recipe therefore no
    longer yields `replay_evidence_unavailable`. Body-only equality was
    rejected because it merges distinct originals that share a body.
  - Eligibility: only messages with more than one DKIM2-Signature are counted.
    A direct `i=1`-only delivery, including every DSN singleton, reports the
    new replay class `not_eligible` with no store command, both in the
    library authenticator and in the daemon coordinator. The class is added to
    the OpenAPI enum, the daemon outcome and telemetry allowlists, the Milter,
    Exim, dkim2ctl, and rspamd coherence checks, and the rspamd symbol
    `DKIM2_REPLAY_NOT_ELIGIBLE`. `not_checked` beside PASS/accept stays
    incoherent everywhere. DSN propagation coordinates keep using the same
    identity regardless of eligibility.
  - Exploded: an authenticated flag on any chain signature remains a policy
    input.
  - Operators: the frame change and draft identifier rotate the replay
    identity space through the existing drain-only epoch procedure. The
    68-byte key grammar, namespace, ACLs, and store commands are unchanged.
- Delivery instant: the daemon has no stored-message verification route; it
  verifies live mail through `/v1/process`, where the daemon clock is the
  delivery instant Section 14.3 requires. Library callers re-verifying stored
  messages pass the original delivery instant through
  `WithVerificationClock`; without it an old message fails closed with
  `timestamp_invalid`. No REST field is needed. See
  `docs/operator/draft-07-migration.md`.
- DSN signing reference instant: `/v1/dsn/sign` previously verified the
  embedded original at bounce time, so a message bounced after the queue
  lifetime with an older signature lost its DSN as `timestamp_invalid`. The
  evidence evaluator now uses the per-message RFC 3464 `Arrival-Date` of the
  local MTA's report as the Section 14.3 reference, accepted only within
  [clock - 14 days, clock + 5 minutes]; otherwise the verifier clock applies.
  Inbound DSN evaluation keeps the outer highest `t=` reference.
- Breaking public Go API removals: `KeyPolicyMetadata` and the DNS-testing
  accessors (the timestamp policy was internal to the verifier). They are
  listed in `docs/operator/draft-07-migration.md`.
- Evidence: declaration golden frame and digest, equality across Recipes and
  base64 folding, SHA-256-only/mixed grouping, SHA-512-only separation,
  changed-header separation, the null-body revision reproducer, direct
  deliveries not counted, forwarded first-seen/replayed/exploded and store
  ambiguity cases (library and daemon), and the updated wire matrix and
  dkim2ctl fixtures.

## 13. Package 7 state

- Inbound DSN authority (Section 16.3 item 1): the evaluator takes
  returned-recipient authority from the d= of the DSN's i=1 signature, its
  originator, and keeps the highest outer t= as the reference instant for the
  embedded completion signature. A forged originator is not rescued by a
  later outer signer that matches, and a forwarded multi-hop DSN keeps its
  originator's authority. An outer chain without an i=1 signature fails
  closed.
- Propagation (Section 16.2) already met D8 and is now pinned by tests:
  - the output is a fresh singleton with one i=1 signature and one m=1
    instance, proven by `ProvePropagatedReport`;
  - every local run signature is removed, including nd= members;
  - parts 1 and 2 are generated fresh from local facts only, and the embedded
    original no longer carries the forwarding destination (privacy sentinel
    over the complete and headers-only forms);
  - the headers-only fallback covers unavailable bodies.
- Null senders: no DSN is signed for or propagated to `<>`. A local hop
  that relayed with `mf=<>` is valid custody since package 3, but it ends the
  local run and makes propagation `forbidden_null_previous_sender`. This is
  deliberate, because the hop's reverse path is the only possible propagation
  target.
- SMTP replies (Section 13):
  - Milter answers a daemon tempfail caused by TEMPERROR `provider_temporary`
    with `451 4.7.5 DKIM2 public key temporarily unavailable`; other
    tempfails keep `451 4.7.1`, and rejections keep `550 5.7.1`.
  - Exim gains the DXI1 tempfail reason `key_temporary` (9), and its
    local_scan texts now lead with the enhanced status codes `5.7.1`, `4.7.1`,
    and `4.7.5`.
- Transmitted bytes (Section 17):
  - The Postfix/Milter qualification verifies the captured downstream bytes
    with the public verifier (`validateSignedMessage`).
  - The Exim real matrix re-submits its captured sign output, which the
    inbound process and revision authority must verify before revising. The
    captured revise output is not yet re-verified; that check belongs to the
    package 8 interoperability requalification.
- Real MTA runs: `make conformance-postfix` passed against this tree. The Exim
  real matrix needs an external patched Exim source tree
  (`DKIM2_EXIM_QUALIFICATION_SOURCE_ROOT`) and runs in the package 8
  requalification. The Exim C changes are covered by
  `make test-exim-local-scan`, including the `4.7.5` reply. The package 8
  Exim run must capture the reply lines and prove each carries exactly one
  enhanced status code (no Exim-added duplicate before the local_scan text).
- SMTPUTF8 adapters (Section 18): adapter signing stays ASCII-path only.
  - Section 18 constrains how envelope domains are recorded (A-labels, which
    the library enforces since package 3); it does not oblige an adapter to
    sign EAI envelopes.
  - The Milter continues unsigned for a non-ASCII originator path and
    tempfails non-ASCII transit paths. Exim rejects non-ASCII outbound
    scalars. Both fail closed.
  - Inbound SMTPUTF8 bytes are preserved for verification.

## 14. 8-bit header values

- Header field values are byte strings. Before this change the raw-message
  parser required valid UTF-8, so any message with a legacy unencoded 8-bit
  header (for example a Latin-1 `Subject`) failed as `malformed_message`, and a
  Recipe `u` step could not restore a non-UTF-8 header value.
- Draft-07 Sections 5 and 18 hash messages as bytes and define `u` steps for
  values that are not valid UTF-8. The parser now enforces CRLF framing only.
  Bare CR or LF in a value stays malformed.
- Downstream owners already treated such values safely: the recipe generator
  emits `u` literals for headers, and both adapters already passed 8-bit
  header octets. The DKIM2-Signature and Message-Instance parsers stay
  ASCII-only, so an 8-bit byte in any of their tag values is still malformed.
- Operator-visible change: a legacy unencoded 8-bit `From` is no longer a
  `malformed_message`; it parses as a message and fails Section 11 as
  `from_not_authentic` (PERMERROR), because the mailbox parser requires
  RFC 6532 UTF-8 for an internationalized author.
- Evidence: a byte-exact parser reproducer, header `u` reconstruction, a
  generator round trip, and an end-to-end PASS for a Latin-1 `Subject`.
