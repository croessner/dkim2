# DKIM2 DNS-03 Migration Disposition

Status: implementation authority, migration implemented, pending independent review

Message specification: `draft-ietf-dkim-dkim2-spec-09`, 1 November 2026 (unchanged)

DNS companion: `draft-ietf-dkim-dkim2-dns-03`, 2 November 2026

Previous baseline: `draft-ietf-dkim-dkim2-spec-09` plus
`draft-ietf-dkim-dkim2-dns-02` (`docs/specs/draft-09-migration-disposition.md`)

## 1. Authority and method

This document is the tracked authority for the migration of the DNS companion
from DNS-02 to DNS-03. It records every behavior change, the owning change
area, and every local interpretation. Historical audit records, reports, and
earlier migration dispositions keep their original identifiers.

The comparison used the IETF archive texts:

| Document | SHA-256 |
| --- | --- |
| `draft-ietf-dkim-dkim2-dns-02.txt` | `18aa5de0d209e7d44c943857ee992fb11ac2f10ec2e57e70758b10745db1a121` |
| `draft-ietf-dkim-dkim2-dns-03.txt` | `a05885354e1b08d975e7002b912d19f8a6dfe089df0cd32e9e205b9cf4bfcd02` |
| `draft-ietf-dkim-dkim2-spec-09.txt` | `19fc054eb5ecbbbe88a39c88b45355ed583f40a473a08a67067fa9bfcf0501fd` |

The DNS-02 and spec-09 digests match the Draft-09 disposition record. DNS-03
cites spec-09 as `[DKIM2SPEC]`, so spec-09 plus DNS-03 is a consistent pair.
Spec-09 still cites DNS-02 as `[DKIMKEYS]`; where both documents state a rule,
the texts agree.

DNS-03 is a rewrite, not an increment: its change log says only "Substantial
rework". The comparison is therefore by rule, not by diff. Requirement
strength is marked MUST/SHOULD/MAY (draft), descriptive (draft prose),
editorial (no behavior), or local (product policy that is stricter than the
draft).

## 2. Section renumbering

DNS-03 has a new structure. Active citations move as follows; DNS citations
are free text and are not checked by the Draft-09 citation validator.

| Subject | DNS-02 | DNS-03 |
| --- | --- | --- |
| Whitespace, FWS | 2.7 | 2.1 |
| Imported ABNF tokens | 2.8 | 2.2 |
| Common ABNF tokens, `base64string` | 2.9 | 2.3 |
| Tag=Value lists | 3.2 | 2.4 (defers to Draft-09 Section 8) |
| Selectors, lookup name, TXT binding | 3.1, 3.4, 3.4.2 | 3 |
| Algorithm and key-type table | 3.3 | 4 (Table 1, key types only) |
| Key record tags | 3.4.1 | 4, 4.1 `v=`, 4.2 `k=`, 4.3 `p=`, 4.4 `h=`, 4.5 `n=`, 4.6 `s=`, 4.7 `t=` |
| Domain Policy Record | none (Draft-09 Section 3.8 only) | 5, 5.1 `v=`, 5.2 `f=` |
| RSA key format | Appendix A | 4.2, 6 |

## 3. DNS-02 to DNS-03

| # | Section | Change | Strength | Disposition | Area |
| --- | --- | --- | --- | --- | --- |
| C1 | 1, title | The document now covers DKIM1 and DKIM2 key records and updates RFC 6376 | descriptive | No behavior. The implementation verifies DKIM2 only | 1 |
| C2 | 2.3 | "A base64string MUST be padded with zero bits and trailing = characters provided if needed." The ABNF keeps the `=` characters optional | MUST | D1: `p=` requires terminal padding | 2 |
| C3 | 2.4 | Key records use the Tag=Value syntax of Draft-09 Section 8 instead of an own grammar | MUST grammar | Already implemented: both scanners implement Section 8 | 1 |
| C4 | 3 | TXT records that begin with a `v=` tag other than `DKIM1` are ignored; more than one remaining record is an error | MUST | Already implemented from Draft-09 Section 3.7 | 1 |
| C5 | 4, Table 1 | Key types are `rsa`, `ed25519`, `mldsa44`. The signing-algorithm list with `rsa-sha512`, `ed25519-sha512`, and the composite is gone | MUST | Already implemented: Draft-09 is authoritative for sig-names; the removed names stay unknown algorithms | 3 |
| C6 | 4 | `h=`, `n=`, `s=`, and `t=` are deprecated; "DKIM2 ignores them if they are present" (was "SHOULD be ignored") | MUST-level | Already implemented: `t=` is unknown, `h=`, `n=`, `s=` have no effect and no tag-specific syntax check | 1 |
| C7 | 4.1 | `v=` must be first and exactly `DKIM1`; unchanged | MUST | No change | 1 |
| C8 | 4.2 | `k=mldsa44`: `p=` is the 1312-octet public key from ML-DSA.KeyGen with no SubjectPublicKeyInfo or other wrapper. The composite key type is removed | MUST | Already implemented as a local interpretation, now normative | 3 |
| C9 | 4.2 | "DKIM2 Verifiers MUST support all three key types" | MUST | Already implemented | 1 |
| C10 | 4.2, 6 | An `rsa` key is an RSAPublicKey or a SubjectPublicKeyInfo containing one | MUST | No change | 1 |
| C11 | 4.3, 8 | An `ed25519` key that is not 32 octets or an `mldsa44` key that is not 1312 octets is malformed | MUST | Already implemented (`invalid_key`) | 1 |
| C12 | 4.2 to 4.7 | ABNF uses RFC 7405 `%s` case-sensitive literals; the DNS-02 `k=` ABNF defect is gone | MUST grammar | Already implemented: lowercase `k=` only | 3 |
| C13 | 3 | The query-method (`q=`) text is gone; the lookup is a TXT RR at the selector name | descriptive | Already implemented: DNS TXT is the only binding | 3 |
| C14 | 5 | The Domain Policy Record is defined here: a TXT RR at `_domainkey.<domain>`, `v=DKIM1` required and first, optional `f=`, records not beginning with `v=DKIM1` ignored, more than one an error, absent means authorized, no inheritance | MUST | Already implemented from Draft-09 Section 3.8 | 1 |
| C15 | 5.2 | ABNF for `f=`: `[ [FWS] flag *( [FWS] ":" [FWS] flag ) ]`, a flag is `strict` or a `hyphenated-word`; unrecognized flags are ignored | MUST grammar | D2: a flag list outside the grammar is invalid | 2 |
| C16 | 7 | IANA requests: tag registry updates, the `f` tag, key type `mldsa44`, a "DKIM2 Domain Policy Flags" registry, the `_domainkey` node name | editorial | No behavior | 1 |

Editorial only: the terminology section defers to Draft-09, the informative
notes on key servers and service types are gone, and the acknowledgments
changed.

## 4. Local interpretations

**D1 Terminal Base64 padding (C2).** DNS-02 had the `base64string` ABNF with
optional `=` and no prose, so a `p=` value that omitted trailing padding was
accepted through a DNS-specific parser path, as RFC 6376 key records allow.
DNS-03 adds the same sentence that Draft-09 Section 2.14 has for header
fields. The prose is a MUST and the ABNF is merely more permissive, so the
implementation follows the prose: a non-empty `p=` that omits needed `=`
characters is `invalid_public_key_data`, which resolves as an invalid key and
verifies as PERMERROR `invalid_key` (Draft-09 Section 14.5: "A key record
that is malformed cannot be used"). The rule applies to every key type,
including a key type the implementation does not support. Header fields and
key records now use the one parser `tagvalue.ParseBase64String`; the
optional-padding variant is removed. Canonical zero pad bits were already
required. No compatibility option is provided: the maintainer decided on
2026-11-20 to keep the strict rule without a switch.

Operator impact depends on the key. A 2048-bit RSA key is 294 octets as
SubjectPublicKeyInfo and 270 octets as PKCS#1 RSAPublicKey, both a multiple
of three, so it carries no padding at all; the same holds for a 1024-bit
SubjectPublicKeyInfo (162 octets). 3072-bit keys (422 and 398 octets),
4096-bit keys (550 and 526 octets), a 1024-bit PKCS#1 key (140 octets),
Ed25519 keys (32 octets), and ML-DSA-44 keys (1312 octets) need padding. A
record is affected only if it was published without the padding its key
generator emitted. The discrepancy between the prose and the ABNF, and the
effect on DKIM1 records that RFC 6376 accepted, is recorded as
`DKIM2-ISSUE-0027`.

**D2 Domain Policy Record flag grammar (C15).** Draft-09 gave no ABNF for
`f=`, so the value was split on `:` with WSP trimmed and every element that
was not `strict` was ignored, including empty and malformed elements. DNS-03
defines the grammar. The implementation now requires it: an empty `f=` value
lists no flags; otherwise every `:`-separated element, after removing the FWS
the grammar admits around the separator, must be a `hyphenated-word`. An
unrecognized but well-formed flag is ignored, as the draft requires. A flag
list outside the grammar (an empty element, inner whitespace, a leading
digit, a trailing hyphen, other punctuation) makes the record invalid.

The drafts do not say what a verifier does with a Domain Policy Record that
begins with `v=DKIM1` but is malformed. The existing fail-closed
interpretation applies: `domain_policy_invalid`, PERMERROR
(`DKIM2-ISSUE-0026`). This is strictly more restrictive than before. A value
such as `f=str ict` was previously read as "no strict flag" and authorized
every subdomain signer; it is now invalid. A value such as `f=strict:` was
previously read as strict and is now invalid; both outcomes deny the upward
Authentic From match.

**D3 Deprecated tags keep their generic validation.** `h=`, `n=`, `s=`, and
`t=` are ignored by DKIM2, but they are still tags of the tag-list: a
duplicate, a control byte, broken framing, or a size-limit violation in one
of them still makes the record malformed under Draft-09 Section 8.

**D4 Upstream questions.** The prose and ABNF disagreement on Base64 padding
and its effect on DKIM1 records (D1); the unspecified result of a malformed
Domain Policy Record (D2). The Draft-09 questions about the missing `f=` ABNF
and trimming rule are answered by DNS-03 Section 5.2. They are recorded in
the draft issue log; posting them is left to the maintainer.

## 5. Draft issue log

| Issue | Before | After |
| --- | --- | --- |
| `DKIM2-ISSUE-0011` (`k=` ABNF octet) | implemented interpretation | superseded: DNS-03 Section 4.2 |
| `DKIM2-ISSUE-0012` (query method) | implemented interpretation | superseded: DNS-03 Section 3 |
| `DKIM2-ISSUE-0020` (`k=mldsa44`) | implemented interpretation | superseded: DNS-03 Section 4.2 |
| `DKIM2-ISSUE-0021` (extra algorithm names) | implemented interpretation | superseded: DNS-03 Section 4 |
| `DKIM2-ISSUE-0022` (composite key-type spelling) | implemented interpretation | superseded: DNS-03 Section 4 |
| `DKIM2-ISSUE-0026` (invalid Domain Policy Record) | open interpretation | unchanged, now covers the flag grammar |
| `DKIM2-ISSUE-0027` (Base64 padding) | new | implemented interpretation |

## 6. Change areas

1. Baseline identifiers, versioned fixtures, section citations, and this
   document (no behavior change).
2. Parser behavior: terminal padding (C2; D1) and the flag grammar (C15; D2).
3. Statements that DNS-03 makes normative or obsolete: the `mldsa44` key
   type, the removed algorithm names, the `k=` ABNF, and the query method.
4. Closeout: gates and independent implementation review.

## 7. Baseline identifiers state

- The DNS draft identifier names DNS-03 in `keyresolver.DNSDraftIdentifier`,
  the conformance, interop, reference, security, and qualification tooling,
  the JSON schemas and fixtures, build metadata, and the agent skill.
- The identifier is local evidence metadata. It is not part of the REST
  contract, the `X-DKIM2-Info` header, the replay keys, or any signed or
  bound value, so no wire value and no draft-bound golden changes. The
  OpenAPI `DraftVersion` enum is unchanged.
- The evidence tooling binds every report to the identifier. Conformance,
  Postfix and Exim qualification, interop discovery and comparison,
  reference, and security reports that were produced under DNS-02 no longer
  validate and must be regenerated from this tree.
- One OpenAPI description text changed (`VerifierHop.signature_algorithms`
  no longer names a DNS registry); no schema, enum, or path changed. The
  generated server and clients were regenerated. A consumer that vendors the
  contract byte for byte resynchronizes it.
- Before the in-place rename, the DNS-02 vector corpus was copied to
  `testdata/vectors/history/draft-ietf-dkim-dkim2-dns-02/`. The DNS-03 corpus
  has the same records; every `p=` value in it was already padded.
- The conformance manifest digests were recomputed through the repository's
  own generator; DNS authority citations name the DNS-03 sections.
- Kept as historical records: earlier dispositions and operator guides,
  reports, the architecture change log, and every statement that an earlier
  draft removed or replaced something.
- The Draft-04 implementation records under `docs/specs/implementation/`
  name `draft-chuang-dkim2-dns-04` again, the DNS document they were written
  and reviewed against. Earlier migrations had replaced that identifier with
  each successive working-group identifier, which left statements such as a
  working-group draft "dated 2026-03-18". Only the current-behavior notes in
  those records name DNS-03.

## 8. Implementation state

- Area 2: `internal/tagvalue` has one Base64 parser; `internal/keyresolver`
  parses `p=` with it and validates `f=` flags as hyphenated words through
  the same predicate that validates `k=` values.
- Area 3: comments, the issue log, known limitations, and the guides state
  the DNS-03 rules; the test that pins the removed algorithm names is
  `TestRemovedDNSAlgorithmNamesAreUnknownSigNames`.
- No public Go API, REST, CLI, or configuration surface changed.
