# DKIM2 Draft-09 Migration Disposition

Status: implementation authority, migration implemented, pending independent review

Message specification: `draft-ietf-dkim-dkim2-spec-09`, 1 November 2026

DNS companion: `draft-ietf-dkim-dkim2-dns-02`, 21 October 2026 (unchanged)

Previous baseline: `draft-ietf-dkim-dkim2-spec-08` plus
`draft-ietf-dkim-dkim2-dns-02` (`docs/specs/draft-08-migration-disposition.md`)

## 1. Authority and method

This document is the tracked authority for the migration from Draft-08 to
Draft-09. It records every behavior change, the owning change area, and every
local interpretation. Historical audit records, reports, and earlier
migration dispositions keep their original identifiers.

The comparison used the IETF archive texts:

| Document | SHA-256 |
| --- | --- |
| `draft-ietf-dkim-dkim2-spec-08.txt` | `f562f73e2c48f7d170f41ba691bd5c6867de59caefece5b122a428d4e07b7d8c` |
| `draft-ietf-dkim-dkim2-spec-09.txt` | `19fc054eb5ecbbbe88a39c88b45355ed583f40a473a08a67067fa9bfcf0501fd` |
| `draft-ietf-dkim-dkim2-dns-02.txt` | `18aa5de0d209e7d44c943857ee992fb11ac2f10ec2e57e70758b10745db1a121` |
| `draft-gondwana-dkim2-authres-01.txt` | `36d82d8469c063e674d60b59edfd352b00175b1828bdd200632102ceb0c75419` |
| `draft-gondwana-dkim2-debug-header-02.txt` | `5a5705453d5a4ebfc1bd01c4645783f02dbe212eaa254de08daf740a97627064` |

Spec-09 cites `[DKIMKEYS]` as DNS-02, `[DKIM2BCP]` as BCP-01, and
`[AUTHRESULTS]` as authres-01, so the new baseline is spec-09 plus DNS-02.
The spec-08 and DNS-02 digests match the Draft-08 disposition record.

Requirement strength is marked MUST/SHOULD/MAY (draft), descriptive (draft
prose), editorial (no behavior), or local (product policy that is stricter
than the draft). The plan was reviewed independently before implementation;
review findings changed decisions D4, D5, D7, and D9 and the reason set of
D3.

## 2. Section renumbering

Draft-09 inserts two subsections, 3.8 (Domain Policy Record) and 11.1 (Using
subdomains to make From header fields Authentic). Every other section keeps
its Draft-08 number, so active citations change only their draft prefix. The
citation validator pins the Draft-09 section set including 3.8 and 11.1.

## 3. DNS-02

Unchanged. Spec-09 Section 3.7 now states the record selection rule that
DNS-02 Section 3.4 left undefined ("if there are multiple records in an RRset,
the results are undefined"); C7 implements the spec-09 rule.

## 4. Draft-08 to Draft-09

| # | Section | Change | Strength | Disposition | Area |
| --- | --- | --- | --- | --- | --- |
| C1 | 2.11, 3.8 | New Domain Policy Record at `_domainkey.<domain>`: a TXT tag-list that begins with `v=DKIM1`, optional `f=` colon-separated flags, flag `strict`; records not beginning with `v=DKIM1` ignored; more than one remaining is PERMERROR; none means subdomains are authorized; a temporary DNS failure is TEMPERROR; no inheritance | MUST-level semantics | D1, D2 | 6 |
| C2 | 7.1 item 3, 11.1, 12.4, 14.8 | Authentic From match is re-run reversed (d= as Parameter1, From domain as Parameter2) when the downward match fails; a strict Domain Policy Record of the From domain removes that reversed match. The other three relaxed-match uses are unchanged | MUST | D2, D8, D9 | 6 |
| C3 | 14.8 | New error texts: From forbids subdomain signing, more than one address, domain literal (FAIL); policy unavailable (TEMPERROR); multiple policy records (PERMERROR) | SHOULD text | D3 | 6 |
| C4 | 14.1, 14.2 | Fifth state NONE: no DKIM2-Signature and no Message-Instance | semantics | D4 | 5 |
| C5 | 14.2 | A null Recipe makes verification PERMERROR ("has a null recipe"); acceptance stays local policy | semantics | D5 | 3 |
| C6 | 14.1 | TEMPERROR covers any temporary DNS record failure, not only the public key | descriptive | D3 | 6 |
| C7 | 3.7, 14.5 | Key TXT records that begin with a `v=` tag other than `DKIM1` are ignored first; more than one remaining record is an error | MUST | D6 | 4 |
| C8 | 14.5 | DNS-02 deprecates `h=`, `n=`, `s=`, `t=`; DKIM2 ignores them | descriptive | Already implemented: `t=` is unknown, `h=`, `n=`, `s=` have no effect | 4 |
| C9 | 2.14 | `ALPHADIGITPS` no longer contains FWS; a base64string neither begins nor ends with FWS; FWS stays admitted inside and before padding | MUST grammar | D10 | 2 |
| C10 | 10.6 | Unchanged `sig-rt-tag` now forbids FWS after the `,` through C9 | MUST grammar | D10 | 2 |
| C11 | 3.2, 14.6, 14.7 | The Verifier MUST NOT below 1024 bits is removed; a Verifier may regard an algorithm insecure or a key too short (PERMERROR intermediate) | MAY | Local floor of 1024 bits kept; PERMERROR `invalid_key` unchanged | 4 |
| C12 | 14.2 to 14.8 | New error texts ("is duplicated", "i=1 has an exploded flag", "has a null recipe"), renamed "mf= and d=", lowercase "recipe" | SHOULD text | Behavior existed; reason codes stay closed and the texts are not emitted (existing documented deviation) | 7 |
| C13 | 8 | Tags in any order "unless otherwise specified"; tag=value also used for the Domain Policy Record | descriptive | Shared scanner; D1 | 6 |
| C14 | 18 | From U-label mapped to A-label before a Domain Policy Record lookup | MUST | D1 | 6 |
| C15 | 20 | Security text on default-authorized subdomains and `f=strict` for hosting platforms | descriptive | Operator guidance | 7 |
| C16 | 1.1, 21 | `[AUTHRESULTS]` authres-01, RFC 4870 reference | editorial | Documentation | 1, 7 |

Editorial only: Section 11 "altered" becomes "modified", the 14.1 PASS
wording, Section 19 wording, RFC 7405 as STD 68.

## 5. Companion documents

| # | Document | Change | Disposition |
| --- | --- | --- | --- |
| A1 | authres-01 | `none` means no DKIM2 field of either family, a partial message is not `none`; a Verifier that attempts DKIM2 verification SHOULD report `dkim2=none`; the `header.i` rule generalized | D4; `header.i` and origin stay omitted as in the existing profile |
| H1 | debug-header-02 | `X-DKIM2-Info` placed immediately above the described field, `date` is a code behavior stamp, one action per field, optional `verify`, `mi-m`, `not-signed` actions | D7; the document is non-normative |
| H2 | email-header-maintenance-03 | IANA registry maintenance only | No change |
| O1 | sender-policy-04, localized-header-fields-00, deployment-profile-08 | Outside the baseline | No behavior |

## 6. Local interpretations

**D1 Domain Policy Record.** One owner in the DNS key resolution layer reuses
the transport, cache, single-flight, and limits with a distinct cache key
space. Closed outcomes: authorized (absent, NXDOMAIN, NODATA, or no `strict`
flag), strict, temporary, ambiguous (more than one record that begins with
`v=DKIM1`), and invalid (a record that begins with `v=DKIM1` but is not a
valid tag-list). Invalid records and permanent transport failures are
PERMERROR, never authorized: the draft is silent and this fails closed.
Flags are case-sensitive (Section 2.14); the `f=` value is split on `:` with
WSP trimmed and unknown flags ignored. A record that also carries `p=` is
still a policy record. The lookup uses the A-label From domain exactly, with
no walk up or down the tree. The owner kind is typed once: a selector owner
`<selector>._domainkey.<domain>.` and a policy owner `_domainkey.<domain>.`.

**D2 Two-phase From evaluation.** The pure phase classifies every From state
as a direct (downward) match, an upward candidate, or not Authentic; a state
that is not Authentic fails without DNS. Upward candidates are deduplicated by
A-label domain and resolved only after every signature proof passed and
before the proof state and the replay projection are decided, so an
unauthenticated message never triggers a policy query. Lookups count as
provider calls in usage. The result algebra follows the Section 14.6
`sig-all` precedence: all authorized is PASS; else any strict is FAIL; else
any ambiguous or invalid is PERMERROR; else TEMPERROR.

**D3 Reasons.** `from_subdomain_forbidden` (FAIL) for a strict Domain Policy
Record, distinct from `from_not_authentic`; `domain_policy_temporary`
(TEMPERROR); `domain_policy_ambiguous` (PERMERROR); `domain_policy_invalid`
(PERMERROR). They pass through every vocabulary: library, service, policy,
Authentication-Results reasons, OpenAPI, adapters, Rspamd, and `dkim2ctl`.

**D4 NONE.** The `DraftVersion` change is the versioned contract change.
`/v1/process` answers a message with no DKIM2 field of either family with
HTTP 200, verification state `none`, policy `{verdict: continue, reason:
none}`, no replay check, and, when a local reporting authority is configured,
exactly one `Authentication-Results: <authority>; dkim2=none` action without a
comment. No verification, policy evaluation, replay, DNS, or signing work
runs. The library protocol class does not gain NONE: applicability stays a
separate pre-verification classification. Signing and delivery-status 204
no-ops are unrelated and unchanged.

**D5 Null Recipe.** `body_history_unavailable` moves from FAIL to PERMERROR
without renaming. Transit and revision signing keep refusing such histories.
Policy dispositions per mode follow the PERMERROR row; no acceptance option is
added.

**D6 Key TXT selection.** Transports carry up to eight TXT payloads of one
answer (`MaxCarriedTXTRecords`, the resolver hard bound); a larger answer stays
count-only and resolves as an ambiguous key without payload traversal. The
resolver first drops records whose first tag-spec is `v=` with a value other
than `DKIM1` (only the first tag-spec is inspected, so malformed text after it
cannot change the classification) and applies the record byte bound to the
remaining candidates only, so an unrelated long record is ignored; it then
resolves zero remaining records as a
missing key, one as the key record, and more than one as an ambiguous key.
The same first-tag primitive serves D1 with the opposite treatment of a record
without `v=`.

**D7 Debug header.** The hop block keeps the v0.2.0 order Message-Instance,
DKIM2-Signature, X-DKIM2-Info. Placing the field above the described
signature as debug-header-02 Section 7 asks would make a v0.3.0 daemon fail
closed against not yet upgraded adapters and would break the contiguous trace
block; the deviation from the non-normative companion is recorded. `date`
becomes a code constant that changes with every change to what is emitted;
`draft=` tracks the baseline; a multi-algorithm signature keeps one `sign`
action with a comma-separated `a=` list.

**D8 Signers stay downward only (local, stricter).** Our Signers and the DSN
identity resolver never use a subdomain `d=` to make a parent-domain From
Authentic and therefore need no policy lookup in signing paths. A transit hop
with an unchanged From relies on the verifier's proof. This is a local
restriction without interoperability cost: we only sign with keys at the
correct level. The refusal stays observable through the existing not-signed
reasons.

**D9 Verifier choice.** The library verifier requires an explicit choice at
construction: a Domain Policy Record provider, or
`WithoutSubdomainFromAuthorization()`; a missing choice is a construction
error. `dkim2d` configures the provider by default
(`verification.domain_policy.allow_subdomain_from: true`), because a downward
only verifier would report conforming messages as FAIL, which is not
fail-closed but non-conformance. Setting it to `false` is a documented local
policy.

**D10 Grammar.** Leading FWS before a base64string in `h=` and `s=` and
trailing FWS directly before the next `:` are rejected. The signer folds `rt=`
inside the next base64string after its first character instead of after the
comma. Verifiers keep accepting FWS directly after an `rt=` comma, because
every signer up to v0.2.0 emitted it and Draft-08 admitted it; this lexical
compatibility weakens no security property and is recorded as a draft issue.
The tag-level FWS after `=` for `r=`, `mf=`, and `rt=` follows the Section 8
`tag-spec`, although their tag ABNF lists no `[FWS]`.

**D11 Upstream questions.** The `rt=` comma grammar; the `_domainkeys`
spelling in the -09 announcement versus `_domainkey` in the draft; the
`r=`/`mf=`/`rt=` ABNF versus `tag-spec`; handling of an invalid Domain Policy
Record; the missing ABNF and trimming rule for `f=`; the duplicated
`[DKIMKEYS]` sentence at the end of Section 3.8; a multi-algorithm `a=` in the
debug header. They are recorded in the draft issue log; posting them is left
to the maintainer.

## 7. Change areas

1. Baseline identifiers, generated contracts, versioned fixtures, draft-bound
   goldens, section citations, and this document (no behavior change).
2. Grammar (C9, C10; D10).
3. Null Recipe (C5; D5).
4. Key TXT selection (C7, C8, C11; D6).
5. NONE (C4, A1; D4).
6. Domain Policy Record and two-way Authentic From (C1 to C3, C6, C13, C14;
   D1 to D3, D8, D9).
7. Debug header and documentation (C12, C15, C16, H1; D7, D11).
8. Closeout: gates and independent implementation review.

## 8. Baseline identifiers state

- Draft identifiers name Draft-09 and DNS-02 in the library constants, the
  daemon JSON preflight, the `X-DKIM2-Info` header, build metadata,
  conformance, interop, reference, security, and qualification tooling, JSON
  schemas, the Rspamd contrib, the agent skills, and the OpenAPI
  `DraftVersion` enum with regenerated server and client code
  (`DraftIetfDkimDkim2Spec09`).
- Before the in-place rename, the Draft-08 versions of the vector and golden
  corpora were copied to
  `lib/testdata/vectors/history/draft-ietf-dkim-dkim2-spec-08/`.
- Draft-bound goldens (replay storage keys and propagation key, origin
  declaration digest and frame, verifier-projection binding, the Rspamd Policy
  E2E projection bindings, and the conformance manifest digests) were
  recomputed through the repository's own tests and generators; the only input
  change is the draft identifier.
- Kept as historical records: earlier dispositions and operator guides,
  reports, the architecture change log, and every statement that Draft-08
  removed or replaced something.

## 9. Implementation state

- Area 2: `lib/internal/tagvalue` rejects leading and trailing FWS on a
  strict base64string (`invalid_base64_whitespace`); hash and signature set
  parsing rejects leading FWS on `h=` and `s=` values. The renderer folds
  `rt=` inside the next recipient; the parser keeps accepting FWS after an
  `rt=` comma and rejects FWS before one (`DKIM2-ISSUE-0024`).
- Area 3: `ProtocolForVerificationReason` maps `body_history_unavailable` to
  PERMERROR.
- Area 4: `lib/internal/keyresolver` carries up to eight TXT records
  (`dkim2.MaxCarriedTXTRecords`), ignores records whose leading `v=` is not
  `DKIM1` before the per-record byte bound, and applies uniqueness and the
  byte bound to the rest. Domain Policy Records use the same order.
- Area 5: `/v1/process` answers HTTP 200 NONE with policy
  `{continue, none}` and `dkim2=none`; every adapter treats HTTP 204 from
  `/v1/process` as a contract failure.
- Area 6: the resolver owns Domain Policy Record parsing, selection, and
  caching in its own key space; the verifier classifies From states without
  DNS, resolves deduplicated upward candidates after all signature proofs,
  and combines them strict, then first ambiguous or invalid, then temporary.
  Construction fails without an explicit choice (`DKIM2-ISSUE-0025`); invalid
  and ambiguous records fail closed (`DKIM2-ISSUE-0026`). Signers and the DSN
  identity resolver use `SignerFromAuthenticFor` (downward only, D8).
  `dkim2d` adds `verification.domain_policy.allow_subdomain_from` and the
  `--domain-policy-strict` DNS export.
- Area 7: `X-DKIM2-Info` `date=` is the code constant `interopBehaviorDate`;
  the operator guide, issue log, known limitations, companion sources, and
  compatibility notes describe the change.
- Area 8: the reviewed Go API baseline (`testdata/reference/go-api-base.json`)
  binds a commit revision and is refreshed in a follow-up commit after the
  migration commit, as for earlier surface changes. Policy lookups have no
  dedicated metric; `dkim2d_dns_lookups_total` counts key lookups only.
