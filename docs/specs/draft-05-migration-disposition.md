# DKIM2 Draft-05 Migration Disposition

Status: implementation authority

Baseline snapshot: Git `HEAD` `01d104567f375590c7c56654c02e38cbf4609a05`

Message specification: `draft-ietf-dkim-dkim2-spec-05`, 25 August 2026

Unchanged companion: `draft-chuang-dkim2-dns-04`, 18 March 2026

## 1. Authority and method

This document is the tracked completeness authority for the repository
migration from message Draft-04 to Draft-05. It preserves historical evidence
while assigning every current identifier and source-diff hunk to an owner,
target state, and proof.

The comparison uses the IETF archive text and XML sources copied to ignored
`temp/`. Their SHA-256 identities are:

| Input | SHA-256 |
| --- | --- |
| Draft-04 text | `827ecdcb580391a0ff74b921b56fd06612eae8d2bc27dd7eb876c5ff82ce16b7` |
| Draft-05 text | `3bbc568f86862d6c44724bd2b3175af3a417c4ca268d939b8bb63494182b28da` |
| Draft-04 XML | `1b205c9f66962bf890db21c5e9e496fa59d26ace9df6f57d3c135ecc551b1567` |
| Draft-05 XML | `a578a1f9f0b92095cacb55a499148359f14dc925fa6c38a460e716eeecd63c5d` |

The clean-HEAD inventory uses `git grep --cached` so later working-tree edits
cannot erase discovery evidence. Counts are occurrences, not matching lines.
Paths are included independently because a version can be encoded in a path
without occurring in file content.

The baseline identity is an existing commit object, not only an abbreviated
display value. At inventory capture, `HEAD`, `features`, `origin/features`, and
`public-mirror/features` all resolved to the full commit above, and
`git diff --cached --quiet` proved that the index read by `git grep --cached`
matched its tree. The durable object evidence is:

| Object fact | Value |
| --- | --- |
| Commit | `01d104567f375590c7c56654c02e38cbf4609a05` |
| Tree | `c0c0cfd0614f78a39222d494b3695ec24bd50a4d` |
| Parent | `e0d5caf642cda044f9039b9bc84e659a89cc1136` |
| Commit time | `2026-08-24T16:31:23+02:00` |
| Subject | `Fix: Authorize exact public mirror workflow updates` |

The object identity remains reproducible with
`git cat-file -e 01d104567f375590c7c56654c02e38cbf4609a05^{commit}` and
`git show -s --format='%H %T %P %cI %s'
01d104567f375590c7c56654c02e38cbf4609a05`. An independent final audit found
that the original long-form suffix did not name any object; it was a
transcription error, while the recorded abbreviated `01d1045` and the actual
capture-time refs identified this commit.

Disposition classes are closed:

| Class | Meaning | Required final state |
| --- | --- | --- |
| `active-stale` | Current message behavior or contract still names a pre-05 draft | Replace with Draft-05 in its owning implementation prompt |
| `active-target-probe` | A future/older draft is intentionally used as a negative compatibility input | Reverse or retain the probe so Draft-05 is accepted and the non-current draft is rejected |
| `historical` | Dated implementation, review, or external-claim evidence | Retain exact identity and make historical context explicit |
| `approved-companion` | `draft-chuang-dkim2-dns-04` or a DNS-04 abbreviation | Retain unchanged |
| `deferred-successor` | `draft-ietf-dkim-dkim2-dns-00` with explicit deferral authority | Retain unchanged; never make active in this migration |
| `invalid` | Malformed or unowned draft identity | Remove; none was found in the baseline snapshot |
| `unrelated-vendored` | Third-party JSON Schema Draft-04 terminology | Retain byte-for-byte under `vendor/` |

## 2. Complete source-diff disposition

The rendered text has 94 unified-diff hunks. The RFCXML has 76 unified-diff
hunks. Every hunk is covered by the following closed interval maps; no interval
overlaps and no hunk number is omitted.

### 2.1 Rendered text hunks

| Hunk IDs | Old/new area | Disposition | Requirement |
| --- | --- | --- | --- |
| T01-T03 | front matter, expiry, title, contents and pagination | Baseline metadata and generated rendering | D05-001, D05-010 |
| T04-T14 | introduction, terminology, glossary and heading capitalization | Editorial terminology only; update equivalent current prose | D05-010 |
| T15 | common ABNF followed by Section 3 algorithm replacement | Implement SHA-512 Message-Instance hashing and relaxed signer implementation levels; signature algorithms stay SHA-256 | D05-002, D05-004, D05-010 |
| T16-T21 | signing-algorithm, Selector and key-management capitalization | Editorial; no key/DNS semantic change | D05-010 |
| T22-T25 | Section 4 unsigned header prose and summary | Add exact trace fields and `Received-*`; narrow ARC wildcard to three exact fields | D05-005, D05-010 |
| T26-T29 | Recipe schema descriptions and capitalization | Editorial schema prose; encoded shape otherwise unchanged | D05-010 |
| T30 | Section 5.1 header Recipe key rule | Require decoded JSON header keys to be lowercase; retain case-insensitive message matching | D05-006 |
| T31-T34 | Recipe step/body wording and pagination | Editorial; no `c`, `d`, or `b:null` shape change | D05-010 |
| T35-T38 | Sections 6 and 7 heading/case plus moved dexterity sentence | Preserve canonical byte construction; hash dexterity rule is owned by `h=` | D05-002, D05-004, D05-010 |
| T39-T40 | Message-Instance pagination, Recipe capitalization, `h=` grammar | Add `sha512`; forbid duplicate hash names case-insensitively | D05-002, D05-009 |
| T41-T47 | Sections 8.1-8.8 headings/capitalization/pagination | Editorial only; existing tags and envelope forms remain | D05-010 |
| T48 | Section 8.9 signature sets | Unique Selectors; permit at most two signatures per algorithm with distinct Selectors | D05-007, D05-009 |
| T49-T50 | flags and Signer-heading capitalization | Editorial; flag vocabulary unchanged | D05-010 |
| T51-T52 | Section 9.1 Message-Instance generation | Remove the redundant-instance SHOULD NOT; accept no-Recipe unchanged transitions while retaining a narrower signer policy | D05-004, D05-008 |
| T53-T59 | Chain of Custody, Selector and calculation capitalization | Editorial only; custody, domain match and signature canonicalization unchanged | D05-010 |
| T60-T67 | Sections 10-11.1 headings, Recipe capitalization and pagination | Editorial only; four result states and SMTP mapping unchanged | D05-010 |
| T68 | Section 11.2 structural errors | Add four distinct typed PERMERROR diagnostics | D05-002, D05-006, D05-007, D05-009 |
| T69-T86 | Sections 11.3-16 capitalization and pagination | Editorial only; timestamps, custody, DNS, signature crypto, hashes, flags, DSN, transport, EAI, IANA and security semantics unchanged | D05-010 |
| T87-T89 | Section 17 history | Add complete Draft-05 change entry; retain prior version history | D05-001, D05-010 |
| T90-T94 | page furniture, references and author pagination | Add HDRMAINT and RFC7208 references; remaining changes are generated rendering | D05-005, D05-010 |

### 2.2 RFCXML hunks

| Hunk IDs | Old/new XML lines | XML owner | Disposition | Requirement |
| --- | --- | --- | --- | --- |
| X01-X04 | 12/12 through 81/81 | front matter | version, date and metadata | D05-001, D05-010 |
| X05-X15 | 101/101 through 335/335 | introduction through imported ABNF | capitalization/terminology | D05-010 |
| X16 | 362/362 | `algorithms` and renamed SHA anchor | SHA-512 and implementation levels | D05-002, D05-004 |
| X17-X22 | 400/402 through 463/465 | signing algorithms, Selectors, key management | capitalization only | D05-010 |
| X23-X24 | 482/484 through 513/530 | `ignoreheaders`, `summary` | unsigned-header semantic set | D05-005 |
| X25-X27 | 568/596 through 602/630 | `JSONrecipe` | description capitalization only | D05-010 |
| X28 | 614/642 | `header-recipes` | lowercase decoded JSON header keys | D05-006 |
| X29-X36 | 639/667 through 845/869 | Recipe/body/hash/canonical/MI prose | capitalization, relocation and unchanged mechanics | D05-002, D05-010 |
| X37-X38 | 860/884 through 873/904 | `h-the-hash-values-for-the-message` | duplicate rule and SHA-512 ABNF | D05-002, D05-009 |
| X39-X40 | 921/952 through 1023/1054 | signature field headings and recipients | capitalization only | D05-010 |
| X41 | 1066/1097 | signature value sets | Selector/per-algorithm cardinality | D05-007, D05-009 |
| X42 | 1157/1190 | flags/Signer heading | capitalization only | D05-010 |
| X43-X44 | 1176/1209 through 1191/1223 | `add-any-necessary-message-instance-header-fields` | redundant unchanged instance relaxation | D05-004, D05-008 |
| X45-X55 | 1215/1252 through 1503/1540 | custody through output states | capitalization only | D05-010 |
| X56-X57 | 1515/1552 through 1522/1565 | structural validation | four typed diagnostics | D05-002, D05-006, D05-007, D05-009 |
| X58-X70 | 1541/1588 through 1823/1870 | timestamps through transport | capitalization only | D05-010 |
| X71-X73 | 1854/1920 through 1893/1959 | changes from earlier versions | Draft-05 history entry and Recipe capitalization in old entries | D05-001, D05-010 |
| X74-X76 | 2179/2245 through 2268/2386 | informative references and generated bibliography entities | RFC7208/HDRMAINT plus generated reference maintenance | D05-005, D05-010 |

### 2.3 Section-anchor accounting

Both XML sources contain 77 section anchors. Seventy-five anchors are common.
Two anchors change because their section names change:

| Draft-04 anchor | Draft-05 anchor | Disposition |
| --- | --- | --- |
| `the-sha256-hashing-algorithm` | `the-sha256-and-sha512-hashing-algorithms` | Update current references; retain historical Draft-04 links only in explicit history |
| `check-most-recent-signature-and-hashes-for-the-message` | `check-the-most-recent-signature-and-hashes-for-the-message` | Update current references; capitalization-only anchor regeneration |

Sixteen common anchors have byte-equivalent normalized section text and need no
behavior change:

`d-the-domain-associated-with-this-signature`, `f-flags`, `forwarder`, `hash`,
`i-the-sequence-number-of-the-dkim2-signature-header-field`,
`m-the-revision-number-of-the-message-instance-header-field`,
`mf-the-mail-from-used-when-the-message-was-sent`, `n-nonce-value`,
`originator`, `reviser`,
`rt-the-rcpt-to-values-used-when-the-message-was-sent`, `signer`,
`t-signature-timestamp`, `tag`, `verifier`, and `whitespace`.

The other 59 common anchors change through the semantic or editorial intervals
above. A changed anchor is not by itself evidence of changed behavior.

## 3. Semantic implementation disposition

| Draft-05 change | Owning implementation | Required final behavior | Proof owner |
| --- | --- | --- | --- |
| SHA-512 Message-Instance hashes | `lib/internal/instance`, `lib/internal/canonical`, `lib/internal/verify` | 32/64-byte lengths, case-insensitive unique names, every supported tuple checked, unknown-only unsupported | Prompts 02, 03, 05 |
| Expanded unsigned fields and exact ARC set | `lib/internal/canonical` | Exact eight named additions, `Received-*`, only three exact ARC exclusions | Prompts 02, 05 |
| Lowercase Recipe header keys | `lib/internal/recipe` | Reject decoded non-lowercase keys including escapes; generate lowercase; typed secret-safe error | Prompts 02, 03, 05 |
| Signature cardinality | `lib/internal/signature`, verifier/key resolver | unique case-insensitive Selector, at most two per algorithm, separate lookup/result order | Prompts 02, 03, 04, 05 |
| Redundant no-Recipe instance | `lib/internal/verify` | Treat absent Recipe as unchanged; verify every prior supported tuple; malformed/present Recipe remains error | Prompts 03, 05 |
| Four diagnostics | parser/history/signature owners and public mappings | distinct PERMERROR reasons; no raw Recipe/Selector/message data; never SMTP 4xx | Prompts 03, 04, 05 |
| Capitalization and references | current docs/comments/generated descriptions | Align current terminology; retain historical wording where truth requires | Prompts 01, 04, 05, 06 |

## 4. Explicit non-changes

The full text/XML comparison proves these are not migration work:

- RSA-SHA256 and Ed25519-SHA256 still hash signature input with SHA-256; no
  RSA-SHA512 or Ed25519-SHA512 algorithm is introduced.
- Required and optional Message-Instance and DKIM2-Signature tags, tag-list
  terminators, FWS handling, padded Message-Instance Base64, and extension-tag
  behavior are unchanged except for `hash-name` adding `sha512`.
- Body bytes, relevant-header canonicalization steps, signature-input
  canonicalization, ordering, WSP rules, and recipe `c`/`d`/`b:null` shapes are
  unchanged. Only the Section 4 relevance set changes canonical header input.
- Sequence gaps, timestamp policy, current-envelope checks, Chain of Custody,
  relaxed domain matching, `nd=` behavior, flags, and four-state results are
  unchanged.
- DNS key record grammar, key resolution, DNSSEC policy, key-type matching and
  the implemented companion baseline remain `draft-chuang-dkim2-dns-04`.
- DSN propagation/authentication, transport conversion, EAI, IANA and Security
  Considerations contain no new behavior. EAI, IANA and security remain `TBA`.
- The deterministic signer may continue emitting SHA-256 only and may continue
  omitting redundant Message-Instances. Those are conforming local output
  policies, not verifier restrictions.
- Replay storage layout, fixed digest width, namespace, ACLs, retention and
  provider ownership do not change.

## 5. Compatibility and public-contract decisions

### 5.1 Intentional compatibility boundaries

- Draft-04 accepted non-lowercase Recipe keys become Draft-05 PERMERROR.
- Duplicate hash algorithms become Draft-05 PERMERROR, including unknown
  extension names and ASCII case variants.
- SHA-512-only and dual-hash instances become valid when every supported tuple
  matches; one matching and one failing supported tuple fails closed.
- A second same-algorithm signature with a distinct Selector becomes valid; a
  duplicate Selector or third same-algorithm signature is PERMERROR.
- A non-origin instance with no Recipe becomes a valid unchanged transition
  only when the prior supported hashes all match.
- Newly ignored trace fields and newly signed unknown `ARC-*` fields create
  intentional bidirectional Draft-04/Draft-05 canonical-hash incompatibility.

### 5.2 Replay epoch

The replay projection remains a local fixed SHA-256 digest of canonical header
input after every advertised supported Message-Instance tuple passes. It does
not require an advertised SHA-256 tuple. The HMAC DraftIdentifier advances to
Draft-05, which rotates the replay epoch. Deployment is drain-only: mixed
Draft-04/Draft-05 replay traffic, fallback, dual epochs and rolling migration
are unsupported. Old records become unreachable and the detection gap is
bounded by configured retention.

### 5.3 OpenAPI enums

`docs/specs/openapi/dkim2d.yaml` remains the source of truth. `DraftVersion`
replaces Draft-04 with Draft-05. `VerificationReason` adds
`duplicate_hash_algorithm`, `invalid_recipe_json`, `duplicate_selector`, and
`too_many_signatures`. Generated server and all clients change only through the
generator. Unknown enum values fail as typed contract errors. Positional
`signature_sets` remain ordered and are never keyed or deduplicated by
algorithm.

### 5.4 Exim qualification

The existing five-row Linux evidence is bound to a Draft-04 candidate and is
not relabeled. The Draft-05 capability is `unqualified_draft05`. The active
Exim conformance case and imported evidence requirement are removed; the full
otherwise-portable suite runs without `EXIM_EVIDENCE_ROOT` and fails closed if
stale evidence is supplied. `qualified_linux` can return only after a fresh,
separately authorized Draft-05 five-row run bound to unchanged candidate bytes.

## 6. Identifier ownership and final-path rules

The following prefix map gives the owner for every row in Appendix A:

| Path owner | Implementation owner |
| --- | --- |
| `AGENTS.md`, `docs/ARCHITECTURE.md`, Spec skill and skills index | Prompt 01 |
| `lib/internal/{canonical,instance,recipe,signature}/**` | Prompt 02 |
| remaining `lib/**`, `docs/replay-store-valkey.md` | Prompt 03 |
| `cmd/**`, `docs/specs/openapi/**`, listed build/qualification scripts | Prompt 04 |
| `testdata/**`, `tools/**` except operator-doc guard, `Makefile`, reference issue log | Prompt 05 |
| remaining current `README.md` and `docs/**`, operator-doc guard | Prompt 06 |
| `vendor/**` | no owner; read-only third-party material |

Final-path rules are deterministic:

1. Active message-suite paths replace
   `draft-ietf-dkim-dkim2-spec-04` with
   `draft-ietf-dkim-dkim2-spec-05` using `git mv`. This applies to the seven
   `cmd/dkim2ctl` fixtures, three canonical goldens, two Recipe goldens, five
   library-vector files including the key file, and the portable Milter
   fixture. String-bound runners and test names move atomically.
2. The `lib/testdata/vectors/draft-chuang-dkim2-dns-04/` path and all DNS-04
   identifiers remain unchanged.
3. Completed `docs/specs/implementation/**` records and dated reports retain
   pre-05 statements as historical evidence; Prompt 06 adds explicit historical
   framing where context is not already unambiguous. They never define the
   active baseline after this migration.
4. External `claimed_draft` values in the interoperability candidate catalog
   retain the peer's claim. Registry/schema/report identities owned by this
   repository migrate to Draft-05.
5. Negative compatibility probes invert around the new baseline: Draft-05 is
   accepted, while Draft-04 and other non-current values are rejected.
6. The five explicitly contextualized DNS `-00` occurrences remain deferred
   successor records in `README.md`, `docs/ARCHITECTURE.md`, the completed
   datasource-provider spec, and `lib/doc.go`.
7. The vendored JSON Schema `draft-04` path is unrelated terminology and is
   byte-for-byte read-only.

Classification overlay for Appendix A is exhaustive:

- The default class for every message-style count is `active-stale` and its
  owner replaces it with Draft-05.
- Message-style counts under `docs/specs/implementation/**` and
  `docs/reports/**` are `historical`; their final path and exact historical
  claim remain. Prompt 06 adds a historical banner where required to prevent
  those records from being mistaken for the current authority.
- Every `claimed_draft` value in
  `testdata/interop/candidate-catalog.json` is `historical` external evidence
  and remains exact. The Draft-03 mutation in the Exim matrix test and the
  clean-HEAD Draft-05 mutations in the Milter and `dkim2ctl` fixture tests are
  `active-target-probe`; their owners retain a non-current negative probe after
  accepting Draft-05.
- `docs/ARCHITECTURE.md` is mixed by explicit line role: document control,
  current package contracts and current examples migrate in Prompt 01; dated
  revision and milestone rows retain their original Draft-02/Draft-04 evidence.
- Every nonzero DNS-04 cell in either appendix is `approved-companion`,
  irrespective of the message-style class in the same row. Every nonzero
  DNS-00 cell is
  `deferred-successor` and has the explicit deferral context named in rule 6.
- The sole vendored path row is `unrelated-vendored`. No baseline row is
  `invalid`.

## 7. Proof and deferred runtime gates

Prompt 01 proves only the governing baseline and inventory. Runtime constants,
OpenAPI generation, active vectors, adapters, conformance reports and Exim
capabilities intentionally remain Draft-04 until their exclusive owners run.
Therefore `make check-conformance`, `make check-openapi`, generated stale checks
and active suite baseline sweeps are deferred, not passing claims.

Prompt-01 proof is:

```text
no Draft-02 active hit in .codex/skills/dkim2-spec-conformance/SKILL.md
git diff --check -- the five Prompt-01 tracked paths
make check-boundaries
approved ignored specification SHA-256 unchanged
```

Final proof requires no unexplained pre-05 message identity, no invalid DNS
identity, all later focused gates, `make check-conformance`, `make conformance`,
`make conformance-all`, `make check-security`, `make check-reference`, and
`make guardrails`.

## Appendix A. Clean-HEAD identifier inventory

The table is exhaustive for tracked clean-HEAD files. `full` counts every full
two-digit message-draft identifier (the observed set is `-02` through `-05`),
`abbr` counts standalone
pre-05 message-style spellings, and DNS columns count the exact companion and
deferred-successor identifiers. `path` marks a version token in the path; the
subject-specific final-path rules above decide whether it moves.

```text
path | full | abbrev | DNS-04 | DNS-00 | path
.codex/skills/dkim2-spec-conformance/SKILL.md | 1 | 0 | 1 | 0 | -
AGENTS.md | 1 | 0 | 1 | 0 | -
README.md | 1 | 1 | 1 | 1 | -
cmd/dkim2-exim/exim/tests/real_matrix_service.py | 1 | 0 | 0 | 0 | -
cmd/dkim2-exim/exim/tests/test_real_matrix_service.py | 3 | 0 | 0 | 0 | -
cmd/dkim2-exim/internal/daemon/generated/client.gen.go | 1 | 0 | 0 | 0 | -
cmd/dkim2-exim/internal/integration/generated/server.gen.go | 1 | 0 | 0 | 0 | -
cmd/dkim2-milter/README.md | 1 | 0 | 1 | 0 | -
cmd/dkim2-milter/internal/daemon/generated/client.gen.go | 1 | 0 | 0 | 0 | -
cmd/dkim2-milter/internal/daemon/handler.go | 0 | 1 | 0 | 0 | -
cmd/dkim2-milter/internal/daemon/handler_behavior_test.go | 2 | 1 | 0 | 0 | -
cmd/dkim2-milter/internal/integration/generated/server.gen.go | 1 | 0 | 0 | 0 | -
cmd/dkim2-milter/internal/integration/milter_fixture_test.go | 4 | 0 | 1 | 0 | -
cmd/dkim2-milter/internal/integration/public_peer_test.go | 0 | 1 | 0 | 0 | -
cmd/dkim2ctl/README.md | 2 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/command/command_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/command/subprocess_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/delivery_status_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/fixture_test.go | 3 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/generated/client.gen.go | 1 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/negative.go | 3 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/negative_test.go | 6 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/operations_test.go | 7 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/output.go | 1 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/public_socket_test.go | 6 | 0 | 0 | 0 | -
cmd/dkim2ctl/internal/testclient/runtime_test.go | 2 | 0 | 0 | 0 | -
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/health.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/process-negative.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/process-report.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/process.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/revise.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/route-negative.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/sign.json | 1 | 0 | 0 | 0 | Y
cmd/dkim2d/README.md | 0 | 1 | 0 | 0 | -
cmd/dkim2d/internal/app/domain_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/app/replay_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/dkim2ctl_integration_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/generated/contract_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/generated/server.gen.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/historical_response_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/http_boundary_context_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/http_boundary_matrix_test.go | 3 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/http_boundary_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/http_wire_response_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/json_preflight.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/json_preflight_test.go | 6 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/known_fields_test.go | 2 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/operations_test.go | 2 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/response.go | 0 | 1 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/response_snapshot_test.go | 2 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/validator_test.go | 5 | 0 | 0 | 0 | -
cmd/dkim2d/internal/httpjson/working_set_test.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/observability/logging.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/observability/tracing.go | 1 | 0 | 0 | 0 | -
cmd/dkim2d/internal/replay/valkey/store_test.go | 1 | 0 | 0 | 0 | -
contrib/qualification/postfix-milter/run.sh | 1 | 0 | 1 | 0 | -
docs/ARCHITECTURE.md | 4 | 12 | 2 | 2 | -
docs/ci.md | 0 | 1 | 0 | 0 | -
docs/conformance.md | 1 | 3 | 1 | 0 | -
docs/operator/postfix-compose.md | 1 | 2 | 1 | 0 | -
docs/reference/compatibility.md | 1 | 1 | 1 | 0 | -
docs/reference/draft-issues.md | 1 | 1 | 1 | 0 | -
docs/reference/known-limitations.md | 0 | 1 | 0 | 0 | -
docs/reference/release-candidate.md | 0 | 1 | 0 | 0 | -
docs/reports/current-semantics-audit-2026-08-21.md | 1 | 2 | 0 | 0 | -
docs/security-testing.md | 1 | 0 | 1 | 0 | -
docs/specs/implementation/canonicalization-and-hashes.md | 7 | 4 | 0 | 0 | -
docs/specs/implementation/datasource-providers.md | 2 | 1 | 3 | 1 | -
docs/specs/implementation/delivery-status-signing.md | 2 | 6 | 0 | 0 | -
docs/specs/implementation/dkim2-tag-parsers.md | 2 | 15 | 2 | 0 | -
docs/specs/implementation/dns-key-resolver.md | 2 | 0 | 2 | 0 | -
docs/specs/implementation/exim-adapter.md | 1 | 0 | 1 | 0 | -
docs/specs/implementation/interop-history-ci-stabilization.md | 3 | 9 | 0 | 0 | -
docs/specs/implementation/interoperability-reference-release-candidate.md | 2 | 8 | 2 | 0 | -
docs/specs/implementation/ldap-sql-datasource-legacy-migration.md | 1 | 5 | 1 | 0 | -
docs/specs/implementation/milter-adapter.md | 1 | 2 | 1 | 0 | -
docs/specs/implementation/mvp-core-verification.md | 4 | 6 | 1 | 0 | -
docs/specs/implementation/native-datasource-key-custody.md | 1 | 0 | 1 | 0 | -
docs/specs/implementation/native-domain-onboarding.md | 1 | 0 | 1 | 0 | -
docs/specs/implementation/observability-foundation.md | 1 | 0 | 1 | 0 | -
docs/specs/implementation/openapi-daemon-foundation.md | 5 | 0 | 1 | 0 | -
docs/specs/implementation/openapi-test-client.md | 1 | 1 | 1 | 0 | -
docs/specs/implementation/packaging-container-delivery-operator-guide.md | 2 | 2 | 2 | 0 | -
docs/specs/implementation/policy-engine.md | 2 | 4 | 2 | 0 | -
docs/specs/implementation/postfix-dsn-origin.md | 1 | 1 | 0 | 0 | -
docs/specs/implementation/raw-message-model.md | 2 | 0 | 1 | 0 | -
docs/specs/implementation/recipe-application.md | 4 | 27 | 0 | 0 | -
docs/specs/implementation/recipe-generation.md | 4 | 12 | 0 | 0 | -
docs/specs/implementation/replay-store-valkey.md | 3 | 2 | 0 | 0 | -
docs/specs/implementation/security-hardening.md | 2 | 14 | 2 | 0 | -
docs/specs/implementation/signing-and-revision.md | 3 | 15 | 2 | 0 | -
docs/specs/implementation/static-key-signature-verification.md | 5 | 10 | 3 | 0 | -
docs/specs/implementation/test-vectors-and-conformance-suite.md | 5 | 5 | 3 | 0 | -
docs/specs/openapi/README.md | 0 | 1 | 0 | 0 | -
docs/specs/openapi/dkim2d.yaml | 2 | 0 | 0 | 0 | -
lib/dns_provider_example_test.go | 0 | 0 | 1 | 0 | -
lib/dns_provider_fuzz_test.go | 1 | 0 | 0 | 0 | -
lib/dns_provider_vector_test.go | 0 | 0 | 2 | 0 | -
lib/doc.go | 1 | 0 | 1 | 1 | -
lib/internal/canonical/doc.go | 1 | 0 | 0 | 0 | -
lib/internal/canonical/golden_test.go | 3 | 0 | 0 | 0 | -
lib/internal/canonical/header_test.go | 0 | 1 | 0 | 0 | -
lib/internal/canonical/options.go | 1 | 0 | 0 | 0 | -
lib/internal/canonical/relevance.go | 0 | 1 | 0 | 0 | -
lib/internal/canonical/signature_test.go | 0 | 2 | 0 | 0 | -
lib/internal/canonical/testdata/golden/body-canonicalization-draft-ietf-dkim-dkim2-spec-04.json | 7 | 0 | 0 | 0 | Y
lib/internal/canonical/testdata/golden/header-canonicalization-draft-ietf-dkim-dkim2-spec-04.json | 1 | 0 | 0 | 0 | Y
lib/internal/canonical/testdata/golden/signature-input-draft-ietf-dkim-dkim2-spec-04.json | 1 | 0 | 0 | 0 | Y
lib/internal/cryptodkim2/golden_test.go | 2 | 0 | 0 | 0 | -
lib/internal/dsn/evidence.go | 0 | 1 | 0 | 0 | -
lib/internal/instance/doc.go | 1 | 0 | 0 | 0 | -
lib/internal/instance/hash.go | 0 | 1 | 0 | 0 | -
lib/internal/instance/parser_test.go | 0 | 1 | 0 | 0 | -
lib/internal/keyresolver/doc.go | 0 | 0 | 1 | 0 | -
lib/internal/keyresolver/record.go | 0 | 0 | 1 | 0 | -
lib/internal/recipe/apply_header_test.go | 0 | 1 | 0 | 0 | -
lib/internal/recipe/doc.go | 1 | 0 | 0 | 0 | -
lib/internal/recipe/generation_golden_integration_test.go | 6 | 0 | 0 | 0 | -
lib/internal/recipe/generation_header_test.go | 0 | 1 | 0 | 0 | -
lib/internal/recipe/generation_serializer_test.go | 2 | 0 | 0 | 0 | -
lib/internal/recipe/golden_test.go | 2 | 0 | 0 | 0 | -
lib/internal/recipe/parser.go | 0 | 1 | 0 | 0 | -
lib/internal/recipe/relevance_integration_test.go | 0 | 2 | 0 | 0 | -
lib/internal/recipe/testdata/golden/recipe-application-draft-ietf-dkim-dkim2-spec-04.json | 1 | 0 | 0 | 0 | Y
lib/internal/recipe/testdata/golden/recipe-generation-draft-ietf-dkim-dkim2-spec-04.json | 1 | 0 | 0 | 0 | Y
lib/internal/recipe/types.go | 0 | 2 | 0 | 0 | -
lib/internal/replay/identity.go | 1 | 0 | 0 | 0 | -
lib/internal/service/mapping_test.go | 0 | 1 | 0 | 0 | -
lib/internal/service/types.go | 1 | 0 | 0 | 0 | -
lib/internal/signature/custody_golden_test.go | 2 | 0 | 0 | 0 | -
lib/internal/signature/doc.go | 1 | 0 | 0 | 0 | -
lib/internal/signature/flags_test.go | 0 | 1 | 0 | 0 | -
lib/internal/signature/parser_test.go | 0 | 2 | 0 | 0 | -
lib/internal/signing/closeout_vectors_test.go | 2 | 0 | 0 | 0 | -
lib/internal/signing/revision_test.go | 0 | 1 | 0 | 0 | -
lib/internal/tagvalue/doc.go | 1 | 0 | 0 | 0 | -
lib/internal/tagvalue/scanner_test.go | 0 | 1 | 0 | 0 | -
lib/internal/verify/doc.go | 2 | 0 | 0 | 0 | -
lib/internal/verify/envelope_test.go | 0 | 2 | 0 | 0 | -
lib/internal/verify/options.go | 1 | 0 | 0 | 0 | -
lib/internal/verify/vector_test.go | 1 | 0 | 0 | 0 | -
lib/replay_facade_test.go | 1 | 0 | 0 | 0 | -
lib/signing_facade_test.go | 1 | 0 | 0 | 0 | -
lib/testdata/vectors/draft-chuang-dkim2-dns-04/dns-golden.json | 1 | 0 | 1 | 0 | -
lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/README.md | 1 | 1 | 0 | 0 | Y
lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/custody-crypto-golden.json | 1 | 0 | 0 | 0 | Y
lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/public-golden.json | 1 | 0 | 0 | 0 | Y
lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/signing-golden.json | 1 | 0 | 0 | 0 | Y
lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/signing-test-rsa.pem | 0 | 0 | 0 | 0 | Y
lib/verification_example_test.go | 1 | 0 | 0 | 0 | -
lib/verifier_vector_test.go | 1 | 2 | 0 | 0 | -
lib/verify_result.go | 1 | 0 | 0 | 0 | -
scripts/build-products.sh | 1 | 0 | 1 | 0 | -
scripts/test-build-contract.sh | 2 | 0 | 0 | 0 | -
testdata/conformance/exim/qualification.schema.json | 1 | 0 | 1 | 0 | -
testdata/conformance/manifest.json | 40 | 0 | 5 | 0 | -
testdata/conformance/milter/draft-ietf-dkim-dkim2-spec-04/portable-fixtures.json | 1 | 0 | 1 | 0 | Y
testdata/conformance/report-golden/portable.md | 1 | 1 | 1 | 0 | -
testdata/conformance/schemas/case.schema.json | 1 | 0 | 1 | 0 | -
testdata/conformance/schemas/manifest.schema.json | 1 | 0 | 1 | 0 | -
testdata/conformance/schemas/report.schema.json | 1 | 0 | 1 | 0 | -
testdata/interop/candidate-catalog.json | 4 | 0 | 0 | 0 | -
testdata/interop/discovery-registry.json | 2 | 0 | 2 | 0 | -
testdata/interop/harness/mailauthlens_overlap_test.go | 0 | 1 | 0 | 0 | -
testdata/interop/schemas/discovery-evidence.schema.json | 1 | 0 | 1 | 0 | -
testdata/interop/schemas/discovery-registry.schema.json | 1 | 0 | 1 | 0 | -
testdata/interop/schemas/external-comparison.schema.json | 1 | 0 | 1 | 0 | -
testdata/reference/draft-issues.json | 6 | 13 | 1 | 0 | -
testdata/reference/schemas/candidate-report.schema.json | 1 | 0 | 1 | 0 | -
testdata/reference/schemas/draft-issues.schema.json | 1 | 0 | 1 | 0 | -
testdata/security/report.schema.json | 1 | 0 | 1 | 0 | -
testdata/vectors/README.md | 4 | 2 | 2 | 0 | -
tools/check-operator-docs.sh | 1 | 0 | 1 | 0 | -
tools/cmd/deploymentfixture/main_test.go | 0 | 1 | 0 | 0 | -
tools/internal/conformance/conformance_test.go | 2 | 0 | 1 | 0 | -
tools/internal/conformance/model.go | 1 | 1 | 1 | 0 | -
tools/internal/interop/model.go | 1 | 0 | 1 | 0 | -
tools/internal/reference/issues.go | 0 | 5 | 0 | 0 | -
tools/internal/security/inventory.go | 1 | 0 | 1 | 0 | -
vendor/github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft-04/schema | 0 | 0 | 0 | 0 | Y
```

Totals: 180 Appendix-A paths; 306 full message-draft occurrences; 229
abbreviated pre-05 Draft-style occurrences; 81 approved full DNS-04
occurrences; five deferred full DNS-00 occurrences; 19 version-bearing paths.
The `abbr` total deliberately
includes approved DNS-04 abbreviations where the surrounding subject is DNS;
the subject classification and owner rules prevent those values from being
mistaken for stale message-draft identifiers.

The 306 full message identities split exactly into two Draft-02, two Draft-03,
300 Draft-04, and two Draft-05 occurrences. The DNS identities split into 81
`draft-chuang-dkim2-dns-04` and five
`draft-ietf-dkim-dkim2-dns-00` occurrences.

The only full pre-05 message identifiers that are not Draft-04 are two
Draft-02 and two Draft-03 occurrences. The stale Draft-02 skill occurrence is
`active-stale` and is fixed by this migration. The other Draft-02/Draft-03
values are exact external-candidate claims or negative compatibility probes and
remain `historical` or `active-target-probe` respectively. The two baseline
Draft-05 occurrences are negative target probes in command tests at clean HEAD;
their owners invert those tests when Draft-05 becomes active.

## Appendix B. Clean-HEAD abbreviated DNS inventory

This table closes the DNS-specific abbreviation space independently of the
Draft-style column in Appendix A. Every `DNS-04`, `dns-04`, `DNS04`, `dns04`,
`DNS_04` or corresponding `00` spelling is counted after ASCII
case-normalization. All 170 DNS-04 values are `approved-companion`. The five
DNS-00 values are `deferred-successor`. Ownership follows Section 6 and no DNS
identifier or DNS-versioned path moves in this migration.

```text
path | DNS-04 abbreviation | DNS-00 abbreviation
.codex/skills/dkim2-spec-conformance/SKILL.md | 1 | 0
AGENTS.md | 1 | 0
README.md | 1 | 1
cmd/dkim2-milter/README.md | 1 | 0
cmd/dkim2-milter/internal/integration/milter_fixture_test.go | 1 | 0
cmd/dkim2d/README.md | 1 | 0
cmd/dkim2d/internal/domainadmin/dnsexport.go | 3 | 0
cmd/dkim2d/internal/domainadmin/dnsexport_test.go | 1 | 0
cmd/dkim2d/internal/rotationadmin/journal_test.go | 1 | 0
contrib/qualification/postfix-milter/run.sh | 1 | 0
docs/ARCHITECTURE.md | 6 | 2
docs/conformance.md | 1 | 0
docs/operator/native-domain-onboarding.md | 1 | 0
docs/operator/opendkim-migration.md | 1 | 0
docs/operator/postfix-compose.md | 1 | 0
docs/reference/compatibility.md | 1 | 0
docs/reference/draft-issues.md | 2 | 0
docs/reference/release-candidate.md | 1 | 0
docs/security-testing.md | 1 | 0
docs/specs/implementation/datasource-providers.md | 3 | 1
docs/specs/implementation/dkim2-tag-parsers.md | 2 | 0
docs/specs/implementation/dns-key-resolver.md | 26 | 0
docs/specs/implementation/exim-adapter.md | 1 | 0
docs/specs/implementation/interop-history-ci-stabilization.md | 1 | 0
docs/specs/implementation/interoperability-reference-release-candidate.md | 8 | 0
docs/specs/implementation/ldap-sql-datasource-legacy-migration.md | 4 | 0
docs/specs/implementation/milter-adapter.md | 1 | 0
docs/specs/implementation/mvp-core-verification.md | 1 | 0
docs/specs/implementation/native-datasource-key-custody.md | 1 | 0
docs/specs/implementation/native-domain-onboarding.md | 5 | 0
docs/specs/implementation/observability-foundation.md | 1 | 0
docs/specs/implementation/openapi-daemon-foundation.md | 1 | 0
docs/specs/implementation/openapi-test-client.md | 1 | 0
docs/specs/implementation/packaging-container-delivery-operator-guide.md | 3 | 0
docs/specs/implementation/policy-engine.md | 8 | 0
docs/specs/implementation/raw-message-model.md | 1 | 0
docs/specs/implementation/security-hardening.md | 5 | 0
docs/specs/implementation/signing-and-revision.md | 3 | 0
docs/specs/implementation/static-key-signature-verification.md | 3 | 0
docs/specs/implementation/test-vectors-and-conformance-suite.md | 4 | 0
lib/dns_provider_example_test.go | 1 | 0
lib/dns_provider_test.go | 1 | 0
lib/dns_provider_vector_test.go | 2 | 0
lib/doc.go | 3 | 1
lib/internal/keyresolver/doc.go | 3 | 0
lib/internal/keyresolver/metadata.go | 2 | 0
lib/internal/keyresolver/record.go | 4 | 0
lib/internal/keyresolver/record_test.go | 1 | 0
lib/internal/tagvalue/doc.go | 1 | 0
lib/internal/tagvalue/scanner.go | 1 | 0
lib/internal/tagvalue/scanner_test.go | 2 | 0
lib/testdata/vectors/draft-chuang-dkim2-dns-04/dns-golden.json | 1 | 0
scripts/build-products.sh | 1 | 0
testdata/conformance/exim/qualification.schema.json | 1 | 0
testdata/conformance/manifest.json | 5 | 0
testdata/conformance/milter/draft-ietf-dkim-dkim2-spec-04/portable-fixtures.json | 1 | 0
testdata/conformance/report-golden/portable.md | 1 | 0
testdata/conformance/schemas/case.schema.json | 1 | 0
testdata/conformance/schemas/manifest.schema.json | 1 | 0
testdata/conformance/schemas/report.schema.json | 1 | 0
testdata/interop/discovery-registry.json | 3 | 0
testdata/interop/harness/mailauthlens_overlap_test.go | 1 | 0
testdata/interop/schemas/discovery-evidence.schema.json | 1 | 0
testdata/interop/schemas/discovery-registry.schema.json | 1 | 0
testdata/interop/schemas/external-comparison.schema.json | 1 | 0
testdata/reference/draft-issues.json | 5 | 0
testdata/reference/schemas/candidate-report.schema.json | 1 | 0
testdata/reference/schemas/draft-issues.schema.json | 1 | 0
testdata/security/report.schema.json | 1 | 0
testdata/vectors/README.md | 2 | 0
tools/check-operator-docs.sh | 1 | 0
tools/cmd/deploymentfixture/main.go | 1 | 0
tools/internal/conformance/conformance_test.go | 1 | 0
tools/internal/conformance/model.go | 1 | 0
tools/internal/interop/current.go | 2 | 0
tools/internal/interop/model.go | 1 | 0
tools/internal/security/inventory.go | 2 | 0
```

Appendices A and B together cover 191 unique tracked paths. Their union has no
unowned or invalid message/DNS identifier.

## Appendix C. Final migration working-tree disposition

Appendices A and B remain the immutable clean-HEAD discovery record. This
appendix is a separate final-state supplement captured after the implementation
and documentation prompts on 26 August 2026. It does not rewrite the original
snapshot, source-diff, XML-hunk, section-anchor, or non-change provenance.

The final-state scans use these exact expressions:

- `COMBINED`: `draft-ietf-dkim-dkim2-spec-0[0-4]|draft-0[0-4]|Draft-0[0-4]|Draft0[0-4]|draft0[0-4]`
- `FULL`: `draft-ietf-dkim-dkim2-spec-0[0-4]`
- `DNS`: `draft-ietf-dkim-dkim2-dns-[0-9][0-9]|draft-chuang-dkim2-dns-[0-9][0-9]`

All scans exclude `temp/**`. `L` is the number of matching lines, `O` is the
number of matching occurrences, and `F` is the subset matching the full
message-draft expression. The occurrence partitions use the closed classes
from Section 1: `H` is `historical`, `P` is `active-target-probe`, `C` is
`approved-companion`, and `V` is `unrelated-vendored`. Each row satisfies
`O = H + P + C + V`; HTML character references in two version-bearing path
cells are decoded before path comparison.

The mechanically reconciled totals are:

| Inventory | Lines | Paths | Occurrences | Exact partition |
| --- | ---: | ---: | ---: | --- |
| Combined retained-message expression | 396 | 63 | 419 | H=348, P=47, C=17, V=7 |
| Full retained-message identifier | - | 36 | 101 | H=94, P=7, C=0, V=0 |
| Full DNS identifier expression | 97 | 62 | 100 | approved companion=93, deferred successor=7 |

The 63-path combined inventory follows. No row is `active-stale` or `invalid`.

| Path | L | O | F | H | P | C | V | Final retention reason |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `README.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical qualification summary |
| `cmd/dkim2-exim/exim/tests/test_real_matrix_service.py` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | older-candidate rejection probe |
| `cmd/dkim2-milter/internal/integration/milter_fixture_test.go` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | predecessor-fixture mutation |
| `cmd/dkim2ctl/internal/testclient/negative_test.go` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | negative enum probe |
| `cmd/dkim2ctl/internal/testclient/operations_test.go` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | negative request fixture |
| `cmd/dkim2d/internal/httpjson/response_scalar_test.go` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | negative enum probe |
| `docs/ARCHITECTURE.md` | 10 | 10 | 0 | 10 | 0 | 0 | 0 | revision history and migration boundary |
| `docs/conformance.md` | 2 | 2 | 0 | 2 | 0 | 0 | 0 | historical qualification boundary |
| `docs/operations/exim-adapter.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical qualification boundary |
| `docs/operator/postfix-compose.md` | 5 | 5 | 0 | 5 | 0 | 0 | 0 | drain-only migration and rollback boundary |
| `docs/reference/README.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical report link |
| `docs/reference/compatibility.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical compatibility evidence |
| `docs/reference/draft-issues.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical qualification issue |
| `docs/reference/known-limitations.md` | 2 | 2 | 0 | 2 | 0 | 0 | 0 | historical evidence and migration boundary |
| `docs/reference/release-candidate.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical candidate evidence |
| `docs/replay-store-valkey.md` | 4 | 4 | 0 | 4 | 0 | 0 | 0 | drain-only replay migration |
| `docs/reports/current-semantics-audit-2026-08-21.md` | 4 | 4 | 1 | 4 | 0 | 0 | 0 | dated historical report |
| `docs/reports/draft-05-semantics-audit-2026-08-26.md` | 7 | 8 | 0 | 8 | 0 | 0 | 0 | current audit of predecessor boundaries |
| `docs/reports/exim-compatibility-2026-07-27.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | dated historical qualification report |
| `docs/security-testing.md` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical qualification boundary |
| `docs/specs/draft-05-migration-disposition.md` | 43 | 48 | 20 | 48 | 0 | 0 | 0 | clean-HEAD inventory and migration self-audit |
| `docs/specs/implementation/canonicalization-and-hashes.md` | 12 | 12 | 7 | 12 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/datasource-providers.md` | 3 | 4 | 2 | 4 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/delivery-status-signing.md` | 9 | 9 | 2 | 9 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/dkim2-tag-parsers.md` | 18 | 18 | 2 | 18 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/dns-key-resolver.md` | 3 | 3 | 2 | 3 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/exim-adapter.md` | 2 | 2 | 1 | 2 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/interop-history-ci-stabilization.md` | 13 | 13 | 3 | 13 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/interoperability-reference-release-candidate.md` | 11 | 11 | 2 | 11 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/ldap-sql-datasource-legacy-migration.md` | 7 | 7 | 1 | 7 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/milter-adapter.md` | 4 | 4 | 1 | 4 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/mvp-core-verification.md` | 11 | 11 | 4 | 11 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/native-datasource-key-custody.md` | 2 | 2 | 1 | 2 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/native-domain-onboarding.md` | 2 | 2 | 1 | 2 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/observability-foundation.md` | 2 | 2 | 1 | 2 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/openapi-daemon-foundation.md` | 6 | 6 | 5 | 6 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/openapi-test-client.md` | 3 | 3 | 1 | 3 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/packaging-container-delivery-operator-guide.md` | 5 | 5 | 2 | 5 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/policy-engine.md` | 7 | 7 | 2 | 7 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/postfix-dsn-origin.md` | 3 | 3 | 1 | 3 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/raw-message-model.md` | 3 | 3 | 2 | 3 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/recipe-application.md` | 35 | 36 | 4 | 36 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/recipe-generation.md` | 16 | 17 | 4 | 17 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/replay-store-valkey.md` | 6 | 6 | 3 | 6 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/security-hardening.md` | 17 | 17 | 2 | 17 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/signing-and-revision.md` | 18 | 19 | 3 | 19 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/static-key-signature-verification.md` | 16 | 16 | 5 | 16 | 0 | 0 | 0 | dated implementation record |
| `docs/specs/implementation/test-vectors-and-conformance-suite.md` | 11 | 11 | 5 | 11 | 0 | 0 | 0 | dated implementation record |
| `lib/dns_provider_vector_test.go` | 16 | 16 | 0 | 0 | 0 | 16 | 0 | implemented companion test names |
| `lib/internal/canonical/header_test.go` | 18 | 27 | 0 | 0 | 27 | 0 | 0 | bidirectional cross-version hash proof |
| `lib/internal/replay/deriver_test.go` | 3 | 3 | 0 | 0 | 3 | 0 | 0 | cross-version replay derivation proof |
| `testdata/conformance/manifest.json` | 2 | 2 | 0 | 0 | 2 | 0 | 0 | bidirectional cross-version cases |
| `testdata/interop/candidate-catalog.json` | 4 | 4 | 4 | 4 | 0 | 0 | 0 | external-source candidate claims |
| `testdata/interop/harness/mailauthlens_overlap_test.go` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | external-source compatibility probe |
| `tools/check-operator-docs.sh` | 4 | 4 | 2 | 2 | 2 | 0 | 0 | historical-banner and active-stale guards |
| `tools/cmd/conformance/main.go` | 3 | 5 | 0 | 0 | 4 | 1 | 0 | mixed message cross-version and companion registry |
| `tools/cmd/conformance/main_test.go` | 2 | 4 | 0 | 0 | 4 | 0 | 0 | cross-version conformance registry proof |
| `tools/cmd/deploymentfixture/main_test.go` | 1 | 1 | 0 | 1 | 0 | 0 | 0 | historical fixture intent comment |
| `vendor/github.com/getkin/kin-openapi/openapi3/schema.go` | 2 | 2 | 0 | 0 | 0 | 0 | 2 | unrelated vendored schema vocabulary |
| `vendor/github.com/getkin/kin-openapi/openapi3/validation_error.go` | 1 | 1 | 0 | 0 | 0 | 0 | 1 | unrelated vendored schema vocabulary |
| `vendor/github.com/santhosh-tekuri/jsonschema/v6/README.md` | 1 | 1 | 0 | 0 | 0 | 0 | 1 | unrelated vendored schema vocabulary |
| `vendor/github.com/santhosh-tekuri/jsonschema/v6/draft.go` | 2 | 2 | 0 | 0 | 0 | 0 | 2 | unrelated vendored schema vocabulary |
| `vendor/github.com/santhosh-tekuri/jsonschema/v6/metaschemas/draft&#45;04/schema` | 1 | 1 | 0 | 0 | 0 | 0 | 1 | unrelated vendored metaschema |

The full DNS inventory is independent of the combined-message inventory.
Every value in the `A` column is `approved-companion`; every value in the `S`
column is `deferred-successor`.

| Path | A | S | Final retention reason |
| --- | ---: | ---: | --- |
| `AGENTS.md` | 1 | 0 | current companion authority or guard |
| `README.md` | 1 | 1 | companion authority plus external-source deferral |
| `cmd/dkim2-milter/README.md` | 1 | 0 | current companion authority or guard |
| `cmd/dkim2-milter/internal/integration/milter_fixture_test.go` | 1 | 0 | companion proof or versioned fixture |
| `contrib/qualification/postfix-milter/run.sh` | 1 | 0 | companion proof or versioned fixture |
| `docs/ARCHITECTURE.md` | 4 | 2 | companion authority plus external-source deferral |
| `docs/agent-skills/README.md` | 1 | 0 | current companion authority or guard |
| `docs/conformance.md` | 1 | 0 | current companion authority or guard |
| `docs/operator/postfix-compose.md` | 2 | 0 | current companion authority or guard |
| `docs/reference/compatibility.md` | 1 | 0 | current companion authority or guard |
| `docs/reference/draft-issues.md` | 1 | 0 | current companion authority or guard |
| `docs/reports/draft-05-semantics-audit-2026-08-26.md` | 1 | 0 | current companion authority or guard |
| `docs/security-testing.md` | 1 | 0 | current companion authority or guard |
| `docs/specs/draft-05-migration-disposition.md` | 7 | 2 | companion/deferred self-audit |
| `docs/specs/implementation/datasource-providers.md` | 3 | 1 | companion authority plus external-source deferral |
| `docs/specs/implementation/dkim2-tag-parsers.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/dns-key-resolver.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/exim-adapter.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/interoperability-reference-release-candidate.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/ldap-sql-datasource-legacy-migration.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/milter-adapter.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/mvp-core-verification.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/native-datasource-key-custody.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/native-domain-onboarding.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/observability-foundation.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/openapi-daemon-foundation.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/openapi-test-client.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/packaging-container-delivery-operator-guide.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/policy-engine.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/raw-message-model.md` | 1 | 0 | historical implementation companion |
| `docs/specs/implementation/security-hardening.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/signing-and-revision.md` | 2 | 0 | historical implementation companion |
| `docs/specs/implementation/static-key-signature-verification.md` | 3 | 0 | historical implementation companion |
| `docs/specs/implementation/test-vectors-and-conformance-suite.md` | 3 | 0 | historical implementation companion |
| `lib/dns_provider_example_test.go` | 1 | 0 | companion proof or versioned fixture |
| `lib/dns_provider_vector_test.go` | 2 | 0 | companion proof or versioned fixture |
| `lib/doc.go` | 1 | 1 | companion authority plus external-source deferral |
| `lib/internal/keyresolver/doc.go` | 1 | 0 | current companion authority or guard |
| `lib/internal/keyresolver/record.go` | 1 | 0 | current companion authority or guard |
| `lib/testdata/vectors/draft&#45;chuang&#45;dkim2&#45;dns&#45;04/dns-golden.json` | 1 | 0 | companion proof or versioned fixture |
| `scripts/build-products.sh` | 1 | 0 | current companion authority or guard |
| `testdata/conformance/exim/qualification.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/conformance/manifest.json` | 5 | 0 | companion proof or versioned fixture |
| `testdata/conformance/milter/draft-ietf-dkim-dkim2-spec-05/portable-fixtures.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/conformance/report-golden/portable.md` | 1 | 0 | companion proof or versioned fixture |
| `testdata/conformance/schemas/case.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/conformance/schemas/manifest.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/conformance/schemas/report.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/interop/discovery-registry.json` | 2 | 0 | companion proof or versioned fixture |
| `testdata/interop/schemas/discovery-evidence.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/interop/schemas/discovery-registry.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/interop/schemas/external-comparison.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/reference/draft-issues.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/reference/schemas/candidate-report.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/reference/schemas/draft-issues.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/security/report.schema.json` | 1 | 0 | companion proof or versioned fixture |
| `testdata/vectors/README.md` | 2 | 0 | companion proof or versioned fixture |
| `tools/check-operator-docs.sh` | 2 | 0 | current companion authority or guard |
| `tools/internal/conformance/conformance_test.go` | 1 | 0 | companion proof or versioned fixture |
| `tools/internal/conformance/model.go` | 1 | 0 | current companion authority or guard |
| `tools/internal/interop/model.go` | 1 | 0 | current companion authority or guard |
| `tools/internal/security/inventory.go` | 1 | 0 | current companion authority or guard |

The DNS table reconciles to 93 `A` plus seven `S` occurrences. The seven
successor occurrences are exactly five external-source deferrals retained from
the clean-HEAD snapshot plus two self-audit references in this disposition;
the final documentation prompt introduced zero successor occurrence.

Mechanical acceptance requires all of the following at once:

1. the `COMBINED` scan returns exactly the 63 path cells above, with no missing,
   duplicate, or extra path;
2. each combined row reproduces `L`, `O`, and `F`, and its four class counts sum to
   `O`;
3. the `F` column sums to 101 occurrences on 36 non-zero paths;
4. the `DNS` scan returns exactly the 62 DNS path cells above and reproduces
   `A + S = 100`; and
5. Appendices A and B continue to describe the original clean-HEAD snapshot,
   rather than being silently rebased to this final working tree.
