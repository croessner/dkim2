# Interoperability, Reference Polish, And Release Candidate Specification

Status: implementation-ready planning baseline.

Implementation base: `3803d52c5279f65f5e659fefe996548adfe6d41d`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` behavior identifier. The active
working-group DNS document has a different identifier but a normatively
identical body. This increment does not silently migrate identifiers,
semantics, or vectors.

The release candidate is the scoped first public-preview candidate for the
implemented library, daemon, generated client, Milter, Postfix, flat-file
datasource, and Valkey replay surfaces. It is not a claim that the DKIM2 drafts
are final, that all DKIM2 implementations interoperate, or that deferred Exim,
LDAP, SQL, and migration work exists.

## Source Documents And Precedence

Authority order is:

1. `draft-ietf-dkim-dkim2-spec-04` for DKIM2 protocol meaning;
2. `draft-chuang-dkim2-dns-04` for the repository's tested DNS behavior;
3. RFC 5321, RFC 5322, RFC 6376, RFC 6531, RFC 6532, RFC 8259, and RFC 8601
   for incorporated SMTP, message, DKIM heritage, internationalized-message,
   JSON, and Authentication-Results behavior;
4. `docs/specs/openapi/dkim2d.yaml` for daemon HTTP operations and DTOs;
5. `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md` for repository,
   module, security, compatibility, and release boundaries;
6. completed implementation specifications for the surface under review;
7. `docs/conformance.md`, `docs/security-testing.md`, and the container and
   operator guides for already implemented evidence and claim limits;
8. exact primary external source material for facts about another
   implementation; and
9. this specification for discovery, comparison, issue tracking, reference
   polish, release-candidate evidence, and closeout.

External source code, package metadata, search results, issue discussions,
generated output, current local code, and test fixtures are evidence. They are
not authority over a draft, RFC, or OpenAPI contract. No disagreement may be
resolved by weakening validation, changing a vector expectation without
proving it wrong, or relabeling project policy as protocol conformance.

## Original Gap

The repository has a reference-quality protocol core, generated service
boundary, operational Milter/Postfix path, deterministic conformance and
security profiles, and reproducible container delivery. It does not yet have
one reviewed public-preview reference baseline.

The remaining gaps are:

- no closed, reproducible inventory of independently developed DKIM2
  implementations or an evidence-backed statement that no eligible runnable
  implementation was available at the observation cutoff;
- no safe execution contract for untrusted external source, fixtures, or
  binaries and no typed comparison result that separates agreement,
  disagreement, unsupported overlap, and unavailability;
- no durable issue log that maps every known Draft-04/DNS-04 ambiguity, TBA,
  erratum-like discrepancy, and local interpretation to exact sections,
  behavior owners, tests, and upstream state;
- no bidirectional check proving that each `documented_interpretation`
  conformance case has one issue-log owner and each behavior-bearing issue has
  executable evidence;
- no final exported Go API, generated OpenAPI, CLI, configuration, report,
  documentation, and compatibility review against one fixed base;
- no candidate version plan for the library and nested command modules, no
  safe prerelease parser contract, and no pre-tag standalone-module proof;
- no single candidate-bound report that merges conformance, security,
  packaging, deployment, API/reference, issue, external-comparison, version,
  and deferral evidence; and
- no narrow release-candidate declaration whose criteria remain truthful when
  external interop is unavailable and Exim/M22 are explicitly absent.

## Goal

Deliver one independently reviewed first-preview release candidate that:

- inventories external DKIM2 implementations through a closed, current,
  primary-source discovery process;
- runs a bounded comparison against every eligible runnable independent
  implementation, or records one exact non-success availability state with
  reproducible evidence;
- never treats discovery failure, network outage, search-engine silence, or
  another implementation's assertion as interoperability success;
- tracks all known draft issues and local interpretations with stable
  identifiers and bidirectional test closure;
- fixes implementation defects at their owning abstraction with a reproducer
  first whenever practical;
- freezes the intended `v0.1.0-rc.1` preview version and exact module-tag plan
  without creating a tag, publishing an artifact, or granting release
  authority;
- reviews and polishes exported Go, OpenAPI/generated, CLI, configuration,
  report, documentation, and operator reference surfaces without duplicating
  their authoritative models;
- proves standalone module resolution for the candidate through a private
  deterministic module proxy before any public tag exists;
- produces deterministic, privacy-safe, candidate-bound machine and human
  reference reports; and
- passes the complete conformance, security, image, deployment, module,
  generated, vulnerability, race, fuzz, and repository gate set.

No unresolved implementation finding is permitted. A draft issue may remain
open only when the upstream draft itself remains ambiguous, incomplete, or
TBA, the local interpretation is explicit and restrictive, tests bind it, and
no public claim describes it as settled normative behavior.

## Delivery Shape

One implementation agent executes these slices sequentially:

1. freeze the external discovery registry, evidence schemas, eligibility
   rules, hostile-artifact policy, and deterministic comparison runner;
2. acquire and compare every eligible external implementation or produce the
   exact evidence-backed unavailability state;
3. create the durable draft issue log and prove bidirectional closure with
   conformance cases, code owners, and public claims;
4. inventory and polish the exported Go, generated OpenAPI/client, CLI,
   configuration, report, and reference-documentation surfaces;
5. implement the `v0.1.0-rc.1` version/module plan, private module-proxy proof,
   compatibility statement, release notes, and candidate report;
6. attack discovery, external execution, issue/report integrity, API
   compatibility, versioning, privacy, and release-evidence boundaries; and
7. run the unchanged-snapshot reference-candidate and complete repository
   gates, then freeze the candidate for review.

One fresh independent reviewer then audits and fixes the cumulative candidate.
There are no slice commits. The orchestrator creates exactly one
project-formatted commit only after every finding is fixed and two approvals
bind one unchanged snapshot.

## Implementation Effort

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 1 to 3 agent-days, excluding a genuine external source or container-runtime outage |
| Highest-risk areas | false interoperability claims, untrusted third-party execution, draft-issue closure, pre-tag module resolution, public API compatibility, cross-report snapshot identity |
| Expected prompt count | seven implementation prompts plus one independent review/fix prompt |
| Required final gate | one complete reference-candidate report plus M18, M19, M20, and repository guardrails on the same unchanged snapshot |

Timing, external retrieval details, raw comparisons, candidate hashes, report
hashes, findings, fixes, and approvals remain in ignored prompt evidence until
closeout.

## Scope

### In Scope

- Closed discovery of independently developed DKIM2 implementations from
  exact primary sources.
- Eligibility, provenance, license, retrieval, source-digest, build, sandbox,
  and comparison policy for external candidates.
- A deterministic external-comparison schema and report.
- Explicit evidence states when no eligible or runnable external
  implementation is available.
- Overlap-only comparison using synthetic reserved-domain fixtures and exact
  Draft-04/DNS-04 claims.
- A durable Draft-04/DNS-04 issue log with stable IDs and authority links.
- Final public Go API, OpenAPI/generated client/server, `dkim2ctl`, daemon,
  Milter, configuration, output schema, documentation, and example review.
- API, CLI, config, module, artifact, and report compatibility statements for
  the first preview.
- Exact preview version and module-tag planning for `v0.1.0-rc.1`.
- A private deterministic Go module proxy that proves command modules resolve
  the exact candidate library with `GOWORK=off` before publication.
- Candidate-bound machine and human reference/conformance reports.
- Release notes, known limitations, compatibility notes, and reproducible
  commands.
- Closed Makefile and least-privilege CI checks.

### Out Of Scope

- Changing the pinned message or DNS draft baseline.
- Inventing semantics for Draft-04 TBA sections.
- Unicode, IDNA, local-part, or SMTPUTF8 envelope normalization not defined by
  the pinned authority.
- DNSSEC as a DKIM2 verdict or policy input.
- Filing an IETF issue, sending mail, opening an upstream pull request, or
  changing an external repository without separate authorization.
- Treating DKIM1-only code, a fork/vendor of this repository, documentation
  prose, or a non-runnable sketch as successful DKIM2 interoperability.
- Fetching or executing arbitrary fixture-controlled commands, URLs, scripts,
  images, packages, plugins, or credentials.
- Adding remote daemon access, a TCP Milter listener, new protocol actions, or
  a fail-open default.
- Creating real Git tags, GitHub releases, registry images, attestations, or
  public module versions.
- Publishing stable, minor, major, or `latest` aliases for a prerelease.
- Implementing, inspecting, restoring, changing, or executing deferred Exim
  work. Exim remains M17.
- Implementing LDAP/SQL providers, schema/DDL, driver/pool configuration,
  immutable database publication, or OpenDKIM migration. Those remain M22.
- Claiming a complete product, final RFC conformance, certification, original
  SMTP-wire fidelity for Milter, or interoperability with an unexecuted peer.
- Staging, committing, pushing, publishing, or tagging from an implementation
  or review prompt.

## Ownership And Repository Layout

Ownership remains aligned with the existing product boundaries:

- `lib/` owns DKIM2 protocol semantics, the exported library facade, and its
  deterministic exported-surface manifest input. It remains independently
  usable and does not gain external-comparison, release, daemon, Milter,
  OpenAPI, CLI, container, LDAP, or SQL dependencies.
- `docs/specs/openapi/dkim2d.yaml` remains the HTTP source of truth.
  Generated server and client artifacts stay in their existing command-owned
  boundary packages.
- `cmd/dkim2d`, `cmd/dkim2-milter`, and `cmd/dkim2ctl` own only their current
  service, adapter, and generated-client reference surfaces.
- `docs/reference/` owns the human-readable draft issue log, compatibility
  statement, known limitations, external-comparison summary, and release
  notes. These documents link authoritative schemas and owners rather than
  duplicating them.
- `testdata/interop/` may own strict durable discovery registries, schemas,
  synthetic comparison fixtures, and normalized report goldens. It contains
  no retrieved third-party source, binary, package cache, or raw output.
- `tools/` may own closed discovery, artifact validation, external sandbox
  orchestration, API manifest, private module-proxy, evidence merge, report
  rendering, and drift checks. Tooling does not own protocol expected values
  or execute registry-selected commands.
- root Makefile and CI own fixed orchestration and least-privilege gates.
- ignored `temp/` and `.artifacts/` own all raw retrievals, external working
  trees, binaries, comparison output, module proxy bytes, logs, caches, and
  current reports.

New structure may use a smaller equivalent layout when one cohesive existing
owner is clearer. It must not create a second protocol model, OpenAPI model,
configuration model, compatibility model, or conformance result model.

## Frozen Invariants

These invariants hold throughout implementation and review:

1. Draft-04 and historical DNS-04 identifiers and behavior remain fixed.
2. Draft, RFC, interpretation, local policy, OpenAPI, adapter, external
   observation, and release-policy claims remain distinguishable.
3. External source and output are hostile evidence, never normative authority.
4. A required discovery outage cannot prove candidate absence.
5. `no_eligible_candidate` is an explicit external-unavailability result,
   never a skipped gate or interoperability PASS.
6. Every eligible safe overlap executes or has exact vectors-only/
   non-runnable evidence; no eligible candidate is silently omitted.
7. Every mismatch is reproduced and classified before an expectation or
   implementation changes.
8. Every documented interpretation has one stable issue owner and executable
   proof; local and upstream issue states never collapse.
9. OpenAPI changes precede generated and handler changes; wire
   `api_version=v1` remains stable.
10. The M20 commit is the exported/reference compatibility comparison base.
11. `v0.1.0-rc.1` is prepared but no real tag, publication, alias, or trusted
    attestation is created.
12. Every report and approval binds one fixed base, empty index, exact
    candidate snapshot, and exact external observation evidence.
13. Raw messages, envelopes, identities, keys, capabilities, protected
    material, paths, peer output, and raw errors remain absent from
    unauthorized output.
14. Exim remains untouched and `deferred_m17`.
15. LDAP, SQL, and migration remain unimplemented and `deferred_m22`.
16. `temp/` and `.artifacts/` remain ignored and unstaged; exactly one final
    durable commit is orchestrator-owned.

## Claim Taxonomy And Normative Separation

Every public and machine-readable assertion has exactly one primary class:

| Class | Meaning |
| --- | --- |
| `draft_normative` | Direct requirement from the pinned DKIM2 or DNS draft |
| `rfc_normative` | Direct requirement from an incorporated RFC |
| `documented_interpretation` | Explicit local interpretation of ambiguous pinned text |
| `local_security_policy` | Restrictive product behavior outside protocol conformance |
| `openapi_contract` | Behavior owned by the authoritative generated HTTP contract |
| `adapter_contract` | Milter or Postfix behavior and fidelity evidence |
| `external_observation` | Bounded fact observed from an independent implementation |
| `release_policy` | Version, compatibility, artifact, or publication criterion |

An assertion may cite related classes, but counts and conclusions remain
separate. In particular:

- external agreement is not normative proof;
- external disagreement does not automatically prove this implementation
  wrong;
- local conformance does not prove interoperability;
- Milter/Postfix success does not prove original RFC 5322 wire fidelity;
- replay, limits, protected files, telemetry, and packaging remain local
  policy;
- OpenAPI agreement does not create DKIM2 semantics; and
- a release-candidate PASS does not make a draft final or deferred capability
  implemented.

Public prose must avoid unqualified `certified`, `fully compliant`,
`complete`, `final implementation`, and `interoperable`. A claim names the
exact snapshot, report profile, peer and peer revision where applicable,
operation overlap, evidence class, and limitation.

## External Implementation Discovery Contract

The repository owns one strict, versioned discovery registry. It contains
only reviewed primary-source locations and fixed query definitions. It cannot
provide commands, shell fragments, environment variables, credentials,
arbitrary working directories, container options, output paths, or dynamic
plugins.

Discovery covers:

- the pinned drafts' implementation/reference sections and author-maintained
  project links;
- the DKIM working-group's official repositories, issue trackers, and mail
  archive when they provide implementation evidence;
- reviewed source-forge repository searches with exact recorded queries;
- reviewed package registries when a DKIM2-specific package is found; and
- candidates already cited by a primary source.

Search snippets are discovery hints only. A candidate fact is accepted only
from its primary repository, package record, release artifact, or maintainer
documentation. An unavailable discovery source is recorded as
`discovery_unavailable` and blocks completion; it cannot be converted into
`no_eligible_candidate`.

The final observation cutoff is exact UTC and no more than seven days old at
approval. The registry and report record:

- source kind and canonical HTTPS location;
- exact query or fixed object identifier;
- observation cutoff;
- response/status class;
- bounded response SHA-256 and normalized result digest;
- candidate canonical location and immutable revision when discovered;
- license and independent-ownership evidence;
- claimed draft/version and supported operation surface; and
- eligibility decision with one closed reason.

Raw retrieved material remains ignored. Normalized evidence contains no
credentials, tokens, local paths, user/host identity, remote client addresses,
arbitrary snippets, or unbounded external text.

### Candidate Eligibility

An eligible external implementation must:

- be independently developed rather than a fork, vendor, generated copy, or
  wrapper of this repository;
- explicitly implement DKIM2 or a named DKIM2 draft, not only DKIM1;
- expose source, an authenticated artifact, or exact vectors sufficient to
  evaluate at least one overlapping operation;
- have an identifiable immutable revision or content digest;
- have license terms that permit the required local inspection and execution;
- accept only synthetic test material for the comparison;
- have a build/execution path that can be reviewed and confined; and
- not require production credentials, live mailboxes, live signing keys,
  privileged host access, or mutation of public infrastructure.

Candidate state is one of:

- `eligible_runnable`;
- `eligible_vectors_only`;
- `ineligible_not_dkim2`;
- `ineligible_not_independent`;
- `ineligible_no_immutable_source`;
- `ineligible_license_unknown`;
- `ineligible_unsafe_execution`;
- `ineligible_no_overlap`;
- `source_unavailable`; or
- `malformed_evidence`.

An eligible runnable candidate must be executed. An eligible vectors-only
candidate is compared byte-for-byte where independently checkable, but the
report must not claim runtime interoperability.

### Overall External Availability

The external profile has one state:

- `compared`: every eligible runnable candidate and every eligible
  vectors-only candidate completed its exact overlap;
- `no_eligible_candidate`: complete current discovery found no eligible
  candidate;
- `eligible_not_runnable`: at least one eligible candidate has no safe
  runnable surface, with its exact source/vector comparison state recorded;
- `disagreement`: a comparison produced a classified mismatch;
- `discovery_unavailable`: a required discovery source could not be observed;
  or
- `evidence_invalid`: provenance, digest, freshness, bounds, privacy, or
  candidate identity failed.

Only `compared`, `no_eligible_candidate`, or a fully evidenced
`eligible_not_runnable` can support release-candidate completion. None is
called interoperability PASS unless at least one independent runtime executed
and all stated overlapping cases agreed. `disagreement` blocks release until
each mismatch is fixed or classified through the draft issue process.
`discovery_unavailable` and `evidence_invalid` always block.

## External Acquisition And Execution Security

External bytes are hostile. Acquisition:

- uses exact allowlisted HTTPS endpoints and immutable revisions;
- verifies archive, commit, tree, artifact, and fixture digests;
- records signed-release or source-forge identity where available;
- rejects redirects outside the reviewed authority;
- bounds redirects, bytes, files, depth, path length, file size, total size,
  and retrieval time;
- rejects path traversal, symlinks, hard links, devices, sockets, FIFOs,
  case-fold collisions, Unicode-normalization collisions, and special files;
- stores bytes only under an invocation-owned ignored directory; and
- performs no credentialed access unless a maintainer separately authorizes
  an exact secret-safe source.

No external build or test runs before a human-readable source/build inventory
and license check. Execution uses:

- an invocation-owned isolated container or equivalent sandbox;
- a read-only source mount and read-only local repository mount;
- no host network after acquisition;
- no Docker socket, host namespace, device, privileged mode, credential,
  SSH agent, home directory, environment secret, or writable source;
- fixed CPU, memory, pids, descriptor, file-size, process-count, and wall-time
  limits;
- a fixed minimal environment and closed entrypoint selected by
  repository-owned code;
- only reserved `.test` messages, envelopes, DNS records, and keys;
- bounded stdout/stderr captured as hostile bytes and normalized to closed
  result classes; and
- project-scoped cleanup on success, failure, timeout, signal, and panic.

The repository never imports external protocol logic, expected values, or
dependencies into production code merely to obtain agreement.

## External Comparison Contract

The comparison schema is `dkim2.external-comparison.v1`. It binds:

- the local base revision and candidate-snapshot digest;
- both pinned draft identifiers;
- discovery registry and normalized discovery digests;
- observation cutoff;
- external candidate canonical identity, immutable revision, source digest,
  license class, and build/artifact digest;
- local and external producer digests;
- exact overlapping operation and claim class;
- input fixture digest;
- independently established expected-value provenance where one exists;
- local result, external result, and closed comparison state;
- limitation and unsupported-state classes; and
- one aggregate availability state.

Comparison cases are drawn from already reviewed synthetic conformance
fixtures or new independently derived fixtures that enter the M18 manifest.
An external candidate cannot provide the sole oracle for the fixture.

The initial overlap inventory considers:

- RFC 5322 byte parsing only when the peer exposes exact bytes;
- Message-Instance parse/format/hash behavior;
- DKIM2-Signature parse/format/canonical input;
- RSA-SHA256 and Ed25519-SHA256 verification;
- current-envelope and custody checks;
- recipe parse, apply, and generation;
- origin signing and revision;
- DNS-04 key-record behavior; and
- structured result mapping only where both implementations expose equivalent
  facts.

Unsupported operations are recorded and excluded from agreement counts. A
field-name coincidence or shared boolean is not sufficient equivalence.
Adapter, replay, OpenAPI, telemetry, container, and deployment behavior is
not compared as DKIM2 protocol interoperability unless the peer independently
implements the same named non-protocol surface.

Every mismatch is first reproduced locally and then classified as:

- local implementation defect;
- external implementation defect;
- fixture/oracle defect;
- draft ambiguity;
- draft-version mismatch;
- unsupported/non-equivalent surface; or
- unresolved contradiction.

Local defects and fixture defects are fixed at the root. Draft ambiguities
enter the issue log. An unresolved contradiction blocks the candidate. The
report contains no raw external error or output text.

## Draft Issue Log

The durable issue log lives under `docs/reference/` and uses stable IDs such
as `DKIM2-DRAFT-001`. IDs are never reused or renumbered.

Each entry contains:

- title and primary class;
- message or DNS draft identifier and exact section;
- incorporated RFC section when relevant;
- exact ambiguity, TBA, internal inconsistency, erratum-like discrepancy, or
  external disagreement stated without copying excessive source text;
- effect on protocol behavior and public claims;
- restrictive local interpretation or explicit unimplemented state;
- owning package/API/adapter;
- conformance/vector/test identifiers;
- external comparison identifiers when applicable;
- upstream reference and observation date when one exists;
- local status and upstream status as separate fields; and
- resolution criterion.

Local status is one of:

- `open_blocks_candidate`;
- `implemented_interpretation`;
- `not_implemented`;
- `not_applicable`;
- `superseded_by_baseline`; or
- `resolved_local_defect`.

Upstream status is one of:

- `not_reported`;
- `reporting_requires_authorization`;
- `reported`;
- `acknowledged`;
- `resolved_in_later_draft`; or
- `not_upstream_issue`.

An implementation fix does not mark a draft ambiguity resolved upstream.
`resolved_in_later_draft` requires exact published draft evidence and does not
change the repository baseline without a separate baseline migration.

The issue-log checker proves:

- every `documented_interpretation` conformance case names exactly one issue;
- every behavior-bearing issue names at least one deterministic test or an
  explicit `not_implemented` gate;
- every Draft-04 TBA section is represented;
- every architecture-recorded draft discrepancy is represented;
- every external mismatch has one issue or one resolved defect record;
- public conformance/reference prose links the relevant open limitation; and
- no issue claims that local policy is normative DKIM2 behavior.

No implementation or review prompt reports or edits an upstream issue without
separate maintainer authorization.

## Reference Surface And API Polish

### Go Library

The `lib/` module remains the standalone protocol library. The increment
creates a deterministic exported-surface manifest from Go syntax/type
information, not formatted `go doc` text alone. It includes:

- exported packages, types, constants, variables, functions, methods, fields,
  interfaces, type parameters, and function signatures;
- public structured error/result enums and JSON representations;
- constructor/options and context behavior;
- module path, Go version, and direct dependency closure; and
- concise English documentation presence.

The M20 commit is the compatibility comparison base. Every change is
classified `additive`, `compatible_clarification`, `breaking_pre_rc_cleanup`,
`draft_correctness_fix`, or `security_fix`. A breaking pre-RC cleanup requires
a durable migration note and exhaustive call-site/test update. No service,
Milter, OpenAPI, Cobra, Viper, Fx, Prometheus, OTLP, LDAP, SQL, or CLI
dependency may enter `lib/`.

### OpenAPI And Generated Clients

OpenAPI remains authoritative. Any HTTP cleanup changes the YAML first,
regenerates all server/client/Milter artifacts with the pinned generator,
reviews generated diffs, and updates positive/negative fixtures.

The review covers:

- operation IDs, route/method closure, media types, status codes, errors,
  required fields, enums, bounds, examples, and discriminator-like relations;
- `api_version=v1` and the exact Draft-04 identifier;
- process/sign/revise capability separation;
- action-plan and disposition consistency;
- request/response size and timeout containment;
- generated server/client/Milter type equality;
- HEAD/conditional behavior already owned by the daemon; and
- absence of generated DTOs from protocol packages.

OpenAPI `info.version` records the intended preview candidate
`0.1.0-rc.1`; it does not change the wire-level `api_version` enum from `v1`.
Any semantic wire break requires an explicit new API version and is outside
mere reference polish.

### CLI, Configuration, Reports, And Documentation

The review freezes:

- Cobra commands, flags, exit behavior, version/help output, and stable JSON
  Lines schemas for all three binaries;
- typed daemon and Milter config paths, defaults, conditional requirements,
  environment placeholder and redaction behavior;
- protected capability and generation ownership;
- conformance, security, image, deployment, external-comparison, and
  reference-report schemas;
- README/operator/reference navigation and copyable commands; and
- explicit Milter, Postfix, Exim, and M22 limitations.

Reference docs link authoritative generated/OpenAPI/config owners rather than
maintaining a second model. Numeric limits, labels, enums, and config tables
are generated or drift-checked.

## Release Candidate Version And Module Plan

The intended preview candidate is exactly `v0.1.0-rc.1`. This is a product
candidate version, not a protocol version and not a stable release.

The planned tag set for one exact future commit is:

```text
v0.1.0-rc.1
lib/v0.1.0-rc.1
cmd/dkim2d/v0.1.0-rc.1
cmd/dkim2-milter/v0.1.0-rc.1
cmd/dkim2ctl/v0.1.0-rc.1
```

The repository does not create these tags in this increment. A later
maintainer-authorized tag operation must prove they all resolve to the exact
approved commit.

Prerelease parsing accepts only:

```text
vMAJOR.MINOR.PATCH-rc.NUMBER
```

with canonical nonzero/zero decimal fields, no leading zeros except `0`,
bounded field lengths, lowercase literal `rc`, no build metadata, no other
prerelease identifiers, and no extra components. Stable
`vMAJOR.MINOR.PATCH` behavior remains unchanged.

RC artifacts:

- never produce stable `vMAJOR.MINOR.PATCH`, minor, major, or `latest` aliases;
- never use the stable publication workflow, which remains non-prerelease
  only;
- have no package write, OIDC, attestation, or registry credential authority;
- are built from an ignored candidate statement generated from one durable
  version plan plus current candidate snapshot;
- bind exact source, module, OpenAPI, image, SBOM, provenance, vulnerability,
  conformance, security, issue, and external-evidence identities; and
- are called prepared/local candidate artifacts unless a separately
  authorized release/tag/publish operation occurs.

The first library candidate replaces adapter sentinel requirements with
`github.com/croessner/dkim2 v0.1.0-rc.1` and removes the pre-tag workspace
bootstrap. Before any tag, a repository-owned tool constructs an invocation-
owned read-only GOPROXY. The candidate library module is built only from exact
candidate bytes using canonical Go module zip, `.mod`, `.info`, and list
files. The proxy also contains only the exact dependency modules required by
the command graphs, authenticated by their committed `go.sum` entries and
reconciled with the checked vendor tree. All command modules then run, with
`GOWORK=off`, the exact tidy-readback, test, vet, and build checks against that
proxy with checksum-database and network access disabled. The proxy digest and
resolved module graph enter ignored candidate evidence.

The private proxy:

- derives the candidate library only from the candidate snapshot and admits
  dependency archives only after exact `go.sum` and vendor reconciliation;
- validates module path and semantic version;
- rejects symlinks, special files, path escape, case collisions, invalid zip
  paths, unexpected files, changing descriptors, and noncanonical timestamps;
- contains no `temp/`, `.artifacts/`, `.git`, command module, test secret,
  protected state, or local path;
- cannot satisfy any module other than the exact candidate library and
  checked-in vendored dependency closure needed by the fixed test mode; and
- is removed by invocation-scoped cleanup.

The release compatibility window begins only if the RC tags are later created.
From that point to `v0.1.0`, breaking exported Go, `api_version=v1`, config,
CLI machine-output, or report-schema changes require a documented
Draft/RFC/security correctness exception, migration notes, and an incremented
candidate. Draft baseline changes remain separately reviewed migrations.

## Reference Candidate Report

The machine schema is `dkim2.reference-candidate-report.v1`. It contains:

- base revision and candidate-snapshot digest;
- intended product and module versions plus planned tags;
- message and DNS draft identifiers;
- public Go API manifest digest and compatibility classification counts;
- OpenAPI source, generated artifact, CLI, config, and reference-doc digests;
- draft issue-log digest and counts by local/upstream status;
- external discovery registry, cutoff, normalized evidence, candidate, case,
  and aggregate availability facts;
- M18 portable/full conformance report identities;
- M19 security, fuzz, race, privacy, and vulnerability evidence identities;
- M20 image, SBOM, provenance, vulnerability, deployment, privacy, and
  operator-document evidence identities;
- private module-proxy and `GOWORK=off` resolution evidence;
- Exim exactly `deferred_m17`;
- LDAP/SQL/migration exactly `deferred_m22`;
- findings by severity and disposition;
- release criteria with pass/fail/deferred state; and
- one overall state.

Required criteria cannot be skipped. Deferral is permitted only for the exact
declared Exim and M22 capabilities. External availability is represented by
its own closed state and never hidden as a skipped PASS.

The human report is generated from the machine report and states:

- exactly what the candidate implements and tests;
- every claim class and limitation;
- the external comparison scope or exact evidence-backed unavailability;
- open draft ambiguities and TBA sections;
- Milter/Postfix fidelity limitations;
- replay as local policy;
- Exim and M22 deferrals;
- version/tag/publication status; and
- exact reproduction commands.

Both reports are deterministic for the same candidate and exact external
evidence cutoff. They contain no raw external text, command output, message,
envelope, key, signature, DNS record, datasource row, replay identity,
capability, protected path, URL query token, credential, hostname, username,
container ID, local absolute path, or raw error.

## Security, Privacy, And Adversarial Requirements

Attack:

- discovery registry commands, URLs, redirects, response sizes, freshness,
  duplicated results, source substitution, mutable refs, and search-result
  spoofing;
- archive extraction, Git trees, path escape, symlink/hard-link/device/FIFO,
  Unicode/case collision, decompression, file count, file size, and total size;
- external builds attempting network, credentials, host mounts, Docker socket,
  process escape, resource exhaustion, output flooding, or source mutation;
- comparison fixtures, operation equivalence, unsupported surfaces,
  version mismatch, expected-value provenance, and mismatch classification;
- issue IDs, duplicate sections, missing TBA/interpretation/test links,
  status laundering, and local/upstream status confusion;
- exported Go API manifest ordering, aliases, embeds, generic signatures,
  methods, JSON enums, and stale baselines;
- OpenAPI source/generated drift, operation/DTO divergence, generated-client
  bypass, examples, bounds, and version separation;
- RC semantic-version parsing, tag plan, module zip/proxy, sum/network bypass,
  sentinel leakage, wrong module version, and prerelease alias publication;
- report merge with stale/wrong candidate, draft, issue, peer, cutoff, API,
  conformance, security, image, or deployment identity;
- all output surfaces with unique markers for messages, envelopes, keys,
  capabilities, paths, source URLs, tokens, external stderr, and identities;
  and
- cleanup on success, failure, timeout, signal, and panic.

Useful failures become stable deterministic regressions. New byte parsers or
hostile boundary code enter the closed M19 fuzz/resource inventory. Every new
or affected fuzz target runs individually for at least ten seconds after its
last edit and again in the final all-target profile.

## Makefile And CI Contract

Closed targets should include:

```text
make check-interop
make interop
make check-reference
make reference-report
make release-candidate
```

Names may be refined only if Make help, CI, docs, and evidence use one
authoritative set.

`check-interop` is deterministic and network-free. It validates discovery
registry/schema closure, cached normalized evidence structure, issue mappings,
fixtures, digests, bounds, and absence of arbitrary command authority.

`interop` performs the exact current primary-source discovery and every
eligible comparison under the isolation policy. It fails on unavailable
required discovery, invalid evidence, or unresolved disagreement. A complete
`no_eligible_candidate` result is successful execution but remains external
unavailability, not interoperability PASS.

`check-reference` validates the exported Go API manifest, OpenAPI/generated
closure, CLI/config/report/doc surfaces, issue-log closure, version/module
plan, private proxy construction, release criteria, and deferrals.

`reference-report` merges only exact candidate-bound, current evidence and
renders the deterministic machine/human report.

`release-candidate` is the non-publishing aggregate. It has no tag, Git write,
registry write, package write, OIDC, attestation, credential, or external
release authority. It runs the current interop/reference report plus every
required lower-level gate and fails unless the report is overall PASS.

CI uses pinned actions, least permissions, bounded timeouts, no repository
secrets, and ignored artifacts. Untrusted pull requests may run deterministic
checks and isolated comparisons but receive no write or signing authority.
External evidence is never reused across a different candidate or stale
observation window.

## Required Tests And Evidence

### Discovery And External Comparison

- closed registry parsing and query-source allowlist;
- primary-source, immutable-revision, license, independence, and eligibility
  classification;
- freshness, digest, redirect, size, path, archive, Git-tree, and response
  normalization negatives;
- complete no-candidate, vectors-only, runnable, disagreement, discovery
  unavailable, and invalid-evidence state tests;
- isolated external execution policy and injected escape/resource/output
  attempts;
- exact overlap and unsupported-surface accounting;
- mismatch reproduction and issue/fix classification; and
- deterministic reports for repeated identical external inputs.

### Draft Issues And Claims

- complete TBA and known-discrepancy inventory;
- bidirectional interpretation-case/issue closure;
- exact draft/RFC section validation;
- separate local and upstream states;
- no local-policy or external-observation normative promotion;
- no unauthorized upstream mutation; and
- public prose checked against machine claim classes.

### API And Reference

- deterministic exported Go API manifest and M20-base comparison;
- call-site and migration coverage for any pre-RC breaking cleanup;
- OpenAPI-first changes, regenerated artifacts, strict diff review, and
  positive/negative fixtures;
- generated server/client/Milter contract equality;
- CLI command/flag/help/version/exit/JSON Lines tests;
- typed config path/default/conditional/env/redaction drift checks;
- report-schema and documentation link/example checks; and
- module and dependency boundary guards.

### Version, Modules, And Candidate

- exact stable and `-rc.N` semantic-version normal/negative tests;
- no RC stable/minor/major/latest publication aliases;
- exact five-tag plan without creating tags;
- command requirements on `v0.1.0-rc.1` and absence of sentinel/bootstrap
  leakage;
- canonical private module proxy and hostile zip/path negatives;
- `GOWORK=off`, network/checksum-disabled tidy readback, test, vet, and build
  for every command module;
- candidate report merge, tamper, stale-evidence, wrong-version, wrong-draft,
  wrong-peer, wrong-subject, and privacy negatives; and
- repeated deterministic candidate reports.

## Final Gates

On one unchanged candidate:

```text
make fmt
make test
make vet
make lint
make race
make check-openapi
make check-workspace
make check-vendor
make check-protected-platforms
make test-valkey
make check-conformance
make conformance
make conformance-postfix
make conformance-all
make check-security
make fuzz-security
make security
make govulncheck
make check-images
make images-multiarch
make image-sbom
make image-provenance
make image-vulnerability
make image-release-evidence
make check-deployment
make deployment-postfix
make deployment-security
make check-operator-docs
make check-release
make check-interop
make interop
make check-reference
make reference-report
make release-candidate
make guardrails
git diff --check
```

Every new or affected fuzz target runs individually for at least ten seconds.
Postfix qualification and deployment normalized reports run at least twice and
remain byte-identical. External comparison repeats from the same exact
retrieved inputs and produces identical normalized output. The final reports
and both approvals bind the same unchanged candidate.

A failed, skipped, stale, unavailable, mismatched, wrong-platform,
wrong-version, wrong-peer, unreviewed-external, or publication-dependent gate
is not approval. `no_eligible_candidate` is not a skipped gate: discovery must
complete and its exact unavailability report must pass.

## Acceptance Criteria

- Complete current primary-source discovery covers the closed registry.
- Every external candidate has a justified eligibility state and immutable
  evidence.
- Every eligible runnable or vectors-only overlap is compared, or exact
  evidence explains why runtime comparison is unavailable.
- No public statement overclaims external interoperability.
- Every external mismatch is fixed or issue-classified; no unresolved
  contradiction remains.
- Every documented interpretation and behavior-bearing draft issue has
  bidirectional test ownership.
- TBA, local, upstream, and resolved-defect states remain distinct.
- Exported Go, OpenAPI/generated, CLI, config, report, and documentation
  surfaces are complete, bounded, drift-checked, and internally consistent.
- Any pre-RC breaking cleanup has an explicit migration note and full tests.
- The exact `v0.1.0-rc.1` product/module plan and private module-proxy proof
  pass without creating a real tag or publishing.
- RC tooling cannot produce stable aliases or obtain publication authority.
- One deterministic reference-candidate report binds every required current
  conformance, security, image, deployment, API, issue, external, module, and
  version identity.
- Exim is exactly `deferred_m17`; no Exim stash or work is inspected,
  restored, changed, or executed.
- LDAP/SQL providers and migration are exactly `deferred_m22`; no executable
  provider, driver, schema/DDL, configuration, or migration work is added.
- All findings are fixed, two approvals bind one unchanged snapshot, `temp/`
  and `.artifacts/` remain ignored and unstaged, and exactly one
  project-formatted milestone commit is ready for the orchestrator.

## Review Requirements

The independent reviewer:

- reads the actual diff, surrounding owners, external source/evidence, issue
  log, API manifests, generated artifacts, module proxy, and reports;
- independently reproduces the external discovery and candidate eligibility
  decisions from primary sources;
- independently verifies source, revision, archive, license, producer,
  fixture, and report digests;
- inspects external build/runner confinement from effective runtime state;
- reruns representative overlap and every mismatch;
- maps every public claim to exactly one primary class;
- proves issue-log/TBA/interpretation/test closure;
- compares exported Go and OpenAPI surfaces independently against the M20
  base;
- regenerates OpenAPI and independently constructs/resolves the private
  module proxy;
- attacks RC version parsing, tag planning, publication separation, report
  merging, privacy, and cleanup;
- fixes every finding at the root with a stable reproducer first where
  practical;
- repeats every required current gate on the final unchanged candidate; and
- records approval only when no unresolved finding remains.

The orchestrator performs a separate second review of the unchanged candidate,
external cutoff/evidence, issue and API closure, module/version plan,
conformance/security/image/deployment/reference reports, diff, index, ignored
paths, Exim/M22 deferrals, and final gates before exact staging.

## Completion Evidence

Fill after implementation and independent review:

- implementation prompt timing and measured effort;
- fixed base and candidate-snapshot digest;
- discovery registry, observation cutoff, source, and normalized evidence
  digests;
- external candidate, source, build, fixture, and comparison report digests;
- issue-log digest and status counts;
- exported Go API and OpenAPI/generated artifact digests;
- version/module plan and private module-proxy evidence;
- portable/full conformance and real Postfix report digests;
- security/fuzz/race/privacy/vulnerability evidence digests;
- image/SBOM/provenance/vulnerability and deployment report digests;
- reference-candidate machine/human report digests;
- full guardrail result;
- reviewer findings and root-cause fixes;
- independent reviewer approval;
- orchestrator approval;
- exact staged durable path inventory; and
- final commit identity.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Authority | Draft/RFC/interpretation/policy/OpenAPI/adapter/external/release claims remain separate | pending | pending | |
| Discovery | Closed, current, primary-source, reproducible candidate inventory | pending | pending | |
| External execution | Immutable, licensed, isolated, bounded, synthetic and secret-free | pending | pending | |
| Comparison | Exact overlap, independent fixtures, typed agreement/disagreement/unavailability | pending | pending | |
| Draft issues | Stable IDs, TBA coverage, local/upstream split, bidirectional test closure | pending | pending | |
| Go API | Deterministic exported surface and reviewed M20-base compatibility | pending | pending | |
| OpenAPI | Source-first generated closure, v1 stability and candidate version | pending | pending | |
| CLI/config/docs | Stable machine surfaces, drift checks, accurate references and limits | pending | pending | |
| Version/modules | Exact RC plan, no tag/publication, private proxy and standalone resolution | pending | pending | |
| Evidence | All reports current, deterministic, private and candidate-bound | pending | pending | |
| Security | Hostile external bytes, parsers, runner, reports, privacy and cleanup | pending | pending | |
| Exim | Exact deferred M17 state; stash and work untouched | pending | pending | |
| M22 | LDAP/SQL execution and migration remain deferred and untouched | pending | pending | |
| Gates | Interop/reference plus M18/M19/M20 and repository gates pass | pending | pending | |
| Commit | One exact project-formatted commit after two approvals | pending | pending | |

## Settled Decisions And Deferred Work

- Settled: Draft-04 and historical DNS-04 remain the behavior baseline.
- Settled: external agreement is evidence, not normative authority.
- Settled: complete discovery with no eligible candidate is explicit
  unavailability, not a skipped test or interoperability PASS.
- Settled: a transient discovery outage blocks; it cannot prove absence.
- Settled: external execution is isolated, bounded, credential-free, and uses
  only synthetic reserved data.
- Settled: every documented interpretation has one durable issue owner and
  executable proof.
- Settled: OpenAPI remains authoritative and wire `api_version` remains `v1`.
- Settled: the intended preview is `v0.1.0-rc.1`; this increment prepares but
  does not tag, publish, or attest it.
- Settled: prereleases cannot produce stable, minor, major, or `latest`
  aliases.
- Settled: command modules resolve the exact candidate library from a private
  deterministic proxy before public module tags exist.
- Settled: the candidate covers the library, daemon, generated client,
  Milter/Postfix, flat-file datasource, and Valkey replay scope only.
- Deferred: actual tags, GitHub release creation, registry publication,
  public module publication, and trusted attestations require separate
  maintainer authority.
- Deferred: Exim remains M17 and is not inspected or executed here.
- Deferred: executable LDAP/SQL providers and legacy migration remain M22.
