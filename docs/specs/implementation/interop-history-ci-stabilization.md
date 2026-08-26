# Interoperability, Chain Verification, and CI Simplification Specification

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

Status: implementation-ready stabilization contract.

Date: 2026-08-12.

## Purpose

This specification returns the repository to a small product-centered shape
before the next stable tag. The supported product consists of:

- the standalone DKIM2 library in `lib/`;
- the HTTP daemon in `cmd/dkim2d/`;
- the generated-client CLI in `cmd/dkim2ctl/`;
- the Milter adapter in `cmd/dkim2-milter/`; and
- the Exim adapter in `cmd/dkim2-exim/`.

Tests, generated contracts, packaging, documentation, and CI support those five
surfaces. They must not become a second product made of evidence orchestration,
CI self-tests, or release-only abstractions.

The stabilization has three functional goals and one repository goal:

1. accept Draft-04 folding whitespace inside Message-Instance hash base64;
2. make authenticated historical verification impossible to confuse with a
   current-only PASS;
3. remove the retained Turscar Draft-02 fixture corpus whose Git blob identity
   did not match the bytes tested after checkout conversion; and
4. replace the current coupled CI and release graph with direct, comprehensible
   Make targets and GitHub Actions modeled on the separation used by Nauthilus
   and Nauthilus Director.

No tag, GitHub Release, GHCR publication, or Mailstack rollout is authorized by
this specification alone.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`;
- `docs/specs/openapi/dkim2d.yaml`;
- `docs/specs/spec-and-prompt-template.md`;
- `docs/conformance.md`;
- `Makefile`;
- `draft-ietf-dkim-dkim2-spec-04`; and
- the review evidence on GitHub PR 1.

If implementation evidence conflicts with one of these sources, reconcile the
durable source before expanding the change.

## Original Gap

Three product defects and one delivery defect block the next release:

- Message-Instance parsing rejects Draft-04 FWS that another implementation
  legitimately emits;
- normal verification can report PASS while authenticated history is explicitly
  unevaluated;
- a checkout-normalized external fixture corpus is represented as immutable
  repository evidence; and
- normal Go checks, MTA integration, conformance, container publication and CI
  self-validation are coupled into a large duplicated graph.

## Goal

Deliver a small, fail-closed DKIM2 product with independently testable library,
daemon, client and adapter surfaces. The normal CI path proves those surfaces
directly. Conformance, Postfix, Exim and release publication remain visible
specialized gates instead of hidden dependencies of unit testing.

## Delivery Shape

1. Lock reproducer and regression tests, then correct folded hash parsing.
2. Make authenticated chain verification the safe public and production path.
3. Project the corrected contract through daemon, OpenAPI, client and adapters.
4. Simplify the Make dependency graph and separate external integration.
5. Replace the GitHub workflow graph with the five workflows defined below.
6. Run an independent final review before any publication is authorized.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 3-6 engineering days |
| Highest-risk area | authenticated historical verification and adapter policy |
| Expected prompt count | 7 |
| Required final gate | all target guardrails and both adapter integrations |

Risk notes:

- Low risk: fixture removal and direct CI duplication removal.
- Medium risk: Make target restructuring, workflow replacement and generated
  OpenAPI projection.
- Highest risk: result precedence and fail-closed behavior across reconstructed
  history, daemon policy and both MTA adapters.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-baseline-and-reproducer-locks.md` |  |  |  |  |  |
| `02-message-instance-fws-interop.md` |  |  |  |  |  |
| `03-authenticated-history-core.md` |  |  |  |  |  |
| `04-service-openapi-and-adapter-policy.md` |  |  |  |  |  |
| `05-makefile-quality-and-adapter-gates.md` |  |  |  |  |  |
| `06-github-actions-and-release-simplification.md` |  |  |  |  |  |
| `07-independent-review-and-release-readiness.md` |  |  |  |  |  |

## Scope

In scope:

- the three interoperability and authenticity findings described here;
- public result and production policy contracts;
- generated REST projections required by that contract;
- Make targets, GitHub workflows and directly associated CI-only helpers; and
- documentation and tests needed to prove the final shape.

Out of scope:

- new DKIM2 protocol features unrelated to the findings;
- a redesign of LDAP, SQL, Valkey or key-custody product behavior;
- removing either supported MTA adapter;
- loosening runtime hardening or secret handling; and
- publication or production rollout.

## Authority

Protocol behavior remains pinned to
`draft-ietf-dkim-dkim2-spec-04` and the repository's historical DNS-04
behavior identifier. Relevant primary text is archived at
`https://www.ietf.org/archive/id/draft-ietf-dkim-dkim2-spec-04.txt`.

- Section 2 defines `base64string` to admit FWS and says that FWS is ignored
  when the value is used.
- Section 7.3 defines Message-Instance `header-hash` and `body-hash` as
  `base64string`.
- Section 9.1 requires a reviser to describe reconstruction of the previous
  message, including an explicit unavailable-body representation when exact
  reconstruction is impossible.
- Sections 10.1 through 10.4 distinguish checking the latest signature and
  current hashes from historical message reconstruction, full signature-chain
  verification, and local policy.

The draft does not justify reporting unevaluated history as full-chain
authentication. It also does not require every low-level diagnostic caller to
perform every historical check. The public API must therefore make the two
operations distinct, and production policy must use the chain-authenticated
operation.

## Verified Current Findings

### Message-Instance folding

`lib/internal/instance.validUnknownHashComponent` rejects every byte below
space before `tagvalue.ParseBase64String` can remove FWS. A literal HTAB left by
header unfolding is therefore rejected even though the same Draft-04 base64
grammar permits it. Brong's focused change on PR 1 is applicable; his separate
RSA SubjectPublicKeyInfo correction is already superseded by current commit
`609c5ff`.

### Historical verification

The library already builds an internal bounded `HistoryWalk` after current
PASS. The service and public facades deliberately discard it and always expose
current scope with historical content and signatures as `not_evaluated`.
Brong's `chain-fraud-*` cases consequently return PASS while clearly signaling
current-only scope. That is internally honest but unsafe as an application
contract because a normal consumer can interpret PASS as message authenticity.

### Removed Turscar fixtures

The removed Draft-02 fixture manifest pinned hashes of CRLF message bytes. The
corresponding Git blobs had different hashes. A later `.gitattributes` rule
recreated CRLF during checkout, making the working-tree files match the
manifest and the parser-refusal test pass. This did not weaken the production
parser, but it made the claim of immutable repository bytes false and made test
behavior checkout-dependent.

The corpus, its dedicated checker, its parser-refusal test, its Make targets,
and its active conformance claims are removed. Runnable Turscar implementation
comparison under the separate interoperability machinery is not the removed
fixture corpus and may remain.

### CI and Make coupling

The current `make test` runs the Exim C `local_scan` harness before testing the
Go modules. `make guardrails` runs `make test` and also reaches Exim matrix
preparation through another dependency. The Guardrails workflow therefore
performs Exim work more than once, while Postfix integration lives in a
different workflow. Unit Tests independently repeats `make test`. Conformance
repeats conformance and security work already reachable from other aggregate
targets. Container evidence runs on every normal branch and PR despite being a
release/package concern.

The five workflows also duplicate checkout, Go setup, temporary-directory
preparation, cleanup, and tool installation. `scripts/check-ci.sh` then tests
many exact textual implementation details of those workflows. CI is therefore
partly occupied proving its own scaffolding instead of proving product behavior.

The repository-wide protected-input vocabulary is legitimate for secrets,
private keys, credentials, and raw mail data. It does not make a GitHub-hosted
runner's ordinary temporary build directory a protected product input. Runtime
container `tmpfs` mounts are legitimate hardening where a read-only image needs
bounded writable state; they do not belong in ordinary Go test setup.

## Required Product Semantics

### Folded hash base64

- Message-Instance hash components must permit SP and HTAB as FWS.
- The shared base64 parser remains responsible for removing FWS and validating
  alphabet, padding, zero pad bits, and decoded length.
- Other control bytes and DEL remain rejected.
- A focused test must fail before the production change and pass afterward for
  both SP and HTAB folding.
- Adjacent negative tests must retain rejection of CR, LF, NUL, DEL, invalid
  alphabet, invalid padding, and wrong SHA-256 length.
- Brong's authorship must be preserved in the fixing commit through an
  appropriate co-author or attribution line.

### Chain-authenticated verification

The public contract must distinguish current verification from chain
verification by construction rather than by a field that callers can ignore.

- The normal public `Verifier.Verify` operation must be chain-authenticated.
- For `m=1`, current verification completes the available chain.
- For `m>1`, PASS requires all of the following:
  - the current Message-Instance hashes match the current raw message;
  - the latest signature set verifies;
  - every required historical message state is reconstructed under bounded
    recipe processing;
  - every reconstructed Message-Instance hash relationship is valid;
  - every required historical signature set verifies; and
  - custody relationships remain valid across the evaluated chain.
- A missing, malformed, inconsistent, unsupported, or resource-exhausting
  historical transition cannot yield aggregate PASS.
- DNS or other transient dependencies map to TEMPERROR; malformed protocol,
  missing required reconstruction information, and unsupported required
  semantics map to a typed permanent result; cryptographic or hash mismatch
  maps to FAIL. Existing result precedence rules remain authoritative where
  they already cover the condition.
- Public historical-content and historical-signature fields must be projected
  from evaluated facts. `not_evaluated` cannot coexist with aggregate PASS for
  `m>1`.
- If a current-only diagnostic operation is retained, it must have an explicit
  name and a result type that cannot be passed directly into accepting daemon,
  policy, Milter, or Exim paths.
- Daemon process policy and both adapters must reject or defer any multi-
  instance result that lacks complete authenticated-chain evidence. They must
  never equate a current-only PASS with an authentication disposition.
- Authentication-Results output must truthfully distinguish current and chain
  scope and must not emit an unqualified `dkim2=pass` for incomplete history.

The existing internal `HistoryCoordinator` owns bounded reconstruction. It
must be extended or projected rather than duplicated in service, OpenAPI, or
adapter packages. Historical signature verification remains library-owned.
Generated REST types remain transport-only projections.

### Regression evidence

- Import or reproduce Brong's three `chain-fraud-*` cases without private key
  material or unreviewed generated bytes.
- Each case must fail before the contract correction.
- The body case with no usable `r=` and different `m=2` versus `m=1` body hash
  must not produce aggregate PASS.
- Add positive two- and three-instance chains so fail-closed behavior does not
  become blanket rejection of legitimate revisions.
- Cover missing recipe, null body, malformed recipe, hash mismatch, signature
  mismatch, unsupported algorithm, resource limit, cancellation, and transient
  key lookup independently.

## Target Make Contract

Make targets must state product intent directly and avoid hidden adapter or
container work.

| Target | Required scope |
| --- | --- |
| `make fix` | Go source modernization only |
| `make fmt` | formatting only |
| `make vet` | Go vet for product modules |
| `make lint` | golangci-lint for product modules |
| `make test` | Go unit tests for library, daemon, client, and adapter modules; no Docker, MTA, external database, Valkey source build, or C ABI harness |
| `make race` | race-enabled Go unit tests only |
| `make build-check` | build all five product surfaces |
| `make check-generated` | OpenAPI and other committed generated-file drift |
| `make check-conformance` | schema and manifest integrity only |
| `make conformance` | portable Draft-04 protocol conformance only |
| `make integration-valkey` | explicit Valkey integration |
| `make integration-datasources` | explicit LDAP and SQL service integration |
| `make integration-postfix` | explicit real Postfix/Milter qualification |
| `make integration-exim` | explicit Exim C ABI and supported-version qualification |
| `make container-smoke` | build product images and run minimal hardened runtime smoke |
| `make guardrails` | fix/fmt, vet, lint, test, race, build-check, generated drift, CI syntax, and repository policy |
| `make release-guardrails` | guardrails, govulncheck, and portable conformance; adapter integration remains separately visible rather than hidden inside this target |

`make test` may run ordinary Go tests inside the Exim module. It must not invoke
the C harness or distribution matrix. Postfix and Exim use the same rule:
adapter-specific external integration is explicit, separately named, and
separately reported.

Extended fuzz campaigns, database service matrices, multi-MTA qualification,
image reproducibility experiments, and destructive packaging tests are useful
developer or scheduled jobs. They are not part of every PR's normal guardrail.

## Target GitHub Actions

Replace the current workflow set rather than preserving accidental structure.
The target has small workflows with direct commands:

1. `guardrails.yml`
   - runs on PRs and pushes to maintained branches;
   - installs Go and the two required quality tools;
   - runs `make guardrails` once;
   - checks that tracked files did not change.
2. `conformance.yml`
   - runs on maintained-branch pushes, pull requests, and manual dispatch so
     adapter and generated-client changes cannot bypass conformance;
   - runs `make conformance` once;
   - uploads only the rendered conformance report when useful.
3. `postfix-integration.yml`
   - runs on relevant library, daemon, Milter, OpenAPI, or Postfix fixture
     changes, on manual dispatch, and for a release candidate;
   - runs `make integration-postfix` once.
4. `exim-integration.yml`
   - runs on relevant library, daemon, Exim, OpenAPI, or Exim fixture changes,
     on manual dispatch, and for a release candidate;
   - runs `make integration-exim` once.
5. `release.yml`
   - triggers only from a published, non-draft, non-prerelease GitHub Release;
   - checks that the release has a semantic stable version, its ref is an
     annotated tag, and tag, release, checkout, and commit are identical;
   - runs `make release-guardrails` once;
   - builds and pushes the daemon, Milter, and client images to GHCR with
     standard GitHub/Docker build provenance and SBOM support;
   - performs a minimal runtime smoke against the exact published digest;
   - publishes no `latest` tag unless separately and explicitly specified.

There is no separate Unit Tests workflow because Guardrails already owns unit
tests. There is no container-evidence workflow on every PR. Development image
publication, if retained, must be a small explicit branch workflow and cannot
share stable release authority.

Actions must remain pinned to reviewed commits and use least permissions. One
small machine-readable dependency source may hold tool versions if it removes
real duplication. CI must not enforce incidental line counts, exact step text,
temporary directory names, or the presence of its own helper scaffolding.

## Supply-Chain Boundary

Keep the controls that directly protect released artifacts:

- exact source commit and annotated stable tag;
- clean source tree;
- reproducible Go build inputs and vendored dependencies;
- non-root, read-only runtime images with only required writable mounts;
- GHCR digest readback;
- standard SBOM and provenance attestations;
- vulnerability scan as a release blocker; and
- exact-digest runtime smoke.

Remove custom machinery whose only purpose is to reproduce, re-hash, import,
re-export, or self-validate those same facts in multiple local evidence
formats. Standard GitHub and Docker attestations are the publication evidence;
the repository does not need a parallel supply-chain protocol.

## Removal Candidates

Implementation must inventory references before deletion, but the default
decision is to remove code that exists solely for the old CI evidence graph,
including bespoke CI temporary-directory lifecycle, textual workflow shape
assertions, local OCI evidence reports, publication-tool download wrappers,
and redundant report schemas. A helper stays only when a named product,
conformance, adapter, or release acceptance criterion uses it directly.

Protected product configuration, secret-safe loaders, runtime filesystem
checks, and adapter message-fidelity checks are not CI scaffolding and must not
be deleted merely because their tests use words such as `protected`, `tmpfs`,
or `evidence`.

## Security And Privacy

- Multi-instance authenticity fails closed unless the required history is
  authenticated completely.
- No test, log, trace, metric, REST response, CLI output or CI artifact may
  expose private keys, tokens, protected configuration, raw message bodies or
  raw recipient lists.
- Resource limits, cancellation, parser strictness, signature-result
  precedence and runtime container hardening remain enforced.
- Workflow permissions are explicit and minimal. Normal PR workflows have no
  package-publish or attestation authority.

## Observability

Existing bounded outcome, scope and reason telemetry may be extended only where
the corrected chain states need a stable distinction. Metrics must not carry
domains, addresses, selectors, message identifiers, raw recipes or other
high-cardinality values. Diagnostics must make incomplete history visible
without embedding protected message material.

## Acceptance

- The removed Turscar fixture corpus and all active claims about it are absent.
- The folded-hash reproducer passes without weakening adjacent control-byte or
  base64 validation.
- All chain-fraud regressions are non-PASS under the normal public verifier and
  production policy paths.
- Positive revised-message chains produce chain-authenticated PASS.
- Library, daemon, OpenAPI, client, Milter, and Exim mappings agree on scope and
  historical state.
- `make test` performs no Docker, MTA, Valkey source, database service, or C ABI
  work.
- `make guardrails` runs each normal quality class once.
- Postfix and Exim integration are independent visible checks.
- Normal PRs do not build release OCI evidence or carry publication authority.
- The stable release workflow accepts only a published stable GitHub Release,
  annotated tag, and exact same commit, then publishes and verifies exact GHCR
  digests.
- An independent review compares this specification with the final Make graph,
  workflow graph, public result contract, generated OpenAPI, and adapter
  behavior before release authorization.

## Non-Goals

- Reintroducing or repairing the removed Draft-02 fixture corpus.
- Treating external fixtures as normative Draft-04 authority.
- Removing the Exim adapter or reducing its supported compatibility claims.
- Weakening secret handling, parser strictness, runtime filesystem hardening,
  vulnerability gates, or fail-closed mail policy.
- Publishing a tag, release, image, or production rollout as part of the
  implementation prompts.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Product and delivery changes stay within this specification |  | pending |  |
| Interoperability | Draft-04 FWS is accepted with adjacent strictness intact |  | pending |  |
| Authenticity | Aggregate PASS proves the required chain |  | pending |  |
| Fixtures | Checkout-dependent Turscar corpus and claims are absent |  | pending |  |
| Boundaries | Library, daemon, client and adapters own their intended concerns |  | pending |  |
| Make graph | Unit quality and specialized integration are separate |  | pending |  |
| Actions | Five direct workflows replace duplicated scaffolding |  | pending |  |
| Security | Fail-closed, secret-safe and least-authority behavior holds |  | pending |  |
| Effort | All prompt timing is measured |  | pending |  |

## Decisions And Open Questions

- Settled: the retained 42-case Turscar fixture corpus is permanently removed.
- Settled: runnable external implementation interoperability remains separate
  from repository fixture authority.
- Settled: normal public verification and production adapters require
  authenticated history for multi-instance PASS.
- Settled: `make test` contains no external MTA or C ABI integration.
- Settled: stable publication requires a published stable GitHub Release, an
  annotated tag and exact commit identity; branch-protection state is not a
  release input.
- Open: no release-blocking design question remains; implementation discoveries
  that alter these decisions must update this specification before proceeding.
