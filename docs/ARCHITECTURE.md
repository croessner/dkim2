# DKIM2 Reference Implementation Architecture

## Document Control

| Field | Value |
| --- | --- |
| Document ID | DKIM2-ARCH-0001 |
| Title | DKIM2 Reference Implementation Architecture |
| Version | 0.1.0-draft |
| Status | Planning baseline |
| Date | 2026-06-24 |
| Owner | Christian Roessner / Codex |
| Language | English |
| Classification | Internal design draft |
| Baseline specification | `draft-ietf-dkim-dkim2-spec-04`, dated 2026-07-05 |
| Related specification | M11 tested behavior baseline: `draft-chuang-dkim2-dns-04`, dated 2026-03-18; replaced by `draft-ietf-dkim-dkim2-dns-00` on 2026-07-20 |
| Baseline status check | Datatracker checked 2026-07-24; the repository behavior and vectors remain pinned to `draft-ietf-dkim-dkim2-spec-04` plus the historical DNS `-04` identifier. The active working-group DNS `-00` has a normatively identical body. Identifier/vector migration is deferred to a separately reviewed baseline update. |
| Change control | While this document is still `0.1.0-draft`, startup decisions may be added without a version bump; after the first committed planning baseline, material architecture changes require a revision-history entry and may require a new version |
| Supersedes | None |
| Next planned revision | Before the first public preview, or when the DKIM2 draft changes materially |

## Revision History

| Version | Date | Author | Notes |
| --- | --- | --- | --- |
| 0.1.0-draft | 2026-06-24 | Christian Roessner / Codex | Initial architecture baseline. Version intentionally remains at 0.1.0 while early project decisions are still being settled. |
| 0.1.0-draft | 2026-07-03 | Christian Roessner / Codex | Recalibrated implementation estimates after measured M1 through M4 prompt-pack execution. |
| 0.1.0-draft | 2026-07-10 | Christian Roessner / Codex | Advanced the implementation baseline to the current DKIM2 working-group draft `-04`; durable specs, versioned vectors, and protocol behavior must migrate together. |
| 0.1.0-draft | 2026-07-13 | Christian Roessner / Codex | Recorded M8 recipe-application completion: strict decoded-JSON parsing, bounded immutable reconstruction, post-current-PASS historical content hash validation, versioned golden/fuzz evidence, and unchanged public historical signature/policy non-evaluation. Exact total effort remains unavailable because several prompt start timestamps were not retained. |
| 0.1.0-draft | 2026-07-13 | Christian Roessner / Codex | Specified M9 recipe generation as a deterministic bounded inverse operation: canonical-owned header relevance, exact unfolded/header and framed-body semantics, explicit body-unavailable policy, compact decoded JSON, and internal M8 parse/apply proof. Message-Instance formatting and hash-gated signing remain M10 ownership. |
| 0.1.0-draft | 2026-07-13 | Christian Roessner / Codex | Completed M9 inverse recipe generation with deterministic non-minimal planning, explicit disclosure and body-unavailable policies, compact decoded JSON, strict parse/apply/self-proof, draft-versioned golden/fuzz evidence, abuse/race/privacy/dependency coverage, and unchanged M10 ownership of revision hash gating, Message-Instance formatting, and signing. |
| 0.1.0-draft | 2026-07-23 | Christian Roessner / Codex | Completed signing and revision support: sealed all-hop revision evidence, exact hash-gated roles, deterministic Message-Instance and DKIM2-Signature generation, opaque RSA/Ed25519 signing, shared custody validation, authority-bound fanout and restricted release, next-domain creation/continuation/completion, public facade integration, and draft-04 vectors/fuzz/privacy/race evidence. |
| 0.1.0-draft | 2026-07-24 | Christian Roessner / Codex | Completed storage-neutral datasource contracts, immutable memory and confined flat-file providers, the exact opaque-handle signing bridge, LDAP/SQL design mappings, and provider parity/fuzz/race/privacy/dependency evidence. Replay storage remains M12. Recorded the DNS draft rename without silently rebasing behavior or vectors. |
| 0.1.0-draft | 2026-07-24 | Christian Roessner / Codex | Specified M12 replay architecture: exact sealed replay inputs, success-only checks with typed failures and separate state, memory and explicit disabled providers, a millisecond-exact Valkey `SET NX PX` backend, and directly addressed standalone-primary authority. This records the specification baseline, not implementation completion. |
| 0.1.0-draft | 2026-07-24 | Christian Roessner / Codex | Completed M12 replay storage: storage-neutral replay contracts, versioned framed HMAC-SHA256 identities, bounded memory and explicit disabled providers, exact Valkey `SET NX PX` behavior, fail-closed indeterminate mutation handling, standalone-primary authority, and parity/fuzz/race/privacy/integration evidence. |
| 0.1.0-draft | 2026-07-26 | Christian Roessner / Codex | Specified the initial `dkim2ctl` generated-client, fixture, smoke, negative-contract, stable-output, and bounded diagnostic contract. This records the M14 implementation baseline, not implementation completion. |
| 0.1.0-draft | 2026-07-26 | Christian Roessner / Codex | Implemented the local-only `dkim2ctl` generated-client runtime, strict draft-versioned fixture runner, stable JSON Lines, protected capability ownership, generated smoke and process calls, closed negative-contract mutations, and adversarial test evidence. |
| 0.1.0-draft | 2026-07-26 | Christian Roessner / Codex | Planned the central daemon observability specification: secret-safe structured logging, explicit bounded debug modules, an instance-owned OpenTelemetry runtime, a process-local Prometheus registry and metrics endpoint, and strict low-cardinality attribute and label allowlists. This records the specification baseline, not implementation completion. |
| 0.1.0-draft | 2026-07-26 | Christian Roessner / Codex | Completed the daemon observability foundation with validated injected library events, bounded structured logging, instance-owned OpenTelemetry export, process-local low-cardinality Prometheus metrics, an untraced `GET /metrics` route, protected tracing CA ownership, adversarial tests, and independent review hardening. |
| 0.1.0-draft | 2026-07-26 | Christian Roessner / Codex | Planned the production Milter adapter specification: bounded Milter-v6 message reconstruction, generated daemon sign/revise/process clients, datasource-backed private signing, closed prevalidated action plans, Authentication-Results policy, deterministic failure mapping, Unix-socket lifecycle, and adversarial MTA protocol-peer evidence. This records the specification baseline, not implementation completion. |
| 0.1.0-draft | 2026-07-27 | Christian Roessner / Codex | Planned the separate Exim adapter specification: a source-linked version-probed C `local_scan()` module, bounded Unix IPC to a Go adapter service, generated daemon clients, persistent incoming revision evidence, full-message `transport_filter` rewriting, closed hook-specific failure policy, and required upstream/Debian/Ubuntu compatibility evidence. This records the specification baseline, not implementation completion. |
| 0.1.0-draft | 2026-07-27 | Christian Roessner / Codex | Planned the versioned conformance suite: digest-bound positive, negative, replay, OpenAPI, and Milter vectors; deterministic CI reporting; and a real Postfix Docker qualification for SMTP and local submission. Live Exim evidence remains explicitly deferred to M17 while an adapter-neutral future fixture/result schema is frozen. |
| 0.1.0-draft | 2026-07-28 | Christian Roessner / Codex | Planned the repository-wide security-hardening specification: a closed first-party fuzz inventory, composable resource-limit audit, recipe-bomb and provider abuse campaigns, OpenAPI and Milter hostile-peer fixtures, whole-product telemetry privacy review, repeated race evidence, vulnerability gates, and unchanged-snapshot proof. Exim hardening and live evidence remain explicitly deferred with M17. |
| 0.1.0-draft | 2026-07-28 | Christian Roessner / Codex | Implemented repository-wide security hardening with a drift-checked first-party fuzz and resource-proof inventory, closed race and vulnerability runners, deterministic snapshot-bound reports, CI gates, privacy-preserving diagnostics, and repeated portable, Valkey, real Postfix, and full-conformance evidence. Exim remains explicitly deferred with M17. |
| 0.1.0-draft | 2026-07-28 | Christian Roessner / Codex | Reserved the RNS LDAP subtree `1.3.6.1.4.1.31612.1.7` for DKIM2, defined stable attribute and object-class allocations, recorded the secret-safe live OpenDKIM migration baseline, and specified a fail-closed out-of-process bootstrap into immutable DKIM2 generations and opaque signing handles. Executable LDAP/SQL providers and migration tooling remain M22. |
| 0.1.0-draft | 2026-07-28 | Christian Roessner / Codex | Specified production packaging and operator delivery: reproducible Go 1.26 multi-stage images for the daemon, Milter adapter, and generated client; digest-pinned hardened runtime inputs; multi-architecture, SBOM, provenance, and vulnerability gates; and a protected, no-host-exposure-by-default Postfix Compose deployment with explicit upgrade and rollback ownership. Exim remains incomplete under M17, and executable LDAP/SQL providers and migration remain M22. |
| 0.1.0-draft | 2026-07-29 | Christian Roessner / Codex | Specified interoperability and reference-candidate closeout: reproducible external-implementation discovery and comparison or explicit evidence-backed unavailability, a bidirectionally complete Draft-04 issue log, generated-contract and exported-reference review, scoped `v0.1.0-rc.1` preparation without publication, and one candidate-bound report that preserves normative, interpretation, policy, OpenAPI, adapter, and external-evidence claim separation. Exim remains deferred to M17 and executable LDAP/SQL providers plus migration remain M22. |
| 0.1.0-draft | 2026-07-30 | Christian Roessner / Codex | Implemented M22 daemon-owned LDAP and PostgreSQL datasource providers, exact schema/DDL delivery, generation-matched protected signer registries, serialized readiness and refresh ownership, provider parity, and the offline OpenDKIM dry-run/apply/higher-generation rollback workflow with separate inventory, key-import, DNS-proof, and publication authorities. |
| 0.1.0-draft | 2026-07-30 | Christian Roessner / Codex | Implemented the M17 Exim adapter candidate: source-linked and version-probed `local_scan()`, bounded same-UID IPC, daemon-backed sign/revise transport filters, authenticated evidence, protected configuration, packaging validators, and a strict five-row upstream/Debian/Ubuntu qualification runner. Release compatibility remains gated on final unchanged-candidate matrix evidence; the RC remains unpublished and Draft-04 limitations are unchanged. |
| 0.1.0-draft | 2026-07-30 | Christian Roessner / Codex | Added fail-closed multi-domain originator routing in the Milter: one static tenant may derive an exact canonical ASCII signing domain from the validated SMTP reverse-path, while null senders, literals, SMTPUTF8 domains, transit use, and every fallback remain rejected. |
| 0.1.0-draft | 2026-07-31 | Christian Roessner / Codex | Qualified the M17 Exim adapter on Linux across all five authenticated upstream, Debian, and Ubuntu rows with 43 passing cases per row and a passing fail-closed privacy scan. Replaced the historical portable deferral with a Linux-only conformance producer: portable reports record not applicable, while full reports require explicit verified evidence imported under current manifest, base-revision, candidate-snapshot, and verifier bindings. |
| 0.1.0-draft | 2026-07-31 | Christian Roessner / Codex | Integrated production corrections for the Postfix Milter and legacy migration: idempotent pre-MAIL abort/HELO restart, exact legacy selector lookup with a separate DKIM2 target selector, bounded inactive-wildcard history, canonical RSA PKCS#1-to-PKCS#8 import, and retained verified-TLS trust bytes across datasource reload cleanup. |

## 1. Purpose

This document defines the first architecture baseline for a Go reference
implementation of DKIM2. The immediate goal is not to freeze a final public API.
The goal is to establish precise implementation boundaries before protocol code
is written.

The design uses these reviewed behavior baselines as its source of truth:

- `draft-ietf-dkim-dkim2-spec-04`
- `draft-chuang-dkim2-dns-04` for the implemented DNS behavior and vectors.

The IETF replaced the DNS document with the working-group
`draft-ietf-dkim-dkim2-dns-00` on 2026-07-20. Its normative body is unchanged.
The repository does not silently rename baselines: durable identifiers and
versioned vectors migrate together in a separately reviewed update.

The DKIM2 specification is still in draft form. The implementation must
therefore make draft-version dependencies explicit in code, tests, vectors, and
documentation. When DKIM2 becomes stable, this architecture should be sharpened
in a new version rather than silently edited into a different design.

## 2. Executive Summary

The project should be built as a standalone Go library first, with adapters
around it. The repository uses `go.work` for local development, but the library
is its own module and should be publishable independently of the adapter
implementations.

Initial modules:

- `lib`: the DKIM2 reference library at the current module path
  `github.com/croessner/dkim2`. A different publication namespace may be
  selected before the first public release, but is not an active module path.
- `cmd/dkim2d`: an HTTP/JSON service module.
- `cmd/dkim2-milter`: a Milter adapter module.
- `cmd/dkim2ctl`: an OpenAPI-generated client and test-client module.

The initial adapters are:

- `dkim2d`: an HTTP/JSON service.
- `dkim2-milter`: a Milter adapter that calls `dkim2d` at EOM time.
- `dkim2ctl`: an OpenAPI-backed CLI/test client for vectors, reproducible
  diagnostics, and daemon integration testing. It may later grow operator
  commands, but the initial role is test and conformance work.

The Exim integration is treated as its own adapter family, not as a
Milter variant. Exim has native message-processing hooks with different
fidelity, build, and action semantics from libmilter-style MTAs.

The core library must own all DKIM2 semantics:

- Raw RFC 5322 message modeling.
- DKIM2 header parsing and formatting.
- Header and body canonicalization.
- Message hash calculation.
- Message-Instance handling.
- Recipe generation and recipe application.
- DKIM2-Signature signing and verification.
- DNS key lookup and key validation.
- Chain-of-custody verification.
- Structured protocol result reporting with local-policy decisions kept
  distinguishable from cryptographic correctness.

Adapters must not duplicate protocol logic. They translate transport-specific
input and output into the core model.

The most important engineering rule is this:

> The reference implementation signs and verifies a controlled RFC 5322 message
> representation, not a friendly mail object reconstructed by a generic parser.

That rule keeps the implementation honest for line endings, header occurrence
order, folding, body bytes, recipe boundaries, and future test vectors.

## 3. Core Design Principles

### 3.1 Precision Before Convenience

DKIM2 is sensitive to exact message state. The implementation must treat email
as structured bytes with controlled views, not as a generic message object that
can be parsed and reserialized at will.

The core must preserve:

- Header field occurrence order.
- Header field names as seen and canonical lowercase names.
- Header field raw values and unfolded values.
- Body bytes after the SMTP-relevant transport state that the verifier is
  expected to receive.
- CRLF handling decisions.
- Line indexes for recipe generation and application.
- EAI/SMTPUTF8-relevant values as bytes unless and until the DKIM2 draft defines
  additional semantics.

The core must not depend on `net/mail` for canonicalization, signing, recipe
handling, or verification. Standard library parsers can be useful for optional
diagnostics, but they must never be the protocol source of truth.

Until the DKIM2 EAI section is complete, the implementation must not invent
Unicode, IDNA, or local-part normalization rules. EAI-capable inputs should be
preserved byte-for-byte in the protocol paths that DKIM2 signs or verifies.

### 3.2 Library First, Adapters Second

The reference implementation should be useful without a daemon or Milter. The
Go library module should allow tests and other programs to call the protocol
engine directly.

The adapter stack is:

```text
cmd/dkim2-milter module      cmd/dkim2d module      cmd/dkim2ctl module
          |                        |                        |
          |                        +-----------+------------+
          |                                    |
          |                         OpenAPI HTTP contract
          |                                    |
          +------------------------+-----------+
                                   |
                    standalone DKIM2 library module
                 current path: github.com/croessner/dkim2
                                   |
                 raw message, canonicalization, recipes,
                    signatures, keys, policy, service API
```

`go.work` is a development convenience, not the product boundary. Once adapter
code imports the library, command modules should require the library module in
their own `go.mod`; the workspace will select the local `lib` module during
development. Released command modules should depend on tagged library versions.
Local `replace` directives should only be needed when an adapter is developed
outside this workspace.

Before candidate preparation, an adapter that imported the unpublished library
used the non-releasable sentinel `github.com/croessner/dkim2 v0.0.0` and one
exact workspace bootstrap. The `v0.1.0-rc.1` candidate boundary replaces that
sentinel with `github.com/croessner/dkim2 v0.1.0-rc.1` and removes the
workspace bootstrap. Before a public library tag exists, a private deterministic GOPROXY
built from exact candidate bytes proves standalone resolution with
`GOWORK=off`, checksum-database and network access disabled, tidy readback,
tests, vet, and builds. Command modules never contain local replace directives.

### 3.3 OOP and DRY in Go Terms

Go does not use class-based OOP, but the project should still use strong object
boundaries:

- Small interfaces for replaceable dependencies.
- Domain structs with explicit invariants.
- Constructors that validate protocol objects.
- Methods on protocol types when behavior naturally belongs to the type.
- Service objects for use cases that coordinate multiple domain components.
- No global mutable state.

DRY is important, but reference readability is also important. The rule should
be:

- Never duplicate protocol rules.
- Do not hide protocol rules behind overly clever generic helpers.
- Prefer named, testable helpers over implicit behavior.
- Keep draft-section references near code that implements non-obvious rules.

### 3.4 Secure by Default

Security behavior must be the default, not an optional hardening layer.

Default behavior:

- No network calls without context deadlines.
- DNS lookup limits and negative-result handling.
- Maximum message size limits.
- Maximum header count and header length limits.
- Maximum recipe size and recipe expansion limits.
- Strict base64 decoding rules where the draft requires padded base64.
- Safe JSON decoding with unknown-field policy defined per API version.
- Algorithm allow-listing.
- Key validation before cryptographic use.
- No private-key material in logs.
- No full-message logging by default.
- Error messages that are operationally useful but do not leak secrets.

### 3.5 Testability as Architecture

Every protocol rule should have a narrow unit test. Larger flows should be
covered by golden vectors and integration tests. The implementation should be
designed so test fixtures can inject:

- A deterministic clock.
- A deterministic nonce source.
- Static DNS key records.
- Known private keys.
- Synthetic SMTP envelope state.
- Draft-version-specific expected errors.

### 3.6 Module Boundary Hygiene

The Go module boundary is part of the architecture:

- The reference library lives in `lib/`.
- Adapter implementations live in separate modules under `cmd/`.
- Adapter-specific dependencies must not appear in the library module.
- The library exposes a public facade at its module root. Its current path is
  `github.com/croessner/dkim2`; any future publication-path change requires an
  explicit module migration.
- Internal implementation packages should remain under `lib/internal`.
- Command modules should normally import only the public library facade.
- Temporary local development uses `go.work`; releases use tagged module
  versions.

This keeps a consumer that only wants DKIM2 verification from also inheriting
HTTP server, Milter, configuration, metrics, or deployment dependencies.

### 3.7 Service Foundation Dependencies

The command and service modules should use a deliberate service foundation that
matches the operational style of sibling projects while preserving the library
boundary:

- Cobra owns command surfaces for `dkim2d`, `dkim2-milter`, and `dkim2ctl`.
- Viper owns configuration file and environment loading in command modules.
- Typed configuration structs own validation and stable path semantics.
- Uber Fx owns runtime dependency composition for `dkim2d`.
- `log/slog` owns structured logging through a central provider.
- OpenTelemetry owns distributed traces through a central observability runtime.
- Prometheus owns metrics through a process-local registry.
- OpenAPI owns the HTTP contract and generated client/server DTOs.
- The pinned OTLP HTTP exporter selects `x/net v0.55.0`; Go 1.26 consequently
  synchronizes `cmd/dkim2ctl`'s pruned Cobra indirects and module sum, which the
  workspace stale-metadata check must track.
- `golangci-lint`, `go vet`, `go test`, race tests, OpenAPI checks, and
  `govulncheck` belong in guardrails.

These dependencies should not leak into the library module unless a later
architecture version explicitly changes that boundary.

### 3.8 Root-Cause and Reproducer Policy

The reference implementation should prefer root-cause fixes over symptomatic
workarounds. Parser laxness, downgraded validation, skipped canonicalization
checks, policy bypasses, and test expectation weakening are not acceptable
substitutes for fixing the actual defect.

Bug work should start with a meaningful reproducer whenever practical:

- Unit reproducer for parser, canonicalization, recipe, signature, policy, or
  datasource behavior.
- Golden vector for protocol-state regressions.
- HTTP/OpenAPI reproducer for daemon contract behavior.
- Public-socket or Milter-flow reproducer for adapter behavior.

Good reproducers should stay in the repository as regression coverage.

## 4. Proposed Repository Layout

The first project layout is:

```text
.
├── go.work
├── Makefile
├── AGENTS.md
├── POLICY.md
├── .golangci.yml
├── README.md
├── .codex/
│   └── skills/
│       ├── dkim2-spec-conformance/
│       ├── dkim2-senior-go-architect/
│       ├── dkim2-mail-domain/
│       ├── dkim2-openapi-service/
│       ├── dkim2-datasource-provider/
│       ├── dkim2-observability/
│       ├── dkim2-milter-adapter/
│       ├── dkim2-security-testing/
│       └── dkim2-review-audit/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── agent-skills/
│   │   └── README.md
│   └── specs/
│       └── openapi/
│           ├── README.md
│           ├── dkim2d.yaml
│           ├── oapi-codegen.server.yml
│           └── oapi-codegen.client.yml
├── lib/
│   ├── go.mod
│   ├── doc.go
│   └── internal/
│       ├── rawmsg/
│       │   └── doc.go
│       ├── canonical/
│       │   └── doc.go
│       ├── instance/
│       │   └── doc.go
│       ├── signature/
│       │   └── doc.go
│       ├── recipe/
│       │   └── doc.go
│       ├── keyresolver/
│       │   └── doc.go
│       ├── datasource/
│       │   └── doc.go
│       ├── observability/
│       │   └── doc.go
│       ├── policy/
│       │   └── doc.go
│       └── service/
│           └── doc.go
├── cmd/
│   ├── dkim2d/
│   │   ├── go.mod
│   │   ├── README.md
│   │   └── internal/
│   │       ├── app/
│   │       │   └── doc.go
│   │       ├── config/
│   │       │   └── doc.go
│   │       └── httpjson/
│   │           └── doc.go
│   ├── dkim2ctl/
│   │   ├── go.mod
│   │   ├── README.md
│   │   └── internal/
│   │       └── testclient/
│   │           └── doc.go
│   └── dkim2-milter/
│       ├── go.mod
│       ├── README.md
│       └── internal/
│           └── milter/
│               └── doc.go
└── testdata/
    └── vectors/
        └── README.md
```

Expected future additions:

```text
docs/
├── ADR-0001-adapter-boundaries.md
├── API.md
├── SECURITY.md
├── TESTING.md
├── specs/openapi/
└── reference/

lib/internal/
├── crypto/
├── dnskey/
├── datasource/
├── errors/
├── observability/
└── version/

cmd/dkim2d/internal/
├── app/
├── config/
├── httpjson/
├── observability/
└── datasource/

cmd/dkim2ctl/internal/
├── generated/
└── testclient/

cmd/dkim2-milter/internal/
├── config/
└── milter/

testdata/
├── corpus/
├── fuzz/
└── interop/
```

Package names may be adjusted as the implementation becomes real. The important
part is that responsibilities stay separate.

## 5. Package Responsibilities

### 5.1 `lib` / public library module

Public facade for callers that want to embed the reference implementation.

Responsibilities:

- Stable exported request and result types.
- High-level verification and signing entry points.
- Version metadata.
- Public errors where callers need type checks.

Non-responsibilities:

- HTTP server implementation.
- Milter implementation.
- Raw DNS client details.
- Private implementation helpers.

Initial public facade sketch:

```go
type Engine struct {
    // Dependencies are injected through options.
}

func NewEngine(opts ...Option) (*Engine, error)

func (e *Engine) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error)
func (e *Engine) Sign(ctx context.Context, req SignRequest) (*SignResult, error)
func (e *Engine) Revise(ctx context.Context, req ReviseRequest) (*ReviseResult, error)
```

The facade should expose protocol results in a structured way. It should not
force callers to parse human-readable messages.

### 5.2 `lib/internal/rawmsg`

Owns the controlled RFC 5322 message representation.

Responsibilities:

- Parse raw RFC 5322 bytes into a loss-aware model.
- Preserve header occurrence order.
- Preserve enough raw data to rebuild the message without accidental semantic
  changes.
- Provide typed access to header fields and body lines.
- Normalize line endings only through explicit policy.
- Detect malformed messages and report precise diagnostics.

Proposed core types:

```go
type Message struct {
    Headers HeaderBlock
    Body    Body
}

type HeaderField struct {
    Index          int
    RawName        []byte
    NameLower      string
    RawValue       []byte
    UnfoldedValue  []byte
    OriginalBytes  []byte
}

type Body struct {
    Bytes []byte
    Lines LineIndex
}
```

Design notes:

- Header values should not be decoded as MIME encoded-words for protocol work.
- MIME structure is not needed for DKIM2 hashes and must not be a signing
  dependency.
- Recipe generation may need line-level body indexing, so line indexing belongs
  near raw message handling.

### 5.3 `lib/internal/canonical`

Implements DKIM2 canonicalization rules.

Responsibilities:

- Body hash input generation.
- Header hash input generation.
- Signature input generation over Message-Instance and DKIM2-Signature fields.
- Strict coverage of draft-specific excluded headers, including
  `Delivered-To` and `X-*` under draft-04 Section 4.
- Stable sorting and duplicate-header ordering rules.
- An immutable draft-04 Section 4 plus Section 6.2 signed-header relevance
  classifier exposed through a validated fallible method set for recipe
  generation without duplicating the exclusion table.

Design notes:

- Canonicalization must be deterministic and golden-test-heavy.
- There should be no hidden dependency on map iteration order.
- The code should expose intermediate canonical bytes in test-only helpers or
  explicit debug APIs.
- Recipe production code must not import this package. The canonical relevance
  implementation satisfies a recipe-owned consumer interface through normal Go
  method-set compatibility; external integration tests prove the wiring.

### 5.4 `lib/internal/instance`

Owns `Message-Instance` parsing, validation, formatting, and relation to message
hashes.

Responsibilities:

- Parse `m=`, `h=`, and optional `r=`.
- Validate sequence numbers and gaps.
- Represent one or more hash sets.
- Decode and encode recipes.
- Build new Message-Instance fields.
- Associate an instance with the message state it represents.

Important invariants:

- `m=1` is the origin instance.
- Gaps make verification impossible per the draft.
- Hash algorithms unknown to the verifier are ignored, not treated as success.
- Base64 values must honor the draft's padding requirement.

### 5.5 `lib/internal/recipe`

Owns recipe generation and application.

Responsibilities:

- Parse decoded JSON recipes after instance-owned base64 decoding.
- Validate the recipe schema.
- Apply recipes to reconstruct previous message instances.
- Generate recipes from before/after message states.
- Bound recipe expansion to prevent resource abuse.

Design notes:

- Recipe generation must be draft-conformant, deterministic, bounded, and
  reproducible, but generated recipes are not required to be minimal.
- Generation is the inverse operation from the current/after source to the
  previous/before target. Header matching uses exact unfolded values within
  case-insensitive name groups; body matching includes exact line terminators
  and framing.
- Generated decoded JSON uses a fixed compact representation and must pass the
  same strict parser and applier limits before success. Padded base64 and
  Message-Instance formatting remain `lib/internal/instance` and M10 concerns.
- Body unavailability is a closed explicit caller policy for content that is
  unrepresentable or forbidden by copy-only disclosure, never a fallback for
  limits, cancellation, or internal failure. Relevant headers have no
  unavailable form and fail closed.
- A later optimization phase can make recipes smaller without changing
  verification semantics or the public model.
- The `b:null` body member must be represented explicitly because body
  unavailability has policy meaning; a null whole recipe is not a valid form.

### 5.6 `lib/internal/signature`

Owns `DKIM2-Signature` parsing, validation, formatting, and signature input
assembly.

Responsibilities:

- Parse required tags: `i=`, `m=`, `t=`, `d=`, `s=`.
- Require exactly one chain-of-custody form: `nd=`, or both `mf=` and `rt=`.
- Parse optional tags: `n=`, `f=`, extension tags, including the draft-04
  `feedhere` flag.
- Validate signature sequence numbers and gaps.
- Build incomplete signature fields with empty signature values for signing.
- Verify chain-of-custody input at the header level.
- Format signatures without introducing unsafe folding or injection.

Important invariants:

- `i=1` is the origin signature.
- Gaps make the message unsigned per the draft.
- The highest `i=` signature must match the current SMTP envelope when it uses
  `mf=` and `rt=`. A highest signature using `nd=` requires explicit
  out-of-band trust and cannot produce a default verification pass.
- The signature only signs DKIM2 protocol fields, while the message content is
  covered through Message-Instance hashes.

### 5.7 `lib/internal/keyresolver`

Owns DNS key lookup and DKIM2 key record parsing.

Responsibilities:

- Validate ASCII selector/domain components and resolve the absolute
  `selector._domainkey.domain.` owner while preserving dotted selector labels.
- Consume one already-concatenated TXT RR payload while retaining RR boundaries
  and failing closed on a multi-record RRset.
- Parse DNS-04 records through `internal/tagvalue`, including revocation,
  ignored extension/retired tags, DNS-optional terminal Base64 padding with
  canonical pad bits, and bounded `t=y`/`t=s` metadata.
- Decode PKCS#1 RSA public DER and raw 32-byte Ed25519 public keys while reusing
  `internal/verify` as the authoritative crypto/key-validation owner.
- Distinguish missing, revoked, invalid, ambiguous, unsupported key type,
  algorithm mismatch, temporary, permanent, and provider-contract states.
- Cache only TTL-backed stable results under bounded deterministic LRU policy.
- Coalesce same-key misses with bounded waiters, non-blocking global lookup
  saturation, and explicit final-waiter cleanup ownership.
- Support deterministic fake transports, injected clocks, and instance parent
  contexts without network or global mutable state.

Design notes:

- The root package owns public transport/provider adapters; keyresolver does not
  import the root package or own four-state verification mapping.
- Derived qnames and cache keys are sensitive and never enter errors or results.
- DNS-04 lowercase `k=` follows prose and RFC 6376 Erratum 5137; no signature
  `q=` API is invented for the active DKIM2 grammar.
- DNSSEC is diagnostic-only. Testing and strict-identity flags are metadata,
  not cryptographic verdict or MTA policy.
- A final canceled waiter cancels and owns the flight until a compliant
  transport returns. No helper goroutine masks an injected transport that
  ignores context.

### 5.8 `lib/internal/datasource`

Defines storage-facing abstractions and first providers without binding
protocol code to service frameworks, LDAP, SQL, or a specific secret store.

Responsibilities:

- Define two context-aware exact lookup operations for immutable signing
  profiles and administrative tenant/domain/use policies.
- Own validated opaque profile, tenant, feedback-route, and private-key-handle
  identifiers plus closed provider states, limits, usage, and typed errors.
- Return self-contained same-generation results so policy, profile, and handle
  facts cannot mix across reloads.
- Provide an immutable static memory provider and a strict bounded JSON
  flat-file provider.
- Confine flat-file loading to one owned duplicated directory descriptor and
  publish complete reload generations atomically.
- Keep a failed-reload snapshot only for explicit recovery while making every
  later resolve unavailable until a successful reload.
- Keep provider-specific types out of protocol packages.
- Distinguish absence, ambiguity, inactivity, malformed data, limit failures,
  unavailability, platform limits, cancellation, and internal invariants.
- Support deterministic fake sources for unit and vector tests.

Design notes:

- `lib/internal/datasource/memory` depends only on datasource core.
  `lib/internal/datasource/flatfile` additionally composes the immutable memory
  provider after strict decoding. Neither imports signing or service
  dependencies. `lib/internal/datasource/signingprofile` is the sole package
  that imports both datasource and signing.
- The signing bridge maps exact provider-neutral handle IDs through an
  immutable registry to existing inert signing handles. Providers never return
  private-key material, key paths, signers, callbacks, or capabilities.
- Datasource success is administrative selection only. It does not replace
  M10's fresh DNS publication check, hash/recipe/custody validation, route
  authorization, or private signing callback.
- LDAP and PostgreSQL mappings are implemented by daemon-owned providers.
  Deployable schema, DDL, protected configuration, and the separately
  authorized migration workflow remain outside the standalone library.
- Replay interfaces, keys, retention, and providers belong entirely to M12.
- Datasource failures that affect verification or signing correctness should
  fail closed by default.

### 5.9 `lib/internal/observability`

Defines library-safe observation events and policy helpers without binding the
library to concrete exporters.

Responsibilities:

- Define bounded event and attribute types for protocol operations.
- Provide no-op observers for pure library use.
- Support injection of service-level observers from `dkim2d`.
- Keep secret and high-cardinality data out of observation events.

Non-responsibilities:

- OpenTelemetry exporter construction.
- Prometheus registry ownership.
- `slog` handler configuration.

### 5.10 `lib/internal/policy`

Owns local policy decisions over verified protocol facts.

Responsibilities:

- Map sealed protocol results to accept/reject/tempfail/continue decisions.
- Evaluate `donotmodify`, `donotexplode`, and `feedback` flags.
- Allow deployments to choose strict, permissive, and testing modes.
- Produce exactly one bounded disposition action for each successful decision.
- Keep policy separate from cryptographic correctness.

Design notes:

- A message can be cryptographically valid and still fail local policy.
- A message can be cryptographically invalid but still be accepted by a
  permissive deployment policy.
- DNS `t=y` is independent of local testing mode. A coherent testing signer is
  handled as unsigned policy input with `continue`, while the authoritative
  verification state remains unchanged.
- The result model must preserve that distinction.

### 5.11 `lib/internal/service`

Coordinates domain packages into use cases.

Core services:

- `Verifier`
- `Signer`
- `Reviser`

The service layer should be where end-to-end workflows live. Lower packages
should stay focused on one protocol concern.

For the current library verifier, service authenticates the verify-owned flag
candidate only after aggregate `PASS` and seals the policy projection from the
authoritative target plus complete signature/key facts. Public
`MaxCheckFacts` and `MaxSignatureFacts` settings are presentation-retention
caps only: they deterministically narrow public detail without rewriting the
four-state result or the complete sealed policy evidence. Hard parser and set
limits remain separate fail-closed input limits. The root `dkim2` facade owns
construction of the policy evaluator, calls it with the sealed projection, and
adapts the immutable decision; service does not duplicate policy mapping or
action planning.

### 5.12 `cmd/dkim2d/internal/app`

Runtime composition for `dkim2d`.

Responsibilities:

- Compose the daemon through Uber Fx.
- Provide lifecycle hooks for HTTP server startup and shutdown.
- Wire typed config, logger, observability, datasource providers, key
  resolvers, and DKIM2 services.
- Keep dependency construction centralized and testable.

### 5.13 `cmd/dkim2d/internal/config`

Configuration loading and validation for `dkim2d`.

Responsibilities:

- Use Cobra/Viper command and config integration.
- Decode into typed configuration structs.
- Expand scalar environment placeholders before validation.
- Preserve secret metadata and redaction.
- Validate stable config paths and unsafe compatibility switches.

### 5.14 `cmd/dkim2d/internal/httpjson`

HTTP/JSON adapter for `dkim2d`.

Responsibilities:

- Decode API requests.
- Enforce request size and timeout limits.
- Call the service layer.
- Encode structured responses.
- Avoid logging message bodies by default.

Non-responsibilities:

- DKIM2 protocol logic, which belongs in the library module.
- Milter-specific action translation.

### 5.15 `cmd/dkim2ctl/internal/testclient`

OpenAPI-backed client and test harness.

Responsibilities:

- Use generated OpenAPI client code.
- Provide vector, fixture, and daemon smoke workflows.
- Offer JSON output for automation.
- Preserve rich transport diagnostics without duplicating REST DTOs.

Initial scope:

- `dkim2ctl` is a test and conformance client first.
- It should send OpenAPI-backed requests to `dkim2d`.
- It should run draft-versioned fixture suites and daemon smoke checks.
- It should emit stable machine-readable JSON for CI and reproducible bug
  reports.
- It should support negative request fixtures for API contract testing.

Future operator scope:

- The binary may become the long-term operator CLI after the daemon API,
  authentication model, authorization model, audit behavior, and redaction
  rules are mature.
- The first command layout should therefore use Cobra command groups that can
  later accept operational subcommands without changing the binary name.
- Early test-client commands must not require privileged mutation APIs.
- Any later operational mutation command must have explicit authn/authz,
  audit, confirmation, and redaction semantics.

### 5.16 `cmd/dkim2-milter/internal/milter`

Milter adapter implementation.

Responsibilities:

- Collect SMTP session metadata.
- Collect envelope sender and recipients.
- Collect headers and body chunks.
- Call the HTTP/JSON service at EOM.
- Apply returned actions using Milter operations.
- Map service decisions to SMTP replies.

Important limitation:

Milter APIs may not expose the exact original RFC 5322 header bytes in the same
form as a raw message source. The Milter adapter must therefore declare its
fidelity mode. It can still be operationally useful, but the reference parser
and vector runner must operate on raw RFC 5322 bytes.

## 6. Domain Model

The initial model should separate four things that are often conflated:

- Raw message state.
- DKIM2 protocol fields.
- SMTP envelope state.
- Local decision and mutation actions.

### 6.1 Raw Message State

```go
type RawMessage struct {
    HeaderBlock HeaderBlock
    Body        Body
}
```

The raw message object should be immutable once parsed. Mutations should create
a `MutationPlan` or a new message object. This prevents accidental changes from
corrupting hash or signature calculations.

### 6.2 DKIM2 Protocol Fields

```go
type MessageInstance struct {
    Number  uint64
    Hashes  []HashSet
    Recipe  RecipeRef
}

type DKIM2Signature struct {
    Sequence       uint64
    InstanceNumber uint64
    Timestamp      time.Time
    MailFrom       MailboxPath
    RcptTo         []MailboxPath
    NextDomain     string
    Domain         string
    Signatures     []AlgorithmSignature
    Flags          SignatureFlags
    Nonce          []byte
}
```

The model should keep parsed protocol fields separate from their original header
field bytes. Both are useful: parsed values for logic, original bytes for
diagnostics and strict reconstruction.

### 6.3 SMTP Envelope State

```go
type Envelope struct {
    MailFrom MailboxPath
    RcptTo   []MailboxPath
    HELO     string
    RemoteIP netip.Addr
}
```

The current envelope is mandatory for normal inbound DKIM2 verification
because the latest `DKIM2-Signature` must match the actual `MAIL FROM` and
`RCPT TO` values. Draft-04 permits a highest signature with `nd=` only when
out-of-band arrangements exist; the secure default is non-success unless that
trust is explicitly modeled.

### 6.4 Result State

```go
type VerificationResult struct {
    State        ResultState
    Protocol     ProtocolFindings
    Chain        ChainFindings
    Instances    []InstanceFinding
    Signatures   []SignatureFinding
    Policy       PolicyFinding
    Actions      []Action
}
```

The result must be machine-readable first. Human-readable strings are secondary.

## 7. HTTP/JSON API Sketch

The first daemon API should be explicit, versioned, and boring.

Endpoint sketch:

```text
POST /v1/verify
POST /v1/sign
POST /v1/revise
POST /v1/process
GET  /healthz
GET  /readyz
```

`/v1/process` can combine verify, revise, sign, and action planning for Milter
use. The narrower endpoints are useful for tests and operational tools.

Request sketch:

```json
{
  "api_version": "v1",
  "operation": "process",
  "draft": "draft-ietf-dkim-dkim2-spec-04",
  "smtp": {
    "mail_from": "<bounce@example.org>",
    "rcpt_to": ["<user@example.net>"],
    "helo": "mx1.example.org",
    "remote_ip": "192.0.2.10"
  },
  "message": {
    "format": "raw_rfc5322_base64",
    "raw_rfc5322_base64": "..."
  },
  "options": {
    "mode": "inbound",
    "policy": "strict",
    "add_authentication_results": true
  }
}
```

Response sketch:

```json
{
  "api_version": "v1",
  "result": "pass",
  "verdict": "accept",
  "errors": [],
  "findings": [],
  "actions": [
    {
      "type": "add_header",
      "name": "Authentication-Results",
      "value": "mx.example.net; dkim2=pass header.d=example.org"
    }
  ]
}
```

Action types should be intentionally small:

- `accept`
- `reject`
- `tempfail`
- `add_header`
- `change_header`
- `delete_header`
- `replace_body`
- `quarantine`
- `log_event`

Every action must document whether it is safe for Milter, raw message rewrite,
or both.

### 7.1 OpenAPI as Contract Authority

`docs/specs/openapi/dkim2d.yaml` is the source of truth for `dkim2d` REST
behavior. The service should not grow hand-written routes that bypass the
contract. Generated code should provide:

- Server request and response DTOs at the HTTP boundary.
- Client DTOs and transport for `dkim2ctl`.
- Operation identifiers for logs, traces, metrics, and tests.
- Reproducible generated artifacts checked by guardrails.

The first OpenAPI generator should be `oapi-codegen` pinned to
`v2.7.1`:

```text
github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1
```

The pinned generator belongs to the build toolchain, not to runtime protocol
logic. It should be managed through a repository-local tool-pinning mechanism
and invoked through `go generate` or `make generate-openapi`, never through an
implicit `latest` dependency.

Generation rules:

- Commit generated server, client, and model artifacts.
- Review generated diffs before they are executed or released.
- Keep generator configuration files in `docs/specs/openapi/`.
- Use strict server generation for the daemon boundary when practical.
- Prefer standard-library HTTP integration unless the service layer needs a
  stronger reason to add a router dependency.
- Keep generated packages behind adapter packages; domain packages must not
  import generated REST types.
- Add a guardrail that regenerates OpenAPI artifacts and fails when committed
  generated code is stale.
- Treat generator upgrades as explicit dependency changes with release-note
  review, generated-code review, and regression tests.

Domain packages should not import generated REST types. HTTP handlers adapt
generated DTOs into explicit DKIM2 domain requests and adapt domain results
back to generated DTOs.

The M13 production contract is deliberately inbound-only: it exposes current
verification, policy, and replay results but no signing, revision, message
mutation, or action plan. M16 owns the first production HTTP sign/revise
contract, the M11 datasource-to-signer bridge, the private signing backend, the
generated OpenAPI extension, and an adapter-safe mutation/action plan before
Milter EOM integration. M17 reuses that service contract for Exim integration.

Starting with the M16 contract, `dkim2d` may return action-plan entries that add
`Authentication-Results` header fields. This is a local trust-boundary output
format, not DKIM2 protocol state. It must be disabled or explicitly configured
by deployment policy, generated by a strict formatter, and tested to avoid raw
errors, secrets, protected values, raw recipient lists, and unbounded text.

### 7.2 Configuration and Runtime Composition

`dkim2d` should use Cobra and Viper for command/config surfaces and Uber Fx for
runtime composition. The intended path is:

```text
Cobra command
  -> Viper config sources
  -> scalar env placeholder expansion
  -> typed config decode
  -> typed validation
  -> Fx providers
  -> runtime lifecycle
```

Important rules:

- Configuration lives in command modules, not in the protocol library.
- Defaults must be inspectable.
- Effective non-default config should be inspectable without exposing secrets.
- Protected output requires explicit operator intent and redaction policy.
- Missing environment variables fail closed.
- Map keys are never environment-expanded.
- Unsafe compatibility switches require explicit config.

### 7.3 Observability Runtime

Observability should follow a central-provider model:

- `slog` is the structured logging API.
- OpenTelemetry is used for traces.
- Prometheus is used for metrics.
- The daemon owns exporters, registries, handlers, and lifecycle.
- The library emits bounded observation events through injected interfaces.

Telemetry uses a tiered allowlist. Default telemetry is intentionally boring
and low-cardinality. Richer DKIM2-specific diagnostics are available only
through explicit debug modules, and even then only as bounded, redacted,
hashed, or bucketed values.

Default logs and traces may carry:

- Operation name.
- Result class.
- Verdict.
- Reason class.
- Error class.
- Draft version.
- Algorithm family.
- Hash algorithm.
- Signature algorithm.
- Policy mode.
- Route template.
- HTTP method.
- HTTP status class.
- Datasource kind.
- Datasource result class.
- Replay state.
- Duration.
- Message size bucket.
- Recipient count bucket.
- Signature count bucket.
- Chain length bucket.

Default Prometheus labels must be stricter than logs and traces. They may use
only stable low-cardinality labels. Buckets belong in histogram or summary
measurements, not in high-cardinality labels.

Explicit debug modules may add bounded diagnostics:

- `debug.identity_hashes`: keyed hashes of signer domain, selector, sender
  domain, and recipient domain set.
- `debug.message_shape`: message size bucket, recipient count bucket,
  signature count, chain length, header count bucket, and body hash algorithm
  class.
- `debug.network`: remote IP prefix, HELO shape class, TLS state class, and
  authenticated upstream class when available.
- `debug.dns`: DNS result class, lookup duration, cache result, resolver class,
  and DNSSEC diagnostic state when available.
- `debug.datasource`: provider kind, result class, latency bucket, and
  degraded-state reason class.
- `debug.replay`: replay state, replay-key algorithm version, retention bucket,
  and store result class.

Debug identity hashes must use a deployment-local keyed hash so values are
stable enough for local diagnosis but not portable correlation identifiers.
Unknown telemetry attributes are rejected by tests and configuration
validation.

Telemetry must never carry:

- Private keys.
- Raw RFC 5322 messages.
- Raw body content.
- Raw header values.
- Full recipient lists.
- Raw sender local parts.
- Raw recipient local parts.
- Raw `Message-ID` values.
- Raw `DKIM2-Signature` fields.
- Raw `Message-Instance` fields.
- Raw replay keys.
- Raw Valkey or Redis keys.
- Raw DNS TXT records.
- Raw LDAP DNs.
- Raw SQL text.
- Raw datasource queries.
- Bearer tokens.
- Passwords.
- Protected configuration values.
- Unbounded error strings.

Prometheus labels must use a low-cardinality allowlist. Candidate labels:

```text
operation
result
verdict
reason_class
error_class
algorithm_family
hash_algorithm
signature_algorithm
draft
policy_mode
route
method
status_class
datasource_kind
datasource_result_class
cache_result
replay_state
```

Forbidden labels:

```text
username
recipient
sender
signer_domain
sender_domain
recipient_domain
signer_domain_hash
selector
selector_hash
message_id
session_id
request_id
trace_id
client_ip
remote_addr
remote_ip_prefix
selector_nonce
private_key_id
raw_error
ldap_dn
sql_text
valkey_key
redis_key
token
password
body_hash
header_hash
```

### 7.4 Datasource Provider Model

The implemented M11 datasource domain owns these operational facts beyond DNS:

- Signing profiles.
- Exact selector/algorithm/public-key-to-opaque-handle bindings inside a
  profile.
- Exact domain and tenant policy selected by `(tenant, domain, use)`.
- Optional feedback routing policy.
- Strict compatibility and closed rollout state.

The provider interface exposes exact `ResolveProfile` and `ResolvePolicy`
operations. Both return immutable complete same-generation results. There is no
wildcard, suffix, tenant-default, provider-chain, first-row, or stale-snapshot
fallback.

General datasource provider classes:

- In-memory provider for tests and examples.
- Flat-file provider for the first public preview.
- LDAP provider in `cmd/dkim2d`, with verified TLS, critical RFC 2696 paging,
  immutable generation loading, and RFC 4528 publication fencing.
- PostgreSQL provider in `cmd/dkim2d`, with verified TLS, fixed keyset queries,
  repeatable-read loading, and transactional publication fencing.

Replay storage is modeled separately in the replay-store interface. Valkey is
the default production replay backend, but it must not become the general
datasource abstraction or leak into protocol packages.

Provider rules:

- Operations are context-aware and bounded.
- Provider-specific identifiers do not leak into protocol packages.
- Only provider-neutral opaque handle IDs cross provider boundaries as
  private-key references; no private key or signing capability crosses. The
  sole signing bridge maps those IDs to inert handles.
- Missing required data fails closed.
- Ambiguous data is a distinct error, not a silent fallback.
- Flat-file reload is explicit, serialized, transactional, and unavailable
  while degraded; there is no background watch, retry, or stale serving.
- Memory and flat-file providers share parity and signing-boundary integration
  evidence.

#### 7.4.1 RNS LDAP Schema Allocation

The LDAP deployment schema uses the RNS Private Enterprise Number `31612`,
registered in the
[IANA Private Enterprise Number registry](https://www.iana.org/assignments/enterprise-numbers/?page=317)
under the enterprise OID root
`1.3.6.1.4.1.31612`. Existing RNS schemas reserve `.1` as the LDAP subtree and
use one application child followed by `.1` for attribute types and `.2` for
object classes. The next unused application child is reserved for DKIM2:

| Purpose | OID |
| --- | --- |
| RNS enterprise root | `1.3.6.1.4.1.31612` |
| RNS LDAP root | `1.3.6.1.4.1.31612.1` |
| DKIM2 schema root | `1.3.6.1.4.1.31612.1.7` |
| DKIM2 attribute types | `1.3.6.1.4.1.31612.1.7.1` |
| DKIM2 object classes | `1.3.6.1.4.1.31612.1.7.2` |

The schema file should be named `rnsdkim2.schema` and declare these symbolic
identifiers:

```text
objectidentifier RNSRoot      1.3.6.1.4.1.31612
objectidentifier RNSLDAP      RNSRoot:1
objectidentifier RNSDKIM2     RNSLDAP:7
objectidentifier RNSDKIM2at   RNSDKIM2:1
objectidentifier RNSDKIM2oc   RNSDKIM2:2
```

The logical LDAP attribute names already defined by
`docs/datasource-ldap-sql-design.md` remain the stable descriptors. Their OIDs
are reserved as follows and must never be reassigned:

| OID | LDAP descriptor |
| --- | --- |
| `RNSDKIM2at:1` | `dkim2SchemaVersion` |
| `RNSDKIM2at:2` | `dkim2Generation` |
| `RNSDKIM2at:3` | `dkim2DatasetState` |
| `RNSDKIM2at:4` | `dkim2HandleID` |
| `RNSDKIM2at:5` | `dkim2ProfileID` |
| `RNSDKIM2at:6` | `dkim2SigningDomain` |
| `RNSDKIM2at:7` | `dkim2RecordStatus` |
| `RNSDKIM2at:8` | `dkim2NotBefore` |
| `RNSDKIM2at:9` | `dkim2NotAfter` |
| `RNSDKIM2at:10` | `dkim2Algorithm` |
| `RNSDKIM2at:11` | `dkim2Selector` |
| `RNSDKIM2at:12` | `dkim2PublicKeySPKI` |
| `RNSDKIM2at:13` | `dkim2TenantID` |
| `RNSDKIM2at:14` | `dkim2ProfileUse` |
| `RNSDKIM2at:15` | `dkim2Rollout` |
| `RNSDKIM2at:16` | `dkim2Compatibility` |
| `RNSDKIM2at:17` | `dkim2FeedbackRouteID` |

The first object-class allocation is:

| OID | LDAP descriptor | Logical ownership |
| --- | --- | --- |
| `RNSDKIM2oc:1` | `dkim2Dataset` | Schema version, generation, and committed publication state |
| `RNSDKIM2oc:2` | `dkim2Handle` | One opaque handle declaration |
| `RNSDKIM2oc:3` | `dkim2Profile` | One bounded signing profile |
| `RNSDKIM2oc:4` | `dkim2Credential` | One selector, algorithm, public SPKI, and handle binding |
| `RNSDKIM2oc:5` | `dkim2Policy` | One exact tenant, domain, and use policy |

M22 owns the exact LDAP syntaxes, matching rules, `MUST`/`MAY` sets, structural
layout, indexes, ACL examples, and reproducible `slaptest` fixtures. Those
deployment details must preserve the existing logical mapping and immutable
generation contract. A configured base DN and record DNs are provider storage
mechanics; they are never profile, tenant, policy, or handle identities.

The historical `rnsMSDKIM` object class and its OIDs remain part of the mail
schema. They are not extended or reused for DKIM2 because they can carry raw
private-key material and do not represent immutable generations, complete
profiles, exact tenant/use policies, public SPKI bindings, or opaque handles.

#### 7.4.2 Legacy OpenDKIM Bootstrap Contract

An existing OpenDKIM LDAP deployment may be used as an explicit migration
source, but it is never a second runtime provider contract and is never read as
DKIM2 data. The migration is an out-of-process administrative operation that
creates and validates a new `dkim2-datasource-v1` generation before publication.
The read-only DKIM2 provider performs no legacy lookup, shape inference,
backfill, or read-time conversion.

The secret-safe production inventory captured on 2026-07-28 provides the
initial migration baseline:

- the active source uses the external `DKIM` object class, not `rnsMSDKIM`;
- 176 complete OpenDKIM objects cover 30 distinct lookup domains;
- 88 objects declare RSA and 88 declare Ed25519;
- 60 objects are active and 116 are inactive;
- every domain has exactly one active RSA and one active Ed25519 object;
- all 176 selectors are globally distinct;
- there is no duplicate active `(domain, algorithm)` group;
- 29 domains have three RSA/Ed25519 rotation pairs and one domain has one pair;
- all 176 objects contain a private-key attribute, whose values were neither
  emitted nor retained by the inventory;
- no live `rnsMSDKIM` object exists in that source;
- 174 objects use the same logical domain for lookup, signing, and the
  conventional `@domain` DKIM AUID;
- one active RSA/Ed25519 pair maps a lookup domain to a different, unrelated
  signing domain, with the AUID matching the signing domain.

This is a dated migration-planning snapshot, not a runtime invariant. M22 must
refresh it through the same bounded, read-only, secret-safe inventory immediately
before an approved migration.

Reusable legacy facts map as follows:

| OpenDKIM fact | DKIM2 migration target | Rule |
| --- | --- | --- |
| `associatedDomain` | `dkim2SigningDomain` | Candidate actual signing domain after canonical validation |
| `DKIMDomain` | Policy lookup evidence only | Must equal the canonical signing domain for automatic migration |
| `DKIMSelector` | Canonical legacy source identity plus explicit `dkim2Selector` | Retain exact LDAP spelling internally only for protected lookup; assign a separately validated canonical DKIM2 DNS selector |
| `DKIMKeyType=rsa` | `dkim2Algorithm=rsa-sha256` | Closed exact mapping |
| `DKIMKeyType=ed25519` | `dkim2Algorithm=ed25519-sha256` | Closed exact mapping |
| `DKIMActive=TRUE` | Active-profile candidate | Does not itself authorize rollout or signing |
| `DKIMActive=FALSE` | Disabled-history candidate | Never joins the current active profile |
| `DKIMKey` | Separate signing-registry import | Never written to a DKIM2 datasource record |
| `createTimestamp` / `modifyTimestamp` | Audit evidence | Never inferred as `not_before` or `not_after` |
| `DKIMIdentity` | No DKIM2 field | DKIM AUID semantics must not be mapped to numeric DKIM2 `i=` |

One automatically migrated active domain becomes one complete profile with one
or two credentials. The current dual-algorithm source therefore maps naturally
to one RSA credential followed by one Ed25519 credential. Historical rotation
pairs cannot be appended to that profile because the datasource contract permits
at most two credentials and rejects duplicate algorithms. They remain legacy
history unless an approved migration creates distinct disabled profiles with
new profile identities and explicit validity policy.

The migration must assign facts absent from OpenDKIM explicitly:

- `dkim2SchemaVersion`, `dkim2Generation`, and `dkim2DatasetState`;
- `dkim2TenantID`, `dkim2ProfileID`, and `dkim2ProfileUse`;
- canonical legacy source identities and explicit canonical DKIM2 target
  selectors, while exact LDAP spelling remains inventory-owned lookup state;
- `dkim2HandleID` declarations and their protected registry bindings;
- canonical public SPKI DER derived inside the protected key-import boundary;
- `dkim2Rollout`, `dkim2Compatibility`, and optional feedback-route policy;
- optional validity intervals based on administrative policy, not LDAP
  timestamps.

Handle IDs are new provider-neutral opaque identifiers. They must not be LDAP
DNs, paths, selectors, private-key hashes, database keys, or other
provider-specific locators. A separately configured signing registry maps each
handle ID to an inert signing handle. The legacy private key may be imported
into that registry only inside an approved protected boundary; raw key bytes
never cross the datasource interface, appear in migration output, or enter the
new LDAP schema.

Existing cryptographic keys are compatibility candidates, but legacy selectors
are source lookup facts rather than implicit DKIM2 DNS identities. A protected
plan must assign an explicit canonical DKIM2 target selector, even when it
deliberately equals the validated lowercase source selector. Before a profile
becomes active, the migration performs the same fresh DKIM2 DNS publication
check required by signing at
`target-selector._domainkey.signing-domain` and proves that the unique public
DNS key matches the canonical public key derived from the protected signing
handle. It never proves publication at an inferred alias or at the exact-case
legacy source selector.

The legacy source permits a SigningTable lookup domain to differ from the
KeyTable signing domain. The DKIM2 datasource deliberately has no alias,
wildcard, suffix, parent-domain, or cross-domain fallback, and a policy must
reference a profile with the same canonical signing domain. A legacy object
with `DKIMDomain != associatedDomain` is therefore `malformed_data` for
automatic migration. It requires an explicit operator decision that produces
an exact DKIM2 policy or a separately reviewed future architecture change; the
migration must never guess which domain owns the DKIM2 policy.

The bootstrap publication sequence is:

1. Acquire a bounded read-only legacy snapshot over authenticated, verified
   LDAP transport without requesting private-key values for inventory.
2. Validate record completeness, unique selectors, one active record per
   domain and algorithm, exact domain agreement, closed algorithms, and source
   limits.
3. Resolve private keys only inside the protected import phase, validate key
   type and strength, derive canonical public SPKI, and create new opaque
   handle bindings.
4. Perform fresh DNS publication checks for every candidate credential.
5. Require explicit tenant, profile-use, rollout, compatibility, profile-ID,
   handle-ID, and optional validity inputs.
6. Build all metadata, handle, profile, credential, and policy records under
   one new nonzero generation.
7. Validate the complete generation through the same constructors, limits,
   cross-reference rules, and immutable indexes used by normal providers.
8. Produce a redacted dry-run report containing only bounded counts and closed
   result classes.
9. Publish `committed` atomically only after the signing registry and complete
   datasource generation agree. The first publication requires the explicit
   canonical zero absence fence: LDAP atomically claims the unique staging
   current DN and activates it with RFC 4528, while PostgreSQL proves every
   datasource table empty in a serializable transaction and uniquely inserts
   the singleton current row. Zero is never a runtime generation, nonempty
   pointerless state fails closed, and concurrent first publishers cannot both
   succeed.

Source absence is `not_found`; duplicate selectors, active
domain/algorithm pairs, metadata, or exact identities are `ambiguous`;
unsupported shapes, domain disagreement, invalid keys, missing explicit
migration facts, and inconsistent references are `malformed_data`; bound
violations are `limit_exceeded`; transport, authorization, or signing-registry
failures are `unavailable`; context termination remains `cancelled` or
`deadline_exceeded`. No error includes a DN, domain, selector, key, handle,
query, endpoint, credential, or raw backend error.

The concrete LDAP provider belongs in the daemon/service module, for example
under `cmd/dkim2d/internal/datasource/ldap`, and implements only the existing
storage-neutral contracts. The migration command belongs to a command/service
module but remains separate from the read-only provider and from protocol
packages. LDAP client types, records, controls, DNs, and schema helpers must
not enter `lib`, signing, verification, OpenAPI DTOs, Milter code, or Exim
code.

M22 integration evidence must include:

- synthetic legacy fixtures for single- and dual-algorithm active profiles,
  rotation history, the observed cross-domain exception shape, missing keys,
  duplicate selectors, and duplicate active algorithms;
- proof that DKIM AUID values and LDAP timestamps are never mapped to DKIM2
  `i=` or validity fields;
- proof that private-key bytes, DNs, domains, selectors, handles, and backend
  errors are absent from dry-run output, logs, traces, metrics, CLI output, and
  test failures;
- disposable OpenLDAP tests for schema installation, ACLs, paging,
  cancellation, immutable generation publication, partial failure, rollback
  publication under a higher generation, and concurrent migration attempts;
- parity tests proving the migrated dataset resolves identically through
  memory, flat-file, LDAP, and SQL providers;
- signing integration tests proving fresh DNS publication validation occurs
  before the private signing callback and that every migration/provider denial
  has no partial datasource, signature, route, or release side effect.

### 7.5 Replay Store Model

The first daemon release includes storage-backed replay detection as an
explicit policy feature. This goes beyond the message-local chain and envelope
checks by remembering bounded replay keys for a configurable retention window.
Replay stores remain separate from the M11 signing-profile datasource
abstraction.

Replay storage requirements:

- Open-source storage backend.
- Atomic first-seen insertion.
- TTL or expiration without full-table scans.
- High write throughput with low latency.
- Horizontal scalability for large mail operations.
- Explicit retention configuration.
- Privacy-preserving keys and values.
- No raw message bodies, raw recipients, private keys, tokens, or protected
  configuration values in the store.
- Bounded typed failures for unavailable, indeterminate, inconsistent,
  misconfigured, and other closed error outcomes, with degradation represented
  separately as store state.

Replay key material is exact:

- the selected current Message-Instance SHA-256 header hash;
- SHA-256 of the exact highest canonical signature input;
- one privacy-preserving recipient-scope SHA-256 digest;
- the pinned draft identifier and replay-key algorithm version.

Sender identities, `Message-ID`, selectors, signer nonces, raw recipients, and
other creator-private facts are not replay-key inputs.

The replay store must be separated from the protocol library. The library
defines replay-check interfaces and result types; `dkim2d` wires concrete
storage providers and local policy.

The default production replay backend should be Valkey. Valkey gives the
reference implementation a permissive open-source baseline, low-latency
key-value operations, native expiry, and an atomic first-seen operation shaped
like `SET replay-key replay-value NX PX retention-milliseconds`. The implementation
must not treat Valkey as a protocol dependency. It is the first production
provider behind a replay-store interface.

Initial replay provider set:

- `memory`: deterministic test and example provider.
- `valkey`: default production provider; the first secure implementation binds
  one directly addressed standalone primary.
- `disabled`: explicit disabled provider for deployments that choose not to run
  replay detection.

Future providers may include PostgreSQL, LDAP-adjacent operational stores,
Cassandra-compatible stores, or other open-source backends. Adding a provider
must not change protocol packages, public result semantics, OpenAPI response
contracts, or Milter adapter behavior.

The replay-store interface should model intent, not Valkey commands:

```go
type ReplayStore interface {
    CheckAndRemember(ctx context.Context, key ReplayKey, retention ReplayRetention) (ReplayCheck, error)
}
```

`ReplayCheck` is success-only and distinguishes exactly first-seen, replayed,
and explicitly disabled outcomes. Unavailable, indeterminate, inconsistent,
misconfigured, limit, context, closed, and invariant outcomes are typed
failures; degraded is separate store state. Local policy decides how successful
checks, typed failures, and store state map to accept, reject, tempfail, or
observe-only behavior.

Valkey-specific design notes:

- Use a single-key first implementation. Production cluster routing is deferred
  until an owned audited router can confine every dispatch to an immutable
  authority set and surface redirects before execution; a dependency-managed
  MOVED/ASK refresh must never route a replay write to an unaudited node.
- Prefer privacy-preserving digest keys with a stable namespace prefix and
  algorithm/version marker.
- Store only bounded metadata needed for diagnosis and policy, never raw
  messages, raw recipient addresses, private keys, bearer tokens, or protected
  configuration.
- Treat asynchronous replication and failover windows as operational risk, not
  protocol failure. Strict deployments may choose stronger local write-safety
  settings or fail closed when the replay store is degraded.

## 8. Milter Adapter Design

The first Milter should be operational glue, not the reference engine.

Flow:

```text
connect
helo
envfrom
envrcpt
header*
eoh
body*
eom
  -> build service request
  -> POST /v1/process
  -> apply actions
  -> accept/reject/tempfail
close
```

At EOM, the adapter should have:

- SMTP envelope sender.
- SMTP recipients.
- Peer IP and HELO.
- Header fields in observed order.
- Body bytes.
- Milter capability and fidelity metadata for local diagnostics.

The adapter must send raw RFC 5322 input to `dkim2d`. The daemon API does not
define a structured Milter-specific message representation. If a Milter
implementation reconstructs RFC 5322 bytes from callbacks, that fidelity
limitation belongs to the adapter's diagnostics and tests, not to a second
daemon input model. If the adapter cannot provide an acceptable raw RFC 5322
message for DKIM2 processing, it should fail closed or tempfail according to
explicit local policy.

Operational defaults:

- Short HTTP timeout, for example 2 seconds initially.
- Fail-closed or tempfail is the secure reference default for service errors,
  invalid daemon responses, unacceptable raw-message fidelity, and ambiguous
  DKIM2 processing state.
- Fail-open may exist only as an explicit deployment or pilot-mode
  configuration. It must be visible in effective config, logs, metrics, and
  operational documentation.
- Request body size limits.
- No message body logging.
- Structured reason codes for SMTP replies.
- Metrics for pass/fail/tempfail/timeout/action counts.

## 9. Exim Adapter Design

Exim integration is a separate MTA adapter path. It should not depend on the
Milter adapter, and it should not introduce Exim-specific message structures
into the DKIM2 protocol library or the daemon API.

The preferred inbound path is an Exim `local_scan()` adapter. That hook runs
after message reception and ACL processing, just before Exim accepts the
message. At that point the adapter can collect Exim's observed header chain,
the body file descriptor, SMTP or local-submission metadata, envelope sender,
recipients, peer address, and HELO state, then submit a `POST /v1/process`
request to `dkim2d`.

The preferred outbound signing or revision path is an Exim `transport_filter`
helper. Exim passes the complete message to the filter on standard input at
transport time and uses the filter output as the transformed message. This path
is suitable for message rewriting actions, but transport-filter failures should
map to delivery deferral rather than late policy rejection.

Exim adapter action support should be declared explicitly:

- `accept`, `reject`, and `tempfail` map to `local_scan()` return decisions.
- `add_header` is supported when Exim can safely add the field at the relevant
  hook point.
- `delete_header` and `change_header` require explicit Exim hook support and
  tests for deleted, rewritten, duplicate, and folded fields.
- `replace_body` is not a default `local_scan()` action. It belongs to the
  transport-filter path or another explicitly designed full-message rewrite
  path.
- `quarantine`, `freeze`, or queue-only behavior are local-policy extensions
  and must remain visibly configured.

Exim fidelity metadata is mandatory. Exim stores and processes messages in its
own internal representation and may normalize line endings or apply receive-time
fixups before adapter code observes the message. The Exim adapter must record
whether the daemon input came from Exim's observed header/body state, a
transport-filter stream, or another source. Any LF/CRLF conversion,
receive-time header fixup, deleted-header handling, recipient batching, or
transport-time rewrite limitation belongs to adapter diagnostics and tests, not
to a second daemon message model.

The Exim adapter compatibility matrix is refreshed for each DKIM2 release. It
includes the current upstream Exim release and the Exim package versions
shipped by the most widely deployed server distributions that published a new
LTS, stable, or enterprise long-term release within the previous 12 months,
provided Exim is shipped in that distribution's official supported package
repositories. Distribution security-update package revisions count as the
tested baseline; unsupported third-party repositories, PPAs, COPR/EPEL-style
extras, and vendor-unmaintained packages do not define support targets.

Compatibility evidence should be recorded with dates and package versions. For
the 2026-07-03 planning baseline, the first expected distribution baselines are
Ubuntu 26.04 LTS `exim4 4.99.1-1ubuntu1.3` and Debian 13 stable
`exim4 4.98.2-1+deb13u3`. Older still-supported distribution releases may be
used as optional smoke targets, but they do not define the default support floor
unless a release plan names them explicitly.

## 10. Verification Flow

Inbound verification should follow the draft order closely:

1. Parse raw message.
2. Extract and validate DKIM2 header fields.
3. Validate Message-Instance numbering.
4. Validate DKIM2-Signature numbering.
5. Check the latest signature against the current SMTP envelope.
6. Check timestamp policy.
7. Resolve public keys for required signatures.
8. Verify signatures over canonical DKIM2 protocol fields.
9. Validate current body and header hashes.
10. Apply recipes where requested to reconstruct previous instances.
11. Validate previous instance hashes.
12. Check chain-of-custody relationships.
13. Evaluate flags such as `donotmodify` and `donotexplode`.
14. Produce protocol findings.
15. Apply local policy.
16. Produce an action plan.

The implementation should support partial verification modes for debugging, but
the default inbound mode should verify the latest signature and current message
hashes before accepting the message.

## 11. Signing and Revising Flow

Outbound signing:

1. Parse or receive a controlled message representation.
2. Compute current body hash.
3. Compute current header hash.
4. Add `Message-Instance: m=1` when needed.
5. Build `DKIM2-Signature: i=1`.
6. Include current SMTP envelope in `mf=` and `rt=`.
7. Resolve the configured private key and selector.
8. Canonicalize DKIM2 protocol fields for signing.
9. Insert signature values.

Revision signing:

1. Parse incoming message.
2. Determine whether body or relevant headers changed.
3. Generate a recipe from the new state back to the previous state.
4. Compute new hashes.
5. Add a new `Message-Instance`.
6. Add a new `DKIM2-Signature`.
7. Ensure chain-of-custody continuity.

The reference implementation must generate and apply draft-conformant recipes.
Generated recipes may be conservative and are not required to be minimal. Later
revisions can optimize recipe size without changing verification semantics.

## 12. Security Architecture

### 12.1 Input Limits

Default limits should exist before public use:

- Maximum request body size.
- Maximum raw message size.
- Maximum header block size.
- Maximum number of headers.
- Maximum single header field length.
- Maximum body line count used for raw-message and recipe indexing.
- Maximum body line length used for recipe indexing.
- Maximum number of recipients in `rt=`.
- Maximum decoded recipe size.
- Maximum reconstructed message size.
- Maximum DNS lookups per message.

Limits should be configurable, but unsafe values should require explicit config.

### 12.2 Cryptography

Crypto code should wrap standard, audited Go libraries.

Rules:

- Use `crypto/rsa` and `crypto/ed25519`.
- Use SHA-256 as required by the draft baseline.
- Reject unknown algorithm names unless explicitly configured for experimental
  draft work.
- Validate RSA key size policy.
- Keep private keys behind interfaces.
- Avoid logging private-key paths if they reveal tenant data.
- Support key rotation by selector.

### 12.3 DNS

DNS resolver behavior must distinguish:

- Temporary lookup failure.
- Authoritative NXDOMAIN or NODATA missing state.
- Multiple TXT records as fail-closed ambiguity.
- Malformed record.
- Revoked key.
- Unsupported key type.
- Algorithm mismatch.
- Permanent transport and provider-contract failure.

TXT character-string chunks are concatenated within one RR without added
whitespace; RR boundaries are never concatenated. RSA records contain PKCS#1
public DER and Ed25519 records contain exactly 32 raw public bytes. The resolver
supports context cancellation, bounded TTL/LRU caching, bounded coalescing, and
non-blocking saturation. DNSSEC remains diagnostic-only and does not alter
verification or cache behavior.

### 12.4 Error Handling

Errors should be typed:

- `TEMPERROR`
- `PERMERROR`
- `FAIL`
- `POLICY`
- `INTERNAL`

The wire API can include human text, but tests should assert structured codes.

### 12.5 Logging

Default logging follows the tiered telemetry allowlist in Section 7.3. Default
logs should include:

- Message size bucket.
- Draft version.
- Result code.
- Verdict.
- Reason class.
- Algorithm family.
- Policy mode.
- Datasource result class.
- Replay state.
- Duration.
- Error code.

Default logs should not include:

- Full raw messages.
- Full body content.
- Raw header values.
- Raw signing domains.
- Raw selectors.
- Raw sender or recipient local parts.
- Raw message IDs.
- Private keys.
- Nonces unless explicitly configured.
- Large header values unless redacted.

Debug logs may include deployment-local keyed hashes for selected identity-like
values only when the corresponding debug module is explicitly enabled. Prometheus
labels must never include raw or hashed identity values.

## 13. Testing Strategy

### 13.1 Unit Tests

Every package should have table-driven unit tests. Priority areas:

- Header parsing.
- Line ending normalization.
- Header canonicalization.
- Body canonicalization.
- Hash calculation.
- Base64 parsing and formatting.
- DKIM2 tag parsing.
- Sequence gap detection.
- Timestamp checks.
- Signature input construction.
- DNS key record parsing.
- Recipe apply and generate.

### 13.2 Golden Tests

Golden vectors should store:

- Raw input message.
- SMTP envelope.
- Expected canonical header hash input.
- Expected canonical body hash input.
- Expected Message-Instance field.
- Expected DKIM2-Signature input.
- Expected verification result.

Golden files must name the draft version they target.

### 13.3 Fuzz Tests

Fuzz targets:

- Raw message parser.
- Tag-value parser.
- Message-Instance parser.
- DKIM2-Signature parser.
- Recipe JSON parser.
- Recipe application.
- DNS key record parser.

Fuzzing goals:

- No panics.
- No unbounded memory growth.
- No illegal UTF-8 assumptions in byte-oriented paths.
- Deterministic error classification.

### 13.4 Integration Tests

Integration layers:

- Core library only with static resolver.
- HTTP/JSON daemon with synthetic requests.
- OpenAPI-generated client against `dkim2d`.
- Milter adapter against a test MTA.
- Exim adapter against supported `local_scan()` and `transport_filter`
  baselines from the release compatibility matrix.
- End-to-end signing and verification through SMTP.

The first public confidence point should be vector-driven core verification,
not Milter or Exim adapter success.

### 13.5 Security Tests

Security regression cases:

- Oversized message.
- Header injection attempt.
- Malformed base64.
- Multiple DKIM2 DNS records.
- Revoked key.
- Algorithm mismatch.
- Recipe expansion bomb.
- Very high `m=` or `i=` value.
- Duplicate required tags.
- Unknown extension tags.
- Expired timestamp.
- Envelope mismatch.
- Multiple recipient replay attempt.
- Datasource ambiguity or missing signing profile.
- Secret-bearing values rejected from logs, traces, metrics, REST, CLI, and
  test output.
- Prometheus forbidden labels rejected before registration or observation.
- OpenTelemetry attributes reject raw messages, raw recipients, raw errors,
  raw datasource queries, and protected values.

### 13.6 Reproducer and Unit-Driven Development

Bug fixes should start with a meaningful failing reproducer whenever practical.
The preferred shape depends on the defect:

- Unit test for parser, canonicalization, recipe, signature, policy, or
  datasource defects.
- Golden vector for draft-level protocol behavior.
- OpenAPI request fixture for daemon contract behavior.
- CLI/test-client workflow for generated-client regressions.
- Milter or SMTP public-socket test for adapter fidelity.

The reproducer should remain as regression coverage unless it is inherently
environment-only or brittle.

Core protocol work should be unit-driven. Write focused unit tests before
production code when the behavior can be exercised cleanly without external
services.

## 14. Development Quality Gates

Recommended local gates:

```text
go test ./lib/...
go test ./cmd/dkim2d/...
go test ./cmd/dkim2-milter/...
go test ./cmd/dkim2ctl/...
go test -race ./lib/...
go vet ./lib/...
go vet ./cmd/dkim2d/...
go vet ./cmd/dkim2-milter/...
go vet ./cmd/dkim2ctl/...
govulncheck ./lib/...
govulncheck ./cmd/dkim2d/...
govulncheck ./cmd/dkim2-milter/...
govulncheck ./cmd/dkim2ctl/...
golangci-lint run ./lib/... ./cmd/dkim2d/... ./cmd/dkim2-milter/... ./cmd/dkim2ctl/...
make check-openapi
gofmt -w lib cmd
```

The canonical local command should become:

```text
make guardrails
```

`make guardrails` should cover formatting, `go vet`, `golangci-lint`, unit
tests, race tests, OpenAPI stale-output checks, and vulnerability checks as the
corresponding targets become available.

CI should eventually include:

- Linux amd64.
- Linux arm64.
- macOS for development parity.
- Race tests.
- Fuzz smoke tests.
- Static analysis.
- Coverage report.
- Vector compatibility report.

## 15. Milestones and Rough Implementation Estimate

These estimates assume one very capable GPT-5.5-extra-high style coding agent
working with an experienced human reviewer and clear draft interpretation. They
are intentionally rough. One agent-day means a focused implementation day for
the AI agent including local tests, guardrails, and concise documentation, but
not long human review pauses, external standards discussion, or waiting on
interoperability partners.

The first committed planning estimate was deliberately conservative. After
measured sequential prompt-pack execution for M1 through M4, the coding-speed
baseline is much faster than originally assumed:

- M1 raw message model: 24m04s measured productive implementation time.
- M2 DKIM2 tag parsers: 44m17s measured productive implementation time.
- M3 canonicalization and hashes: 36m39s measured productive implementation
  time.
- M4 static-key signature verification: 50m20s measured productive
  implementation time, or 1h02m45s including spec and prompt-pack preparation.

M1 through M4 total 2h35m20s of measured productive implementation time. This
is enough evidence to replace the original day-scale estimates with
hour-scale estimates for library-internal slices. Adapter, daemon, DNS,
Milter, datasource, recipe, security-hardening, and interop milestones remain
less certain because they introduce external contracts, runtime behavior, or
draft-ambiguity risk not yet exercised by M1 through M4.

The estimates below remain reference-implementation estimates, not quick
prototype estimates. They include meaningful unit tests, negative tests,
security review, generated-code discipline, and enough documentation for later
maintainers to understand why behavior exists.

| Milestone | Scope | Calibrated agent work | Review and stabilization risk |
| --- | --- | ---: | --- |
| M0 - Project foundation | `go.work` repository structure, standalone library module, adapter modules, architecture document, AGENTS/POLICY, repo-local skills, Makefile guardrails, golangci-lint baseline, OpenAPI location, draft baseline | 2 to 4 hours | Low |
| M1 - Raw message model | RFC 5322 raw parser, header/body model, CRLF policy, immutable message representation, parser unit tests, malformed input tests | measured 24m04s; future similar slice 30 to 90 minutes | Medium |
| M2 - DKIM2 tag parsers | Message-Instance parser, DKIM2-Signature parser, strict tag-value handling, base64 behavior, structured errors, duplicate/unknown tag tests | measured 44m17s; future similar slice 45 to 120 minutes | Medium |
| M3 - Canonicalization and hashes | Header hash input, body hash input, signature input canonicalization, golden tests, byte-level debug helpers | measured 36m39s; future similar slice 45 to 120 minutes | High |
| M4 - Static-key signature verification | RSA-SHA256 and Ed25519-SHA256 verification with injected static keys, multi-signature behavior, timestamp checks, envelope checks, negative crypto vectors | measured 50m20s productive, 1h02m45s with spec/prompt prep; future similar slice 1 to 2 hours | High |
| M5 - MVP core verification | Library-only vertical slice: parse raw message, parse DKIM2 headers, validate numbering, canonicalize, hash, verify current Message-Instance and latest DKIM2-Signature with static keys, produce structured result, golden vectors, fuzz seeds, guardrails | 1 to 3 hours | High |
| M6 - DNS key resolver | TXT lookup, key record parser, resolver interface, fake resolver, key validation, cache policy, TEMPERROR/PERMERROR split, DNS failure tests | measured 3h11m08s; future similar slice 3 to 6 hours | Medium |
| M7 - Policy engine | Strict/permissive/testing modes, `donotmodify`, `donotexplode`, feedback flags, local decision model, action plan, policy/result separation tests | measured 2h35m33s prompt wall-clock, 2h42m32s elapsed; future similar slice 2 to 4 hours | Medium |
| M8 - Recipe application | Completed: strict JSON recipe parser, bounded immutable reconstruction, null-body state, previous-instance hash validation, resource abuse/fuzz/race tests, and draft-04 golden fixture | Exact total unavailable; retained prompt spans are recorded in the ignored timing ledger referenced by the durable M8 spec without inferring missing starts | High; completed with independent normative and architecture review |
| M9 - Recipe generation | Completed: deterministic inverse header/body planning, non-minimal compact decoded JSON, explicit policies, strict self-proof, and draft-versioned golden/fuzz/abuse/race/privacy evidence | Retained exact seven-slice prompt spans are recorded in the ignored timing ledger; active engineering time was not separately tracked | High; completed with independent normative and architecture review |
| M10 - Signing and revising | Completed: sealed revision verification, Message-Instance and DKIM2-Signature generation, opaque private-key callbacks, shared custody continuity, authority-bound fanout/release, next-domain transitions, public facade, and signing vectors | Retained exact prompt spans are recorded in the ignored timing ledger; missing starts remain unavailable rather than inferred | High; completed with independent normative and architecture review |
| M11 - Datasource abstraction and general providers | Completed: exact storage-neutral profile/policy contracts, immutable memory provider, confined flat-file provider with atomic fail-closed reload, opaque-handle signing bridge, LDAP/SQL design contracts, and parity/fuzz/race/privacy/dependency evidence | Exact nine-prompt wall-clock ledger is recorded in the ignored prompt pack; active engineering time was not separately tracked | High; completed with independent normative and architecture review |
| M12 - Replay store and Valkey provider | Completed: storage-neutral replay contracts, versioned privacy-preserving identities, bounded memory and disabled providers, exact Valkey first-seen behavior, fail-closed lifecycle and authority checks, and parity/fuzz/race/privacy/integration evidence | measured 8h47m27s before terminal closeout review; active engineering time was not separately retained for all prompts | High; completed with independent normative, security, architecture, and implementation review |
| M13 - OpenAPI daemon foundation | `dkim2d` Cobra/Viper config, typed validation, Fx composition, OpenAPI generated server boundary, `/healthz`, `/readyz`, `/v1/process`, request limits, structured errors | 4 to 10 hours | High |
| M14 - OpenAPI test client | `dkim2ctl` generated client, fixture runner, JSON output, daemon smoke tests, negative request fixtures, reproducible diagnostics | 2 to 5 hours | Medium |
| M15 - Observability foundation | `slog` provider, debug modules, OpenTelemetry tracing, Prometheus registry, low-cardinality label policy, secret-safe attributes, metrics endpoint, redaction tests | 3 to 8 hours | High |
| M16 - Milter adapter | SMTP context collection, EOM service call, action application, timeout behavior, fidelity metadata, MTA integration tests, fail-open/fail-closed tests | 5 to 12 hours | High |
| M17 - Exim adapter | Completed and Linux-qualified: source-linked `local_scan()` inbound adapter, daemon-backed sign/revise `transport_filter`, exact action/fidelity/evidence contracts, protected runtime and packaging validation, and 5 × 43 passing authenticated upstream/Debian/Ubuntu matrix cases with passing privacy verification | 4 to 10 agent-days | High; completed with candidate-bound evidence import |
| M18 - Test vectors and conformance suite | Implemented: digest-bound draft-versioned positive/negative/replay vectors, generated-client OpenAPI fixtures, portable Milter fixtures, real Postfix Docker qualification, deterministic CI reports, and a separate Linux Exim qualification producer. Portable reports never claim Exim execution; full reports fail closed without verified imported evidence bound to the current candidate | 4 to 12 hours | High |
| M19 - Security hardening | Implemented: closed first-party fuzz inventory, composable resource limits, whole-product logging/privacy review, repeated race tests, govulncheck, datasource/replay abuse, recipe bombs, OpenAPI abuse fixtures, Milter hostile-peer and real Postfix regression evidence, plus the candidate-bound Exim qualification capability consumed through full conformance | 5 to 14 hours | High |
| M20 - Packaging, container delivery, documentation, and operator guide | Reproducible Go 1.26 multi-stage Dockerfiles or Containerfiles for `dkim2d`, `dkim2-milter`, and `dkim2ctl`; non-root minimal runtime images; health checks; OCI metadata; multi-architecture build and release automation; image SBOM/provenance and vulnerability gates; example Compose deployment; API docs, architecture update, security/config/datasource/replay/observability guides, Milter and Exim deployment notes, rollback guidance, and examples | 1 to 3 agent-days | High |
| M21 - Interop and reference polish | External implementation comparison, draft issue log, final API cleanup, conformance report, release candidate | 1 to 3 days | Very high |
| M22 - LDAP and SQL datasource providers and legacy migration | RNS DKIM2 LDAP schema under `1.3.6.1.4.1.31612.1.7`, bounded read-only LDAP provider, transactionally consistent SQL provider, immutable generation publication, provider parity suites, schema/DDL delivery, secret-safe OpenDKIM bootstrap tooling, protected signer-registry import, fresh DNS publication proof, migration dry-run/rollback, and operator documentation | 2 to 6 agent-days | Very high |

Total rough implementation estimate:

- MVP core verification path without recipes, DNS, daemon, datasource providers,
  or Milter: 4 to 8 agent-hours including guardrails and vectors.
- Useful HTTP verification daemon with DNS, policy, OpenAPI, config, Fx
  composition, generated test client, and observability: 2 to 5 agent-days.
- Signing plus conservative revision support: 3 to 7 agent-days.
- Operational Milter with datasource/replay integration and strong tests: 5 to
  12 agent-days.
- Operational Exim adapter with datasource/replay integration, inbound
  `local_scan()`, outbound `transport_filter`, and distribution-baseline tests:
  4 to 10 agent-days.
- Operational LDAP/SQL providers and a protected legacy OpenDKIM migration:
  2 to 6 agent-days after the first public preview.
- Reference-quality implementation with vectors, fuzzing, security hardening,
  datasource providers, replay storage, observability, documentation, and
  interop work: 14 to 36 agent-days.

### 15.1 Stabilization And Real-Operation Budget

The calibrated milestone estimates above measure implementation throughput:
specification, prompt-pack execution, code, focused tests, fuzz smoke, local
guardrails, and concise documentation. They do not pretend that the first
completed implementation is release-final.

Real operation needs a separate stabilization budget on top of implementation:

- Beta cycles for realistic message corpora, real DNS behavior, daemon runtime
  configuration, datasource/replay behavior, Milter integration, and operator
  workflows.
- RC cycles for bug fixing after packaging, deployment, upgrade, rollback,
  logging, metrics, and interop feedback.
- Draft-follow-up work when DKIM2 or DKIM2 DNS text changes after vectors or
  implementation behavior already exist.
- Regression work from external test vectors, other implementations, MTAs,
  malformed-but-observed mail, and operational edge cases.
- Release engineering, changelogs, compatibility notes, migration notes,
  support diagnostics, and security review sign-off.

Plan stabilization independently from implementation. A practical first budget
is:

| Release scope | Implementation estimate | Additional stabilization budget |
| --- | ---: | ---: |
| Library MVP, no daemon or Milter | 4 to 8 agent-hours | 1 to 3 beta/RC days |
| HTTP verification daemon | 2 to 5 agent-days | 3 to 7 beta/RC days |
| Signing and revision support | 3 to 7 agent-days | 4 to 10 beta/RC days |
| Operational Milter path | 5 to 12 agent-days | 1 to 3 beta/RC weeks |
| Operational Exim path | 4 to 10 agent-days | 1 to 3 beta/RC weeks |
| Operational LDAP/SQL and legacy migration path | 2 to 6 agent-days | 1 to 3 beta/RC weeks |
| Reference-quality public release | 14 to 36 agent-days | 2 to 6 beta/RC weeks |

The stabilization budget should shrink only after repeated production-like
runs show low defect rates. It may grow if draft semantics change, if external
test vectors disagree with local interpretation, or if Milter fidelity and
operational replay/datasource behavior expose real-world edge cases.

The highest uncertainty is not Go coding speed. M1 through M4 show that
library-internal implementation with focused specs, prompt packs, and guardrails
is usually hour-scale. The highest remaining uncertainty is draft
interpretation around recipes, DNS/key-record behavior, Milter message
fidelity, Exim hook fidelity, generated service contracts, runtime integration,
and the lack of mature external DKIM2 test vectors.

## 16. Milestone Dependency Graph

```text
M0
 |
M1 --> M2 --> M3 --> M4 --> M5 MVP
                         |
                         +--> M6 DNS --> M7 Policy
                         |                |
                         |                +--> M13 OpenAPI daemon --> M14 test client
                         |                                      |          |
                         |                                      +----------+--> M15 observability
                         |
                         +--> M8 recipe apply --> M9 recipe generation --> M10 signing/revising
                                                    |                      |
                                                    +----------------------+
                                                                           |
M11 datasource --> M12 replay store --------------------------------------+
       |
       +-------------------------> M22 LDAP/SQL providers and migration
                                      ^
M13 daemon config/lifecycle ---------+
                                                                           |
M13/M14/M15/M10/M12 --------------------------------------------------> M16 Milter
                         |
                         +--------------------------------------------> M17 Exim

M18 vectors should grow continuously from M1 onward.
M19 security hardening should run continuously after M2 and becomes mandatory
before public reference releases.
M20 packaging and documentation should run continuously after M0, with final
runtime images gated on the daemon and adapter binaries they contain.
M21 library, daemon, and Milter interop starts once M13, M14, M16, and the M18
vector suite are useful. Exim compatibility is Linux-qualified through the
completed M17 five-row matrix and remains limited to its exact candidate-bound
evidence.
M22 starts after the M11 contracts and M13 daemon configuration/lifecycle are
stable. It remains after the first public preview and does not block the
flat-file-backed preview, M16, or M17.
M17 Exim starts after the daemon action contract, signing/revision behavior,
datasource/replay policy, observability, and release compatibility matrix are
stable enough to test against real Exim baselines.
```

## 17. Draft Baseline Risks

The current draft has unfinished or unstable areas:

- Architecture references are still marked `TBA`.
- EAI considerations are marked `TBA`.
- IANA considerations are marked `TBA`.
- Security considerations are marked `TBA`.
- Recipe details may still change.
- The DNS key draft and header draft may not evolve in lockstep.
- Implementers may discover ambiguous Milter and SMTP edge cases.
- Exim integration has separate hook and message-fidelity semantics from
  Milter integration.

The implementation should track these as explicit issues rather than burying
interpretation choices in code.

## 18. Planning Questions

### 18.1 Resolved Decisions

1. Public module namespace:
   The current library module path is `github.com/croessner/dkim2`, with command
   modules below `github.com/croessner/dkim2/cmd/`. A possible public target is a dedicated
   `github.com/go-dkim2/...` namespace. The reference library is likely to be
   published as `github.com/go-dkim2/libdkim2`; daemon, Milter, and test-client
   components should use analogous names under the same namespace if that
   organization/repository structure is created. This is not binding, is not
   the current module identity, and must be revisited before the first public
   release.
2. Daemon message input model:
   `dkim2d` accepts raw RFC 5322 message input for DKIM2 processing. The stable
   API does not include a structured Milter-specific input model, and no later
   Milter-only API change is planned by default. Milter adapters must submit raw
   RFC 5322 input to the daemon; any callback reconstruction or fidelity
   limitation is handled in the adapter layer and its diagnostics.
3. Milter failure policy:
   The reference Milter defaults to fail-closed or tempfail for daemon
   unavailability, invalid daemon responses, unacceptable raw-message fidelity,
   and ambiguous DKIM2 processing state. A fail-open mode may exist for pilot or
   deployment compatibility, but only as an explicit configuration that is
   visible in effective config, logs, metrics, and operator documentation.
4. Recipe conformance and minimization:
   The reference implementation must fully support draft-conformant recipe
   parsing, validation, application, generation, the `b:null` body-unavailable
   state, previous-message reconstruction, and hash verification. Generated
   recipes must be
   correct, deterministic, bounded, and reproducible, but they are not required
   to be minimal. Recipe minimization is deferred as an optimization milestone
   and must not affect verification correctness.
5. DNSSEC handling:
   DNSSEC is not modeled as part of DKIM2 protocol conformance because the
   current DKIM2 specification and DKIM2 DNS draft define no DNSSEC
   MUST/SHOULD/MAY behavior. DNSSEC validation state may be exposed only as
   optional, non-normative resolver diagnostics when a resolver can provide it.
   It must not affect default DKIM2 verification results, output states,
   `Authentication-Results` style output, or policy. This decision must be
   revisited if later drafts add DNSSEC guidance, especially when the currently
   open Security Considerations section is completed.
6. EAI handling before the draft is complete:
   EAI/SMTPUTF8-relevant message and envelope values are handled in a
   byte-preserving manner until the DKIM2 EAI section defines additional
   semantics. The implementation must not invent Unicode normalization, IDNA
   mapping, or local-part normalization rules. Tests should prove that
   EAI-capable inputs are not corrupted, not that non-draft EAI semantics are
   enforced.
7. `Authentication-Results` output:
   `dkim2d` may optionally produce action-plan entries for adding
   `Authentication-Results` header fields. This output is configured local
   trust-boundary reporting and is not part of DKIM2 protocol verification
   state. It must be generated by a strict formatter and must not include raw
   errors, secrets, protected values, raw recipient lists, or unbounded text.
8. First public preview datasource providers:
   M11 provides an immutable in-memory general datasource for tests, examples,
   and static deployments plus a confined flat-file general datasource for
   later daemon use. Both implement the same exact storage-neutral contracts.
   LDAP and SQL providers are deferred to M22 after the first public preview.
   Their durable mapping, consistency, paging, cancellation, redaction, RNS
   LDAP OID allocation, and legacy OpenDKIM bootstrap contracts are
   architecture-only until M22 and introduce no drivers into the library.
   Replay storage is tracked separately: Valkey is the first production replay
   store backend, behind a storage-neutral replay interface. All datasource and
   replay interfaces must be designed so providers can be added without
   changing protocol packages or public domain contracts.
9. Storage-backed replay detection:
   Storage-backed replay detection is part of the first daemon release as an
   explicit policy-capable feature. It must use an open-source storage backend,
   privacy-preserving replay keys, configurable retention windows, bounded error
   handling, and clear policy semantics. It is implemented in daemon/service
   layers rather than as hidden protocol-core behavior.
10. Default replay store backend:
    Valkey is the default production replay-store backend. The first secure
    implementation supports one directly addressed standalone primary only;
    Valkey cluster production remains deferred until an owned audited routing
    boundary prevents redirects or topology refresh from selecting an unaudited
    authority. The architecture still requires a storage-neutral replay-store
    interface so later PostgreSQL, Cassandra-compatible, LDAP-adjacent, or
    other open-source providers can be added without changing protocol
    packages, public result semantics, OpenAPI contracts, or Milter adapter
    behavior.
11. OpenAPI generator:
    The first generated server/client artifacts use `oapi-codegen` pinned to
    `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1`.
    Generated artifacts are committed, reviewed, and checked by guardrails for
    stale output. Generator upgrades are explicit dependency changes, not
    implicit `latest` drift.
12. `dkim2ctl` initial role:
    `dkim2ctl` starts as an OpenAPI-backed test and conformance client with
    fixture execution, daemon smoke checks, negative API request tests, stable
    JSON output, and rich transport diagnostics. It may later become the
    operator CLI, but early commands must avoid privileged mutation APIs and the
    command layout must reserve room for future authenticated, authorized,
    audited, and redacted operational subcommands.
13. DKIM2 telemetry attributes:
    DKIM2 telemetry uses a tiered allowlist. Default logs, traces, and metrics
    carry only low-cardinality operational facts. Richer diagnostics require
    explicit debug modules and may use only bounded, redacted, bucketed, or
    deployment-local keyed-hash values. Prometheus labels remain strictly
    low-cardinality and must not include raw or hashed identity values.
14. Exim adapter compatibility:
    Exim integration is a separate adapter family from Milter integration. The
    compatibility matrix is refreshed for each DKIM2 release and covers the
    current upstream Exim release plus the Exim package versions from the most
    widely deployed server distributions that published a new LTS, stable, or
    enterprise long-term release in the previous 12 months, provided Exim is in
    the distribution's official supported package repositories. Unsupported
    third-party repositories and vendor-unmaintained packages do not define
    support targets.
15. RNS LDAP schema and legacy OpenDKIM migration:
    DKIM2 owns the dedicated RNS LDAP subtree
    `1.3.6.1.4.1.31612.1.7`, with `.1` for attributes and `.2` for object
    classes. The historical `DKIM` and `rnsMSDKIM` schemas are never runtime
    compatibility aliases. M22 may bootstrap a new immutable generation from
    validated active OpenDKIM RSA/Ed25519 pairs through a separate secret-safe
    migration command. Private keys move only into the signing registry behind
    new opaque handles; DKIM AUIDs and LDAP timestamps do not become DKIM2
    fields. Legacy lookup-domain/signing-domain disagreement is rejected for
    automatic migration because the datasource contract has exact domain
    identity and no alias or fallback semantics.

### 18.2 Remaining Open Questions

No remaining open architecture start questions are tracked in this version.
Later draft changes, implementation findings, interoperability tests, or
security review may open new questions without changing the document version
while this remains an initial `0.1.0-draft`.

## 19. First Implementation Recommendation

The first implementation target should be the MVP core verification path. That
means a library-only vertical slice that proves the DKIM2 protocol core before
adding daemon, datasource, observability, Milter, or recipe complexity.

Implementation order:

1. Build `lib/internal/rawmsg`.
2. Build `lib/internal/instance` and `lib/internal/signature` parsers.
3. Build `lib/internal/canonical` with golden tests.
4. Build static-key signature verification without DNS.
5. Build structured verification results and current-message checks.
6. Add draft-versioned MVP golden vectors.
7. Add fuzz seeds and first resource-limit tests.
8. Run `make guardrails` as the MVP quality gate.

This order keeps the project anchored in deterministic local tests before
network behavior, datasource behavior, observability exporters, recipe
generation, or Milter behavior complicates the feedback loop.
