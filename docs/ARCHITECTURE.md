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
| Baseline specification | `draft-ietf-dkim-dkim2-spec-02`, dated 2026-05-17 |
| Related specification | `draft-chuang-dkim2-dns-04`, dated 2026-03-18 |
| Baseline status check | Datatracker checked 2026-06-24; DKIM2 spec latest is `-02`, DKIM2 DNS latest is `-04` |
| Change control | While this document is still `0.1.0-draft`, startup decisions may be added without a version bump; after the first committed planning baseline, material architecture changes require a revision-history entry and may require a new version |
| Supersedes | None |
| Next planned revision | After implementation slice 1, or when the DKIM2 draft changes materially |

## Revision History

| Version | Date | Author | Notes |
| --- | --- | --- | --- |
| 0.1.0-draft | 2026-06-24 | Christian Roessner / Codex | Initial architecture baseline. Version intentionally remains at 0.1.0 while early project decisions are still being settled. |

## 1. Purpose

This document defines the first architecture baseline for a Go reference
implementation of DKIM2. The immediate goal is not to freeze a final public API.
The goal is to establish precise implementation boundaries before protocol code
is written.

The design assumes the current DKIM2 draft as the working source of truth:

- `draft-ietf-dkim-dkim2-spec-02`
- `draft-chuang-dkim2-dns-04`

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

- `lib`: the DKIM2 reference library. The current module path is a local
  placeholder. The intended public namespace is expected to be in the
  `github.com/go-dkim2/...` family, with `github.com/go-dkim2/libdkim2` as the
  likely library path.
- `cmd/dkim2d`: an HTTP/JSON service module.
- `cmd/dkim2-milter`: a Milter adapter module.
- `cmd/dkim2ctl`: an OpenAPI-generated client and test-client module.

The initial adapters are:

- `dkim2d`: an HTTP/JSON service.
- `dkim2-milter`: a Milter adapter that calls `dkim2d` at EOM time.
- `dkim2ctl`: an OpenAPI-backed CLI/test client for vectors, reproducible
  diagnostics, and daemon integration testing. It may later grow operator
  commands, but the initial role is test and conformance work.

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
              likely future path: github.com/go-dkim2/libdkim2
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
- The library should expose a public facade at its module root. The likely
  future public path is `github.com/go-dkim2/libdkim2`.
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
- Strict coverage of draft-specific excluded headers.
- Stable sorting and duplicate-header ordering rules.

Design notes:

- Canonicalization must be deterministic and golden-test-heavy.
- There should be no hidden dependency on map iteration order.
- The code should expose intermediate canonical bytes in test-only helpers or
  explicit debug APIs.

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

- Parse base64 JSON recipes.
- Validate the recipe schema.
- Apply recipes to reconstruct previous message instances.
- Generate recipes from before/after message states.
- Bound recipe expansion to prevent resource abuse.

Design notes:

- Recipe generation must be draft-conformant, deterministic, bounded, and
  reproducible, but generated recipes are not required to be minimal.
- A later optimization phase can make recipes smaller without changing
  verification semantics or the public model.
- Null recipes must be represented explicitly because they have policy meaning.

### 5.6 `lib/internal/signature`

Owns `DKIM2-Signature` parsing, validation, formatting, and signature input
assembly.

Responsibilities:

- Parse required tags: `i=`, `m=`, `t=`, `mf=`, `rt=`, `d=`, `s=`.
- Parse optional tags: `n=`, `f=`, extension tags.
- Validate signature sequence numbers and gaps.
- Build incomplete signature fields with empty signature values for signing.
- Verify chain-of-custody input at the header level.
- Format signatures without introducing unsafe folding or injection.

Important invariants:

- `i=1` is the origin signature.
- Gaps make the message unsigned per the draft.
- The highest `i=` signature must match the current SMTP envelope.
- The signature only signs DKIM2 protocol fields, while the message content is
  covered through Message-Instance hashes.

### 5.7 `lib/internal/keyresolver`

Owns DNS key lookup and DKIM2 key record parsing.

Responsibilities:

- Resolve `selector._domainkey.domain`.
- Parse and validate DKIM2-compatible DNS TXT key records.
- Enforce one usable record per selector.
- Distinguish temporary DNS failures from permanent key absence.
- Cache results only within safe TTL and policy boundaries.
- Support deterministic test resolvers.

Design notes:

- The resolver interface must be injectable from day one.
- DNS timeouts must be controlled by context.
- Key revocation must be represented as a distinct permanent state.

### 5.8 `lib/internal/datasource`

Defines storage-facing abstractions needed by DKIM2 services without binding
the reference library to LDAP, SQL, flat files, or a specific secret store.

Responsibilities:

- Define context-aware interfaces for retrieving signing profiles, selector
  policy, private-key handles, domain policy, replay metadata, and tenant-level
  defaults.
- Keep provider-specific types out of protocol packages.
- Separate read-only protocol lookup paths from operational mutation paths.
- Represent unavailable, ambiguous, malformed, and unauthorized data as typed
  errors.
- Support deterministic fake sources for unit and vector tests.

Design notes:

- The library should define contracts; concrete LDAP, SQL, and flat-file
  providers belong in service modules or explicit provider packages.
- Private key material should be exposed through signing handles or callback
  interfaces, not raw byte slices, unless a test fixture explicitly requires
  raw key material.
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

- Map protocol results to accept/reject/tempfail/defer decisions.
- Evaluate `donotmodify`, `donotexplode`, and `feedback` flags.
- Allow deployments to choose strict, permissive, and testing modes.
- Keep policy separate from cryptographic correctness.

Design notes:

- A message can be cryptographically valid and still fail local policy.
- A message can be cryptographically invalid but still be accepted by a
  permissive deployment policy.
- The result model must preserve that distinction.

### 5.11 `lib/internal/service`

Coordinates domain packages into use cases.

Core services:

- `Verifier`
- `Signer`
- `Reviser`
- `ActionPlanner`

Example:

```go
type Verifier struct {
    Keys   keyresolver.Resolver
    Clock  Clock
    Policy policy.Evaluator
}
```

The service layer should be where end-to-end workflows live. Lower packages
should stay focused on one protocol concern.

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

The current envelope is mandatory for inbound DKIM2 verification because the
latest `DKIM2-Signature` must match the actual `MAIL FROM` and `RCPT TO` values.

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
  "draft": "draft-ietf-dkim-dkim2-spec-02",
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

`dkim2d` may optionally return action-plan entries that add
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

The implementation will likely need operational data beyond DNS:

- Signing profiles.
- Selector-to-key mapping.
- Private-key handles or key references.
- Domain and tenant policy.
- Optional replay or seen-message metadata.
- Optional feedback routing policy.
- Compatibility or rollout flags.

This should be modeled as datasource interfaces, not as a concrete database
dependency in the protocol core.

General datasource provider classes:

- In-memory provider for tests and examples.
- Flat-file provider for the first public preview.
- LDAP provider after the first public preview.
- SQL provider after the first public preview.

Replay storage is modeled separately in the replay-store interface. Valkey is
the default production replay backend, but it must not become the general
datasource abstraction or leak into protocol packages.

Provider rules:

- Operations are context-aware and bounded.
- Provider-specific identifiers do not leak into protocol packages.
- Secrets are returned as protected values or signing handles.
- Missing required data fails closed.
- Ambiguous data is a distinct error, not a silent fallback.
- Read-only lookup paths are separated from mutation paths.
- Unit tests use fake providers; integration tests may use real provider
  processes.

### 7.5 Replay Store Model

The first daemon release includes datasource-backed replay detection as an
explicit policy feature. This goes beyond the message-local chain and envelope
checks by remembering bounded replay keys for a configurable retention window.

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
- Bounded error classification for unavailable, degraded, ambiguous, and
  inconsistent store state.

Likely replay key material:

- Highest DKIM2 signature identity.
- Message-Instance hash material.
- Envelope recipient scope, represented by privacy-preserving digests.
- Optional signer nonce when present.
- Draft version and algorithm version for forward compatibility.

The replay store must be separated from the protocol library. The library
defines replay-check interfaces and result types; `dkim2d` wires concrete
storage providers and local policy.

The default production replay backend should be Valkey. Valkey gives the
reference implementation a permissive open-source baseline, low-latency
key-value operations, native expiry, and an atomic first-seen operation shaped
like `SET replay-key replay-value NX EX retention-seconds`. The implementation
must not treat Valkey as a protocol dependency. It is the first production
provider behind a replay-store interface.

Initial replay provider set:

- `memory`: deterministic test and example provider.
- `valkey`: default production provider for scalable deployments.
- `noop`: explicit disabled provider for deployments that choose not to run
  replay detection.

Future providers may include PostgreSQL, LDAP-adjacent operational stores,
Cassandra-compatible stores, or other open-source backends. Adding a provider
must not change protocol packages, public result semantics, OpenAPI response
contracts, or Milter adapter behavior.

The replay-store interface should model intent, not Valkey commands:

```go
type ReplayStore interface {
    CheckAndRemember(ctx context.Context, key ReplayKey, retention time.Duration) (ReplayCheck, error)
}
```

`ReplayCheck` should distinguish first-seen, replayed, unavailable, degraded,
ambiguous, inconsistent, and misconfigured states. Local policy decides how
those states map to accept, reject, tempfail, or observe-only behavior.

Valkey-specific design notes:

- Use a single-key first implementation so cluster slot placement remains
  straightforward.
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

## 9. Verification Flow

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

## 10. Signing and Revising Flow

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

## 11. Security Architecture

### 11.1 Input Limits

Default limits should exist before public use:

- Maximum request body size.
- Maximum raw message size.
- Maximum header block size.
- Maximum number of headers.
- Maximum single header field length.
- Maximum body line length used for recipe indexing.
- Maximum number of recipients in `rt=`.
- Maximum decoded recipe size.
- Maximum reconstructed message size.
- Maximum DNS lookups per message.

Limits should be configurable, but unsafe values should require explicit config.

### 11.2 Cryptography

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

### 11.3 DNS

DNS resolver behavior must distinguish:

- Temporary lookup failure.
- Permanent NXDOMAIN or missing record.
- Multiple TXT records.
- Malformed record.
- Revoked key.
- Algorithm mismatch.

The resolver should support context cancellation and cache control.

### 11.4 Error Handling

Errors should be typed:

- `TEMPERROR`
- `PERMERROR`
- `FAIL`
- `POLICY`
- `INTERNAL`

The wire API can include human text, but tests should assert structured codes.

### 11.5 Logging

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

## 12. Testing Strategy

### 12.1 Unit Tests

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

### 12.2 Golden Tests

Golden vectors should store:

- Raw input message.
- SMTP envelope.
- Expected canonical header hash input.
- Expected canonical body hash input.
- Expected Message-Instance field.
- Expected DKIM2-Signature input.
- Expected verification result.

Golden files must name the draft version they target.

### 12.3 Fuzz Tests

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

### 12.4 Integration Tests

Integration layers:

- Core library only with static resolver.
- HTTP/JSON daemon with synthetic requests.
- OpenAPI-generated client against `dkim2d`.
- Milter adapter against a test MTA.
- End-to-end signing and verification through SMTP.

The first public confidence point should be vector-driven core verification,
not Milter success.

### 12.5 Security Tests

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

### 12.6 Reproducer and Unit-Driven Development

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

## 13. Development Quality Gates

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

## 14. Milestones and Rough Implementation Estimate

These estimates assume one very capable GPT-5.5-extra-high style coding agent
working with an experienced human reviewer and clear draft interpretation. They
are intentionally rough. One agent-day means a focused implementation day for
the AI agent including local tests, guardrails, and concise documentation, but
not long human review pauses, external standards discussion, or waiting on
interoperability partners.

The estimates are deliberately reference-implementation estimates, not quick
prototype estimates. They include meaningful unit tests, negative tests,
security review, generated-code discipline, and enough documentation for later
maintainers to understand why behavior exists.

| Milestone | Scope | Estimated agent work | Review and stabilization risk |
| --- | --- | ---: | --- |
| M0 - Project foundation | `go.work` repository structure, standalone library module, adapter modules, architecture document, AGENTS/POLICY, repo-local skills, Makefile guardrails, golangci-lint baseline, OpenAPI location, draft baseline | 1 to 2 days | Low |
| M1 - Raw message model | RFC 5322 raw parser, header/body model, CRLF policy, immutable message representation, parser unit tests, malformed input tests | 3 to 5 days | Medium |
| M2 - DKIM2 tag parsers | Message-Instance parser, DKIM2-Signature parser, strict tag-value handling, base64 behavior, structured errors, duplicate/unknown tag tests | 3 to 5 days | Medium |
| M3 - Canonicalization and hashes | Header hash input, body hash input, signature input canonicalization, golden tests, byte-level debug helpers | 5 to 9 days | High |
| M4 - Static-key signature verification | RSA-SHA256 and Ed25519-SHA256 verification with injected static keys, multi-signature behavior, timestamp checks, envelope checks, negative crypto vectors | 4 to 8 days | High |
| M5 - MVP core verification | Library-only vertical slice: parse raw message, parse DKIM2 headers, validate numbering, canonicalize, hash, verify current Message-Instance and latest DKIM2-Signature with static keys, produce structured result, golden vectors, fuzz seeds, guardrails | 5 to 10 days | High |
| M6 - DNS key resolver | TXT lookup, key record parser, resolver interface, fake resolver, key validation, cache policy, TEMPERROR/PERMERROR split, DNS failure tests | 3 to 6 days | Medium |
| M7 - Policy engine | Strict/permissive/testing modes, `donotmodify`, `donotexplode`, feedback flags, local decision model, action plan, policy/result separation tests | 3 to 5 days | Medium |
| M8 - Recipe application | JSON recipe parser, bounded reconstruction, null recipes, previous-instance hash validation, resource abuse tests | 6 to 12 days | High |
| M9 - Recipe generation | Conservative diff strategy for headers and body, deterministic output, revision tests, non-minimal but reproducible recipe guarantees | 8 to 16 days | High |
| M10 - Signing and revising | Message-Instance generation, DKIM2-Signature generation, private key abstraction, chain continuity, signing fixtures | 6 to 12 days | High |
| M11 - Datasource abstraction and general providers | Domain datasource interfaces, in-memory provider, flat-file provider, signing profile lookup, private-key handle model, LDAP/SQL design stubs, provider-state tests | 5 to 10 days | High |
| M12 - Replay store and Valkey provider | Storage-neutral replay interface, in-memory replay provider, Valkey provider, TTL/first-seen behavior, privacy-preserving keys, degraded-store policy tests | 5 to 10 days | High |
| M13 - OpenAPI daemon foundation | `dkim2d` Cobra/Viper config, typed validation, Fx composition, OpenAPI generated server boundary, `/healthz`, `/readyz`, `/v1/process`, request limits, structured errors | 6 to 12 days | High |
| M14 - OpenAPI test client | `dkim2ctl` generated client, fixture runner, JSON output, daemon smoke tests, negative request fixtures, reproducible diagnostics | 4 to 8 days | Medium |
| M15 - Observability foundation | `slog` provider, debug modules, OpenTelemetry tracing, Prometheus registry, low-cardinality label policy, secret-safe attributes, metrics endpoint, redaction tests | 5 to 10 days | High |
| M16 - Milter adapter | SMTP context collection, EOM service call, action application, timeout behavior, fidelity metadata, MTA integration tests, fail-open/fail-closed tests | 6 to 12 days | High |
| M17 - Test vectors and conformance suite | Draft-versioned vectors, negative vectors, replay cases, OpenAPI fixtures, Milter fixtures, CI vector report, public conformance notes | 8 to 18 days | High |
| M18 - Security hardening | Fuzzing, resource limits, logging review, race tests, govulncheck, datasource abuse cases, recipe bombs, OpenAPI abuse fixtures, Milter abuse fixtures | 8 to 18 days | High |
| M19 - Documentation and operator guide | API docs, architecture update, security guide, config reference, datasource guide, replay-store guide, observability guide, milter deployment notes, examples | 5 to 10 days | Medium |
| M20 - Interop and reference polish | External implementation comparison, draft issue log, final API cleanup, conformance report, release candidate | 10 to 25 days | Very high |

Total rough implementation estimate:

- MVP core verification path without recipes, DNS, daemon, datasource providers,
  or Milter: 21 to 39 agent-days including guardrails and vectors.
- Useful HTTP verification daemon with DNS, policy, OpenAPI, config, Fx
  composition, generated test client, and observability: 42 to 80 agent-days.
- Signing plus conservative revision support: 50 to 95 agent-days.
- Operational Milter with datasource/replay integration and strong tests: 75 to
  150 agent-days.
- Reference-quality implementation with vectors, fuzzing, security hardening,
  datasource providers, replay storage, observability, documentation, and
  interop work: 110 to 220 agent-days.

The highest uncertainty is not Go coding speed. The highest uncertainty is
draft interpretation around recipes, exact canonicalization edge cases, Milter
message fidelity, and the lack of mature external DKIM2 test vectors.

## 15. Milestone Dependency Graph

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
M13/M14/M15/M10/M12 --------------------------------------------------> M16 Milter

M17 vectors should grow continuously from M1 onward.
M18 security hardening should run continuously after M2 and becomes mandatory
before public reference releases.
M19 documentation should run continuously after M0.
M20 interop starts once M13, M14, M16, and the M17 vector suite are useful.
```

## 16. Draft Baseline Risks

The current draft has unfinished or unstable areas:

- Architecture references are still marked `TBA`.
- EAI considerations are marked `TBA`.
- IANA considerations are marked `TBA`.
- Security considerations are marked `TBA`.
- Recipe details may still change.
- The DNS key draft and header draft may not evolve in lockstep.
- Implementers may discover ambiguous Milter and SMTP edge cases.

The implementation should track these as explicit issues rather than burying
interpretation choices in code.

## 17. Planning Questions

### 17.1 Resolved Decisions

1. Public module namespace:
   The current local module paths remain placeholders while the project is still
   in early planning. The preferred public target is a dedicated
   `github.com/go-dkim2/...` namespace. The reference library is likely to be
   published as `github.com/go-dkim2/libdkim2`; daemon, Milter, and test-client
   components should use analogous names under the same namespace if that
   organization/repository structure is created. This is not yet binding and
   must be revisited before the first public release.
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
   parsing, validation, application, generation, null recipes, reconstruction of
   previous message instances, and hash verification. Generated recipes must be
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
   The first public preview requires only an in-memory general datasource for
   tests and examples plus a flat-file general datasource for real daemon use.
   LDAP and SQL providers are deferred until after the first public preview.
   Replay storage is tracked separately: Valkey is the first production replay
   store backend, behind a storage-neutral replay interface. All datasource and
   replay interfaces must be designed so providers can be added without
   changing protocol packages or public domain contracts.
9. Datasource-backed replay detection:
   Datasource-backed replay detection is part of the first daemon release as an
   explicit policy-capable feature. It must use an open-source storage backend,
   privacy-preserving replay keys, configurable retention windows, bounded error
   handling, and clear policy semantics. It is implemented in daemon/service
   layers rather than as hidden protocol-core behavior.
10. Default replay store backend:
    Valkey is the default production replay-store backend for scalable
    deployments. The architecture still requires a storage-neutral replay-store
    interface so later PostgreSQL, Cassandra-compatible, LDAP-adjacent, or other
    open-source providers can be added without changing protocol packages,
    public result semantics, OpenAPI contracts, or Milter adapter behavior.
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

### 17.2 Remaining Open Questions

No remaining open architecture start questions are tracked in this version.
Later draft changes, implementation findings, interoperability tests, or
security review may open new questions without changing the document version
while this remains an initial `0.1.0-draft`.

## 18. First Implementation Recommendation

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
