# Delivery-Status Evidence and Signing

Status: M25 implemented; outgoing initial DSN signing is enabled only through
the dedicated daemon and library boundary.

M25 defines a bounded, byte-preserving implementation of the Draft-04 Section
12 delivery-status-notification (DSN) initial-signing boundary. The originator
Milter continues to tempfail every null reverse-path. The follow-on
`postfix_dsn` mode is a distinct qualified source and remains undeployable
until the corresponding Postfix patch and harness are complete.

The follow-on Postfix-specific adapter contract is defined in
[`postfix-dsn-evidence.md`](postfix-dsn-evidence.md). It deliberately retains
the default null-sender rejection until the Postfix patch and its qualification
evidence are complete.

## Source Documents

This specification is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/specs/openapi/dkim2d.yaml`
- `draft-ietf-dkim-dkim2-spec-04`, Sections 12 through 12.1.2
- RFC 3462 and RFC 3464
- `docs/specs/implementation/milter-adapter.md`
- `docs/specs/implementation/signing-and-revision.md`
- `docs/specs/implementation/openapi-test-client.md`
- `Makefile`

If these sources disagree, implementation stops until the durable authority is
reconciled. The active protocol baseline remains
`draft-ietf-dkim-dkim2-spec-04`.

## Original Gap

The library treats `<>` as a valid generic SMTP reverse-path and can perform
the low-level DKIM2 envelope comparison. It has no RFC 3462 parser or DSN
evidence model. The daemon's ordinary `/v1/sign` request similarly accepts a
generic message, SMTP envelope, and signing context without DSN evidence. The
originator Milter currently prevents this path from being reached by tempfailing
all null senders.

That temporary Milter restriction is safe, but it is not DSN support. A
trusted DSN signer must derive all required evidence from exact message bytes,
the current outer envelope, and an independently supplied original SMTP
envelope. It must never trust a caller-supplied boolean such as `is_dsn`, an
SMTP HELO name, an arbitrary header, a tenant default, a wildcard, or a
configured DSN domain alone.

## Goal

The product provides a separate, locally authorized DSN path that:

1. accepts only an outer SMTP reverse-path `<>` and one outer recipient;
2. derives DSN structure and embedded-message evidence from bounded raw bytes;
3. requires a top-level `multipart/report` with exactly three parts: human
   text, `message/delivery-status`, and either `message/rfc822` or
   `text/rfc822-headers`;
4. validates the embedded original's relevant DKIM2 fields before any profile
   or private-key access;
5. proves the Draft-04 Section 12.1.2 local-system and recipient-alignment
   conditions from a daemon-owned local identity and exact observed envelope
   evidence;
6. signs only the validated outer DSN using a dedicated datasource policy and
   route capability; and
7. exposes the flow to `dkim2ctl` exclusively through generated OpenAPI DTOs
   and draft-versioned fixtures.

The ordinary originator and revision APIs must reject a null reverse-path.
The generic low-level verifier remains able to evaluate a DKIM2 signature whose
current `mf=` is `<>`; DSN semantic conclusions belong exclusively to the new
DSN boundary.

## Scope

Implemented in M25:

- bounded RFC 3462/RFC 3464 DSN structure parsing from exact bytes;
- generic null-path rejection in ordinary library and daemon signing
  operations;
- Draft-04 Section 12.1 embedded-original verification and Section 12.1.2
  local identity/recipient alignment for outgoing initial DSN signing;
- public library evidence and purpose-specific signing facades without service
  dependencies;
- a daemon-owned `delivery_status` profile use, route ticket, local identity,
  and distinct protected capability;
- `POST /v1/dsn/sign`, generated server/client artifacts, and generated-client
  `dkim2ctl` DSN fixtures; and
- focused parser, evidence, capability-isolation, daemon, client, privacy,
  race, and adversarial regression coverage.

Out of scope:

- Milter DSN acceptance or Milter callback trust changes;
- DSN propagation and the Draft-04 Section 12.1.1 original-message rebuild;
- arbitrary MIME support beyond the closed DSN structure;
- SMTP transmission, queueing, DSN generation policy, or delivery retry;
- recipient groups, Bcc disclosure, generic caller attestation, and protocol
  behavior outside the Draft-04 baseline.

## Protocol and Local Semantics

### Evidence

The DSN library package owns immutable parsed evidence. It preserves raw input
bytes and validates MIME framing itself; it does not use a lossy map-based mail
parser or a general multipart convenience API as semantic authority. It bounds
the outer message, header lines, MIME depth, part count, boundary length, and
embedded-message bytes before allocating or invoking DNS/key providers.

For a complete `message/rfc822` third part, the embedded message's relevant
DKIM2 signatures and Message-Instances are verified from exact bytes. For a
`text/rfc822-headers` third part, only the Draft-allowed header evidence is
available; absence of body evidence is explicit and never silently treated as
a complete-message verification.

The initial local policy is stricter than the draft's receipt-time SHOULD:
insufficient, malformed, unverifiable, or ambiguous evidence cannot authorize
signing. A permanent DSN/evidence fault produces no output fields and a
permanent result. A typed transient DNS/key or context failure produces no
output fields and a temporary result.

### Alignment and Local Identity

The outer DSN signing domain must have a daemon-owned delivery-status policy.
It may not fall back to an originator profile. The embedded highest signature
must verify, must have a non-null `mf=`, and its `rt=` recipient must match the
outer DSN signing identity according to one explicit local alignment rule.
Until the draft specifies a DSN-specific alignment algorithm, M25 uses exact
canonical ASCII DNS-domain equality for this relationship. It does not reuse
the relaxed ordinary `d=`/`mf=` alignment rule by implication.

The daemon independently supplies the original observed SMTP envelope. The
evidence gate proves that the embedded highest signature was generated by the
receiving system using the configured local identity and exact original
envelope. No header, route, HELO, suffix, tenant default, or caller-provided
claim substitutes for that proof.

### API Shape

`POST /v1/dsn/sign` validates an outgoing DSN and returns only a completed
outer Message-Instance and DKIM2-Signature action plan on success. Its request
carries raw outer message bytes, an exact outer `<>` envelope with exactly one
recipient, an independently observed original SMTP envelope, and a signing
context. It contains no caller-derived DSN validity, alignment, identity, or
verification fields. The route requires the distinct
`X-DKIM2-DSN-Sign-Capability` capability and cannot use the ordinary sign or
revise capability.

Received-DSN validation and DSN propagation remain intentionally deferred.
They need a separately designed, evidence-bearing receive-time boundary rather
than a structural `process` endpoint or a caller attestation.

`/v1/sign` and `/v1/revise` now reject `smtp.mail_from == "<>"` at the HTTP
mapper and daemon-owned domain boundary. The generated client and test client
must use the completed DSN DTOs and route methods; they must not construct a
parallel REST model.

## Package Boundaries

- `lib/internal/dsn`: owns byte-preserving DSN framing, bounded immutable
  evidence, and typed DSN parse/evidence failures.
- `lib`: owns narrow public DSN request/result facades and purpose-specific
  signing/verification methods. It imports no daemon, OpenAPI, Milter, or
  datasource implementation dependencies.
- `cmd/dkim2d/internal/app`: owns DSN operation orchestration, local identity
  injection, policy/profile use, and result mapping.
- `cmd/dkim2d/internal/httpjson`: owns generated DTO mapping, capability
  routing, request bounds, and HTTP mapping only.
- `cmd/dkim2d/internal/signingstore` and datasource providers: own the
  explicit `delivery_status` profile use, without originator fallback.
- `cmd/dkim2ctl`: owns only generated-client fixture and stable-output support.
- `cmd/dkim2-milter`: remains unchanged except mechanical generated interface
  conformance; it keeps the null-sender tempfail.

## Security and Privacy

- Every ambiguous DSN, nested message, identity, recipient, profile, key, or
  route state fails closed before signing.
- Raw DSN bytes, embedded messages, mailbox values, recipients, message IDs,
  signatures, route capabilities, private keys, and provider data never enter
  errors, logs, traces, metrics, REST output, CLI output, or test diagnostics.
- DSN errors are typed, bounded, deterministic, and content-free.
- Evidence and request accessors return defensive copies. No partial fields
  may escape after cancellation, provider failure, or rejected evidence.
- Metric labels may contain only existing low-cardinality operation/result
  classes. They may not contain DSN-derived identifiers or values.

## Delivery Shape

1. Freeze Draft/RFC evidence, local alignment interpretation, contracts,
   limits, typed errors, and public-library seams with reproducer tests.
2. Implement byte-preserving DSN framing and embedded evidence in `lib`.
3. Add daemon policy/identity ownership and separate DSN operations; make
   generic null-path signing unavailable.
4. Change OpenAPI first, regenerate all server/client artifacts, and map the
   generated DSN DTOs at HTTP boundaries.
5. Extend `dkim2ctl` with separate DSN capabilities, fixture kinds, stable
   projections, and public-socket integration coverage.
6. Run adversarial, privacy, race, generated-output, conformance, and full
   guardrail evidence followed by independent review.

## Required Tests

Unit tests:

- valid three-part DSNs with complete-original and headers-only third parts;
- malformed report type, wrong part count/order/type, duplicate or conflicting
  content types, boundary/line/size/depth abuse, and malformed embedded input;
- non-null outer sender, empty or multiple recipient, embedded null `mf=`,
  alignment mismatch, non-local embedded origin, and unverified current hash;
- typed temporary key/DNS and cancellation behavior before profile/key access;
- immutability, redaction, fuzz, and race coverage.

Daemon and client tests:

- `/v1/sign` and `/v1/revise` null-path rejection at mapper and domain layers;
- route/capability/policy isolation for `delivery_status`;
- OpenAPI generated contract and stale-output checks;
- positive and negative DSN HTTP fixtures with spies proving invalid DSNs never
  reach datasource or signer access;
- `dkim2ctl fixture validate` and generated loopback execution for DSN routes;
- unchanged originator-Milter null-sender tempfail test as an explicit compatibility
  control.

Final gate:

- `make guardrails`
- `git diff --check`
- exact focused Library, daemon, client, and generated OpenAPI checks recorded
  in the completion evidence.

## Implementation Effort

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 2-4 engineering days |
| Highest-risk area | byte-preserving DSN evidence and authorization boundary |
| Expected prompt count | 6 |
| Required final gate | `make guardrails` |

Measured effort is recorded in the ignored prompt ledger during execution.

## Acceptance Criteria

- A generic signing or revision caller cannot authorize `<>`.
- Only a complete, evidence-derived DSN can reach a delivery-status profile and
  private signing operation.
- The library and daemon independently enforce the DSN boundary; the Milter is
  not required for that enforcement.
- All REST changes originate in OpenAPI and generated artifacts are current.
- `dkim2ctl` executes draft-versioned DSN positive and negative fixtures over
  the generated client with separate protected capabilities.
- The Postfix patch and live qualification remain an explicit deployment gap;
  the generic originator path remains closed.

## Completion Evidence

M25 closure requires the authoritative OpenAPI schema and generated artifacts,
dedicated daemon and generated-client integration tests, independent security
and specification reviews, and repository guardrails. The recorded review also
verifies that originator Milter behavior remains unchanged while the dedicated
Postfix mode cannot be confused with it.

## Review Matrix

| Area | Required result | Status |
| --- | --- | --- |
| Scope | Outgoing initial DSN signing and the DKIM2-side Postfix adapter are complete; the Postfix patch, received DSNs, and propagation remain deferred | complete |
| Protocol | Draft-04 Section 12 and RFC 3462/3464 evidence is explicit, including exact highest `mf=` recipient binding | complete |
| Security | Generic null-path bypass is closed; identity, evidence, profile, ticket, and capability are purpose-separated | complete |
| Boundaries | Library, daemon, generated OpenAPI client, `dkim2ctl`, and dedicated Postfix Milter path are purpose-separated | complete |
| Tests | Parser, fuzz, race, evidence, capability, daemon, client, and adapter-regression coverage exists | complete |
| Documentation | Architecture, configuration, limitations, and implementation scope agree | complete |
