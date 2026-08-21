# OpenAPI Daemon Foundation

<!-- mutable-status:start -->

Status: implementation complete; closeout recorded externally.

<!-- mutable-status:end -->

Implementation base: commit
`26e23bfedf8882d59d1c112ad35e68ce61e5d12d`.

<!-- normative-projection:start -->

This specification defines the first truthful `dkim2d` runtime and HTTP
boundary. The daemon accepts one bounded inbound process request, performs
current DKIM2 verification, evaluates server-owned local policy, applies
server-owned replay policy, and returns one closed final disposition. This is
not the signing/mutation action plan deferred to M16. The daemon does not
advertise signing or revision behavior that the repository cannot yet wire
without bypassing the M10 signing authorities or M11 datasource boundaries.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`, especially Sections 3.4, 3.7, 5.12 through
  5.14, 7, 12, 13, 14, 15, 16, and 18;
- `docs/specs/spec-and-prompt-template.md`;
- `docs/specs/implementation/raw-message-model.md`;
- `docs/specs/implementation/mvp-core-verification.md`;
- `docs/specs/implementation/policy-engine.md`;
- `docs/specs/implementation/dns-key-resolver.md`;
- `docs/specs/implementation/signing-and-revision.md`;
- `docs/specs/implementation/datasource-providers.md`;
- `docs/specs/implementation/replay-store-valkey.md`;
- `docs/specs/openapi/dkim2d.yaml`;
- `docs/specs/openapi/oapi-codegen.server.yml`;
- `docs/specs/openapi/oapi-codegen.client.yml`;
- `draft-ietf-dkim-dkim2-spec-04`;
- `draft-chuang-dkim2-dns-04`, under the repository's documented historical
  DNS baseline policy;
- RFC 4648 for strict canonical padded Base64;
- RFC 5321 for SMTP reverse-path and forward-path bytes;
- RFC 5322 for the authoritative raw message representation;
- RFC 6532 for internationalized RFC 5322 header-field syntax and exact
  non-ASCII message bytes;
- RFC 8259 for JSON interoperability and UTF-8;
- RFC 9110 for HTTP semantics, methods, status codes, field semantics, and
  `Expect`;
- RFC 9111 for the frozen `no-store` cache-control semantics;
- RFC 9112 for HTTP/1.1 request-target, framing, connection management, and
  message reuse;
- the official `oapi-codegen` v2.7.1 documentation, including its OpenAPI 3.0
  support boundary, strict-server composition, and runtime validation limits;
- the Go 1.26 `net/http`, `encoding/json`, `net`, `context`, and `crypto/tls`
  contracts;
- `Makefile`.

The protocol behavior baseline remains exactly
`draft-ietf-dkim-dkim2-spec-04`. HTTP, replay disposition, configuration,
readiness, and action planning are local service policy, not additional DKIM2
normative behavior. A later draft or generator release is not an implicit
behavior or toolchain update.

If this specification conflicts with an authoritative source, implementation
stops until the durable source set, generated artifacts, and tests agree.

## Original Gap

`cmd/dkim2d` currently contains package documentation and the completed M12
Valkey provider, but no executable command, typed configuration loader, Fx
application, HTTP listener, generated OpenAPI server or client, runtime schema
validator, request mapper, readiness aggregator, or lifecycle-managed replay
composition.

The current OpenAPI planning file is not executable truth:

- it declares OpenAPI 3.1.0 although pinned `oapi-codegen` v2.7.1 supports
  OpenAPI 3.0;
- it uses 3.1-only `const` and `contentEncoding`;
- its strict-server generator config names no concrete server generator;
- no generated output or stale-output guard exists;
- it advertises `verify`, `sign`, `revise`, and `process` operations even
  though the request has none of M10's profile, capability, route-ticket,
  authorization, private-signer, or restricted-release inputs;
- M11 intentionally exposes no command-consumable datasource or private-key
  custody bridge;
- it conflates protocol `TEMPERROR` with policy `tempfail`, invents
  `neutral`, omits policy `continue`, and advertises mutation actions not owned
  by the current public policy facade;
- free-form messages, findings, readiness reasons, and errors are unbounded
  and unsafe for protected input; and
- request-controlled policy mode and Authentication-Results behavior would
  let an unauthenticated caller change server trust policy.

M12 also assigns concrete Valkey TLS/auth/secret loading, startup audit,
periodic revalidation, readiness, and lifecycle wiring to this increment.
There is no safe daemon path until those frozen invariants are composed
without a parallel client or fallback provider.

Finally, the architecture still describes M12 only as specified rather than
completed. That historical drift must be reconciled append-only with the M13
change; it must not create a second M12 commit.

## Goal

Deliver one cohesive inbound-only daemon that:

- exposes exactly three resource paths: `GET` and `HEAD` on `/healthz` and
  `/readyz`, and `POST` on `/v1/process`;
- accepts exactly API version `v1`, draft
  `draft-ietf-dkim-dkim2-spec-04`, independent SMTP envelope bytes, and one
  strict canonical Base64 encoding of raw RFC 5322 bytes;
- maps generated DTOs into explicit daemon-domain values, then into
  `dkim2.NewVerifyRequest`, `Verifier.Verify`, and `EvaluatePolicy`;
- keeps the authoritative four-state verification result unchanged and
  separate from local policy, replay aggregation, final daemon disposition,
  and HTTP transport failures;
- evaluates a server-owned policy mode that request data cannot weaken;
- derives replay identities only from the sealed aggregate current PASS,
  derives the complete key batch before mutation, processes every identity,
  and computes one deterministic fail-closed aggregate;
- starts and manages explicit disabled, memory, or production Valkey replay
  backends with no fallback;
- loads all Valkey authority, TLS roots, credentials, HMAC secret, attestation,
  retention, and lifecycle settings through protected typed configuration;
- authenticates every mutation-capable process request with one protected
  local capability that is never request-configurable or observable;
- runs the M12 startup audit and revalidation at most sixty seconds apart,
  treats five-minute evidence expiry as not ready, and never bypasses
  `NewProductionStore`, `Revalidate`, or the provider-owned freshness check;
- composes runtime dependencies with constructors and Fx lifecycle hooks;
- exposes liveness and readiness with closed status only and no reason;
- enforces body, decoded-message, JSON, Base64, header, timeout, concurrency,
  waiter, and shutdown bounds before disproportionate work;
- generates and commits reproducible server and client artifacts from one
  OpenAPI 3.0.3 source through pinned `oapi-codegen` v2.7.1; and
- remains loopback-only because this increment defines no HTTP TLS, user/role
  authorization, proxy-trust, CORS, or remote-exposure model.

No raw message, envelope path, recipient, signature, selector, replay key,
credential, protected config, raw provider failure, or signing material is
returned, logged, formatted, traced, metric-labeled, or included in test
diagnostics.

## Delivery Shape

Implementation is divided into sequential, independently reviewable slices:

1. Reconcile the architecture/M10 handoff and replace the aspirational
   OpenAPI file with the truthful inbound-only OpenAPI 3.0.3 contract.
2. Pin the generator toolchain, generate server/client artifacts, and add
   deterministic stale-output and import-boundary guards.
3. Implement immutable Cobra/Viper configuration loading, scalar environment
   expansion, exact typed validation, and stable path tests.
4. Implement protected local capability and file loading, CA conversion, and
   content-free configuration diagnostics.
5. Implement the daemon-domain processor, DNS-backed verifier, server-owned
   policy mapping, and exact DTO/domain/result vocabulary.
6. Implement the bounded replay batch coordinator and explicit
   disabled/memory/Valkey composition with the complete local disposition
   matrix.
7. Implement Fx lifecycle, HTTP admission, strict request validation,
   liveness/readiness, periodic Valkey revalidation, and bounded shutdown.
8. Add positive, negative, abuse, fuzz, race, privacy, generated-output, and
   lifecycle evidence plus durable operator-facing documentation.
9. Run complete guardrails, reconcile this specification, obtain two
   independent approvals of one unchanged snapshot, and create exactly one
   project-formatted commit.

The ignored prompt pack belongs under
`temp/openapi-daemon-foundation-prompts/`. It is prepared only after this
durable specification receives independent normative and architecture
approval. `temp/` must never be staged or committed.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 4-10 agent-hours |
| Highest-risk area | strict OpenAPI mapping, protected Valkey configuration, replay partial-mutation aggregation, lifecycle/readiness |
| Expected prompt count | 9 |
| Required final gate | `make guardrails`, generated stale check, focused fuzz, and `make test-valkey` |

Risk notes:

- Low risk: fixed liveness response and closed enum formatting.
- Medium risk: OAS 3.0 migration, reproducible generation, Cobra/Fx
  composition, loopback listener, and ordinary positive request mapping.
- Highest risk: duplicate-safe JSON validation, Base64/message resource
  accounting, protected configuration loading, replay batch uncertainty, M12
  revalidation/readiness, and shutdown races.

Measured effort is filled during closeout:

<!-- mutable-effort:start -->

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| `01-architecture-openapi-generation.md` | 2026-07-25T01:41:22Z | 2026-07-25T01:48:47Z | 7m25s | Not separately measured | Architecture, generation, and stale-output foundation |
| `02-configuration-loading.md` | 2026-07-25T02:11:03Z | 2026-07-25T02:29:53Z | 18m50s | Not separately measured | Strict layered configuration and validation |
| `03-protected-material.md` | 2026-07-25T02:33:23Z | 2026-07-25T03:39:05Z | 1h05m42s | Not separately measured | Descriptor-owned protected generation |
| `04-domain-mapping.md` | 2026-07-25T03:39:25Z | 2026-07-25T04:48:34Z | 1h09m09s | Not separately measured | Domain construction and generated DTO mapping |
| `05-replay-composition.md` | 2026-07-25T04:48:58Z | 2026-07-25T06:01:39Z | 1h12m41s | Not separately measured | Replay composition, authority, and readiness |
| `06-http-boundary.md` | 2026-07-25T06:02:06Z | 2026-07-25T20:33:45Z | 14h31m39s | Not separately measured | HTTP transport, authentication, and resource policy |
| `07-lifecycle-readiness.md` | 2026-07-25T20:33:46Z | 2026-07-25T23:11:54Z | 2h38m08s | Not separately measured | Cobra, Fx, lifecycle, readiness, and shutdown |
| `08-adversarial-proof.md` | 2026-07-25T23:12:24Z | 2026-07-25T23:55:49Z | 43m25s | Not separately measured | Fuzz, race, dependency, documentation, and audit proof |
| `09-closeout.md` | 2026-07-25T23:56:33Z | 2026-07-25T23:58:00Z | 1m27s | Not separately measured | Tracked closeout freeze; later facts are external |

<!-- mutable-effort:end -->

## Scope

### In Scope

- A `dkim2d serve` Cobra command and one fresh non-global Viper instance.
- One versioned strict YAML configuration document and stable typed paths.
- Exact one-pass scalar `${NAME}` environment expansion before typed decode.
- Secret metadata, protected file loading, immutable config snapshots, and
  content-free validation diagnostics. M13 exposes no effective-config dump.
- A protected local capability required for every `/v1/process` request.
- Fx providers and lifecycle for listener, HTTP server, DNS provider,
  verifier, replay provider, replay revalidation, readiness, and processor.
- OpenAPI-authoritative generated server and client artifacts.
- Strict runtime request validation in addition to generated strict-handler
  adaptation.
- Inbound current verification, server-owned policy, replay aggregation, and
  one final disposition action.
- Loopback-only HTTP on one listener shared by process, health, and readiness.
- M12 disabled, memory, and Valkey replay wiring.
- Minimal append-only architecture and M10 integration amendments that record
  the truthful ownership correction.
- Unit, integration, fuzz, abuse, race, privacy, dependency, generation,
  real-Valkey, lifecycle, and guardrail proof.

### Out Of Scope

- HTTP signing, revision, raw-message rewrite, or signed-message output.
- Production private-key custody, `PrivateKeySigner`,
  `RouteFanoutAuthority`, `SigningAuthorizer`, restricted-result release, or a
  public M11 datasource bridge.
- Construction of memory or flat-file signing datasource providers.
- `POST /v1/verify`, `POST /v1/sign`, or `POST /v1/revise`.
- Request-selected operation, policy mode, trust mode, Authentication-Results,
  debug mode, replay mode, datasource, or backend.
- Mutation actions such as add/change/delete header or replace body.
- Milter, Exim, SMTP replies, queue behavior, delivery, or fidelity metadata.
- `dkim2ctl` commands and fixture-runner UX beyond committing the generated
  client package required for M14.
- Concrete slog, OpenTelemetry, Prometheus, exporter, metrics endpoint, or
  debug-module integration.
- HTTP TLS, remote or user identity, role authorization, proxy headers,
  forwarded-client identity, CORS, compression, non-loopback exposure, Unix
  sockets, or multiple listeners.
- Valkey cluster, Sentinel, hostname/load-balancer endpoints, provider
  fallback, secret rotation in progress, or a parallel Valkey client.
- New DKIM2, DNS, EAI, SMTPUTF8, signing, datasource, replay-key, or protocol
  semantics.

## Settled Decisions

1. M13 is inbound-only and advertises one `process` behavior. The OpenAPI
   request has no operation selector.
2. `POST /v1/process` performs verify, server-owned policy, replay, and final
   disposition. It never returns a raw or transformed message.
3. HTTP signing/revision and the missing production signing-authority,
   datasource bridge, and private-key backend are reassigned to M16 as an
   explicit prerequisite to Milter action integration; M17 reuses that
   contract. M16 must amend OpenAPI and regenerate both artifacts before using
   it.
4. The authoritative OpenAPI document is migrated to 3.0.3 for the pinned
   generator. This is toolchain compatibility, not protocol semantic drift.
5. Generated DTOs exist only at HTTP/client boundaries. Daemon-domain and
   root-library values remain explicit and independent.
6. Policy mode and replay policy are server configuration. A request cannot
   select a weaker mode.
7. Verification has exactly PASS, FAIL, PERMERROR, and TEMPERROR. Local
   policy verdict/action has exactly accept, reject, tempfail, and continue.
8. Replay is an independent local-policy aggregate and never rewrites the
   verification result or the underlying policy decision.
9. Disabled replay is an explicit configured backend, not a fallback.
10. M13 has no secure remote HTTP exposure contract; only canonical loopback
    IP literals are accepted.
11. Loopback location is not caller authority. Possession of the protected
    local capability is required before `/v1/process` can reach
    readiness, body parsing, DNS, policy, or replay mutation. Status routes
    remain unauthenticated and content-free.
12. Health reports process liveness only. Readiness reports whether the
    inbound dependency graph can safely admit work.
13. M12 completion is recorded append-only in architecture history and its
    milestone row is reconciled in the M13 commit; no M12 history is rewritten
    and no second M12 commit is created.

## Decisions And Open Questions

Settled:

- The first daemon API is truthful and inbound-only.
- The draft and API version are required exact request values and echoed from
  server-owned constants.
- DNS verification uses the existing public library transport/provider
  boundary; no command module imports `lib/internal`.
- Disabled, memory, and Valkey are the only replay backend choices.
- Every replay-enabled request processes the complete sealed recipient
  identity set before one deterministic disposition.
- Remote HTTP, signing, datasource/private-key custody, mutation actions,
  client UX, observability exporters, and adapters retain the explicit owners
  listed above.

Open:

- None that may be silently resolved during implementation. Evidence that
  requires a different API, trust boundary, or backend contract must amend
  this durable specification and receive fresh independent approval before
  implementation continues.

## Authority And Package Boundaries

Authority is scoped rather than linear. The pinned drafts own DKIM2 and DNS
protocol semantics. RFC 5321 and RFC 5322 own SMTP-path and message syntax.
This specification owns M13 service policy, resource bounds, configuration,
composition, and the intended REST behavior. Once reconciled with this
specification, `docs/specs/openapi/dkim2d.yaml` is the sole source of truth for
REST paths and schemas. Generated code implements that document but never
overrides it. A conflict between authorities stops work; no lower layer
silently wins.

`lib/` remains the sole owner of DKIM2 parsing, canonicalization, verification,
DNS key interpretation, policy evaluation, and replay identity semantics. M13
may add a narrow public facade only when it delegates to an existing library
owner without changing semantics. The library MUST NOT import Cobra, Viper,
Fx, HTTP, OpenAPI-generated types, Valkey, or daemon configuration.

`cmd/dkim2d/internal/httpjson` owns generated REST types, transport preflight,
domain mapping, status selection, and bounded error serialization. Generated
DTOs never cross into `lib/`.

`cmd/dkim2d/internal/config` owns raw YAML preflight, Viper source merge,
placeholder expansion, typed decode, protected-file loading, and immutable
configuration. It must not become a datasource or protocol-policy package.

`cmd/dkim2d/internal/app` owns Fx construction, readiness aggregation, listener
ownership, and lifecycle order. Package globals, the default HTTP mux, global
Viper state, global telemetry state, and global DNS state are forbidden.

The existing M12 Valkey package remains the sole owner of its `valkey-go`
client factory, wire commands, startup audit, revalidation, state, and close
behavior. M13 supplies validated inputs and coordinates lifecycle; it MUST NOT
create another Valkey client or option model.

## OpenAPI Contract

### Contract and observed generator defect

`docs/specs/openapi/dkim2d.yaml` is migrated from OpenAPI 3.1.0 to 3.0.3. This
is required because a direct proof with the pinned generator shows that
`oapi-codegen` v2.7.1 warns that 3.1 is unsupported and then silently emits
plain strings for the former `const` fields, supplies no
`contentEncoding: base64` canonical-decoding guarantee, and preserves the
false operation/result enums. M13 replaces each constant with a singleton
enum and performs canonical Base64 validation locally.

The document omits `servers`; M14's generated client must receive an explicit
base URL. It declares exactly these operation IDs:

| Method and path | Operation ID |
| --- | --- |
| `GET /healthz` | `getHealth` |
| `HEAD /healthz` | `headHealth` |
| `GET /readyz` | `getReadiness` |
| `HEAD /readyz` | `headReadiness` |
| `POST /v1/process` | `processMessage` |

There is no operation selector and no sign, verify-only, revise, mutation, or
Authentication-Results route.

The document declares one `components.securitySchemes.localCapability` API-key
scheme in the `X-DKIM2-Capability` header. This is a repository-local
capability scheme, not OAuth Bearer and not a remotely transportable
credential. `processMessage` requires exactly that scheme.
The four status operations declare explicit empty security so liveness and
readiness probes remain unauthenticated. The generated client represents the
scheme through its normal request-editor/authentication hook; no generated DTO
contains the capability.

### Process request schema

`ProcessRequest` is an object with `additionalProperties: false` and exactly
four required properties:

- `api_version`: string, singleton enum `v1`;
- `draft`: string, singleton enum `draft-ietf-dkim-dkim2-spec-04`;
- `message`: required `MessageInput`;
- `smtp`: required `SMTPInput`.

`MessageInput` has `additionalProperties: false` and one required property,
`raw_rfc5322_base64`. It is declared `type: string`, `format: byte`, and with a
target-specific generator overlay that keeps the wire value in a structurally
opaque string wrapper. Its schema explicitly sets `minLength: 0` and
`maxLength: 44739244`. A generated `[]byte` or builtin `string` field is a
stale-output failure: `[]byte` loses the original Base64 spelling, while a
builtin string makes default diagnostic formatting expose raw message data.

`SMTPInput` has `additionalProperties: false` and exactly two required
properties:

- `mail_from`: JSON string with schema `minLength: 0`, `maxLength: 256`, whose
  decoded UTF-8 byte length is also at most 256;
- `rcpt_to`: array with `minItems: 1`, `maxItems: 2000`, unique-items disabled,
  and string items with schema `minLength: 0`, `maxLength: 256` whose decoded
  UTF-8 byte length is also at most 256.

The HTTP layer validates JSON encoding, Unicode-scalar string integrity, types,
and these wire bounds. Invalid JSON UTF-8, invalid scalar encoding, wrong
types, and bound violations are transport errors and never reach the domain.
It does not otherwise duplicate SMTP grammar. For a schema-valid string it
passes the exact UTF-8 encoding of those Unicode scalar values, without
normalization, to `dkim2.NewVerifyRequest`. The existing verifier and its
shared `internal/signature` owner classify bytes that violate its current RFC
5321 path grammar as a coherent domain result. Those schema-valid but
SMTP-invalid paths are HTTP 200 `PERMERROR`, not HTTP 400. This preserves
representable EAI/SMTPUTF8 spellings without claiming that arbitrary invalid
octet sequences can cross an RFC 8259 JSON string boundary or inventing new
SMTPUTF8 envelope semantics.

The request accepts no HELO, client address, request ID, policy, mode, replay
backend, key, handle, selector, profile, or output switch.

### Successful response schema

`ProcessResponse` has `additionalProperties: false` and these required
properties in every HTTP 200 response:

- `api_version`: singleton `v1`;
- `draft`: singleton `draft-ietf-dkim-dkim2-spec-04`;
- `verification`: `VerificationResult`;
- `policy`: `PolicyResult`;
- `replay`: `ReplayResult`;
- `disposition`: enum `accept`, `reject`, `tempfail`, or `continue`.

`VerificationResult` has these required properties:

- `state`: enum `PASS`, `FAIL`, `PERMERROR`, `TEMPERROR`;
- `primary_reason`: one exact public verification reason listed below;
- `scope`: `current` or `chain`;
- `historical_content`: `not_evaluated`, `complete`, or `partial`;
- `historical_signatures`: `not_evaluated` or `complete`;
- `custody_structure`: enum `not_evaluated`, `not_present`,
  `nd_links_evaluated`, `terminal_nd_requires_oob`;
- `checks`: array, `minItems: 1`, `maxItems: 128`, of `VerificationCheck`;
- `signature_sets`: array, `maxItems: 16`, of `SignatureSetResult`.

It has one optional property, `target`. When present, `target` requires both
`sequence` and `instance` as canonical unsigned decimal strings matching
`^[1-9][0-9]{0,19}$` and semantically no greater than
18,446,744,073,709,551,615. They are never independently present. This
response-only string form preserves the public uint64 range without generator
or JSON-number loss. Zero, leading zero, sign, whitespace, exponent, float,
and overflow are forbidden.

The exact serializable verification reason enum is:

`none`, `limit_exceeded`, `malformed_message`,
`malformed_protocol`, `missing_protocol`, `sequence_invalid`,
`unsupported_algorithm`, `hash_mismatch`, `signature_mismatch`,
`missing_key`, `invalid_key`, `ambiguous_key`, `revoked_key`,
`unsupported_key_type`, `key_algorithm_mismatch`, `provider_temporary`,
`provider_permanent`, `provider_contract`, `timestamp_invalid`,
`envelope_mismatch`, `domain_alignment_mismatch`, `next_domain_mismatch`,
`out_of_band_required`, and `internal_contract`.

The public `invalid_request` reason belongs only to API/programmer-misuse
errors returned without a verification result. No valid verifier result can
carry it, so the REST mapper rejects it as an impossible internal value rather
than advertising it on the wire.

`VerificationCheck` has exactly required `class` and `reason`. `class` is one
of `message`, `protocol`, `body_hash`, `header_hash`, `signature`, `key`,
`timestamp`, `envelope`, `domain_alignment`, `next_domain`, `provider`, or
`internal_contract`. `reason` uses the verification reason enum.

`SignatureSetResult` has exactly required `algorithm`, `status`, `reason`, and
`key_policy`. `algorithm` is `rsa-sha256`, `ed25519-sha256`, or `unknown`;
`status` is `pass`, `fail`, `permerror`, `temperror`, or `ignored`; `reason`
uses the verification reason enum. `key_policy` has exactly three required
booleans: `testing_declared`, `strict_identity_declared`, and
`strict_identity_applicable`. The last property is a singleton `false`, matching
the current public facade invariant; OpenAPI cannot advertise an impossible
true value.

`PolicyResult` has exactly these required properties:

- `mode`: `strict`, `permissive`, or `testing`;
- `verdict`: `accept`, `reject`, `tempfail`, or `continue`;
- `primary_reason`: one exact M7 public policy reason;
- `do_not_modify`: one compliance value;
- `do_not_explode`: one compliance value;
- `dns_testing_effective`: boolean;
- `feedback`: `PolicyFeedback`;
- `findings`: array, `maxItems: 128`, of `PolicyFinding`.

Current-scope verification reports both compliance properties as
`not_evaluated`. Full-chain verification preserves the authenticated policy
projection: `do_not_modify` is `not_requested`, `indeterminate`, or
`not_evaluated`; `do_not_explode` is `not_requested`,
`violated`, `indeterminate`, or `not_evaluated`. `honored` is intentionally
not a valid explosion-compliance value because absence of a later authenticated
`exploded` report is not positive single-recipient evidence.

The policy-reason enum is the exact reachable decision/finding inventory. The
error-only public constants `invalid_input`, `limit_exceeded`, and
`internal_contract` are not serializable:

`protocol_pass`, `protocol_fail`, `protocol_permerror`, `protocol_temperror`,
`permissive_override`, `testing_mode_observe`, `dns_testing_effective`,
`dns_testing_mixed`, `dns_testing_ineligible`,
`donotmodify_indeterminate`, `donotmodify_not_evaluated`,
`donotexplode_violated`, `donotexplode_indeterminate`,
`donotexplode_not_evaluated`,
`feedback_requested`, `feedback_relay_selected`, `feedhere_inert`, and
`exploded_reported`.

The service shares the current-target verifier and descends into authenticated
history only after current PASS. A single-instance message therefore remains
current scope without recipe work. A multi-instance PASS is emitted only after
bounded full-chain verification, and the response mapper preserves the sealed
multi-instance policy values instead of inferring them from wire fields. A failed
or incomplete chain cannot be promoted to PASS merely to obtain a serializable
response.

`PolicyFeedback` requires `requested`, `relay_required`, and
`history_coverage`. Coverage is `not_evaluated` for current scope, `complete`
for contiguous authenticated history, or `indeterminate` for explicitly
partial authenticated history.
`relay_sequence` is present in the same canonical uint64 decimal-string form
if and only if `relay_required` is true.

`PolicyFinding` requires `reason` and `severity`; it has an optional
`sequence`. Its reason enum is the policy-reason inventory above. Severity is
`info`, `warning`, `permanent`, or `temporary`. Sequence presence follows the
immutable M7 `PolicyFinding.Sequence` invariant and uses the same canonical
uint64 decimal-string form; the adapter does not infer it. The findings array
has `minItems: 1` and `maxItems: 128`, matching valid public decisions.

The adapter validates that `PolicyDecision.VerificationState` equals
`verification.state` and that the immutable one-action plan equals the policy
verdict. Those redundant values are intentionally omitted from `PolicyResult`;
M13 emits neither a second verification state nor an adapter mutation plan.
Likewise, verification check/signature count methods are validated against the
emitted array lengths rather than serialized as duplicate counters.

`ReplayResult` has `additionalProperties: false` and exactly one required
property, `class`, whose enum is `not_checked`, `disabled`, `first_seen`,
`replayed`, or `indeterminate`. This intentionally lossy, privacy-preserving
projection is sufficient for the final disposition. Provider kind, store
state, typed error code, identities, keys, recipients, counts, and
per-recipient outcomes are not REST data.

The authenticated `exploded` fact is represented only through the immutable
policy result. It neither bypasses replay nor changes the response shape.

### Health, readiness, and error schemas

`HealthResponse` and `ReadinessResponse` each have
`additionalProperties: false` and exactly required `api_version`, `draft`, and
`status`. Health status is singleton `alive`; readiness status is singleton
`ready`. They are distinct generated schemas, so one route cannot validate the
other route's status. Values are server constants, never request echoes.

`ErrorResponse` has `additionalProperties: false` and exactly required
`api_version`, `draft`, `code`, and `category`. Category is exactly
`request`, `availability`, or `internal`. There is no message, detail, cause,
path, field value, timestamp, request identifier, or dependency name.

The exact application error codes are:

`invalid_json`, `invalid_contract`, `unsupported_version`,
`unsupported_draft`, `request_too_large`, `unsupported_media_type`,
`not_found`, `method_not_allowed`, `forbidden`, `service_not_ready`,
`service_overloaded`, `request_timeout`, `request_deadline`,
`expectation_failed`, `precondition_failed`, and `internal_error`.

The OpenAPI document has no `default` response. Its exact operation response
map is:

| Operation | Response keys and schemas |
| --- | --- |
| `getHealth` | 200 `HealthResponse`; 304 with no response content; 400/412/417/500 `ErrorResponse` |
| `headHealth` | 200/304/400/412/417/500 with no response content |
| `getReadiness` | 200 `ReadinessResponse`; 304 with no response content; 400/412/417/500/503 `ErrorResponse` |
| `headReadiness` | 200/304/400/412/417/500/503 with no response content |
| `processMessage` | 200 `ProcessResponse`; 400/403/408/413/415/417/500/503 `ErrorResponse` |

Every non-HEAD response listed above except 304 declares JSON content. Every
listed response declares reusable, `required: true` `Cache-Control` (singleton
`no-store`) and `Connection` (singleton `close`) headers. Every response except
304 also declares `required: true` `X-Content-Type-Options` (singleton
`nosniff`) and `Content-Length` (canonical non-negative decimal). Status-route
200 responses additionally declare one required strong `ETag` with exact
schema pattern `^"[0-9a-f]{64}"$`.
Each HEAD operation description additionally requires the same status and
representation metadata that its corresponding GET would produce. For every
status except 304 this includes `Content-Type` and the corresponding GET
`Content-Length`; 304 uses its deliberately minimal header shape and has
neither. HEAD Response Objects omit `content` so generated clients cannot
expect response bytes. OpenAPI 3.0.3 requires a response header named
`Content-Type` to be ignored, so this metadata is deliberately expressed in
the HEAD operation descriptions and enforced by raw wire tests rather than an
invalid Header Object or a false body `content` entry.
Every 503 declares `Retry-After` with singleton decimal value `1` and
`required: true`. Each status-route 304 has no content or trailers and declares
only required `Cache-Control`, `Connection`, and the selected representation's
required strong `ETag`, plus optional `Date`; it declares and emits no
`Content-Length`, `Content-Type`, `X-Content-Type-Options`, `Last-Modified`,
`Vary`, `Expires`, `Content-Location`, `Allow`, `Retry-After`,
`Accept-Ranges`, or `Content-Range`. This is the minimal RFC 9110 cache-update
shape. It carries `Date` exactly when the corresponding selected 200 would
carry the same provider value. The universal `Cache-Control: no-store` retains
its RFC 9111 meaning:
recipients must not store these responses, but an origin server still evaluates
a received conditional request as required by RFC 9110. Router 404 and 405
are deliberate outer-gate responses rather than operation responses; 405 sets
the exact `Allow` header. Every syntactically captured unsupported, mixed, or
route-invalid Expect class uses the declared application 417 after the bounded
neutralization; malformed HTTP field-line syntax remains Go-owned 400.
Go-owned 505, the pre-handler HTTP/2-preface 505 defined below, and
connection-level failures are intentionally outside OpenAPI. No other
application-controlled status is permitted once an operation handler is
selected.

The process 403 body is the same bounded `ErrorResponse` shape with code
`forbidden`; absence, malformed syntax, and mismatch are indistinguishable.

Every listed response also declares one reusable optional `Date` Header Object
whose string schema uses the exact pattern
`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$`.
It is optional in OpenAPI because RFC 9110 requires omission when the origin
server has no usable clock and permits omission on 1xx/5xx. Production
application 2xx through 4xx wire responses require it whenever the validated
provider is available; direct Go and outer responses follow the same
response-filter contract. Semantic parse/format round-trip tests supplement
the schema's lexical pattern.

OpenAPI 3.0.3 Header Objects inherit the applicable Parameter Object
`required` property. The document uses that property for every universally
mandatory header above; adapter contract, generated-type, mapper, and wire
tests enforce the same presence.

Semantically empty or malformed RFC 5322 bytes and malformed DKIM2/SMTP facts
are not transport errors. Canonical Base64 for an empty byte string is valid
input and reaches the verifier, which returns the coherent HTTP 200 domain
result.

All objects in the OpenAPI document set `additionalProperties: false`. Every
required/optional rule above is asserted by schema tests and adapter invariant
tests.

## Generation And Validation Toolchain

A dedicated Go 1.26 module at `tools/` is added to `go.work` and pins both a
tool directive for
`github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen` and the exact module
`github.com/oapi-codegen/oapi-codegen/v2 v2.7.1`. Both the tools module and
`cmd/dkim2d` directly pin `github.com/getkin/kin-openapi v0.135.0`, aligned
with the generator.
The frozen parameter-free operations generate no
`github.com/oapi-codegen/runtime` import under v2.7.1. Neither generated owner,
`cmd/dkim2d` nor `cmd/dkim2ctl`, pins that unused runtime. If a later OpenAPI
amendment generates a runtime import, its owning milestone adds the exact
direct dependency proven by the generated bytes rather than pre-pinning an
unused module. Dependency guards
require the generator and validator pins, require synchronized workspace
module metadata, reject a runtime dependency in `lib/`, and reject an untagged
middleware repository.

The server generator enables models, embedded specification,
`std-http-server: true`, and `strict-server: true`. Both generator
configurations set
`compatibility.preserve-original-operation-id-casing-in-embedded-spec: true`;
generation and embedded-spec guards prove the exact five lower-camel operation
IDs remain byte-for-byte aligned with the source contract rather than being
normalized by the generator. The client generator enables models and client.
Each generator config applies one checked-in
OpenAPI overlay that changes only Go type bindings for the raw-message,
reverse-path, and forward-path scalar schemas. The server overlay imports
`cmd/dkim2d/internal/httpjson/wire`; the client overlay imports
`cmd/dkim2ctl/internal/testclient/wire`. Both packages implement the same
JSON-string wire semantics without sharing generated DTOs or introducing a
library dependency. Generator configuration contains no output path; root
Make targets pass explicit repository-root-relative output locations:

- `cmd/dkim2d/internal/httpjson/generated/server.gen.go`;
- `cmd/dkim2ctl/internal/testclient/generated/client.gen.go`.

The two `wire.ProtectedString` implementations are not hand-maintained.
One checked-in generator at `tools/cmd/wiregen` owns the security-critical
template and emits target-local `protected_string.gen.go` files with only the
package/import differences required by their modules. `make
generate-openapi` runs this generator from the tools module before
`oapi-codegen`; `make check-openapi` regenerates and byte-compares both wrapper
outputs and runs shared parity vectors. This is the sole implementation source
for JSON, zero-value, accessor, formatting, and structural-opacity behavior.

`make generate-openapi` runs the tool in its owning module as
`go -C tools tool oapi-codegen`; every config, input, and output argument is an
explicit absolute path derived from the repository root, so changing the Go
command working directory cannot redirect generated files.
`make check-openapi` uses the same module-scoped invocation, generates both
files into a mode-0700 temporary directory, byte-compares them with committed
artifacts, and runs compile, route, operation-ID, embedded-spec, and
import-boundary guards. It also proves
the three protected request properties use their target-local opaque wrapper,
not `[]byte` or builtin `string`. `make guardrails` includes the check. A
clean-build-cache test invokes the exact root Make targets from the repository
root and proves that the workspace-local tool directive is found without a
globally installed binary.

Each target-local package defines `wire.ProtectedString`, which holds request
text only behind a private pointer to immutable state. Its zero value is
invalid. It provides bounded JSON string marshal/unmarshal behavior required
by the generated client/server, a checked client constructor, and one explicit
byte-preserving accessor for its owning adapter; marshal or access on an
invalid value fails with a constant error. It provides no ordinary raw-value
`String` or text-marshaling path. Its `String`, `GoString`, and `Format`
behavior is content-free for value and pointer forms. Consequently default
formatting of a generated DTO, including invalid value `%p`, can reveal at
most wrapper type names and private pointer addresses, never Base64, envelope,
or decoded bytes. Copying a DTO copies only opaque handles; request teardown
releases all owning references. The wrapper is transport-only and is never a
domain, config, log, error, or test-diagnostic type.

Strict generated handling is not complete request validation. A small owned
net/http wrapper loads the embedded document once, builds
`routers/legacy.NewRouter(document)`, and calls
`openapi3filter.ValidateRequest`. It is constructed without global state. The
wrapper sits after route/method/media/admission/body/token preflight and before
generated strict decoding. All default generated error handlers are replaced
by the closed mapper. Validator and generated-handler errors are classified
without wrapping or formatting their values; only the closed mapper's constant
code/category crosses the response, process-error, or test-diagnostic
boundary.

The embedded document contains no remote or file references. Startup loading
disables external reference resolution and validates the document once before
readiness.

## HTTP Containment And Error Precedence

M13 binds one canonical loopback IP literal and port. The default is
`127.0.0.1:8080`. Typed validation rejects hostnames, wildcard or unspecified
addresses, non-loopback addresses, IPv4-mapped IPv6 addresses, non-canonical
IP spelling, zone identifiers, Unix sockets, multiple listeners, and port
zero. The port range is 1 through 65,535. There is no compatibility switch for
remote plaintext exposure.

The local threat boundary is explicit: the daemon effective UID, local root,
and the kernel are trusted; other local UIDs and any process reachable only
through localhost are not. Operators run the daemon under a dedicated service
UID and grant the same capability bytes only to approved local adapters.
Loopback location alone never authorizes mutation. Possession of the
generation-bound capability is required for the process route, while protected
ownership/mode/ACL rules prevent another ordinary local UID from loading it.
M13 does not claim confidentiality against root, the daemon UID, kernel
compromise, or local memory inspection.

The service owns a private `http.Server`, `http.ServeMux`, and listener. It
sets `DisableGeneralOptionsHandler` and places an exact outer path gate before
the mux, preventing ServeMux redirects or path cleaning. Only the literal URI
paths `/healthz`, `/readyz`, and `/v1/process` are routable. Non-empty
`URL.RawPath`, percent-encoded path octets, doubled slashes, dot segments, and
trailing slashes are rejected without redirect.

The server implements only the HTTP/1 family; plaintext HTTP/2 and h2c are
disabled. HTTP/1.0 is accepted with the same stricter mandatory Host,
target-authority, limit, and connection-close policy and receives the
HTTP/1.0 response version selected by Go. A request with major version 1 and
minor version 1 or greater is processed under the server's highest supported
HTTP/1.1 semantics and receives an HTTP/1.1 response. RFC 9110 recommends that
handling for a higher minor version; M13 makes it a required local contract.
Unsupported major versions remain Go-owned 505 except for Go 1.26's special
acceptance of the exact cleartext `PRI * HTTP/2.0` request-line tuple. Go first
performs its normal request-line, transfer-framing, field, and Host parsing.
For this Go-specific exception, an "empty-header" tuple or a tuple "carrying
headers" is classified from the parsed header map that Go 1.26 presents to its
`isH2Upgrade` check after `readTransfer`, not from raw wire field occurrence.
`readTransfer` removes one Go-compatible `Transfer-Encoding: chunked` field
and removes any syntactically valid Content-Length field that chunked
overrides. A tuple whose only wire fields are those consumed fields therefore
uses Go's documented empty-header Host exception and can reach the explicit
505 without Host. Any field that survives transfer parsing retains Go's
ordinary Host and header validation. Immediately after that parsing boundary
and before local Host, target-form, method, path, authorization, readiness, or
domain work, the outer pre-handler protocol gate
recognizes only `ProtoMajor == 2`, `ProtoMinor == 0`, method `PRI`, and
request-target `*` and returns one HTTP/1.1 header-only 505 with
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Connection: close`, `Content-Length: 0`, no `Content-Type` or `Allow`, and no
body. It closes without interpreting the following HTTP/2 connection-preface
octets and never upgrades to h2 or h2c. The intentionally bodyless constant
response departs from RFC 9110's recommendation that 505 explain supported
versions: at this unauthenticated pre-handler boundary, information
minimization and parser-independent constant output take precedence over that
non-mandatory representation. Any other unsupported major version continues
through Go's standard 505 path. The transfer-framing exception frozen below
applies first: Go's non-admitted Transfer-Encoding 501 on any complete
unsupported-major head, including the PRI tuple, is preserved rather than
rewritten or replaced by 505.
It calls `SetKeepAlivesEnabled(false)` before serving and every
application-controlled response sets `Connection: close`. One accepted
connection therefore carries at most one application request. This deliberate
HTTP/1.1 connection-close policy permits a bounded first-head metadata capture
without duplicating message-body or chunk framing.

Before releasing request bytes to `net/http`, the tracked connection uses the
same at-most-69,632-byte backing storage as its first-head capture to find the
first two SP delimiters. It validates RFC 9110 `tchar` while scanning the
method; an invalid method byte or an LF before either delimiter releases the
bounded prefix unchanged to Go's malformed-request path. Bare CR is not a line
terminator. A method token is inspected through at most 64 octets. Valid
`tchar` octet 65 releases the prefix unchanged and disables request-target
prefiltering; it never emits a raw response or records method bytes/facts.
After Go has enforced version and mandatory Host parsing, the outer gate reads
the parsed method length directly, while the exact `RequestURI` length still
selects 414 before server-wide 501. If that method instead exhausts Go's
aggregate head budget, Go-owned 431 wins.
The 65-byte prefix backing transfers into the first-head capture, so there is
no separate allocation.

For a within-limit method, the request-target limit is 8,192 octets between
the two SP delimiters. If the
second SP occurs after that limit but within the effective head budget, the
prefix is replayed unchanged and the outer gate applies version/Host
precedence before returning header-only 414. If that already-over-limit target
itself exhausts the entire 69,632-byte backing storage before the second SP
exists, the request
version and Host are unavailable behind the rejected target; the wrapper emits
one raw fixed-version `HTTP/1.1 414 URI Too Long` with
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`,
`Connection: close`, `Content-Length: 0`, no `Content-Type` or `Allow`, and no
body. Resource-limit precedence is explicit only for that within-method-limit,
incomplete request-line case; the HTTP/1.0/higher-minor/505 and Host promises
apply once the bounded prefix exposes a complete version token/head to Go.

Every released prefix is replayed byte-for-byte before subsequent socket
bytes, so accepted request lines are unchanged. The sole raw-response path is
exactly-once and possible only before any byte has reached `net/http`;
therefore Go cannot emit a competing response. Before writing it, the wrapper
sets that connection's write deadline to current time plus a fixed five
seconds. Deadline-setting failure closes before writing. A bounded write-all
loop handles partial writes, stops and closes on any error or zero-byte write,
and never retries or appends a second response after a partial failure. The
connection-cap owner can still close the socket concurrently during shutdown,
so a non-reading peer cannot extend the serve-loop or shutdown bounds.
After a successful raw write, the wrapper closes the exact tracked connection,
releases its cap token exactly once, and returns constant terminal EOF to
`net/http`; Go therefore cannot append a parser response. Partial/error paths
perform the same terminal close and return a constant non-content-bearing read
error without a second wire response.

The injected Date provider normalizes to UTC, requires a year from 1970 through
9999, formats with exact `http.TimeFormat`, and requires parse/format
round-trip equality to the same whole second. When valid, the raw 414 includes
that IMF-fixdate `Date`. When invalid or unavailable, the mandatory 414 is
still emitted without `Date`, as RFC 9110 requires for an origin server
without a usable clock. Boundary tests cover both accepted years, adjacent
unavailable values, subsecond removal, and exact IMF-fixdate bytes.

The tracked connection captures the remainder of the at-most-69,632-byte first
request head in that transferred backing storage. Except for the narrowly
specified Expect neutralization and semantically-single-chunked normalization,
it passes the same bytes unchanged to `net/http`. It records only bounded
private facts: whether a complete request line has exact case-sensitive `HEAD`; the
parsed HTTP major/minor version; the Host occurrence count and, only when its
field value is at most 64 octets, an owned exact value; the
combined `Expect` class; one content-free boolean recording any
Content-Length field occurrence and one recording a captured Content-Length
conflict, including coexistence with Transfer-Encoding or differing duplicate
values; whether obs-fold occurred within an Expect or
Transfer-Encoding field; and one Transfer-Encoding class. The private Expect
and framing classifications never retain values. Apart from the owned
at-most-64-octet Host fact, original values can exist only transiently in the
bounded capture and, after name replay, in Go's parser-owned request headers
until the outer gate deletes the original and inert field names. The outer
gate consumes and clears the owned Host fact immediately after its
origin-, absolute-, or authority-form target and authority decision. All value-bearing transport state is therefore gone
before generic middleware, OpenAPI validation, or domain work and is never
logged, formatted, serialized, or copied into errors. The
64-octet Host fact cap exceeds the longest possible canonical configured
loopback IP-literal-plus-port authority. A longer Host therefore uses an
explicit mismatch sentinel for origin- and authority-form checks and remains
ignored for absolute-form after its occurrence count proves presence. The
fixed capture is cleared and released after replay; no string or slice may
alias its backing storage.

The combined Transfer-Encoding grammar is parsed linearly within the existing
head bound into exactly one of `absent`, `single_chunked`,
`unsupported_final_chunked`, or `bad_framing`. RFC list-empty elements are
ignored. `single_chunked` is therefore exactly one semantic,
case-insensitive, parameterless `chunked` coding even when one or more field
lines contain surrounding empty elements. A syntactically valid list whose
final coding is `chunked` but which contains another supported-syntax coding
is `unsupported_final_chunked`. Malformed coding syntax, a nonempty coding
list without final `chunked`, repeated `chunked`, parameters on `chunked`, and
any simultaneous Content-Length are `bad_framing`. A present only-empty
Transfer-Encoding field is also faulty because no transfer coding was applied.
Any obsolete line folding within Transfer-Encoding is `bad_framing` and, for
supported HTTP/1, must select 400 rather than being interpreted after Go's
permissive unfolding. Unsupported-major requests retain their separately
frozen Go 501/505 precedence.
No second complete HTTP parser is introduced: the classifier owns only the
framing facts that Go 1.26 either discards or maps too coarsely for the required
RFC 9112 outcomes.

Go 1.26 does not accept every semantically valid list-empty spelling. If
`single_chunked` is already one Go-compatible field value, the layer replays it
unchanged. Otherwise it rewrites only those captured field lines without
changing their aggregate or individual lengths. The occurrence containing the
sole semantic `chunked` coding becomes `Transfer-Encoding:chunked` followed
only by enough SP octets to preserve that line's original length; every other
occurrence receives the same-length inert field name `X-DKIM2-Framing-X` while
retaining its value. Because an occurrence that contains `chunked` is never
shorter than that 25-octet canonical field line, normalization cannot require
capture growth, consume body-tail capacity, or depend on TCP segmentation.
The handler deletes every parsed `X-DKIM2-Framing-X` occurrence before generic
middleware, clears Go's parsed `Request.TransferEncoding` slice after copying
no value from it, and ignores client-supplied collisions. Framing policy uses
only the private captured class while `Request.Body` retains Go's already-owned
decoder. This bounded normalization
changes no request-line, non-framing field, body, or chunk bytes and publishes
the immutable `single_chunked` fact before Go can write a response.

Multiple/malformed Host and ordinary missing Host remain Go-owned pre-handler
400. Go 1.26 exempts CONNECT from its missing-Host check and removes the Host
field before the handler; the captured Host metadata therefore supplies that
otherwise-lost RFC check and the equivalent local mandatory-presence check for
HTTP/1.0 absolute-form, whose URI authority otherwise masks an absent field
after Go deletes it. Go also deletes Transfer-Encoding on HTTP/1.0 and maps
different HTTP/1.1 transfer-coding failures to one pre-handler 501; the
captured framing facts solely restore the RFC outcomes frozen below. The
facts are carried through the private `ConnContext` transport capability,
never logged or serialized, and cannot be supplied through a request header.

For HTTP/1.1 and higher HTTP/1 minor requests, Go's transfer-framing parser
runs before its supported-version and later Host validation. Exact or
normalized `single_chunked` enters the handler. A valid
`unsupported_final_chunked` request remains Go-owned pre-handler 501, matching
the RFC recommendation for an unrecognized request transfer coding.
`bad_framing` must instead produce 400 and close as RFC 9112 requires. When Go
rejects it before the handler as 501, the response filter applies the narrowly
guarded 501-to-400 correction below; if a Go behavior change admits it, the
outer gate returns application 400 `invalid_contract` before form, method,
path, authorization, readiness, body, or domain work.

Go applies transfer parsing to textual requests with major version 2 or
higher before rejecting the unsupported version. M13 preserves that concrete
Go boundary: "admitted" in the unsupported-major branch means that Go 1.26's
transfer parser returned no error, not that the private supported-HTTP/1
semantic class is `single_chunked`. A transfer-coding form rejected by Go
remains Go-owned 501 and is never rewritten to 400. A Go-compatible exact
single `chunked` field can continue to the normal Go-owned or explicit
HTTP/2-preface 505. The same is true when that field is accompanied by
syntactically valid Content-Length that Go accepts and removes, even though
the private classifier records `bad_framing`: unsupported-major version
rejection wins, the fixed 505 closes the connection, and no body, trailer,
application, or replay work occurs. Invalid or conflicting Content-Length
remains Go-owned 400. This exception is not applied to supported HTTP/1, where
Transfer-Encoding plus Content-Length remains 400.

For HTTP/1.0, any captured non-absent Transfer-Encoding is faulty framing
because that version does not define the field. The outer gate rejects it as
400 `invalid_contract`, advances the read deadline, and closes without reading
or interpreting body bytes. A complete over-limit request-target still selects
414 first because Go discards HTTP/1.0 Transfer-Encoding before the outer gate;
otherwise this framing rejection precedes form, method, path, authorization,
readiness, and domain policy. The incomplete-target raw 414 remains earlier
than any head fact that was not yet available.

Go's parser-owned error path can write a response before a `Request` or
`ResponseWriter` exists, omits Date on direct 400/431 output, and does not
suppress response content for HEAD. The tracked connection therefore owns one
16,384-byte response-head filter. It buffers each response status/header
section through `CRLF CRLF`, parses only Go-produced status and field-name
syntax, and closes without forwarding if that bound or invariant is violated.
Captured request facts are immutable before Go can complete a response head,
and `handler-entered` is a monotonic atomic flag set before any handler-owned
write.

The only permitted informational response is 100. The filter forwards its
complete head unchanged, requires the frozen bare shape, adds no Date or
Connection field, resets for the final response, and does not release the
connection token. Status 101 or any other unexpected 1xx is a terminal
invariant failure and is not forwarded.

For a final response, the filter first determines the effective status. Only
when `handler-entered` is false, the immutable captured class is
`bad_framing`, the captured version has major exactly 1 and minor at least 1,
and Go supplied its transfer-coding 501 does it replace the status line with
exact `HTTP/1.1 400 Bad Request`; the constant Go explanation body and its
matching Content-Length may remain because neither contains request data. No
other 501 is changed. The filter then applies Date policy to
the effective status: for a final 2xx, 3xx, or 4xx without Date it inserts one
validated provider value immediately before the terminating empty line; when
the provider is unavailable it omits Date rather than emitting an invalid
value. An existing case-insensitive Date field is preserved and never
duplicated. It next removes every case-insensitive Connection field and inserts
exactly one canonical `Connection: close` into every final head, including
HTTP/1.0, repairing Go's stripping behavior without changing the response
protocol version. The separate raw 414 already contains its one Connection
field and never traverses this filter.

Once the captured complete request line identifies exact `HEAD`, the same
filter forwards the final status/header section and discards every later
response octet until the one-request connection closes, while reporting
consumed writes to `net/http`. It buffers no response body. HEAD handlers never
read a request body and therefore cannot trigger an interim `100 Continue`;
tests prove the filter sees exactly one final response. This covers
handler-controlled and Go-owned pre-handler outcomes, including Date on direct
400/431, without replacing Go's parser or changing received request bytes.

The outer gate marks the tracked connection handler-entered before any
handler response. A response flush before that marker sets the same fixed
five-second write deadline used by the raw prefilter; a handler-owned flush
uses Go's already-active configured write deadline and never extends or clears
it. Pre-handler deadline-setting failure forwards nothing, consumes the
current input with the same constant terminal error, closes the exact tracked
connection, releases once, and makes later writes return `net.ErrClosed`.
The filter uses one internal write-all loop for transformed headers,
inserted Date bytes, informational heads, ordinary body passthrough, and final
heads. Partial nonzero writes continue; zero or error marks the filter
terminal, closes the exact tracked connection, and releases its cap token once.
Because one input call can complete previously buffered bytes and add generated
bytes, success returns `len(p), nil`; a terminal flush consumes the current
input and returns `len(p)` with one constant error so `net/http` cannot retry
any prefix. Later writes return zero with `net.ErrClosed`. HEAD-discarded body
bytes return `len(p), nil`. Generated Date bytes never count toward caller
input. No terminal path retries, emits a second response, or exposes the raw
socket error.
Connection close cannot wait for a blocked write while holding the same
response-state mutex. Terminal write state is atomic, and both connection-cap
release and any process permit/reservation release use `sync.Once` ownership
so concurrent close, write, 100/final, timeout, and shutdown paths release each
resource exactly once.

Every request must use one RFC 9112 request-target form valid for its method:

After Go has parsed a complete version/head and enforced its mandatory Host
rules, the outer gate checks the exact original request-target octet length
before form-specific authority, route, or method policy. A target over 8,192
octets receives header-only 414 with `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, `Connection: close`,
`Content-Length: 0`, no `Content-Type` or `Allow`, and no body. CONNECT's
captured missing/multiple/malformed Host rule still selects 400 first. This
outer transport response is not an OpenAPI operation response and has no
application error code.

- Origin-form uses an exact route path and requires the received Host authority
  to equal the configured canonical loopback listener authority, including
  IPv6 brackets and explicit port.
- Absolute-form is accepted as RFC 9112 requires. Its scheme is `http`
  compared case-insensitively; userinfo, fragment, opaque form, empty
  authority, and noncanonical or nonmatching authority are rejected. The
  request-target authority, not the received Host field, must exactly equal
  the configured loopback authority. The received Host value is ignored even
  when it disagrees, but the captured occurrence count proves a Host field was
  present for the stricter HTTP/1.0 local policy as well as HTTP/1.1. Exact
  path and query policy then match origin-form without redirect or cleaning.
- Authority-form is valid only for `CONNECT`. The authority must exactly equal
  the configured loopback authority. The captured request head must contain
  exactly one Host field whose parsed value equals that authority; absence or
  disagreement is application 400, while multiplicity or malformed syntax is
  Go-owned pre-handler 400. The server does not implement tunnels and returns
  header-only 501 with `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, `Connection: close`, no `Allow`,
  `Content-Type`, a required `Content-Length: 0`, and no body.
- Asterisk-form is valid only for `OPTIONS`. Exact `OPTIONS *` with the
  configured Host, no query, no body framing, no `Content-Type`, no
  `Content-Encoding`, and no `Expect` returns server-wide 204 with
  `Allow: GET, HEAD, POST, OPTIONS`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, no `Content-Length`, and no body or CORS
  fields. It also sets `Connection: close`.

A method/form mismatch, malformed absolute/authority target, or target
authority mismatch is 400 `invalid_contract`. Origin-form alternate Host and
absolute-form alternate target authority therefore cannot reach domain work,
while an absolute-form Host-field disagreement is deliberately accepted and
ignored as RFC 9112 requires. After request-target validation, the server
recognizes exact case-sensitive `GET`, `HEAD`, `POST`, and `OPTIONS` as its
implemented application methods. Any other origin- or absolute-form method,
including a lowercase spelling, a registered method not implemented by this
server, or an extension token, receives the same header-only 501 shape as
CONNECT with `Content-Length: 0` and no `Allow`. This capability decision
precedes path selection. CONNECT remains governed by its required
authority-form branch above.

The fixed bodyless 414 and 501 responses intentionally depart from RFC 9110's
generic recommendation that non-HEAD 4xx/5xx responses explain the error. At
these unauthenticated pre-routing boundaries, constant information-minimizing
output avoids reflecting a target, method, transfer coding, parser detail, or
supported-capability inventory and avoids invoking JSON allocation/encoding on
attacker-controlled framing. The mandatory status and retry semantics remain
intact, and `Cache-Control: no-store` prevents heuristic storage.

The exact server defaults and allowed ranges are:

| Setting | Default | Allowed |
| --- | ---: | ---: |
| process requests in flight | 1 | 1 through 2 |
| admission waiters | 64 | 0 through 1024 |
| admission wait | 100 ms | 0 through 1 s |
| handler deadline | 60 s | 1 s through 120 s |
| read-header timeout | 5 s | 1 s through 30 s |
| whole-request read timeout | 30 s | 1 s through 120 s |
| write timeout | 65 s | handler deadline + 1 s through 180 s |
| `http.Server.MaxHeaderBytes` | 65,536 | fixed |
| effective Go request-head read budget | 69,632 | fixed |
| method-token inspection | 64 bytes | fixed |
| request-target | 8,192 bytes | fixed |
| raw prefilter response write | 5 s | fixed |
| response-head filter | 16,384 bytes | fixed |
| Go post-handler body-close discard ceiling | 262,144 bytes | fixed |
| accepted connections | 128 | fixed |
| shutdown drain | 30 s | 1 s through 120 s |

Go 1.26's HTTP parser adds a fixed 4,096-byte initial-buffer allowance to
`MaxHeaderBytes`. M13 therefore documents and tests the effective 69,632-byte
request-head read budget instead of claiming an unenforceable 65,536-byte
wire cutoff. Oversize-head tests use a raw connection and prove rejection
above that effective budget without asserting that every syntactically valid
69,632-byte head must be accepted.

An owned listener wrapper caps accepted connections, including slow-header,
active, status-route, and process connections, at 128. It
acquires one token immediately after `Accept` and wraps the connection so
every close path releases exactly once. When full, it closes the newly
accepted socket immediately without starting an HTTP goroutine or promising a
JSON response; a bounded 10-millisecond refusal backoff prevents a local
accept/close spin. Listener shutdown interrupts the backoff. The cap is fixed,
not operator-widenable, and uses no global state.

The handler deadline begins on entry to the exact outer path gate, before
readiness, admission, or body reads. `http.Server.ReadTimeout` is the
configured `server.read_timeout`. Go 1.26 anchors its whole-request read
deadline to a fresh per-request read start, not to TCP accept time. M13 closes
after one request, but retains Go's per-request anchor rather than inventing an
accept-time deadline.
Because typed validation requires
`server.read_header_timeout <= server.read_timeout <=
server.request_deadline`, the header deadline cannot exceed the whole-request
deadline and the built-in body deadline is never later than the handler
deadline. A blocked header or body read therefore cannot outlive the promised
request budget. M13 never extends or clears that deadline. The tracked
listener connection exposes one private narrow transport-control capability
to its requests through `ConnContext`; it is not an accept-time deadline
anchor or application data channel. An application-controlled early final
response is the sole narrowing operation: before committing the response, it
advances that exact connection's read deadline to the current time so Go's
mandatory request-body close cannot wait for future client bytes.

Ordinary process admission is acquired before reading a process body; the
special immediate `100-continue` path instead uses the nonblocking atomic
acquisition frozen below. At most the configured number of ordinary waiters
may wait. Waiter exhaustion or expiration returns 503
`service_overloaded` with `Retry-After: 1`. Cancellation releases every
counter. While queued, simultaneous events use this fail-closed precedence:
already-observed request-context cancellation (no fabricated response), owned
handler deadline (503 `request_deadline`), readiness/admission closure (503
`service_not_ready`), admission-wait expiry (503 `service_overloaded`), then
permit acquisition. Go HTTP/1.1 cannot necessarily observe a peer disconnect
while an unread request body prevents its background read, so this contract
does not fabricate an impossible immediate-disconnect signal: if the
disconnect is not yet reflected in the request context, the next enforceable
event wins. A partial body is then stopped by its read failure before
mutation. A fully transmitted body can remain available in kernel or Go
buffers after the peer disconnects; in that case processing and possible
replay mutation may complete before the response write detects closure. Only
an observed terminal context before possible dispatch guarantees zero
mutation. After acquiring a permit, the handler rechecks
already-observed request context, owned deadline, and readiness in that order
before reading. Every 503 sets `Retry-After: 1`; none performs domain, DNS, or
replay work.

M13 has exactly one response representation and performs no proactive content
negotiation. As RFC 9110 permits when an origin server chooses not to honor
the field, every `Accept` occurrence is ignored, including malformed or
nonmatching values; it never selects status 406. Responses remain the exact
JSON media type declared below. `Vary: Accept` is not emitted because
representation selection does not vary on that field.

The bounded first-head layer classifies the combined RFC 9110 `Expect` list
before releasing the head to Go. Empty elements are ignored semantically
within the already-fixed 69,632-byte request-head bound. An absent or
only-empty list is `none`. One or more
case-insensitive, parameterless `100-continue` elements and no other element is
`continue`, including repeated values and multiple fields. Any other valid
expectation, parameterized member, or mixture is `unsupported`; invalid list,
token, quoted-string, quoted-pair, or parameter syntax is `malformed`. Only
this content-free class is retained; no supplied value is logged, formatted,
or released beyond the outer gate.

RFC 9112 obsolete line folding is never given expectation or framing
semantics. Any captured obs-fold within Expect is a transport-level 400 with
connection close after Go's request-line/header parse and before route,
expectation, authorization, or body policy. Obs-fold within Transfer-Encoding
is the `bad_framing` case above. Other request fields retain Go's RFC-permitted
unfold-to-SP behavior. This explicit split prevents Go's permissive MIME
unfolding from changing the private classifiers' security decisions.

Go 1.26 consults only its first parsed `Expect` field and would therefore reject
some legal empty/repeated list forms or auto-handle only part of a mixed list.
The first-head layer narrowly replaces the case-insensitive six-byte field name
of every captured `Expect` occurrence with the valid inert six-byte name
`X-Dk2E` before replaying the otherwise unchanged head to `net/http`. This is
one of only two frozen accepted-request head rewrites; request-line,
field-value, delimiter, body, and chunk-framing bytes remain unchanged by this
one. The outer handler deletes every
parsed `X-Dk2E` occurrence before generic middleware and never derives policy
from it, so a client-supplied field with that name cannot forge or alter the
private captured class. The helper name is never emitted.

For HTTP/1.0, a captured `continue` class is ignored as `none` on every route
and no interim response is sent. For HTTP/1.1 or a higher HTTP/1 minor version,
status routes and `OPTIONS *` require `none`; `continue`, `unsupported`, and
`malformed` select application 417 `expectation_failed`. Process accepts
`none` or `continue`; `unsupported` and `malformed` select the same 417.
Those final outcomes set `Connection: close`, perform no application body read,
and emit no interim 100.

For a process request classified `continue` with content announced by a
positive `Content-Length` or accepted chunked transfer coding, every
header-determinable final decision is completed before an interim response.
This includes target, route, method, query, framing, media, capability,
already-expired deadline, readiness, and a known oversized `Content-Length`.
The known oversized `Content-Length` selects 413 before admission even when
process capacity is unavailable; it emits no interim response and owns no
permit or reservation. Any other such request never enters the ordinary
admission waiter queue. It atomically tries to acquire both one process permit
and the fixed 512 MiB reservation;
unavailability immediately selects 503 `service_overloaded`. After successful
acquisition it rechecks observed request cancellation, deadline, and readiness
in that fail-closed order. Any selected final response is committed immediately
without 100 and releases the acquired resources exactly once.

Only after those checks succeed does the handler require an empty response
header map and call `WriteHeader(100)` exactly once. Go synchronously flushes
that bare informational response, disables its automatic continue behavior,
and retains the ability to write the final response; the handler MUST NOT call
`ResponseController.Flush`, which would commit an unintended final 200. The
response-head filter forwards the 100 unchanged, adds no Date, Connection,
Content-Length, or other field, resets for the final response, and does not
release the connection cap. A terminal transport-write state observed
immediately after the call closes without body/domain work and releases the
permit and reservation once. A `continue` request with no announced content
emits no 100 and proceeds to its normal body classification.

For `POST /v1/process`:

- the request-target must contain no `?` delimiter, including an empty query;
- exactly one `Content-Type` field value must be semantically
  `application/json` with either no parameter or the sole `charset` parameter
  whose decoded value is `utf-8`; type, subtype, parameter name, and decoded
  charset value are compared case-insensitively, and RFC-valid optional
  whitespace plus either token or quoted-string spelling of `utf-8` is
  accepted. Quoted-pair decoding occurs before comparison. Empty parameter
  elements permitted by the RFC grammar are ignored; after they are removed,
  duplicate `charset`, MIME-style `charset*` or continuation names, malformed
  quoting/escaping, or any other nonempty parameter is rejected. Multiple
  field lines or comma/list values are 415;
- `Content-Encoding` must have no field occurrence; even an empty value,
  multiple values, or `identity` is rejected;
- request compression is never decoded;
- transfer chunking is allowed only through the standard bounded reader; and
- no forwarding, proxy, client-IP, or request-ID header is trusted.

M13 assigns no semantics to request trailers. Syntactically valid declared and
undeclared trailers remain in Go's separate `Request.Trailer` channel while the
body is read and are never merged into `Request.Header`. Immediately after the
body reaches chunk/trailer EOF and before JSON, OpenAPI, authentication
middleware, domain, DNS, policy, or replay work, the handler sets
`Request.Trailer` to nil; a deferred teardown repeats the clearing on every
exit. Trailer values are never inspected, retained, logged, formatted, traced,
or returned. In particular, trailer occurrences of `X-DKIM2-Capability`,
`Content-Type`, `Expect`, Host, or conditional fields cannot authenticate,
replace, extend, or influence their initial-header counterparts. Go-owned
pre-handler rejection of a prohibited declared trailer name remains 400.
Malformed or oversized chunk/trailer framing after handler entry is a bounded
400 `invalid_contract` when a response remains writable; a read timeout is 408
and a disconnect has no fabricated response. The process permit and reservation
remain owned through body EOF, trailer discard, mapping, and final response
ownership. An outer body-limit overflow retains precedence over a simultaneous
trailer parse error.

Both status routes support GET and HEAD. For either method, any `?` delimiter,
any `Content-Encoding` occurrence, a non-zero `Content-Length`, any
`Transfer-Encoding`, or any `Content-Type` is `invalid_contract`. OPTIONS and
POST on a status route are 405 with exact `Allow: GET, HEAD`.
`/v1/process` supports only POST; GET, HEAD, and OPTIONS there are 405 with
exact `Allow: POST`. These route-specific rules apply only after the
server-wide implemented-method decision to origin-form and accepted
absolute-form targets; authority-form CONNECT, unimplemented methods, and
`OPTIONS *` use their server-wide outcomes above. Unknown exact paths reached
by an implemented application method are 404 `not_found`.

`GET` and `HEAD` on each status route select a current representation only
when the same request without preconditions would produce 200. The handler
samples the complete content-free health/readiness state once, serializes the
corresponding compact GET representation into its bounded response buffer, and
derives one strong entity tag as DQUOTE, lowercase hexadecimal SHA-256 of those
exact representation bytes, and DQUOTE. HEAD derives the same bytes, length,
and tag but does not emit the bytes. The route sends that required `ETag` on
200 and 304. It intentionally sends no `Last-Modified`: liveness and readiness
have no stable stored modification timestamp, and fabricating one would create
false date-validator semantics.

RFC 9110 preconditions are evaluated only after all ordinary version, Host,
target, path, method, query, body-framing, media, Expect, and status-sampling
checks, and only when the unconditional status would be 200. An unconditional
400, 404, 405, 417, 500, or 503 wins and every precondition is ignored,
including malformed field values. On the 200 path, evaluation uses the RFC
order and the one sampled representation:

1. `If-Match` is parsed as `*` or the RFC entity-tag list. `*` succeeds because
   the current representation exists. A list succeeds only when one strong tag
   strongly matches the selected strong `ETag`; weak tags never strongly
   match. False selects 412 `precondition_failed`.
2. `If-Unmodified-Since` is ignored because no `Last-Modified` exists and is
   also ignored whenever `If-Match` is present.
3. `If-None-Match` is parsed as `*` or the RFC entity-tag list. `*` fails
   because the current representation exists. A list fails when any strong or
   weak member weakly matches the selected strong `ETag`. False selects 304
   for GET or HEAD.
4. `If-Modified-Since` is ignored because no `Last-Modified` exists and is
   also ignored whenever `If-None-Match` is present.

Multiple `If-Match` or `If-None-Match` field lines are combined in received
order under the RFC list grammar. Legal empty list elements are ignored. An
empty or only-empty `If-Match` list is therefore valid but has no strong match
and selects 412; an empty or only-empty `If-None-Match` list is valid, has no
weak match, and leaves the selected response at 200. A malformed entity tag or
opaque-tag octet, or `*` mixed with any other member, is 400
`invalid_contract` on the otherwise-200 path when that field is reached by the
ordered evaluation.

The entity-tag parser is byte-oriented and does not apply quoted-string
semantics. Comma is legal within an opaque tag, backslash is a literal octet
and is never unescaped, only exact case-sensitive `W/` denotes weakness, and
an empty opaque tag plus the RFC-permitted `obs-text` octets from 0x80 through
0xff are accepted. Comparison is bytewise with no Unicode, case, or escape
normalization. Parsing is linear within the fixed request-head bound, retains
no field bytes, and never formats a supplied tag.

No route supports ranges. Every `Range` and `If-Range` field is ignored without
parsing, and the service emits no 206, 416, `Accept-Ranges`, or
`Content-Range`. Date preconditions are likewise ignored without error when
invalid or list-valued as RFC 9110 requires. OPTIONS, CONNECT, unknown or
unsupported routes, and `POST /v1/process` ignore all five standard
precondition fields. The process operation is an action/report endpoint: its
200 body is a processing result, not a selected or current representation of
the `/v1/process` target resource, and the operation does not modify such an
HTTP representation.

The 304 response contains no content or trailers and uses exactly the minimal
header shape frozen above. A 412 status GET returns the bounded
`ErrorResponse` with code `precondition_failed` and category `request`; HEAD
returns the identical 412 representation metadata and `Content-Length` but no
bytes. Neither response echoes a field value or validator. Range and
precondition evaluation performs no readiness, provider, DNS, policy, replay,
or domain mutation beyond the one already-required content-free status sample.

Status operations do not consume or authenticate `X-DKIM2-Capability`; any
occurrence is ignored and never logged, formatted, traced, or returned.
`POST /v1/process` requires exactly one `X-DKIM2-Capability` field before
readiness, admission, body reads, OpenAPI validation, DNS, policy, or replay
work. Its value is exactly 43 ASCII unpadded Base64url characters that
canonically decode to 32 bytes. Leading or trailing whitespace remaining after
HTTP field-value normalization, padding, comma members, another field
occurrence, malformed Base64url, absence, or a value that does not
constant-time equal the loaded capability all select the same 403 `forbidden`
response. The mapper neither distinguishes nor formats the cause. The
successful outer preflight deletes every `X-DKIM2-Capability` entry from the
request header before installing its private boolean context marker. The
openapi3filter authentication function consults only that marker; generated,
domain, panic, and later middleware layers cannot access or reparse the
capability bytes.

Whenever an application-controlled final response is selected before a framed
request body has been fully consumed, the response sets `Connection: close`
and the connection is not reused. Before response commit, the owned
per-connection control sets the read deadline to the current time. If that
operation fails, the same control closes the tracked connection immediately,
the handler emits no fabricated application response, and domain/replay work
does not begin. Both operations are exactly-once safe and release the
connection-cap token through the same wrapper. This applies to path, method,
media, readiness, admission, limit, timeout, and malformed-body decisions as
applicable.

Go 1.26 still unconditionally closes the original request body after the
handler returns. Its server-side early-close path may discard bytes already
present in the fixed connection read buffer and is internally capped at
262,144 bytes, but the expired read deadline prevents waiting for or reading
future client bytes. That bounded, unparsed discard is included in the
resource model and is not described as absent. Tests observe reads at the
underlying connection, not merely calls through the handler-visible body. An
early final response selected before the explicit 100 boundary for a supported
`Expect: 100-continue` performs no application body read and emits no interim
100 response; the final response closes the connection. A fully consumed
successful or domain-error process request also
closes the connection after its single application response.

An absent or whitespace-only process body is `invalid_json`. Every body-bearing
application-controlled JSON success or error sets
`Content-Type: application/json` and `X-Content-Type-Options:
nosniff`, plus `Cache-Control: no-store`.

Every HEAD request that reaches the handler is evaluated exactly as the corresponding
GET request for target, status, readiness, representation metadata, and error
selection, then emits no body bytes. `Content-Length`, when present, is exactly
the octet length of that GET representation. Thus HEAD on the two status
routes returns the same 200/503 and headers as GET without content; HEAD on
`/v1/process` returns the GET-equivalent 405/`Allow: POST`; and HEAD on an
unknown target returns the GET-equivalent 404. Pre-handler Go failures are
made bodyless by the tracked-connection output filter. The two supported status
HEAD methods are explicit OpenAPI operations; other HEAD targets retain the
same transport semantic wrapper. Server-wide `OPTIONS *` 204, CONNECT 501, and
other server-wide 501 outcomes are the other handler-controlled no-body
responses.

After common protocol/Host/path/method/query/media checks, route behavior is
exactly:

| Route | Readiness | Admission/body/domain | Outcome |
| --- | --- | --- | --- |
| `GET /healthz` | ignored | never entered | 200 `HealthResponse` with singleton `alive` |
| `HEAD /healthz` | ignored | never entered | GET-identical 200 headers and no body |
| `GET /readyz` | sampled without I/O | never entered | 200 singleton `ready`, otherwise 503 `service_not_ready` |
| `HEAD /readyz` | sampled without I/O | never entered | GET-identical 200/503 headers and no body |
| `POST /v1/process` | required before and after admission | full process pipeline | closed process/error matrix below |
| `OPTIONS *` | ignored | never entered | server-wide 204 with exact `Allow` and no body |

Health therefore remains liveness while handler registration is open, even
when startup is incomplete, readiness is false, or process admission is
closed. Once the owned stopping transition closes handler registration, a
late entry is connection-closed without a fabricated response as specified by
the lifecycle contract. Readiness returns no component or reason.

Application-controlled process responses use this ordered precedence:

1. the incomplete-request-line raw target cap, but only when the second SP is
   still unavailable at the full capture bound, otherwise header-only 414;
2. Go request-line/header parsing and its early malformed or duplicate-Host
   400;
3. for a complete major-1, minor-1-or-higher head, transfer framing before
   supported-version and later Host checks: `bad_framing` is corrected or
   rejected as 400, `unsupported_final_chunked` remains Go 501, and
   `single_chunked` continues;
4. for a complete unsupported-major head, Go transfer parsing first: a coding
   or Content-Length form rejected by Go remains Go 501 or 400 respectively,
   while an actually Go-admitted transfer form, including exact chunked plus
   syntactically valid overridden Content-Length, continues to the version
   decision regardless of the private supported-HTTP/1 framing class;
5. supported HTTP/1 semantics plus Go/local mandatory Host presence and syntax,
   otherwise Go-owned or captured-metadata 400/505; after Go's checks but
   before local Host validation, the exact Go 1.26 HTTP/2-preface exception is
   intercepted as the explicit pre-handler header-only 505;
6. complete request-target at most 8,192 octets, otherwise header-only 414;
7. for HTTP/1.0 only, any captured Transfer-Encoding, otherwise 400 and close;
8. captured obs-fold within Expect, otherwise 400 and close;
9. method token within the 64-octet inspection bound, otherwise header-only
   501;
10. a method-appropriate origin/absolute target with the applicable exact
   authority rule, otherwise 400 `invalid_contract`;
11. exact server-implemented application method, otherwise header-only 501;
12. exact path or 404;
13. route-supported method or 405;
14. query, GET-body, captured Expect class, Content-Type,
    Content-Encoding, and remaining body-framing rules;
15. process local-capability authentication;
16. server deadline already elapsed;
17. readiness;
18. for `continue` with announced content, a known oversized
    `Content-Length`, otherwise Expect-specific nonblocking admission; for
    every other process request, ordinary queued admission;
19. the remaining outer body-limit cases;
20. body-read and trailer completion or classified server read timeout;
21. trailer discard;
22. JSON lexical preflight and JSON resource accounting;
23. bounded extraction of API version, then draft;
24. known-field encoded/decoded resource preflight;
25. OpenAPI schema validation;
26. canonical Base64 decoding; and
27. domain processing.

This list records the deliberate Go-version exceptions: a complete-head
HTTP/1.1 framing failure can preempt later 505, 414, or 501 decisions, and a
complete unsupported-major transfer-coding 501 can preempt its later 505,
whereas the early raw incomplete-target 414 has no complete head from which to
derive that fact. In HTTP/1.0, Go discards Transfer-Encoding before handler
entry, so the complete target-length check precedes the captured-fact 400.

After lexical safety, the constant extractor accepts only string members at
the exact root names. Missing or non-string values are `invalid_contract`; a
wrong string value is `unsupported_version` or `unsupported_draft`. Version is
checked before draft. These stable codes therefore remain reachable despite
the same singleton enums in OpenAPI. They precede unknown-field and other
schema findings. Once a higher-precedence condition selects an error, lower
layers do no additional parsing, network work, or mutation. A MaxBytesReader
overflow dominates a simultaneous JSON error.

A timeout returned while the application is reading an incomplete process body
under the effective Go per-request read deadline stops before JSON, domain,
DNS, or replay work and selects RFC 9110 status 408 `request_timeout` if a
response can still be written. It sets `Connection: close`; unread bytes are
never reused as another request. A client disconnect or other non-timeout
socket read error stops the request without fabricating an application result
and may leave no writable response. Neither branch formats, unwraps, or emits
the raw I/O error.

After the complete request body has been received, expiration of the owned
handler deadline is rechecked at every stage boundary. Before possible replay
mutation it selects 503 `request_deadline`; during verifier execution this
local timeout is distinguished by its owned context cause from a
resolver-owned timeout. After possible mutation it follows the HTTP 200
indeterminate rule. Client-originated cancellation remains no fabricated
response.

Malformed syntax, malformed UTF-8, lone/reversed/invalid surrogate escapes,
duplicate object names after escape decoding, trailing values, and trailing
non-whitespace bytes are 400 `invalid_json`. They are rejected by lexical
preflight before constant extraction or OpenAPI validation. Syntactically
valid JSON that exceeds depth, token, decoded member-name,
API-version-string, or draft-string limits is 413 `request_too_large`. A
version or draft string within its resource cap but different from the
supported singleton is respectively
`unsupported_version` or `unsupported_draft`. Before general OpenAPI
validation, the local resource preflight checks raw Base64 encoded length,
recipient count, schema character lengths, decoded UTF-8 per-path and
aggregate envelope bytes. Those maxima and their maximum-plus-one cases are
413 even though the OpenAPI document repeats `maxLength`/`maxItems`. Ordinary
missing, type, enum, and unknown-field schema failures remain 400
`invalid_contract`. After schema validation, invalid canonical Base64 is 400
`invalid_contract`; a canonical string that decodes one byte over the
raw-message maximum is 413.

The application status matrix is:

| Status | Code and condition |
| ---: | --- |
| 200 | complete domain result, including FAIL, PERMERROR, TEMPERROR, or post-mutation replay indeterminate |
| 304 | status-route `If-None-Match` false for the current selected representation; no error object or content |
| 400 | `invalid_json`, `invalid_contract`, `unsupported_version`, or `unsupported_draft` |
| 403 | `forbidden` for absent, malformed, duplicate, or mismatching local capability |
| 404 | `not_found` |
| 405 | `method_not_allowed`, with exact `Allow` |
| 408 | `request_timeout` while receiving an incomplete request body, with connection close |
| 412 | status-route `precondition_failed` for false `If-Match` |
| 413 | `request_too_large` |
| 415 | `unsupported_media_type` |
| 417 | application `expectation_failed` for invalid forms that reached the handler |
| 500 | `internal_error` for panic or impossible mapper/generated invariant |
| 503 | `service_not_ready`, `service_overloaded`, or local `request_deadline` before replay mutation |

Categories are `request` for 400/403/404/405/408/412/413/415/417,
`availability` for 503, and `internal` for 500. Domain HTTP 200 and
status-route 304 have no error object.
HEAD carries no serialized code/category/body, but its status and
representation headers are exactly those selected for the corresponding GET.
Header-only 414 is an outer request-target-limit response and server-wide 501
is an outer transport capability response. Both use `Content-Length: 0` and
add no application error code.

An application-owned handler deadline before possible replay mutation is a
local availability failure and uses 503 `request_deadline`, not gateway status
504. A DNS resolver's own lookup timeout while the handler context remains live
is a verification `TEMPERROR` and HTTP 200. M13 emits no 504 response. Client
cancellation may leave no writable response and never fabricates a protocol
result.

After a replay mutation may have been dispatched, security classification
dominates transport timeout: the replay class is `indeterminate`, the final
disposition is `tempfail`, and the handler attempts the complete HTTP 200
domain response if the connection is still writable. It does not claim that a
client received that response.

The JSON guarantee applies only after a request reaches the application path
gate. Malformed request lines, oversized headers, read-header timeout, TLS-free
socket failures, Go-owned unsupported HTTP versions/505, malformed HTTP
field-line syntax, client disconnects, and write timeout are owned by
`net/http`; they may close the
connection or use a standard non-JSON response. The exact HTTP/2-preface tuple
is instead owned by the explicit outer pre-handler protocol gate and always
uses the frozen header-only 505 shape above.
Tests prove these pre-handler paths cannot expose application secrets or
application-derived diagnostics. The specification does not promise an
impossible JSON rewrite below the handler boundary.

The adapter maps and marshals every body-bearing success or error into an owned
bounded buffer before writing headers. Error JSON is at most 4,096 bytes and
success JSON at most 262,144 bytes. It validates the mapped DTO, buffer bound,
and closed enums before committing one status, exact Content-Length, and body.
HEAD computes the corresponding GET mapping only to derive status and headers
and suppresses the body; server-wide OPTIONS/CONNECT bypass body mapping and
obey their exact header contracts above.
Mapper/encoder panic before commit can therefore become `internal_error`.
A socket short write after commit cannot be rewritten; tests prove the already
validated buffer contains no protected data and the failure triggers no raw
diagnostic.

## Resource And JSON Preflight

The decoded raw RFC 5322 maximum is the public
`dkim2.HardMaxRawMessageBytes`: 33,554,432 bytes. Its maximum canonical padded
Base64 spelling is 44,739,244 bytes.

The raw-message parser and recipe engine share a non-configurable hard maximum
of 65,536 indexed body lines. `rawmsg.ParserOptions.MaxBodyLines` defaults to
that value, rejects values outside 1 through 65,536, and `indexBodyLines`
returns the typed `limit_exceeded`/`max_body_lines` result before allocating or
appending line 65,537. Exactly 65,536 lines remain accepted and byte-preserved.
This is a local implementation resource ceiling, not an RFC 5322 syntax rule;
the public verifier preserves its existing `PERMERROR`/`ReasonLimitExceeded`
outcome rather than misclassifying the message as malformed. The cap is
aligned with recipe application and generation so no earlier raw-message
index can exceed the later recipe owner.

The current envelope accepts the public `dkim2.HardMaxRecipients` value of
2,000 forward paths plus one reverse path. RFC 5321 and the shared library
owner bound every path to 256 UTF-8 octets, so the simultaneous decoded
envelope maximum is 512,256 bytes. JSON escaping may expand each envelope byte
to at most six ASCII bytes. A fixed 65,536-byte structural allowance covers
object names, delimiters, exact version/draft values, and whitespace. The exact
outer body limit is therefore:

`44,739,244 + (512,256 * 6) + 65,536 = 47,878,316` bytes.

Per-request limits are not an aggregate memory policy. Before reading any
process body, admission reserves one fixed 536,870,912-byte working-set unit
from a non-configurable 1,073,741,824-byte process-request budget. Every
request uses one full unit regardless of `Content-Length`; chunked and absent
length therefore cannot under-reserve. The reservation accounts
conservatively for the encoded body, OpenAPI generic validation, generated
protected strings, canonical decode, public/internal immutable request clones,
raw-message parsing, envelope copies, bounded response, and fixed overhead.
Waiters allocate no request-sized application body buffer and hold no
working-set unit; bounded bytes may already exist in the HTTP connection's
parser/socket buffers, transferred request-prefix/first-head backing, and
response-head filter. They are covered by the fixed 128-connection limits of
69,632 request-head plus 16,384 response-head bytes per connection; the prefix
and first-head capture never overlap as separate allocations. At most two
units can be owned, matching the hard `server.max_in_flight` maximum; the
secure default owns one.

Acquisition is atomic with the process admission permit and occurs before
`MaxBytesReader`, JSON scanning, or any request-sized allocation. Release
happens only after every request-owned DTO, buffer, decoded value, domain
request/result, and response buffer is unreachable. An implementation
ownership inventory plus a maximum-input allocation harness must prove one
legal request stays below the 512 MiB reservation, including transient
overlap; exceeding the reservation is a release blocker, not permission to
raise it silently.

The normative 512 MiB proof is the peak sum of all simultaneously live
request-owned capacities and fixed per-request storage, including transient
overlap while a buffer, wrapper, DTO, decoded value, immutable clone, domain
value, or response is copied, grown, converted, replaced, or released. A
reviewed ownership inventory supplies conservative upper bounds for library-
or runtime-owned objects that the boundary cannot instrument directly, and
boundary-owned allocations maintain checked live-byte and high-water
accounting across every ownership transfer and release. The isolated
maximum-legal-input harness MUST prove that high-water total is strictly less
than 536,870,912 bytes. Allocation counts and process RSS MAY be supplemental
evidence only. Go `TotalAlloc` is cumulative rather than a peak-live ownership
measure and MUST NOT be used as the normative proof.

`http.MaxBytesReader` is installed before any body decoder. Exact simultaneous
maximum and maximum-plus-one tests prove the outer value. Lower decoded limits
are also checked independently; no legal combination of all individual maxima
is preempted.

The process body is read exactly once into one bounded request-owned encoded
buffer. JSON preflight, the OpenAPI validator, and generated decoding receive
fresh readers over those same bytes; they do not reread the socket or make
unbounded duplicate buffers. The encoded buffer and decoded raw-message bytes
are released after the request and never retained in readiness, errors, or
diagnostics.

The remaining fixed JSON bounds are nesting depth 32, 8,192 RFC 8259 lexical
tokens, and 64 decoded UTF-8 bytes per object-member name. RFC 8259 Section 2
owns token membership: each of the six structural characters `{`, `}`, `[`,
`]`, `:`, and `,`, each string, each number, and each literal name `false`,
`null`, or `true` is one token; insignificant whitespace is not a token. The
scanner charges each token before accepting it, so token 8,192 is accepted and
token 8,193 selects 413 `request_too_large`. Nesting depth is the number of
currently open array or object containers after accepting their opening
structural character: a root container has depth one, a root scalar has depth
zero, depth 32 is accepted, and opening container 33 selects 413 before any
child token is accepted. API version is capped at 16 decoded bytes and draft
at 128 before comparison. These values safely cover the fixed schema and
2,000 recipient strings. The scanner skips unknown scalar value bodies without
retaining them and keeps only bounded decoded member names per object. It:

- accepts exactly one RFC 8259 JSON text;
- rejects malformed UTF-8;
- validates `\u` escapes as Unicode scalar values, accepting a valid surrogate
  pair and rejecting lone, reversed, or otherwise invalid surrogates;
- detects duplicates after escape decoding, so `api_version` and
  `api_\u0076ersion` collide;
- rejects depth or token exhaustion before generated decoding;
- rejects trailing values and non-whitespace bytes;
- rejects non-string object names; and
- retains no request-derived spelling in errors.

JSON string decoding converts scalar values to exact UTF-8 bytes. It never
uses replacement runes and performs no NFC/NFD, case, IDNA, local-part,
domain-literal, or EAI normalization.

The raw-message string rejects every byte outside the standard Base64 alphabet
and final padding position, including CR, LF, space, tab, URL-safe alphabet,
missing or excess padding, data after padding, and non-zero pad bits. It uses
`base64.StdEncoding.Strict()` and then requires byte-for-byte equality with
canonical padded re-encoding. The decoded size is checked before constructing
domain copies. Tests cover zero bytes, one/two/three-byte boundaries, 32 MiB,
maximum plus one, pad bits, CRLF, and the generator string-type invariant.
Its JSON string token must spell every Base64/padding character as literal
unescaped ASCII; `\u` or other JSON escapes are rejected for this property even
when they would decode to the same character. This preserves one canonical
wire spelling and makes the exact outer-size proof valid.

## Processing Pipeline

One immutable process service owns this sequence:

1. map the already validated wire values to exact UTF-8 envelope bytes and raw
   RFC 5322 bytes;
2. construct `dkim2.NewVerifyRequest` without normalization;
3. call the configured `Verifier.Verify` using the daemon request context;
4. require one valid, complete public verification result;
5. call `dkim2.EvaluatePolicy` with the one server-configured M7 mode;
6. require one valid, complete immutable policy decision;
7. apply the replay gate and coordination contract below;
8. derive the one final disposition; and
9. map immutable domain values into the exact generated response DTO.

Generated strict DTOs are never the process service's domain model. Unknown,
zero, incoherent, or impossible public result values are an `internal_error`;
the mapper never emits a partial success.

Verification state, policy decision, replay aggregate, and final disposition
remain separate. Replay may change only final disposition. It MUST NOT rewrite
verification state, verification facts, policy mode, policy verdict, policy
reason, findings, feedback, or compliance.

Panic recovery exists only at the outer HTTP containment boundary. A recovered
panic marks readiness false, requests orderly Fx shutdown, and returns only
`internal_error` if a response is still possible. A panic after possible
replay mutation never becomes success.

## Replay Gate, Batch, And Disposition

### Gate

Replay is output-neutral for every non-PASS result and for policy verdict
`reject`, `tempfail`, or `continue`. Those cases emit `not_checked`, do not
construct identities or keys, do not call a store, and preserve the policy
verdict as final disposition.

For verification `PASS` plus policy `accept`:

- an explicitly configured disabled backend emits `disabled` and final
  `accept` without loading an HMAC secret, constructing a deriver, deriving an
  identity or key, or calling a store;
- memory or Valkey follows the enabled batch below.

Authenticated exploded state is output-neutral and never bypasses this gate or
changes replay retention.

### Enabled batch

`dkim2.ReplayIdentities` is called with the exact `VerifyResult` returned by
the verifier. The returned `ReplayIdentitySet` already owns canonical
deterministic recipient order. M13 iterates `Identity(0)` through
`Identity(Len()-1)` unchanged. It MUST NOT inspect protected identity bytes or
invent a second sort key.

All identities are derived into opaque `ReplayKey` values before the first
store call. Any identity-set or derivation failure yields zero store calls,
`indeterminate`, and final `tempfail`. An unexpectedly empty set is the same
closed failure.

Terminal request context has precedence over an ordinary identity or
derivation error while no store dispatch has occurred. The coordinator checks
context before identity construction, before and after each derivation, and
immediately before the first store call. If the context is terminal at any of
those boundaries, it uses the transport cancellation/deadline rule rather
than fabricating an HTTP 200 replay aggregate. A derivation error while
context remains live retains the zero-write `indeterminate`/`tempfail` rule.

After successful preflight, the coordinator calls `CheckAndRemember`
sequentially in set order with the same validated
`dkim2.DefaultReplayRetention()` or the configured retention. Ordinary
typed store failures are recorded and processing continues for every remaining
identity while the request context remains live. The coordinator does not stop
on the first replay or ordinary backend failure.

The coordinator owns an explicit `possibleMutation` fact rather than equating
method entry with dispatch. It becomes true after `first_seen`, typed
`indeterminate`, an unknown error, an invalid/contradictory result, or any
other outcome whose M12 contract cannot prove pre-dispatch refusal. An
authoritative `replayed` result does not set it. M12 typed `cancelled` and
`deadline_exceeded` are guaranteed pre-dispatch for that call.

On typed context failure, or context termination between calls, the
coordinator stops. If `possibleMutation` is false, including after zero or more
authoritative `replayed` outcomes or while provider admission was still
waiting, it uses the client-cancellation/local-503 transport rule and emits no
HTTP 200 aggregate. If `possibleMutation` is true, security classification
dominates transport: replay is `indeterminate`, final disposition is
`tempfail`, and the handler attempts the complete HTTP 200 result if writable.
The implementation does not dispatch new storage work under a terminal
context merely to satisfy the ordinary-error continue rule.

### Ordered aggregate

The enabled aggregate uses this precedence:

1. any typed error, unknown error, invalid result, enabled-store `disabled`
   result, contradiction, or possible partial mutation => `indeterminate`;
2. otherwise, one or more `replayed` results, with all remaining results
   `first_seen` => `replayed`;
3. otherwise, every result `first_seen` => `first_seen`;
4. every other combination => `indeterminate`.

An enabled provider can never produce aggregate `disabled`. Mixed
`first_seen`/`replayed` is `replayed`; any mixture containing `disabled` is
`indeterminate`. M12 error codes remain internal closed classification and all
map to `indeterminate` for the privacy-minimal REST aggregate.

The exact final matrix is:

| Verification/policy gate | Replay class | Final disposition |
| --- | --- | --- |
| non-PASS, any policy | `not_checked` | policy verdict |
| PASS + `reject` | `not_checked` | `reject` |
| PASS + `tempfail` | `not_checked` | `tempfail` |
| PASS + `continue` | `not_checked` | `continue` |
| PASS + `accept`, configured disabled | `disabled` | `accept` |
| PASS + `accept`, enabled | `first_seen` | `accept` |
| PASS + `accept`, enabled | `replayed` | `reject` |
| PASS + `accept`, enabled | `indeterminate` | `tempfail` |

No identity, storage key, recipient, provider kind, provider state, error code,
or result count is serialized or logged.

## Configuration Contract

### Version, stability, and sources

The YAML root requires `config.version: dkim2d-config-v1`. The version must be
present in YAML and cannot be overridden by environment or flag. Every path
listed in this section is stable from the first M13 release through the
complete `0.1.x` release line. A rename, removal, type change, default change,
or semantic inversion requires an architecture/spec amendment, migration
notes, examples, and compatibility tests.

The `dkim2d serve` command requires `--config <absolute-path>`. It uses one
fresh Viper instance with `AllowEmptyEnv(true)` and without `AutomaticEnv`.
Precedence is:

1. typed defaults;
2. the one explicit YAML document;
3. explicitly bound environment variables; and
4. the three allowed configuration flags.

The only configuration flags besides `--config` are:

| Flag | Path |
| --- | --- |
| `--listen` | `server.listen` |
| `--policy-mode` | `policy.mode` |
| `--replay-backend` | `replay.backend` |

Standard Cobra help behavior is not configuration. No secret,
credential, trust bytes, HMAC bytes, attestation value, retention, or Valkey
address can be supplied as a flag.

Every stable operational path other than YAML-only `config.version` and
`protected.generation` has one exact environment name: `DKIM2D_` followed by
the path uppercased with each dot replaced by one underscore. Thus
`server.listen` is
`DKIM2D_SERVER_LISTEN` and `replay.hmac_key_file` is
`DKIM2D_REPLAY_HMAC_KEY_FILE`. The implementation contains a literal allowlist
of every path/name pair and tests the mechanical mapping; it does not derive
or accept arbitrary variables at runtime. Secret bytes are never environment
values. Protected file paths may be.

Viper is used only as a checked merger of known source values. Before invoking
it, the loader captures an owned per-leaf record from the preflighted YAML
node, each literal `os.LookupEnv` result, and each Cobra flag's `Changed`
state. It selects the winner by the declared precedence while retaining source
kind and explicit presence. Typed defaults are applied only after that
presence/provenance map is frozen. The same layers are given to the fresh
Viper instance, and its known-key result must equal the owned canonical merge;
a mismatch is an internal configuration failure. The loader never uses
Viper's weak conversion or rereads Viper after snapshot creation.

Scalar conversion is exact:

- string, enum, address, username, and path leaves accept their winning string
  spelling after permitted placeholder expansion;
- boolean YAML leaves must be native scalars spelled exactly `true` or
  `false`; an environment override or exact whole-placeholder uses the same
  lowercase grammar;
- unsigned integer YAML leaves use canonical decimal `0` or
  `[1-9][0-9]*` with no sign, separators, exponent, or whitespace; environment
  overrides and exact whole-placeholders use the same grammar before checked
  range conversion; and
- duration leaves from YAML or environment use one positive canonical token
  `[1-9][0-9]*(ms|s|m|h)` followed by checked `time.ParseDuration` and
  field-specific range/unit validation. The only zero-duration spelling is
  singleton `0s`, accepted only for `server.admission_wait`.

For a non-string boolean or integer leaf, a YAML string is valid only when it
is exactly one `${NAME}` placeholder. Duration leaves are string-valued by
contract and may be either one literal canonical duration or one exact
placeholder. Adjacent, embedded, or mixed literal/placeholder expansion is
allowed only for destination string leaves. Unknown fields, missing required
values, empty required strings, invalid provenance/type combinations, and
values outside exact ranges fail with stable field codes and no values.

### Raw YAML preflight

The configuration file is opened once through the descriptor-safe path
resolver and retained until the complete protected generation bundle has
loaded. Before reading, `fstat` and ACL inspection prove a regular file,
effective-UID ownership, mode 0400 or 0600, link count one, and the closed ACL
policy. It is read through that same descriptor with a 262,144-byte cap plus
one and exact EOF. Immediate post-read metadata and ACL state must equal the
pre-read state across device, inode, type, UID, mode, link count, size,
modification time, and change time. Those exact bytes, not a reopened path,
are passed to Viper after preflight. Before Viper sees them, a YAML-node
preflight requires exactly one document, mapping root, maximum depth 32,
maximum 4,096 nodes, and string mapping keys. Every key must use the exact
lower-case declared spelling;
case variants that Viper would conflate are rejected. The raw node tree is
validated against the exact declared nested schema before Viper: unknown
mapping nodes, including empty maps, are rejected, and a component key may not
contain `.`. Dotted flat aliases such as `server.listen` therefore cannot
shadow the canonical `server: {listen: ...}` hierarchy. The preflight rejects
duplicate decoded keys at every mapping, semantic duplicates across alternate
hierarchies, anchors, aliases, merge keys, explicit/custom tags, complex keys,
multiple documents, trailing non-comment content, cyclic graphs, and every
implicit or explicit YAML null scalar (`null`, `Null`, `NULL`, `~`, or an
empty value). Null never means absent, defaulted, or present-without-value.
Each scalar is at most 65,536 decoded bytes.

Map keys are never environment-expanded. Scalar strings support one
non-recursive pass over zero or more placeholders with exact grammar
`${NAME}`, where `NAME` matches `[A-Za-z_][A-Za-z0-9_]*`. There is no default,
operator, nesting, or escape syntax. A literal `${` must therefore form one
valid placeholder. `os.LookupEnv` distinguishes missing from present-empty;
missing fails, while present-empty is passed to later typed validation.
Replacement text is not rescanned. `config.version` and
`protected.generation` are excluded from placeholder expansion.
`config.version` must already equal the exact literal `dkim2d-config-v1`;
`protected.generation`, when required, must already match
`^[a-f0-9]{32}$`. `${...}` is rejected in both.
After file/env/flag merge, the loader
charges the decoded bytes of every scalar key and value, including environment
and flag values, before allocating expanded copies. Both the pre-expansion and
post-expansion aggregate are at most 262,144 bytes, and every expanded scalar
remains at most 65,536 bytes.

### Stable paths, defaults, and ranges

Server paths and values are exactly the HTTP table:

- `server.listen`, default `127.0.0.1:8080`;
- `server.capability_file`, required absolute protected capability path;
- `server.read_header_timeout`, default `5s`;
- `server.read_timeout`, default `30s`;
- `server.write_timeout`, default `65s`;
- `server.request_deadline`, default `60s`;
- `server.shutdown_timeout`, default `30s`;
- `server.max_in_flight`, default `1`, range 1 through 2;
- `server.max_waiters`, default `64`;
- `server.admission_wait`, default `100ms`.

The exact ranges are those in the HTTP table and are cross-validated, including
read-header timeout being no greater than whole-request read timeout, read
timeout being no greater than request deadline, and write timeout being at
least request deadline plus one second.

`policy.mode` defaults to `strict` and accepts only `strict`, `permissive`, or
`testing`.

DNS exposes only:

- `dns.lookup_timeout`, default `5s`, range 1 ms through 30 s;
- `dns.max_concurrent_lookups`, default 64, range 1 through 1,024;
- `dns.cache.max_entries`, default 4,096, range 0 through 65,536;
- `dns.cache.positive_ttl_cap`, default 1 hour, range 0 through 24 hours;
- `dns.cache.negative_ttl_cap`, default 5 minutes, range 0 through 1 hour; and
- `dns.cache.stable_error_ttl_cap`, default 1 minute, range 0 through 5 minutes.

Zero disables the cache as a whole or the corresponding lifetime class. TTL
settings are caps, not synthetic lifetimes: the effective lifetime is the
shorter of DNS TTL evidence and the configured cap. Positive answers retain
the shortest TTL across the CNAME chain. NXDOMAIN and NODATA use the RFC 2308
minimum of SOA TTL and SOA MINIMUM. Answers without positive or negative TTL
evidence are not cached. The values replace the matching defaults only within
the public hard bounds; widening away from the secure default is therefore
explicit and visible in typed configuration. Every other default remains frozen:
selector/signing-domain/owner 253 bytes and 127 labels where applicable, one
TXT record of at most 8 KiB, 32 tags, tag-name 63 bytes, tag-value and decoded
key 8 KiB, and 64 coalesced waiters.

The process cache keeps one mutex around a key map, a doubly linked LRU list,
and an indexed expiry min-heap. Hits and LRU eviction are constant-time;
insertion and expiry maintenance are logarithmic. A complete map scan is
reserved for a detected internal-index corruption repair path and is not part
of normal admission.

`protected.generation` is a required YAML-only lowercase 128-bit hexadecimal
generation identifier for every replay backend. It binds the YAML snapshot to
the immutable protected bundle containing at least the process capability and,
when applicable, replay secrets described below; it is not secret, an
environment override, a placeholder target, or a reload signal.

Replay has these provider-neutral stable paths:

- `replay.backend`, default `valkey`, enum `valkey`, `memory`, `disabled`;
- `replay.hmac_key_file`, required for `valkey` and `memory`;
- `replay.epoch`, required for `valkey` and `memory`, integer 1 through
  4,294,967,295;
- `replay.retention`, default `336h` (fourteen days), range `1s` through
  `720h`, with exact whole-millisecond representation;
- `replay.limits.max_entries`, default 65,536, maximum 1,048,576;
- `replay.limits.max_waiters`, default 1,024, maximum 65,536;
- `replay.limits.prune_budget`, default 4,096, maximum 65,536;
- `replay.limits.max_in_flight`, default 1,024, maximum 65,536;
- `replay.limits.max_admission_waiters`, default 1,024, maximum 65,536; and
- `replay.revalidate_interval`, Valkey-only, default `30s`, range `10s`
  through `60s`.

All replay limits are positive. The memory backend injects one instance-owned
`time.Now` clock through `dkim2.ReplayClockFunc`; there is no clock config path.

Valkey-only stable paths are:

- `replay.valkey.address`, required canonical IP-literal `host:port`;
- `replay.valkey.server_name`, required exact M12-valid TLS identity: either
  canonical IP text or a 1-through-253-byte lowercase ASCII DNS name;
- `replay.valkey.ca_file`, required absolute protected trust path;
- `replay.valkey.application_username`, required M12-valid ACL username;
- `replay.valkey.application_password_file`, required absolute secret path;
- `replay.valkey.auditor_username`, required M12-valid distinct ACL username;
- `replay.valkey.auditor_password_file`, required absolute secret path;
- `replay.valkey.dial_timeout`, default `2s`, range `100ms` through `30s`;
- `replay.valkey.tcp_keepalive`, default `30s`, range `1s` through `5m`;
- `replay.valkey.connection_write_timeout`, default `2s`, range `100ms`
  through `30s`;
- `replay.valkey.attestation.persistence_mode`, required enum `rdb`, `aof`,
  `rdb_aof`;
- `replay.valkey.attestation.append_fsync_policy`, required enum `inactive`,
  `always`, `everysec`;
- `replay.valkey.attestation.save_schedule`, required/forbidden according to
  the exact M12 persistence grammar;
- `replay.valkey.attestation.min_replicas_to_write`, integer 0 through 3;
- `replay.valkey.attestation.min_replicas_max_lag_seconds`, integer 1 through
  3,600;
- `replay.valkey.attestation.loss_window_acceptance`, singleton
  `asynchronous_acknowledged`;
- `replay.valkey.attestation.rotation_state`, enum `unchanged`,
  `drain_completed`; and
- the required booleans
  `no_global_exactly_once_claim`, `dedicated_deployment`,
  `dedicated_database_zero`, `direct_ip_authority`,
  `no_endpoint_substitution`, `standalone_authority`, `shared_draft`,
  `shared_algorithm`, `shared_namespace`, `shared_epoch`,
  `shared_secret_set`, and `shared_retention`.

Every attestation leaf has explicit pre-default presence. This includes all
enums, both replica integers, the singleton acknowledgment, rotation state,
every boolean, and `save_schedule` when its mode requires it; no attestation
leaf receives a decoded zero-value default. In particular,
`min_replicas_to_write: 0` is valid only when explicitly supplied.
`save_schedule` remains explicitly forbidden in modes where M12 forbids it.
Every attestation boolean must be true. The complete combination must be
accepted by `valkey.NewOperatorAttestation`; M13 adds no alternative.

M13 populates non-configurable `ClientConfig` invariants from constants:
standalone-primary topology, database zero, empty client name, cache disabled,
retry disabled, exact DKIM2 draft, exact
`dkim2-replay-hmac-sha256-v1` algorithm, exact `dkim2:replay:v1:` namespace,
minimum retention one second, and maximum retention thirty days. They are not
operator paths and cannot be overridden.

### Backend-conditional key matrix

The raw presence/provenance map is retained through validation across YAML,
direct environment bindings, and changed flags, before defaults. A forbidden
key supplied by any source cannot hide behind a higher-precedence value or a
default. A YAML whole-placeholder counts as explicit presence of its YAML
leaf. An unbound placeholder environment name does not become a config path,
but a name that is also in the literal `BindEnv` allowlist retains independent
presence for its own mapped path even when referenced as a placeholder
elsewhere.

| Backend | Required | Optional/defaulted | Forbidden |
| --- | --- | --- | --- |
| `disabled` | protected generation, server capability file, and `replay.backend` | none | every other `replay.*` key |
| `memory` | protected generation, server capability file, backend, HMAC file, epoch | retention and replay limits | revalidate interval and every `replay.valkey.*` key |
| `valkey` | protected generation, server capability file, HMAC file, epoch, all required Valkey authority/attestation fields | backend (defaults to Valkey), retention, replay limits, revalidate interval, Valkey timeouts | none of the declared Valkey paths |

The process capability is a common server requirement, not a replay setting.
The default backend is Valkey, but missing its required authority fails
configuration; it never falls back to memory or disabled. The disabled backend
loads only the process capability; it does not load a replay secret, construct
a deriver, apply replay defaults, or create a store dependency beyond
`NewReplayDisabledStore`.

## Protected Files And Redaction

For every backend, the process capability path is a direct child of one
absolute protected generation directory. For memory or Valkey, every HMAC,
password, and CA path is another direct child of that same directory. Its
final path component must
equal the YAML-only `protected.generation` token, all protected paths must
resolve through the same opened directory inode, and no nested subdirectory is
allowed. The generation directory is owned by the effective UID, mode 0500,
and free of nontrivial ACLs. The loader opens it once, records a pre-bundle
descriptor stat, opens and prechecks every required child relative to that
descriptor before reading any child, then reads them and performs the complete
final checks below. It finally requires an identical post-bundle stat including
device, inode, type, UID, mode, link count, size, modification time, and change
time. The YAML config path is outside and inode-distinct from the bundle.

Operators create a complete new read-only generation directory, then atomically
replace the YAML file with a snapshot naming that new generation. They never
replace children within an active generation or reuse a generation token.
Because the already-read YAML selects one immutable directory inode, atomic
replacement before, between, or after child reads cannot mix the process
capability, epoch/HMAC, application/auditor credentials, or trust roots from
different generations.
Any bundle-directory metadata change during load fails closed. M13 has no
reload; a new generation becomes active only on restart.

Every config, process-capability, password, HMAC, and CA path is absolute,
cleaned, and opened with no-follow, nonblocking, and close-on-exec semantics.
Each path component is
resolved relative to owned directory descriptors using directory-only,
no-follow, close-on-exec flags; the final descriptor uses read-only,
no-follow, close-on-exec, and nonblocking flags. Symlinked components and
group/other-writable parent directories are rejected. Parent directories are
owned by root or the effective UID. Before the content open, descriptor-
relative `fstatat` with no-follow semantics requires a regular file; FIFO,
device, and socket entries are rejected at that preflight. The subsequent
opened descriptor must have the same device/inode/type and pass the complete
checks below. Secure parent ownership prevents an untrusted user from
substituting a special inode between those steps. `O_NONBLOCK` is defense in
depth, not a false claim that every device driver or regular-file filesystem
syscall is context-cancellable or wall-clock bounded; the supported local
filesystem/kernel availability prerequisite still applies. A protected path
is at most 4,096 UTF-8 bytes, has at most 64 non-empty components, and each
component is at most 255 bytes; these bounds are checked before descriptor
traversal.

Validation and bounded reading use the same final descriptors. Before any
child content is read, every required child is open and has passed `fstat` and
ACL preflight proving a regular file, expected effective-UID ownership,
accepted mode, link count, and size. Secret files require link count one. The
loader then reads each retained descriptor through cap plus one and requires
exact EOF. An immediate post-read `fstat`/ACL check must match that child's
pre-read state. After every child is read, the loader repeats `fstat` and ACL
inspection on every still-open child and requires equality with both its
pre-read and immediate post-read state, then performs the final directory
check. This ordering catches a completed same-inode rewrite of an earlier or
later child during any other child read. Protected generation children are
never replaced or rewritten. Rotation creates a never-reused generation
directory/token and atomically replaces only the YAML config that selects it.
A string-path precheck is not trusted for security.
After the final all-child and generation-directory checks, the still-open YAML
descriptor receives one final `fstat` and ACL inspection equal to its pre-read
and immediate post-read states. A YAML hard link, same-inode rewrite, or
metadata/ACL change during any protected child load therefore fails before
readiness; the YAML and every child descriptor close exactly once afterward.

Mode bits are not the complete access policy. Every traversed directory, the
generation directory, the YAML config, and every protected file is checked
through its already-owned descriptor with `fstatfs` before ACL classification.
Linux accepts only the local filesystem types identified by
`EXT4_SUPER_MAGIC`, `XFS_SUPER_MAGIC`, `BTRFS_SUPER_MAGIC`, or `TMPFS_MAGIC`.
Darwin accepts only exact `apfs` or `hfs` filesystem type names. NFS, CIFS/SMB,
FUSE, OverlayFS, network, automount, and every unknown or unproven filesystem
fail as unsupported even when POSIX ACL xattrs appear absent. This allowlist is
the explicit local-filesystem and access-model prerequisite; it is not widened
by configuration. Inspectors never shell out or reopen a pathname.

On Linux, a build-tagged `x/sys/unix` implementation reads both
`system.posix_acl_access` and, for directories, `system.posix_acl_default`
through descriptor-based `fgetxattr`. Before that, descriptor-based
`flistxattr` performs a size probe, caps the exact NUL-separated name list at
65,536 bytes and 256 names, rejects malformed/growing/truncated lists, and
rejects every `system.*` name other than those two POSIX ACL names. Other
xattr namespaces on the allowlisted filesystems cannot bypass Unix DAC; LSM
security labels may only add checks after DAC. Each ACL read performs its own
size probe, caps returned bytes at 65,536 and decoded entries at 256, then uses
cap-plus-one/growth checks. An absent access ACL or an access ACL containing
only the three base owner/group/other entries whose effective permissions
equal the accepted mode bits is trivial; a default ACL, named user/group,
mask, unknown tag/version, malformed encoding, or any other entry is
nontrivial or unsupported and fails closed.

On Darwin with cgo enabled, a build-tagged implementation calls libc
`acl_get_fd_np(fd, ACL_TYPE_EXTENDED)`, iterates only with `acl_get_entry`, and
always releases the returned object with `acl_free`. Darwin's
`ACL_MAX_ENTRIES` value of 128 is the allocation/iteration bound; the API has
no separate descriptor-native size probe. Zero extended entries is trivial
because mode bits are checked separately; any extended entry is nontrivial.
Retrieval, iteration, bound, or cleanup ambiguity fails closed. A
`darwin && !cgo` implementation and every other platform compile but return a
constant unsupported result. No raw syscall number or pathname fallback is
allowed.

Descriptor open, stat, and read operations retry `EINTR` without losing
partial-read progress. Every acquired descriptor has one owner and is closed
exactly once on every path; `close` is never retried after `EINTR`. OS failures
map to stable content-free classes without wrapping or formatting raw errors.

The YAML config file may be mode 0400 or 0600. Its owner is the daemon
effective UID, its link count is one, and group/other access is forbidden.

Application and auditor password files:

- are mode 0400 or 0600 and owned by the effective UID;
- contain 1 through 1,024 opaque bytes;
- contain no NUL, CR, or LF;
- are used byte-for-byte with no trimming, decoding, or optional newline; and
- are loaded into distinct owned buffers.

The process capability file follows the secret ownership/mode/link rules and
contains exactly 32 raw opaque bytes, not text, hex, or Base64. No delimiter or
optional final newline is stripped; all byte values are valid and the all-zero
value is rejected. The loader stores it only in a private fixed-size owner
whose value/pointer `String`, `GoString`, and `Format` behavior is constant and
content-free. It exposes only a constant-time equality method and has no raw
byte, Base64, request-editor, text-marshal, JSON, or ordinary accessor.
M14 must own a separate protected client-side loader and generated-client
request editor; it cannot import this server-internal owner. Ownership moves
once from prebootstrap to the runtime and closes once after handlers join.

The HMAC file follows the same ownership/mode/link rules and contains exactly
32 raw opaque bytes, not hex or Base64. No delimiter or optional final newline
is stripped; a `0x0a` byte inside those exact 32 bytes is key material. The
all-zero value is rejected by the M12 deriver. It is loaded only for memory or
Valkey.

The process capability, application password, auditor password, HMAC, CA, and
YAML paths must resolve to distinct device/inode identities. Application and
auditor usernames and password byte strings are distinct; the process
capability must not equal either 32-byte password or the HMAC secret, and a
32-byte password must not equal the HMAC secret. Role separation is validated
without formatting any value.

The CA file may be mode 0400, 0440, 0444, 0600, 0640, or 0644 and contains
only PEM `CERTIFICATE` blocks plus SP (0x20), HTAB (0x09), CR (0x0d), or LF
(0x0a) between/around blocks. VT, FF, NUL, and Unicode whitespace are rejected.
The loader also rejects encrypted blocks, headers, every other PEM type,
non-whitespace trailing data, duplicate DER certificates, and parse failures.
It produces 1 through 128 unique DER roots, each at most 65,536 bytes and at
most 262,144 DER bytes in aggregate. Each certificate must be a CA and, when
KeyUsage is present, allow certificate signing. Parsed DER is passed to M12's
production constructor.

Protected reads are capped independently of metadata sizes: passwords at 1,024
bytes, process capability and HMAC each at exactly 32 bytes, CA PEM at 524,288
bytes, and YAML at 262,144 bytes. One-byte-under/over where exact, one-byte-
over where ranged, nonblocking FIFO/device, atomic replacement, and
deterministic same-inode concurrent-rewrite tests are mandatory.

Typed config and protected wrapper types reject JSON/text marshaling and
return constant content-free `String`, `GoString`, and `Format` results.
Usernames, addresses, paths, values, loaded bytes, certificate subjects,
attestation values, and raw errors are never emitted. M13 has no generic
effective-config dump. Stable validation codes may identify a declared field
class but never repeat a path supplied by the user.

Formatting safety does not rely only on `fmt.Formatter`, because unsupported
or pointer-oriented verbs can bypass ordinary string methods. Any type that
owns protected or user-supplied config is structurally opaque: its
format-visible value contains only safe constants or private pointers/handles,
never raw strings or byte slices. Value, pointer, interface, and nested
container marker tests exercise `%s`, `%q`, `%v`, `%+v`, `%#v`, `%x`, and
`%p`. A pointer address may appear for `%p`; protected contents may not. An
invalid `%p` applied to a non-pointer value must likewise remain content-free.

No false Go memory-erasure claim is made. Owned buffers are short-lived,
cloned only at defined constructors, kept out of Viper after snapshot decode,
and released during deterministic shutdown.

## DNS, Replay Provider, And Readiness Wiring

The daemon creates one instance-owned TTL-aware DNS TXT transport from the
system resolver configuration and one
`dkim2.NewDNSPublicKeyProviderWithConfig` under a daemon-owned parent context.
The transport uses bounded resolver failover, retries truncated UDP responses
over TCP, retains the shortest TTL across CNAME chains, and derives negative
lifetimes from authoritative SOA records according to RFC 2308. It validates
response questions and answer ownership before returning TXT data. There is no
DNS startup probe, readiness lookup, custom recursive server, local DNSSEC
validation, or IDNA normalization. Runtime DNS provider outcomes stay inside
the four-state verification result.

Memory replay uses `dkim2.NewReplayDeriver`, the configured retention and
resolved public replay limits, one instance clock, and
`dkim2.NewReplayMemoryStore`. Disabled replay constructs only
`dkim2.NewReplayDisabledStore`.

Valkey constructs the same deriver plus one M12 `ClientConfig`, one immutable
`OperatorAttestation`, and fresh protected `AuditorConfig`. Auditor credential
bytes are loaded once into an immutable startup-owned protected source. Each
audit receives a short-lived clone and releases that clone on return; periodic
revalidation never reopens or watches the password path. Rotation requires an
operator restart in this increment. Shutdown releases the startup-owned source
only after the revalidation loop and all handlers have joined. The daemon calls
`NewProductionStore`; no direct `valkey-go` constructor, retry, alternate
endpoint, cluster, Sentinel, database, plaintext, trust fallback, or
application-credential audit is allowed.

The initial M12 startup audit must complete before listener readiness. A
single non-overlapping revalidation loop calls
`Store.Revalidate(context.Context, fresh AuditorConfig)` at the configured
interval, which is never greater than 60 seconds. Scheduling is start-to-start
from the preceding scheduled start. Each call inherits M12's 30-second global
audit bound. Calls never overlap; if one crosses one or more interval ticks,
the loop collapses all missed ticks and starts exactly one call immediately
after return. It never queues catch-up calls. Therefore call starts remain no
more than 60 seconds apart under the provider's enforced audit bound.

M13 adds one narrow provider-owned `AuthorityReady() bool` method to the
existing M12 Valkey store. It samples the same serialized security clock and
the same internal evidence deadline used by `CheckAndRemember`, publishes
stale or impossible evidence through the existing M12 recovery facts, checks
lifecycle/recovery state, performs no network or datastore I/O, returns only a
boolean, and exposes no time, reason, endpoint, or credential. Daemon
readiness MUST use that method; a daemon-owned timestamp is forbidden because
it can lag the authoritative audit-completion deadline. This is a minimal M12
provider API completion in the M13 commit, not a parallel readiness model.

M12 authority evidence is valid while the provider's monotonic time since the
last complete successful probe is strictly less than five minutes; at exactly
five minutes it is stale. `AuthorityReady` is false for stale evidence,
revalidation-clearable sticky degradation, restart-only degradation, and
closing or closed lifecycle state. A complete successful revalidation
atomically refreshes evidence and clears only stale and
revalidation-clearable facts. It never clears `NOAUTH`/`WRONGPASS`
application-client binding, malformed/impossible/contradictory contract,
panic, internal-invariant, or other restart-only facts; those require closing
the store and constructing a new provider.

An auditor call refused before dispatch because its exclusive revalidation
token is occupied returns M12 `limit_exceeded` without changing current
evidence or readiness. Exact caller cancellation/deadline before or during the
non-mutating audit likewise returns its typed error and does not by itself
invalidate still-fresh prior evidence. A non-context transport failure,
well-formed runtime policy mismatch, or other M12
revalidation-clearable result publishes not-ready degradation. Recovery is
never inferred from elapsed time, ordinary replay traffic, or a daemon-owned
timestamp.

Health is pure in-process liveness and performs no I/O. Readiness is a
bounded, no-I/O snapshot of:

- successful immutable configuration and protected loads;
- completed dependency graph;
- live listener/serve loop;
- process admission open; and
- replay backend authority: explicitly disabled, live memory, or Valkey-ready
  with unexpired successful audit evidence.

Readiness performs no DNS/Valkey call and exposes no component or reason. A
concurrent transition may conservatively return not ready.

## Cobra And Fx Lifecycle

The root command owns `serve`; `serve` accepts zero positional arguments,
requires `--config`, and rejects unknown flags. The command sets
`SilenceUsage` and `SilenceErrors`. Expected configuration/start errors
produce one stable process exit class without raw error text. Usage is printed
only for explicit help or command-shape errors and contains no effective
configuration. Exit status is 0 for explicit help and clean shutdown, 2 for
command-shape/flag errors, and 1 for configuration, startup, dependency, serve,
or shutdown failure.

Before `fx.New`, the command performs one security prebootstrap: it opens and
preflights YAML, builds the immutable typed snapshot, and loads the selected
protected generation into one closeable owner. This is the only pre-Fx
resource owner. Byte, allocation, descriptor, path, filesystem, and ACL bounds
are exact, but synchronous regular-file metadata/read syscalls are not falsely
claimed to be cancellable by a Go context. Supported local filesystem and
kernel availability are an explicit operational prerequisite; an unavailable
kernel/storage stack can delay process startup, but the process never
publishes a listener or readiness. External service supervision may impose a
process-level startup watchdog.

The command closes the prebootstrap owner on every later `fx.New` or start
failure. On successful start, ownership transfers exactly once to the
lifecycle owner and is released only in the ordered stop path. Fx uses
constructors and narrow interfaces; every Fx constructor is pure, nonblocking
assembly and opens no file, listener, network connection, replay store, or
resolver transport. Until M15 provides the central observability runtime, Fx
uses `fx.NopLogger`, the HTTP server has a bounded content-free `ErrorLog`, and
no prebootstrap, constructor, or hook error is formatted through default
Fx/Cobra paths.

Because the validated snapshot exists before `fx.New`, both Fx `StopTimeout`
and the command-owned stop context are the actual
`server.shutdown_timeout + 50s`, checked against overflow. The documented
inner worst case is the configured shutdown timeout plus 45 seconds: listener
close/serve-loop join owns five seconds, forced close/handler-join owns five
seconds, cancellation/join of one in-flight M12 audit owns its full 30-second
global bound, and final joined-resource cleanup owns five seconds. The extra
five seconds is outer orchestration/scheduler margin, so neither outer
deadline equals or cuts the documented inner bound.

The application sets `fx.StartTimeout(115s)` and does not rely on Fx's
default. The single bootstrap `OnStart` hook gives acquisition at most 100
seconds and reverse-order rollback ten seconds; the outer timeout retains five
seconds of orchestration/scheduler margin. The acquisition budget covers the
maximum sequential M12 Valkey startup path: one 30-second global auditor bound
followed by context-free application-client construction, whose configured
dial and connection-write timeouts are each at most 30 seconds, plus ten
seconds for bounded local composition and loopback listener publication. The
hook checks its context between every stage. Network calls use their frozen
inner timeouts; no context-free call has a bound beyond the accounted maxima.

The single bootstrap `OnStart` order is:

1. construct DNS context/transport/provider and verifier from the snapshot;
2. construct policy and selected replay backend/deriver;
3. for Valkey, complete `NewProductionStore`, including the startup audit and
   application-client construction;
4. construct process service, readiness, preflight, validator, and generated
   handler;
5. bind the canonical loopback listener;
6. start the serve loop and Valkey revalidation loop; and
7. atomically publish ready only after both loops are owned.

If any start step fails or its 100-second acquisition budget expires, the
bootstrap hook cleans every resource acquired inside that hook exactly once in
reverse order within its ten-second rollback bound, returns one stable
failure, and never publishes readiness. The command then closes the still-
owned prebootstrap material. No listener is published early. Previously
completed Fx hooks, if any, retain ordinary Fx reverse rollback, but no hook
depends on that mechanism to clean ownership acquired inside the failing
bootstrap hook.

Stop order is:

1. atomically enter the instance-owned stopping state, publish not ready,
   close process admission, and close the mutex-protected handler-registration
   gate so no later `ServeHTTP` entry can increment the active-handler group;
2. close the owned listener and join the serve loop within one fixed
   five-second bound;
3. after that join, call HTTP shutdown and drain within the configured bound;
4. if graceful drain is unsuccessful for any reason or the already-closed
   handler gate's wait group has not proved quiescence, cancel the daemon-owned
   parent of every registered request context, call `http.Server.Close`, and
   allow one fixed five-second force-join bound;
5. only after the serve loop and all registered handlers have joined, cancel and join the Valkey
   revalidation loop;
6. cancel the DNS parent context;
7. close replay store and deriver exactly once; and
8. release protected runtime references.

The registration gate combines its closed bit and active count under one
mutex/condition owner; entry either increments before closure or is refused
without touching DNS, replay, policy, protected material, or any other runtime
dependency. A refused late entry closes its exact tracked connection through
the private connection control and returns without writing; the peer receives
no fabricated status, and net/http's post-return write cannot reach the closed
socket. Closure and waiting therefore cannot race `WaitGroup.Add`.

If listener close or serve-loop join does not complete within its bound, the
stop path cancels request contexts and returns the stable failure class without
synchronously calling `http.Server.Close`, whose own listener-group wait is
unbounded when that join has not been proved. It deliberately does not close
DNS, replay, or protected dependencies. `http.Server.Close` is used only after
the serve-loop join succeeded, in the forced handler branch. The same
no-teardown failure applies if registered handlers do not join within the
force bound. The command then terminates through its failure path. Dependency
teardown never races a live handler or accept owner. The listener wrapper's
idempotent `Close` closes the underlying
listener and interrupts both a blocked `Accept` and the refusal-backoff timer
before returning; the separately joined serve loop therefore removes Go's
otherwise unbounded pre-context `http.Server.Shutdown` listener wait.
`BaseContext`/owned request derivation, graceful shutdown, forced close,
cancellation, and the serve/handler wait groups are instance-owned; no global
cancellation state is used.

A serve return observed before the stopping transition always marks not ready
and requests Fx shutdown, including an otherwise recognizable
`http.ErrServerClosed`, because no owned stop has yet authorized listener
loss. After the stopping state is published, the listener-close-induced serve
return is expected regardless of its opaque error value and cannot turn an
ordinary clean stop into a serve failure. Repeated stop, partial bootstrap
rollback, pure-constructor failure, and concurrent serve/revalidation failure
are idempotent and race-safe. Shutdown never logs a raw cause.

## Architecture Reconciliation

The one M13 commit includes minimal append-only durable corrections:

- `docs/ARCHITECTURE.md` receives a revision row recording completed M12
  implementation and the M12 milestone row becomes `Completed`;
- the architecture and M10 signing specification record that M13 is
  inbound-only; and
- M16 becomes the required owner of the first production HTTP sign/revise
  contract, M11 datasource-to-signer bridge, private signing backend, generated
  OpenAPI extension, and adapter-safe mutation/action plan before Milter EOM
  integration. M17 reuses it.

M14 remains an inbound generated-client/test-fixture milestone. M15 may observe
M13 but cannot change protocol or policy behavior. Historical completion
evidence is appended or narrowly reconciled, never rewritten to pretend the
old plan was already implemented.

## Dependency Policy

M13 pins direct service dependencies in `cmd/dkim2d/go.mod`:

- `github.com/spf13/cobra v1.10.2`;
- `github.com/spf13/viper v1.21.0`;
- `go.uber.org/fx v1.24.0`;
- `github.com/getkin/kin-openapi v0.135.0`;
- `go.yaml.in/yaml/v3 v3.0.4`;
- `golang.org/x/sys v0.47.0` for build-tagged descriptor-safe Unix operations;
- the existing `github.com/valkey-io/valkey-go v1.0.76`.

M13 keeps `cmd/dkim2ctl/go.mod` free of the unused
`github.com/oapi-codegen/runtime`: the generated client imports only the
standard library and its target-local wire package for this contract. The
dedicated tools module pins `oapi-codegen v2.7.1`. The YAML pin matches the
reviewed Viper v1.21.0 graph and is direct because M13 imports its node API.
No remote Viper provider, config watcher, alternate HTTP router, logging
framework, retry library, or generic validation framework is added. Workspace
and module guardrails enumerate the tools module explicitly: the authoritative
workspace-sync check evaluates the complete package graph and governs module
metadata, while dependency-policy, vulnerability, and vendor checks either
include the tools module or document why executable tool dependencies are
checked through the pinned module rather than copied into product vendor
trees. A standalone `GOWORK=off go mod tidy` result is not a second source of
truth for this workspace-governed tools module. Generated
artifacts are never accepted merely because a locally installed generator
matches by accident.
Product vendor output and all module files remain deterministic.

The `x/sys/unix` use is isolated behind Linux/Darwin protected-loader files and
narrow internal interfaces. The Linux implementation uses its supported
descriptor/xattr calls. Darwin ACL inspection is instead isolated behind
`darwin && cgo` and links only the system libc ACL API; it adds no Go module
dependency. `darwin && !cgo` and other platforms compile a closed unsupported
implementation. Build and dependency guards compile both supported and
unsupported tag selections, require the direct `x/sys` pin, and reject raw
syscall numbers, unsafe ad-hoc wrappers, shelling out, or pathname fallbacks.

## Security And Privacy

Ambiguity fails closed at every boundary:

- invalid transport input is rejected before domain or provider work;
- malformed message/protocol facts and schema-valid UTF-8 path spellings that
  violate the delegated SMTP grammar become bounded domain results;
- an impossible domain value is internal failure, never a guessed enum;
- replay uncertainty or possible mutation tempfails;
- unavailable secure Valkey authority prevents readiness;
- provider selection never falls back; and
- shutdown closes admission before dependencies.

The protected inbound REST request necessarily transports its exact bounded
Base64 message and SMTP path/recipient/EAI spellings to the daemon and the
generated test client necessarily emits those request bytes. Outside that
explicit request representation, no raw or canonical message, header field,
body, SMTP path, recipient, EAI value, selector, signing domain, DNS
owner/answer, public-key bytes, private material, datasource value, replay
identity/key, Valkey key/address/username, credential, HMAC, certificate
subject/bytes, config path/value, client IP, raw error, validator detail, or
test marker may appear in REST responses or other
server-generated REST output, stdout, stderr, logs, traces, metrics, panic
output, CLI errors, test failure formatting, or generated default handlers.
The only allowlisted request-derived protocol identifiers in REST output are
the bounded canonical decimal `verification.target.sequence`,
`verification.target.instance`, `policy.feedback.relay_sequence`, and
`policy.findings[].sequence` projections required above. They may appear only
in their declared typed response positions; they remain forbidden from every
diagnostic, observability, error, header, and other output sink.

All named handwritten functions and methods receive concise English doc
comments. Production names and comments describe domain behavior and never
mention milestone or prompt identifiers.

## Observability

M13 constructs no OpenTelemetry provider/exporter, Prometheus registry/vector,
metrics route, debug module, or provider-specific event channel. M15 owns those
facilities. Before M15, the daemon is deliberately quiet: health/readiness
return only closed status, and process responses carry only the exact domain
projection.

Any minimal lifecycle logger seam is injected, content-free, and restricted to
stable event/error classes. Readiness is not a second protocol model or
datastore. Future observability cannot change a result, policy, replay gate, or
store state.

## Required Tests

### OpenAPI and mapping

- OpenAPI 3.0.3 loads under the exact pinned validator.
- Operation IDs, routes, methods, schemas, required/optional fields, enums,
  integer ranges, array maxima, and `additionalProperties: false` match this
  specification.
- Each operation has exactly its frozen response keys/schemas/headers, no
  default; health/readiness singleton schemas cannot cross-validate; status
  200/304 strong `ETag`, 304 content/header omissions, status 412, 503 and 408
  headers, and conditional early-close headers, including status-route 400,
  are exact; OpenAPI `required` flags and adapter wire tests jointly enforce
  universal `Connection: close` and other mandatory header presence; router
  and Go pre-handler exceptions stay outside.
- Generator output and both binding overlays are byte-reproducible; embedded
  spec is current; server and client compile; raw Base64 and envelope values
  stay target-local structurally opaque JSON-string wrappers.
- The one `tools/cmd/wiregen` source reproduces both wrapper files byte for
  byte, and shared parity vectors prove identical JSON, accessor, zero-value,
  and formatting behavior.
- Root `make generate-openapi` and `make check-openapi` find the generator only
  through the `tools/` module under a fresh build cache and do not depend on a
  globally installed `oapi-codegen`.
- Module/dependency guards prove synchronized workspace metadata, prove the
  generated owners neither import nor pin an unused
  `github.com/oapi-codegen/runtime`, and prove `lib/` imports neither that
  runtime nor the generator.
- No generated type enters `lib/`; no hand-written parallel REST DTO exists.
- Every wire-exposed public verification/policy value maps one-to-one,
  including coherent target and feedback optionality; intentionally omitted
  redundant values are checked for coherence.
- Unknown/zero/forged values fail without a partial response.
- A zero-length verification check list is rejected by both the mapper
  invariant and generated-schema tests; every valid current result has at
  least one check.
- Synthetic raw-message and envelope markers never appear when generated
  request DTOs are formatted as values, pointers, interfaces, or nested
  containers with `%s`, `%q`, `%v`, `%+v`, `%#v`, `%x`, or valid/invalid `%p`.
  The generated client still emits the exact JSON string bytes and the server
  accessor recovers the exact preflight-approved UTF-8 spelling.

### HTTP, JSON, and resource abuse

- Exact route, encoded/doubled/dot/trailing path, unknown path, method, Allow,
  query, Content-Type, Content-Encoding, GET body, HEAD, OPTIONS, and
  `OPTIONS *` cases exercise the ordered mapper. HTTP/1.0, HTTP/1.1,
  higher HTTP/1 minor versions processed as 1.1, the exact Go 1.26 HTTP/2
  preface tuple returning the frozen header-only 505 after Go parsing but
  before local Host validation, including a raw vector with the trailing `SM`
  preface octets, tuple variants with exact, missing, malformed, and duplicate
  Host, h2c attempts, other unsupported major versions/Go-owned 505, and the
  complete unsupported-major/PRI cross-product with admitted and non-admitted
  Transfer-Encoding proving the preserved pre-handler 501 precedence,
  absent/empty-only/repeated/list/mixed/parameterized/malformed/route-invalid
  Expect forms, HTTP/1.0 continue-ignore behavior, exact immediate
  100-continue, canonical and non-canonical Host
  variants, and every method/target-form pairing are covered. Absolute-form
  positive cases accept a disagreeing received Host but reject a mismatching
  target authority or noncanonical target; origin-form retains exact Host.
  Canonical CONNECT authority-form with exact captured Host reaches
  server-wide header-only 501 with `Content-Length: 0`; missing/mismatching
  Host is 400. Exact
  `OPTIONS *` reaches header-only 204 with no Content-Length. Every HEAD result
  is status/header-identical to corresponding GET, including exact legal
  Content-Length, and emits no body bytes, including Go-owned pre-handler
  errors suppressed by the bounded 16,384-byte response-head filter.
  Exact GET/HEAD/POST/OPTIONS on a wrong route reach truthful 405/Allow;
  uppercase registered but unimplemented methods, extension methods, and
  lowercase method spellings reach header-only 501 before path selection.
  Prefilter fixtures cover valid method-token octets 64/65, invalid tchar
  release, 65-byte method crossed with target octets 8,192/8,193, target
  delimiters split across reads, CRLF and bare-LF malformed termination, and a
  method exhausting the aggregate head budget as Go-owned 431. Only a target
  that exhausts the capture before its second SP exercises the raw 414 path;
  tests prove its fixed HTTP/1.1 status, optional valid Date, deadline-set
  failure, partial/zero/failed writes, non-reading peer, and concurrent close
  without a second response.
  Response-filter fixtures cover exact/max-plus-one response heads, split and
  coalesced bare 100/final heads, informational reset without token release,
  terminal 101, existing mixed-case Date without duplication, valid Date
  injection into direct Go 400/431 and framing-rewritten 400, unavailable-clock
  omission, exactly one canonical Connection field on HTTP/1.0
  200/204/304/4xx/5xx, HEAD body suppression, upstream split writes,
  pre-handler deadline-set failure, downstream partial-plus-error,
  zero-plus-nil, terminal subsequent writes, ordinary body passthrough, and
  close on malformed Go-output invariants. Concurrent 100/final, write/close,
  and shutdown races prove terminal state and every token release are
  exactly-once without mutex-coupled write deadlock.
  HTTP/1.0 origin- and absolute-form cases include missing, exact, and
  disagreeing Host fields and prove captured presence cannot be masked by the
  URI authority. Raw transfer-framing vectors distinguish exact and
  empty-element-normalized `chunked`, `gzip`, `gzip, chunked`,
  `chunked, gzip`, repeated/parameterized/malformed/only-empty codings,
  multiple field lines, obs-fold, Transfer-Encoding with Content-Length, and
  every HTTP/1.0 occurrence. Expect vectors likewise cover obs-fold and both
  inert-name collisions. They prove the frozen 400/501/handler outcomes, close
  behavior, Go-order precedence, bounded parser-only transient retention,
  deletion before generic middleware, and absence from every emitted or
  diagnostic sink.
- Conditional status-route tests derive the exact strong tag from the emitted
  200 bytes and cover If-Match/If-None-Match star, matching/nonmatching
  strong/weak lists, multiple field lines, zero-member/only-empty and embedded
  empty list members, empty opaque tags, commas and literal backslashes inside
  opaque tags, obs-text, malformed tags, mixed star/list forms, and lazy RFC
  precedence. They prove empty If-Match selects 412 while empty If-None-Match
  preserves 200. They prove 304 has no content, trailers, Content-Length,
  Content-Type, X-Content-Type-Options, or unrelated metadata, while carrying
  exact ETag/cache/connection and Date iff the corresponding 200 would;
  412 GET/HEAD
  behavior and `precondition_failed` are exact. Not-ready 503, every earlier
  non-2xx outcome, process, OPTIONS, CONNECT, unknown/unimplemented routes,
  malformed/date conditionals, Range, and If-Range prove the required ignore
  behavior and perform no extra I/O or mutation.
- While handler registration remains open, health remains 200 during
  not-ready/closed-admission states; readiness is exactly 200 or 503; process
  alone reaches admission/body/domain work.
- Local-capability tests cover missing, empty, whitespace, padded,
  noncanonical, malformed, comma, duplicate, wrong-length, and mismatching
  `X-DKIM2-Capability` values as indistinguishable 403 responses. Exact
  canonical unpadded Base64url succeeds only for the matching 32 bytes.
  Instrumented gates prove capability failure occurs before readiness,
  admission, body reads, OpenAPI authentication, DNS, policy, or replay work;
  timing is exercised without asserting a brittle wall-clock equality. Status
  routes ignore the field without emitting it, and marker tests cover every
  response, error, formatting, Fx/Cobra, and test-diagnostic sink. Successful
  preflight tests prove all header occurrences are deleted before the private
  success marker reaches openapi3filter and every lower layer.
- Every application response carries `Connection: close`; a pipelined or
  sequential second request on the same socket is never dispatched. The
  bounded first-head capture preserves bytes except for the two frozen
  same-bound neutralization/normalization cases, records/releases only the
  exact-HEAD, HTTP-version, Host, Expect, Content-Length occurrence/conflict, and
  transfer-framing facts, detects CONNECT and HTTP/1.0 absolute-form missing
  Host, and retains raw Expect or Transfer-Encoding values only in the bounded
  capture/Go parser until the outer gate deletes them before generic
  middleware. It never copies them into a classifier or emits them. Client
  collisions with both inert field names are deleted and cannot alter the
  immutable facts. Boundary regressions prove Host length 64 is owned exactly,
  length 65 becomes the mismatch sentinel, neither fact aliases the cleared
  capture, absolute-form ignores the Host value after proving one occurrence,
  and the outer gate clears the owned Host fact before generic middleware.
  Transfer-Encoding regressions place the sole semantic `chunked` coding in a
  non-first occurrence and prove every rewritten line and the aggregate
  capture retain their length. An exact-full capture with coalesced body tail
  and the equivalent segmented input produce identical facts and replay bytes
  without normalization allocation or growth. Split-write fixtures
  prove its HEAD response filter forwards through the first header terminator,
  buffers no body, discards every later octet, and reports writes consumed.
- Early final responses selected before the explicit continue boundary with
  unread framed bodies set `Connection: close`, emit no interim 100, advance
  the underlying read deadline before commit, and cannot reuse a slow
  connection. A valid HTTP/1.1 continue request with announced content gets
  exactly one bare 100 only after all header-determinable final checks and
  nonblocking permit/reservation acquisition; occupied capacity returns
  immediate 503 without joining a free waiter queue. Instrumented-connection
  tests prove Go's
  mandatory body close can discard only already-buffered bytes within its
  fixed 262,144-byte internal ceiling and cannot wait for or read later client
  bytes; injected deadline-setting failure closes the exact tracked connection
  with no fabricated response and releases its cap token. The test does not
  falsely claim that post-handler close performs no discard.
- Declared and undeclared trailer tests include capability, Content-Type,
  Expect, Host, conditional fields, duplicates, malformed/oversized framing,
  timeout, disconnect, and body-limit races. They prove trailers remain
  separate and semantically inert, are nil before lexical/OpenAPI/domain work,
  never authenticate or mutate, and retain the frozen 400/408/no-response
  outcomes with exactly-once permit and reservation release.
- Connection-cap tests hold 128 mixed slow-header, active, stalled-body, and
  status-route connections, prove the 129th accepted socket is closed before
  an HTTP goroutine or handler starts, and prove exact token recovery across
  ordinary close, listener close, shutdown, and concurrent close races.
  Saturated accept loops demonstrate the bounded refusal backoff and no
  unbounded goroutine growth or local busy spin.
- Header tests prove `Accept` is ignored for absent, matching, nonmatching,
  wildcard, weighted-list, multiple-field, empty, and malformed forms and
  never produces 406 or `Vary`; `Content-Type` tests distinguish zero, one,
  multiple field lines, comma members, empty values, and case-insensitive
  permitted media types and charset names/values, including semantically
  equivalent token and quoted-string `utf-8` with RFC-valid optional
  whitespace, quoted-pair decoding, and ignored empty parameter elements as
  positive cases, plus malformed, duplicate, MIME-extended, and extra nonempty
  parameters as negative cases. Resource-limit precedence over repeated
  OpenAPI maxima is
  asserted explicitly. Raw-connection tests prove the documented Go 69,632
  request-head read budget and rejection above it without a false 65,536
  acceptance-boundary claim.
- Body, raw-message, recipient, per-path, aggregate-envelope, JSON depth/token,
  decoded member-name, API-version-string, draft-string, waiter, concurrency,
  and timeout limits pass at exact maximum and fail at maximum plus one. Tests
  prove that within-cap wrong version/draft strings retain the dedicated
  unsupported codes while their cap overflows are 413. Raw-message tests use
  empty CRLF-delimited lines to prove exactly 65,536 indexed body lines pass,
  line 65,537 returns typed `max_body_lines`/`limit_exceeded` before append,
  and public verification preserves `PERMERROR`/`ReasonLimitExceeded` without
  provider, recipe, policy, or replay work.
- Simultaneous maximum raw message, 2,000 paths, maximum UTF-8/escaped envelope,
  and structural overhead fits the exact outer cap.
- One maximum legal request stays below its fixed 512 MiB ownership
  reservation. Exact one/two-unit acquisition, a blocked third request,
  chunked/full reservation, cancellation/release, maximum-input transient
  allocation, and concurrent race tests prove the 1 GiB aggregate bound.
- Duplicate keys at every depth, escaped-name duplicates, invalid UTF-8,
  valid/invalid surrogate pairs, trailing JSON, multiple values, unknown
  fields, malformed number/type, and token/depth exhaustion are rejected.
- Canonical Base64 covers empty, padding, pad bits, whitespace, alternate
  alphabet, CRLF, decoded maximum, decoded maximum plus one, and otherwise
  equivalent JSON escape spellings that must be rejected.
- Decimal-string sequence and instance fields cover zero, `MaxInt64`,
  `MaxInt64+1`, and `MaxUint64`; signs, leading zeroes, overflow, and
  non-decimal forms fail closed.
- Application errors are exact JSON; pre-handler net/http failure behavior is
  bounded and secret-safe without a false JSON assertion.
- Admission saturation, waiter cancellation, client cancellation, server
  handler deadline, server body-read timeout, partial-body client disconnect,
  DNS-owned timeout, panic, and response-write failure leak no data and release
  all resources. Configuration rejects read-header timeout greater than
  whole-request read timeout and rejects a 1-second request deadline paired
  with a 120-second server read timeout. An accepted case with all three
  read-header/read/request deadlines set to one second interrupts a slow body
  at the owned deadline and maps to 408 with connection close before
  domain/replay work when writable; a disconnect need not produce a response.
  Simultaneous observed client cancellation, handler deadline, readiness
  closure, admission expiry, and permit delivery obey the exact queue
  precedence and perform no mutation. A separate wire case sends a complete
  framed body, disconnects while admission is queued, and proves the
  unobservable disconnect may still lead to processing/possible replay
  mutation while response failure remains secret-safe. Mapper and encoder
  panics before commit become bounded `internal_error`; a post-commit short
  write cannot trigger a second response or disclose unvalidated bytes.
- A raw client that pipelines or attempts a sequential second legal request
  observes connection close after the first response; only one handler,
  deadline, admission decision, and possible mutation occurs.

### Configuration and protected files

- YAML byte/node/depth/document/scalar caps, duplicate decoded keys, dotted
  aliases, hierarchy shadowing, unknown empty maps, anchors, aliases, merges,
  tags, implicit/explicit null spellings, empty values, complex keys, multiple
  documents, and trailing content fail.
- Every stable operational path has the exact environment name while
  `config.version` and `protected.generation` remain pre-expansion exact YAML
  literals; placeholder attempts there fail, unknown variables do nothing, and
  `AllowEmptyEnv(true)`, precedence, explicit flags, and no Viper reread are
  proven.
- Placeholder grammar covers multiple, adjacent, empty, missing, malformed,
  nested, recursive-looking, map-key, whole-placeholder source conversion,
  mixed string-only expansion, and size-limit cases.
- Cross-source tables prove retained YAML/environment/flag/default provenance,
  exact boolean/integer/duration lexical grammars, Viper merge equality,
  the `server.admission_wait`-only `0s` exception, no weak coercion, and
  pre-default presence for forbidden-key checks. A bound environment name used
  as a placeholder for another leaf still counts independently for its own
  forbidden backend path.
- Backend matrices prove required/optional/forbidden presence, secure Valkey
  default, disabled loading of only the common capability, and no fallback.
- Attestation tables distinguish every explicitly supplied zero value from an
  absent leaf, including valid `min_replicas_to_write: 0`, and exercise every
  required boolean, enum, integer, singleton, and conditionally
  required/forbidden `save_schedule` before defaults.
- The protected generation bundle proves no mixed YAML/process-capability/
  epoch/HMAC, application/auditor credential, or CA generation can become
  ready when the YAML, generation directory, or any child is atomically
  replaced between every load step. Phase-order tests prove every required child descriptor is
  opened and prechecked before any child content is read. Final all-child
  re-stat/ACL passes occur only after all reads and catch a completed same-inode
  rewrite of an earlier child during a later child read. The retained YAML
  descriptor has link count one and matching pre-read, immediate-post-read,
  and final post-bundle metadata/ACL state; hardlink and same-inode rewrite
  fixtures fail before readiness.
- Same-descriptor/no-follow checks cover symlink, atomic replacement, and
  same-inode rewrite races, ownership, mode, hard links, descriptor-relative
  special-file preflight, FIFO/device/socket/non-regular files, empty/oversize
  files, exact EOF,
  partial reads, `EINTR`, exactly-once close, password CR/LF/NUL, raw process
  capability and HMAC length/all-zero, cross-secret equality,
  distinct-inode enforcement, PEM types/trailing data, certificate
  count/size/uniqueness/CA usage, and cleanup.
- Linux fixtures cover the exact four-filesystem allowlist, rejection of
  NFS/CIFS/FUSE/OverlayFS and unknown filesystem magic, bounded
  `flistxattr`, alternate `system.*` ACL namespaces, access/default xattrs,
  base-entry/mode equality, named entries, masks, malformed/growing data, and
  the 65,536-byte and 256-name/entry bounds through descriptor-native
  inspection. Absence of POSIX ACL xattrs on an unproven filesystem remains
  unsupported.
  Darwin-cgo fixtures cover zero/nonzero extended ACLs, iteration/cleanup
  failures, and the 128-entry system bound; `darwin && !cgo` and other
  platforms fail closed. No platform test or implementation uses pathname or
  shell fallback.
- Formatting and serialization tests cover value, pointer, interface, and
  nested-container forms of all config/protected wrappers with synthetic
  markers, including valid and invalid `%p` paths that can bypass ordinary
  formatting methods.

### Domain, replay, and lifecycle

- Raw RFC 5322/RFC 6532 message bytes and each schema-valid SMTP Unicode-scalar
  spelling's exact UTF-8 bytes arrive unchanged at the public verifier.
- Invalid RFC 5322, RFC 6532, and DKIM2 syntax, plus schema-valid UTF-8 path
  spellings that violate the delegated SMTP grammar, yield HTTP 200 domain
  PERMERROR or FAIL as owned by the library, never adapter normalization.
  Invalid JSON encoding, scalar integrity, type, or bounds remains HTTP 400/413
  and cannot be represented as domain input.
- Four verification states, three policy modes, four policy verdicts, all
  closed findings/feedback/compliance, and DNS testing behavior map exactly.
- Replay is untouched for non-PASS or non-accept; disabled uses no deriver.
- Identity order, complete derivation before mutation, zero-write derivation
  failure, terminal-context precedence during derivation,
  first-seen/replayed mixtures, ordinary-error continuation, enabled-store
  disabled contradiction, store-state race, and explicit `possibleMutation`
  tracking are proven. Cancellation while provider admission waits, after only
  authoritative replayed outcomes, after first-seen, after typed
  indeterminate, and after unknown/invalid results exercises both the local
  transport and HTTP-200 indeterminate branches.
- Memory clock/expiry/capacity and Valkey `SET NX PX` behavior retain M12
  parity.
- Valkey startup audit, 30-second default revalidation, five-minute evidence
  expiry boundary (`<5m` valid, `>=5m` stale), start-to-start scheduling,
  missed-tick collapse, overlap/queue prevention, provider-owned readiness
  sampling, startup-owned auditor credentials with per-call clones, and no
  fallback are covered with the hermetic Valkey 9.1.0 harness. An
  old-code-failing regression proves daemon readiness cannot substitute its
  own post-`Revalidate` timestamp. Recovery tables prove successful
  revalidation clears only stale/revalidation-clearable facts, never
  restart-only facts, while pre-dispatch exclusive-token refusal and exact
  caller cancellation/deadline preserve still-fresh prior evidence.
- Valkey TLS identity tests preserve M12's exact canonical-IP or bounded
  lowercase-DNS grammar and reject every normalization or DNS-only narrowing.
- Pre-Fx configuration/protected ownership closes exactly once on `fx.New` or
  start failure and transfers exactly once only after successful start. Fx
  start/stop order, in-hook bootstrap rollback, listener failure, unexpected
  serve return including pre-stop `http.ErrServerClosed`, clean
  stopping-state serve return without a spurious failure,
  repeated shutdown, refusal-backoff interruption, listener-close failure,
  serve-loop join failure, drain timeout, injected non-timeout shutdown
  failure, forced request cancellation/connection close, active-handler join,
  mutex-gated Add-versus-wait races, late-entry dependency refusal, and refusal
  to tear down dependencies under a deliberately non-cooperative accept owner
  or handler, revalidation join, DNS cancellation, goroutine leak, and race
  behavior are proven. Late health, readiness, process, unknown-path, and HEAD
  entries racing gate closure all observe connection close without response,
  touch no runtime dependency, and cannot add after the closed-gate wait
  begins.
- Fx timeout tests prove pure constructors perform no owned or blocking work,
  the 115-second outer start ownership exceeds the complete 100-second
  acquisition and ten-second rollback bounds by five seconds, and both
  dynamic configured shutdown-plus-50-second stop contexts exceed the
  complete inner stop bound without truncating any lifecycle phase. Boundary
  tests include the sequential 30-second audit plus maximum 30-second dial and
  30-second write timeouts.
- Health performs no I/O; readiness performs no I/O and follows every
  initialization/audit/lifecycle transition.

### Fuzz and privacy campaigns

Retained fuzz targets cover JSON lexical preflight, Base64 boundary decode,
OpenAPI/domain mapping, YAML node preflight, placeholder expansion, strict
typed decode, replay aggregation, and HTTP error precedence. Each campaign
uses bounded time recorded in the prompt pack. Marker tests capture REST,
stdout, stderr, server error log, Fx/Cobra error paths, and test output.

## Prompt Pack

Only after one normative/security reviewer and one
architecture/implementation reviewer approve the exact SHA-256 of this
unchanged durable file is the ignored pack created at
`temp/openapi-daemon-foundation-prompts/`. Before Prompt 1, any spec-byte
change invalidates those approvals and pauses pack work for re-review. After
Prompt 1 starts, only the explicitly mutable
status/effort/evidence/review regions may change while the
normative-projection hash remains exact; a normative byte change still
invalidates approval and pauses implementation. The pack contains
sequential prompts:

1. `01-architecture-openapi-generation.md`: architecture/M10 reconciliation,
   tool module, OpenAPI 3.0.3, generation, and stale guards;
2. `02-configuration-loading.md`: YAML/config source merge, placeholders,
   immutable typed validation, and stable path tests;
3. `03-protected-material.md`: protected descriptor loaders, certificate
   conversion, and redaction;
4. `04-domain-mapping.md`: DNS/verifier/policy construction and exact
   domain/DTO mapping;
5. `05-replay-composition.md`: replay gate, batch coordinator,
   memory/disabled/Valkey composition, audit, revalidation, and readiness;
6. `06-http-boundary.md`: HTTP path/media/admission/token/validator/error
   containment;
7. `07-lifecycle-readiness.md`: Cobra/Fx listener lifecycle,
   health/readiness, cancellation, and shutdown;
8. `08-adversarial-proof.md`: adversarial integration, fuzz, race, privacy,
   docs, and dependency proof; and
9. `09-closeout.md`: complete unchanged-candidate guardrails and freeze the
   tracked candidate; its tracked timing ends at that freeze. The two formal
   approvals, staging/tree proof, commit, and post-commit timing/evidence are
   then recorded only in the ignored execution ledger.

Every immutable prompt declares its fixed start preconditions, allowed paths,
mutable spec closeout regions, normative projection, focused gates, reviewer
roles, and the exact ledger fields that must be completed. The excluded
mutable `execution-ledger.md` records the actual start/end hashes, start/end
timestamps, wall-clock duration, gate results, content-free finding
identifiers/status, and both approvals.
Prompts execute strictly in order. Live RFC/draft oversight and independent
implementation review remain active; all findings are fixed and re-reviewed
before the next prompt. `temp/` is checked with `git check-ignore` and never
staged.

Before Prompt 1, the immutable membership is exactly `index.md` plus the nine
prompt filenames above. A separately stored
`temp/openapi-daemon-foundation-prompts/manifest.sha256` contains exactly ten
ASCII records, one per member, sorted by raw repository-relative path bytes:

`<64-lowercase-hex-sha256><SP><SP><repository-relative-path><LF>`.

All ten paths are the fixed ASCII paths beneath the pack directory, are unique,
and contain no CR, LF, TAB, space, backslash, or `..` component. The manifest
ends with exactly one LF. It is derived output and is excluded from its own
membership, avoiding self-reference; regeneration must be byte-identical. The
lowercase `manifest-sha256` is SHA-256 of those exact manifest bytes. The pack
identifier is the lowercase hex result of the exact ASCII byte sequence
`SHA256("M13-PACK\n" + manifest-sha256 + "\n" +
approved-spec-sha256 + "\n")`.

A separate `execution-ledger.md` is mutable and excluded from both membership
and the manifest; it may record only timings, snapshot hashes, gate results,
content-free finding identifiers/status, and approvals, never finding prose or
new behavior. The directory therefore contains exactly twelve files: ten
immutable members, the derived manifest, and the mutable ledger.

One normative/security reviewer and one architecture/implementation reviewer
independently approve the same pack identifier and prove the directory is
ignored. Prompt 1 cannot start before both approvals. Any immutable pack-byte
change invalidates both approvals and requires a new manifest and two fresh
reviews. Pack authoring/review changes no production file and uses no real
index entry.

## Required Gates

Each prompt runs focused package tests. The final unchanged candidate runs:

- `make test`;
- `make vet`;
- `make lint`;
- `make race`;
- `make check-openapi`;
- `make check-vendor`;
- `make test-valkey`;
- every named bounded fuzz campaign;
- `make govulncheck`; and
- `make guardrails`.

Skipped gates are not silently accepted. A genuine environmental blocker is
recorded exactly and stops commit approval.

## Closeout Integrity

The fixed implementation base is
`26e23bfedf8882d59d1c112ad35e68ce61e5d12d`.
Before implementation starts, the exact bytes between the
`normative-projection:start` and `normative-projection:end` markers are the
immutable normative projection after replacing bytes between the
`mutable-effort:start` and `mutable-effort:end` markers with the fixed ASCII
text `MUTABLE-EFFORT\n`, bytes between the `mutable-evidence` markers with
`MUTABLE-EVIDENCE\n`, and bytes between the `mutable-review` markers with
`MUTABLE-REVIEW\n`. The explicitly marked `mutable-status` region lies outside
that projection. During implementation only those four marked regions may
change without a fresh spec approval. Evidence that changes behavior, scope,
default, schema, or trust boundary pauses work and requires a reviewed
normative amendment.

Before candidate construction, the real index must have no staged delta,
intent-to-add entry, assume-unchanged bit, or skip-worktree bit, and its
complete stage-zero entry tree must equal the fixed base tree. It remains
untouched throughout candidate review.

A provisional NUL-delimited working-tree path list is used only to populate a
new private temporary index. Before any path reaches Git as a pathspec, every
provisional path must pass the same ASCII/component grammar below. The private
index is initialized from the fixed base with `git read-tree`, never copied
from the real index, and the complete provisional change is applied with
`git --literal-pathspecs add -A --pathspec-from-file=<file>
--pathspec-file-nul`. Literal mode and the grammar jointly reject pathspec
magic, leading `:`, globbing, exclude rules, and option-like ambiguity.

After `git write-tree`, the authoritative final tracked path set is derived
from the fixed base tree versus that candidate tree. It contains every added,
renamed, modified, or deleted path and excludes ignored `temp/` by
construction. Every provisional and authoritative candidate path must be
ASCII and match
`^[A-Za-z0-9][A-Za-z0-9._/-]*$`, with no empty, `.` or `..` component and no
leading or trailing slash. This rejects CR, LF, TAB, space, backslash,
non-UTF-8, absolute, and ambiguous path bytes before serialization.

A manifest sorted by raw ASCII path bytes records one record for every unique
path and ends with exactly one final LF:

`<git-mode><TAB><path><TAB><sha256-of-file-or-DELETED><LF>`.

`git-mode` is exactly six lowercase octal digits obtained from the applicable
candidate-tree entry, or from the base-tree entry for a deletion. A present
regular file uses exactly 64 lowercase hexadecimal SHA-256 digits computed by
streaming the blob named by that candidate-tree entry through SHA-256; it is
never hashed from a live working-tree path. A deletion uses the literal
uppercase token `DELETED`. A rename is represented by the old base-tree path
and mode with `DELETED` plus the new candidate-tree path/mode/blob content
hash. Candidate symlink additions or modifications are forbidden; the
manifest therefore hashes only regular candidate-tree blobs. Git submodule
entries are likewise forbidden.

An independent manifest checker re-derives the NUL-delimited base-versus-
candidate path set, each base/candidate mode and blob identifier, and every
SHA-256 directly from Git object bytes, then requires byte-identical manifest
output. It also proves that applying the manifest's additions, modifications,
and deletions to the fixed base describes exactly the already-written
candidate tree. NUL-delimited path discovery plus hostile path fixtures prove
validation occurs before the line format is emitted. Only after that binding
passes is the candidate identifier computed:

`SHA256("M13\n" + base-commit + "\n" + candidate-tree + "\n" +
manifest-sha256 + "\n" + normative-projection-sha256 + "\n")`.

The temporary index is removed. The real index must still satisfy the exact
clean-base entry/flag proof before final staging. The evidence records base,
tree, manifest, normative projection, candidate identifier, path count/status
classes, manifest-to-tree proof, and `git diff --check` only in the ignored
execution ledger. A tree-derived candidate identifier or later approval,
staging, commit, or post-commit fact is never written into the candidate tree
that it identifies.

Immediately before candidate approvals and again immediately before real
staging, a fresh private index is independently initialized from the fixed
base and populated from the complete current nonignored live worktree using
the same revalidated literal NUL path list. Its written tree must equal the
approved candidate tree, and its base-versus-tree path set must equal the
manifest path set. This catches any omitted, added, removed, or changed live
path before approval or commit rather than relying on a post-commit dirty-tree
failure.

Two independent reviewers approve that exact unchanged candidate:

1. draft/RFC/mail/security and replay-conformance review; and
2. Go/OpenAPI/config/lifecycle/implementation review.

Any tracked byte change invalidates both approvals. After both approvals, the
real index stages exactly the manifest path set; a staged-tree equality check
must equal the approved candidate tree. Exactly one project-formatted M13
commit is created. Its subject/body use domain language and no prompt or
milestone-planning identifiers. The post-commit tree must equal the approved
tree, its parent must equal the fixed base, the worktree/index must be clean,
and `temp/` must remain ignored.

All allowed tracked status, effort, evidence, and review updates finish before
candidate construction. Once the candidate tree/identifier is written, no
tracked status, Prompt-09 completion, approval, staging, commit, or post-commit
fact is edited. Those later facts and timestamps live only in the ignored
`execution-ledger.md`; this avoids candidate self-reference and approval
invalidation.

Immediately before candidate construction, the tracked status becomes the
timeless statement `implementation complete; closeout recorded externally`.
Prompt 09's tracked completion time is that same pre-candidate freeze instant;
it does not claim that later review or commit work had already completed.

<!-- mutable-evidence:start -->

## Completion Evidence

Implementation closeout evidence known before the tracked freeze:

- focused prompt gates: passed for every implementation prompt;
- OpenAPI/generated checks: passed with pinned, offline-capable generation and
  byte-for-byte stale-output checks;
- configuration/security/replay integration: passed, including protected
  platform builds and the hermetic Valkey 9.1.0 suite;
- fuzz campaigns: all nine retained bounded campaigns passed;
- `make guardrails`: passed on the unchanged implementation snapshot; the
  final tracked-snapshot repeat is recorded externally;
- candidate projection/hash: recorded externally after tracked freeze;
- normative approval: recorded externally after tracked freeze;
- implementation approval: recorded externally after tracked freeze;
- staged-tree and post-commit proof: recorded externally after tracked freeze;
- skipped checks: none.

<!-- mutable-evidence:end -->

<!-- mutable-review:start -->

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Inbound daemon foundation only | Inbound-only daemon implemented | complete | Signing, revision, and mutation remain outside this boundary |
| Protocol | Exact -04 baseline and byte preservation | Independently reviewed against the frozen drafts and mail RFCs | complete | No implicit draft update |
| OpenAPI | Exact generated 3.0.3 contract | Pinned server/client generation and stale checks pass | complete | Generated DTOs remain at HTTP boundaries |
| Config | Closed stable paths and protected loading | Strict merge, validation, and descriptor-owned loading implemented | complete | No fallback or effective-config dump |
| Replay | Complete fail-closed batch | Disabled, memory, and standalone Valkey composition proven | complete | No replay identities on the wire |
| Lifecycle | Ordered Fx start/stop and readiness | Bounded startup, readiness, drain, force, and teardown proven | complete | Health and readiness perform no dependency I/O |
| Tests | Unit/integration/abuse/fuzz/race/privacy | Required focused and repository-wide gates pass | complete | Final tracked-snapshot evidence is external |
| Effort | Every prompt timed | Exact wall-clock prompt timings recorded | complete | Active engineering time was not separately measured |
| Commit | Two approvals and one clean commit | External candidate approval and commit procedure ready | ready | Tree equality and post-commit proof remain external |

<!-- mutable-review:end -->

## Acceptance Criteria

M13 is complete only when:

- this durable specification, OpenAPI contract, architecture, and M10
  reconciliation agree;
- the daemon truthfully exposes exactly three inbound resource paths and five
  OpenAPI operations;
- raw RFC 5322/RFC 6532 message bytes and representable SMTP Unicode-scalar
  spellings remain byte-preserving through the generated boundary;
- verification, policy, replay, and final disposition remain distinct;
- request-controlled trust policy and private signing state are absent;
- replay uncertainty, Valkey authority loss, configuration ambiguity, and
  lifecycle races fail closed;
- all protected material and failure paths are secret-safe;
- generated server/client artifacts reproduce byte-for-byte;
- `lib/` remains free of command/service dependencies;
- all focused, integration, fuzz, race, vulnerability, and guardrail checks
  pass on one unchanged candidate;
- two independent reviewers approve its exact identifier;
- `temp/` is ignored and unstaged; and
- exactly one structured M13 commit has the approved tree and fixed parent.

<!-- normative-projection:end -->
