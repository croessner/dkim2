# OpenAPI Test Client Implementation Specification

Status: implemented; independent review and closeout pending.

Implementation base: `248c00a0bcfe03166ad9002c7b1251f3ae217b6b`.
Protocol behavior is pinned to `draft-ietf-dkim-dkim2-spec-04` and the
repository's historical `draft-chuang-dkim2-dns-04` baseline.

## Purpose

This increment turns `dkim2ctl` into the first executable OpenAPI-backed test
and conformance client for `dkim2d`. It provides deterministic fixture
execution, local daemon smoke checks, negative HTTP contract probes, stable
machine-readable results, and bounded transport diagnostics.

The client is an adapter and test harness. It does not implement DKIM2
protocol semantics and it does not introduce a second REST model. Every typed
ordinary request uses the generated OpenAPI client and generated DTOs.

## Governing Authority

This specification is governed by `AGENTS.md`, `POLICY.md`,
`docs/ARCHITECTURE.md`, the M13 daemon specification,
`docs/specs/openapi/dkim2d.yaml`, its generated client, the pinned drafts,
RFC 8259, RFC 9110 through RFC 9112, Go 1.26 contracts, and `Makefile`.
Authority is ordered as follows:

1. the two draft baselines above for protocol meaning;
2. `docs/specs/openapi/dkim2d.yaml` for REST operations and DTOs;
3. `docs/ARCHITECTURE.md` and this specification for client behavior;
4. fixtures only as executable expectations of those authorities.

A fixture may never redefine protocol or REST behavior. A conflict stops the
increment and requires the durable authority to be corrected first. The client
must remain usable when later OpenAPI regeneration changes generated Go names;
hand-written code adapts at the generated boundary without copying DTOs.

## Scope

The increment provides:

- a Cobra root command named `dkim2ctl`;
- `smoke` for unauthenticated health and readiness checks;
- `fixture validate` for offline schema and policy validation;
- `fixture run` for deterministic positive or negative daemon fixtures;
- a generated-client construction boundary with explicit loopback authority;
- a separate protected capability-file owner and generated request editor;
- stable JSON Lines output suitable for CI and reproductions;
- bounded, content-free transport diagnostics and stable exit classes;
- draft-versioned checked-in fixture examples and daemon integration tests;
- focused unit, negative, privacy, abuse, race, and subprocess tests;
- Makefile and documentation integration needed to build and test the client.

## Non-Goals

This increment does not add or expose:

- signing, revision, message mutation, action-plan, or operator mutation APIs;
- a hand-written REST request or response model;
- protocol verification, policy, replay, recipe, or datasource logic;
- remote transport, TLS, proxy, discovery, retry, redirect, or authentication
  negotiation;
- config files, Viper, environment expansion, interactive prompts, shell
  expansion, or credential values passed on the command line;
- logs, traces, metrics, exporters, or debug modules;
- a generic raw HTTP command.

Negative fixtures may exercise deliberately malformed requests through a
narrow test-only transport builder. That builder is not a second client and
may target only the existing three route families and declared negative
mutations.

## Command Contract

The root command writes every executed result or failure as stable JSON Lines
to stdout. Stderr remains empty except for explicit Cobra help or command-shape
usage. It never writes progress banners or raw errors. `--output=jsonl` is the
only initial output mode and is the default. Commands reject positional
arguments not declared below.

Global flags:

| Flag | Default | Contract |
| --- | --- | --- |
| `--server-url` | `http://127.0.0.1:8080` | Absolute canonical loopback HTTP URL with no userinfo, query, fragment, path other than empty, or trailing slash |
| `--timeout` | `10s` | Finite duration from 100 ms through 60 s |
| `--capability-file` | empty | Absolute protected file path; required only for authenticated process fixtures |
| `--output` | `jsonl` | Exact closed value `jsonl` |

The URL permits canonical `127.0.0.1` and `[::1]` IP literals only, with a
canonical decimal port from 1 through 65535. Hostnames, unspecified addresses,
IPv4-mapped IPv6, zones, noncanonical ports, alternate schemes, redirects,
and URL credentials fail before file or network access.

`smoke` accepts `--expect-ready=true|false`. It performs GET health followed by
GET readiness using the generated client. It never reads the capability file.
A healthy process with the requested readiness state succeeds; every malformed
response, transport failure, or unexpected state fails closed.

`fixture validate PATH...` loads, validates, and orders fixtures without
opening the capability file or network. `fixture run PATH...` validates the
complete set before file or network access, then runs it in deterministic
path-and-case order. One invocation accepts at most 256 fixture files and 4096
cases. Duplicate fixture identifiers are rejected.

## Protected Capability

The capability is never accepted as a flag value, environment value, stdin
value, or fixture field. The file contains exactly 32 opaque bytes and rejects
the all-zero value. It is opened and validated using descriptor-safe,
fail-closed platform behavior consistent with the M13 protected-file contract:
regular file, effective-user owner, link count one, mode 0400 or 0600, no
symlink, no device/FIFO/socket, no pathname re-open, and no ambiguous metadata.

The client implementation is separate from server-internal packages. A small
client-owned type holds the bytes, has content-free `String`, `GoString`, and
`Format`, exposes only request editing, and zeroes its storage on close.
Request editing adds exactly one `X-DKIM2-Capability` field after rejecting any
existing field of that name. It is usable only for generated process requests
and is never attached to health or readiness calls.

Overwriting the one owned fixed-size array on close is lifecycle hygiene, not
a claim that Go, copied request headers, or process memory can be securely
erased. Encoded capability text is short-lived and not retained after request
construction.

Unsupported platform inspection fails closed. The platform matrix and
descriptor-race tests must match the supported M13 platforms. Shared test
vectors freeze parity without importing server-internal types.

## Fixture Format

Fixtures are UTF-8 JSON documents with a maximum encoded size of 1 MiB each,
maximum nesting depth 16, no duplicate object member, no unknown member, no
trailing JSON value, and no BOM. Aggregate fixture bytes per invocation are at
most 32 MiB. Files must be regular, non-symlink files and are read with a
bounded reader. Directories are not recursively expanded.

The top-level object requires exact schema `dkim2ctl.fixture.v1`, exact
Draft-04, one stable identifier, and one `cases` array.

Each file contains 1 through 256 cases. The file-wide encoded message total is
at most 32 MiB after Base64 decoding. Case identifiers are 1 through 64 ASCII
lowercase letters, digits, dot, underscore, or hyphen and are unique globally
within one invocation.

Closed case kinds:

- `health`: generated GET health with an expected status and typed body;
- `readiness`: generated GET readiness with expected status and typed body;
- `process`: generated process request plus expected status and selected
  generated response fields;
- `negative`: one declared raw-contract mutation plus an expected status and
  bounded response metadata.

Process input uses fields corresponding exactly to generated `ProcessRequest`.
The runner converts fixture values into generated DTOs at one adapter boundary.
It must not define a parallel Go response structure. Expected projections are
explicit allowlisted assertions, not full raw-response snapshots.

Negative mutations are closed and independently bounded:

- missing, duplicate, empty, or mismatching capability;
- unsupported media type;
- malformed JSON;
- unknown JSON member;
- truncated request body;
- one byte over the declared body limit;
- unsupported method on a declared route;
- query or fragment-like request-target contamination where representable;

Fixture files cannot specify arbitrary headers, methods, URLs, filesystem paths,
timeouts, redirects, or response bodies.

Unexpected response content types and bounded malformed responses are exercised
only through injected fake transports in unit and fuzz tests. They are response
classification inputs, not fixture-selectable request mutations.

## Transport Boundary

The production client uses one private `http.Client` with:

- no redirects;
- proxy disabled;
- cookie jar absent;
- compression disabled;
- one fixed overall command context deadline;
- dial and response-header bounds no greater than that deadline;
- connection reuse disabled for deterministic local tests;
- a custom dial check proving the connected peer is the configured loopback
  address and port.

Every response body is closed exactly once. Health/readiness bodies are capped
at 4 KiB and process/error bodies at 1 MiB. Reads beyond the bound fail without
printing bytes. Response status, declared content type, content length class,
operation, and stable error class may be diagnostic facts.
Raw errors, URLs supplied by a user, headers, bodies, message data, envelope
data, capability bytes, and fixture content may not be diagnostic facts.

The client validates the generated typed response for the expected status and
rejects missing, multiple, malformed, unknown, or internally contradictory
representations. An HTTP status alone is never sufficient for a positive
fixture.

## Stable Output And Exit Classes

Each executed case produces exactly one compact JSON object followed by LF.
Keys are emitted in a fixed order:

```text
schema,draft,fixture,case,operation,outcome,http_status,error_class,
duration_bucket,disposition,verification_state,policy_verdict,replay_class
```

Fields not applicable are `null`, not omitted. Values are closed enums or
validated bounded identifiers. No timestamp, clock reading, or exact duration
enters the stable record; executed network cases use only the closed
`under_100ms`, `under_1s`, `under_10s`, or `at_least_10s` duration bucket.
The output never includes input messages,
envelope values, server URLs, paths, headers, response bodies, raw errors,
credentials, selectors, domains, recipients, or hashes derived from them.

Exit status is stable:

- `0`: every requested case matched;
- `2`: command usage or flag validation failed;
- `3`: fixture loading or validation failed;
- `4`: protected capability loading failed;
- `5`: local transport or deadline failed;
- `6`: response contract was malformed or unsupported;
- `7`: a valid response did not match the fixture expectation;
- `8`: internal invariant failure.

When several cases fail, execution continues only for independent already
validated cases and returns the highest-priority lowest numeric nonzero class.
Capability load or transport-authority failure stops all authenticated cases.

## Testing

Required evidence includes:

- literal tests for every flag, limit, output key, enum, and exit status;
- generated-client spy, transport, response-contract, and close-ownership tests;
- protected-file platform, replacement-race, lifecycle, and formatting tests;
- fixture syntax, bound, ordering, deterministic-output, smoke, negative,
  subprocess, marker-privacy, and race tests;
- fuzz targets for fixture decoding, negative mutation construction, response
  classification, and output privacy.

Every new fuzz target runs separately for at least ten seconds after the last
code change. `make guardrails` is mandatory on the final unchanged candidate.
`make check-openapi` must prove generated output remains current.

## Completion Criteria

- `dkim2ctl` builds and exposes only the specified test-client commands.
- Ordinary operations use generated OpenAPI transport and DTOs exclusively.
- Capability and all mail data remain secret-safe outside explicit requests.
- Fixtures and output are deterministic, bounded, draft-versioned, and closed.
- All negative behavior fails closed with stable content-free classes.
- No service dependency enters `lib/`.
- Focused tests, all new fuzz targets, race tests, OpenAPI checks, and
  `make guardrails` pass on one unchanged snapshot.
- An independent reviewer reports no unresolved finding.
- `temp/` remains ignored and unstaged.
- The milestone is represented by exactly one commit using the project format.

## Implementation Evidence

The implementation adds the Cobra command surface, strict loopback authority
and timeout validation, a separately owned protected capability loader,
generated-client transport and DTO boundaries, bounded response
classification, strict deterministic fixtures, stable JSON Lines, generated
smoke and process calls, and the closed negative-contract builder.

Draft-versioned checked examples, subprocess and privacy coverage, platform
build checks, race tests, and four fuzz targets exercise fixture decoding,
negative construction, response classification, and output privacy. OpenAPI
source and generated artifacts remain unchanged; the stale-output guard
continues to prove that boundary. Final unchanged guardrail and independent
review evidence is recorded outside this immutable implementation contract.
