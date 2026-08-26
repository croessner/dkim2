# Security Hardening Implementation Specification

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit. Its `qualified_linux` evidence does not
> qualify Draft-05.

Status: implemented; independent review and commit closeout pending.

Implementation base: `5f51ed500351c7efabe0ab70579d9a62639f6f43`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` behavior baseline. This increment
hardens the existing library, daemon, generated-client, datasource, replay,
observability, Milter, conformance, and build boundaries. It does not change
the pinned protocol baseline and must not turn local security policy into a
DKIM2 conformance claim.

The Exim adapter remains deferred. No Exim worktree, stash, package, binary,
fixture execution, or live compatibility evidence is part of this increment.
The conformance capability remains exactly `deferred_m17`.

## Later M17 Qualification Addendum (2026-07-31)

The preceding deferral remains the historical scope boundary of this security
increment. M17 later qualified the source-linked Exim adapter on Linux across
five authenticated upstream, Debian, and Ubuntu rows, with all 43 cases passing
per row and the fail-closed privacy verifier passing. The candidate-bound run
ID remains in generated full-profile evidence.
The active capability is `qualified_linux`; portable security and conformance
reports do not claim Exim execution, and full reports fail closed unless the
separate imported qualification summary is bound to the current manifest, base
revision, candidate snapshot, and verifier digest. See
`docs/security-testing.md` and `docs/conformance.md`.

## Source Documents And Precedence

This specification is governed, in order, by:

1. `draft-ietf-dkim-dkim2-spec-04` for DKIM2 protocol meaning;
2. `draft-chuang-dkim2-dns-04` for the repository's tested DNS record
   behavior;
3. RFC 5321, RFC 5322, RFC 6376, RFC 6531, RFC 6532, RFC 8259, and RFC 8601
   for the SMTP, message, DKIM heritage, internationalized-message, JSON, and
   authentication-reporting rules incorporated by the implemented surfaces;
4. `docs/specs/openapi/dkim2d.yaml` for the HTTP contract;
5. `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md` for repository
   boundaries and security defaults;
6. the completed implementation specifications for the package or adapter
   under test;
7. `docs/specs/implementation/test-vectors-and-conformance-suite.md` and
   `docs/conformance.md` for evidence classification and claim limits; and
8. this specification for the hardening campaign, abuse inventory, proof
   profile, and closeout requirements.

An expected result, fixture, fuzz seed, scanner result, or current
implementation is never authority over a draft, RFC, OpenAPI contract, or
durable architecture decision. A failing security test first triggers root
cause analysis. Production validation, protocol meaning, or a test expectation
may not be weakened merely to obtain a passing result.

The DKIM2 Draft-04 Security Considerations section remains `TBA`. Therefore
this increment classifies implementation limits, isolation, replay retention,
protected-file policy, error privacy, fail-closed behavior, and abuse
resistance as local security policy unless a separate normative rule below
directly governs the tested input. No finding or fix may be presented as a
normative Draft-04 security requirement solely because it is prudent.

## Original Gap

The repository already has substantial unit, negative, abuse, fuzz, race,
privacy, generated-output, vulnerability, conformance, Valkey, and real
Postfix evidence. The remaining gap is not the absence of all security tests.
It is the absence of one complete, auditable hardening pass over the assembled
product.

In particular:

- fuzz targets were introduced milestone by milestone, but there is no closed
  repository-owned inventory proving that every parser, byte transform,
  external boundary, and hostile response mapper has a maintained seed corpus,
  bounded execution property, and explicit owner;
- resource ceilings exist in multiple cohesive owners, but there is no
  cross-boundary proof that decoded and encoded sizes, work counters,
  concurrency gates, output caps, and downstream allocations compose without
  an amplification gap;
- recipe parsing, application, generation, and historical reconstruction have
  strong local tests, but require one coordinated bomb campaign across JSON
  structure, duplicate-heavy matching, copy ranges, literal expansion,
  reconstruction depth, integer overflow, cancellation, and public-service
  entry points;
- datasource, protected-file, signing-store, DNS, replay-memory, and Valkey
  providers require one shared abuse matrix for ambiguity, malformed or
  changing records, slow and context-ignoring sources, generation races,
  indeterminate mutation, saturation, and recovery;
- OpenAPI and generated clients require a complete adversarial fixture family
  across media type, headers, JSON, Base64, request size, response size,
  response shape, capability separation, timeout, cancellation, concurrency,
  and action-plan contradictions;
- the Milter adapter requires a consolidated hostile-peer campaign across
  framing, callback order, message and envelope accounting, daemon behavior,
  action admission, partial writes, overload, reset/reuse, socket lifecycle,
  Postfix SMTP, and Postfix non-SMTP paths;
- telemetry policy has focused tests, but the whole product needs one seeded
  marker campaign that proves raw message, envelope, identity, key,
  capability, protected-path, datasource, replay, DNS, and raw-error values
  cannot escape through logs, traces, metrics, REST, CLI, reports, test
  diagnostics, or panic containment;
- race tests run broadly, but ownership-sensitive lifecycle and saturation
  paths need repeated, adversarial race schedules rather than only ordinary
  package coverage;
- `govulncheck` is already a guardrail, but dependency reachability,
  generated/vendor synchronization, scanner freshness, and exception policy
  require an explicit release-blocking closeout; and
- security evidence must remain deterministic, content-free, tied to one
  unchanged candidate snapshot, and clearly separated from Draft-04
  conformance evidence.

## Goal

Deliver a reproducible, reproducer-first hardening campaign that:

- finds and fixes reachable security and robustness defects at their owning
  abstraction;
- proves finite resource use at every untrusted-input and external-I/O
  boundary;
- proves hostile recipes cannot produce unbounded parsing, planning,
  reconstruction, or historical-verification work;
- proves provider ambiguity, degradation, races, and indeterminate writes fail
  with the existing closed typed outcomes;
- proves OpenAPI and Milter peers cannot bypass capability, fidelity,
  action-plan, mutation, timeout, or fail-closed policy;
- proves telemetry and all machine/human outputs remain secret-safe and
  low-cardinality;
- runs every maintained fuzz target through one closed inventory and preserves
  every useful crashing input as a deterministic regression;
- exercises race-sensitive state repeatedly under the race detector;
- treats reachable vulnerability findings as release blockers unless the
  maintainer records an explicit durable exception;
- preserves M18 portable, Valkey, and real Postfix conformance; and
- leaves one independently reviewed, unchanged snapshot ready for one
  project-formatted commit.

Successful completion means no unresolved critical, high, or medium finding.
Low findings must also be fixed unless they are demonstrably false positives or
an explicit durable deferment names the owner, safety impact, and future gate.
No scanner-only statement substitutes for behavior tests and manual boundary
review.

## Authority And Classification Matrix

Every new case records one primary class and authority:

| Surface | Governing authority | Security classification | Required proof |
| --- | --- | --- | --- |
| RFC 5322 message framing and bytes | RFC 5322 Sections 2 and 3; RFC 6532 Section 3.4 where UTF-8 headers are accepted | `rfc_normative` plus local ceilings | exact/one-over parser tests, fuzz properties, no lossy normalization |
| SMTP reverse and forward paths | RFC 5321 imported grammar; the completed parser and Milter specs | `rfc_normative` for grammar, `adapter_contract` for callbacks | null path, duplicates, ordering, bare Postfix simulation, ESMTP argument closure |
| DKIM2 tag lists and Base64 | Draft-04 Sections 3, 7, and 8 | `draft_normative` | duplicate/conflicting tags, malformed/canonical Base64, numeric overflow, no panic |
| Message hashes and signature input | Draft-04 Sections 3.1, 4, 6, 9.6, and 11.7 | `draft_normative` | byte-level golden preservation, bounded parsing, deterministic output |
| Verification and custody | Draft-04 Sections 8 through 11 and recorded interpretations | `draft_normative` or `documented_interpretation` | gaps, envelope mismatch, key ambiguity, history exhaustion, typed result |
| Recipes | Draft-04 Sections 5, 6, 7.2, 9.1, 10.2, and 11.7 | `draft_normative` or `documented_interpretation`; ceilings are local policy | strict JSON, apply/generate self-proof, bombs, cancellation, work accounting |
| DNS key records | DNS-04 Section 3 and completed DNS resolver specification | `draft_normative` for record meaning, local policy for transport/cache bounds | RR ambiguity, key shape, cancellation, coalescing, cache saturation |
| Datasource and private signing | completed datasource and Milter specifications | `local_security_policy` | exact lookup, generation isolation, protected descriptors, opaque handles |
| Replay | completed replay specification | `local_security_policy` after protocol success | first-seen/replayed/indeterminate, concurrency, authority, no fallback |
| HTTP and generated DTOs | authoritative OpenAPI plus RFC 8259 | `openapi_contract` and local containment policy | preflight precedence, capability separation, body/response caps, timeout |
| Authentication-Results | RFC 8601 Sections 4.1 and 5 plus local formatter policy | `rfc_normative` for trust-boundary syntax, `adapter_contract` for mutation | forged-local removal, bounded formatter, no identity/error additions |
| Milter | completed Milter spec and real Postfix evidence | `adapter_contract` | wire FSM, reconstruction limitation, action admission, partial mutation |
| Logging, traces, and metrics | architecture and observability specification | `local_security_policy` | allowlist, marker absence, bounded errors, low-cardinality series |
| Fuzz, race, vulnerability, CI | Go toolchain and repository policy | `local_security_policy` and release gate | closed inventory, repeatability, clean scanner, immutable evidence |
| Exim | deferred adapter specification state | `deferred` | exact `deferred_m17`, zero execution, no restored or inspected work |

If one case spans classes, it is split or reports each assertion separately.
For example, signature verification and the local minimum RSA key-size policy
are not one normative result. Milter reconstruction robustness is not raw-wire
RFC 5322 conformance. Replay remains local policy even when its input follows
a Draft-04 PASS.

## Threat Model And Abuse Inventory

### Assets

Protected assets are:

- exact RFC 5322 message and SMTP envelope bytes;
- protocol correctness and immutable verified/signing authority;
- private signing keys and opaque signing handles;
- route, process, sign, and revise capabilities;
- protected configuration, datasource generations, replay secrets, and replay
  identities;
- DNS and datasource authority boundaries;
- daemon, Milter, client, and provider availability;
- deterministic conformance and security evidence;
- local trust assertions such as `Authentication-Results`; and
- telemetry privacy and bounded metric cardinality.

### Untrusted Inputs And Faulting Peers

Treat as hostile:

- every raw message, header, body, SMTP path, tag list, Base64 value, recipe,
  DNS TXT response, provider record, replay response, HTTP request, HTTP
  response, Milter frame, callback sequence, config file, protected file,
  environment placeholder, CLI fixture, conformance artifact, and Docker
  report;
- clocks, nonce sources, resolvers, provider callbacks, signers, observers,
  exporters, sockets, and filesystems that return errors, short reads,
  changing metadata, delays, cancellation races, contradictory states, or
  panics within the behaviors their contracts permit; and
- concurrent clients attempting to saturate admission, memory, goroutine,
  descriptor, socket, queue, replay, reload, exporter, and shutdown ownership.

No test needs a production secret, live mailbox, live domain, or public
internet endpoint. Use reserved `.test` identities and unique synthetic marker
families.

### Adversary Goals

The campaign covers attempts to:

- consume unbounded CPU, memory, goroutines, file descriptors, sockets, disk,
  log volume, trace volume, or metric series;
- trigger quadratic or worse work through duplicate-heavy headers, recipients,
  signatures, recipe candidates, copy ranges, JSON members, or provider rows;
- exploit integer overflow, decoded-versus-encoded size gaps, nested-input
  depth, count multiplication, response amplification, or retry multiplication;
- confuse authority through duplicate tags, ambiguous DNS RRs, conflicting
  datasource records, generation mixing, replay uncertainty, capability reuse,
  or request/response operation mismatch;
- bypass restrictive defaults through timeout, cancellation, fail-open,
  partial mutation, restart, reload, or error-classification paths;
- leak messages, identities, keys, capabilities, paths, queries, provider
  records, replay keys, DNS data, or raw errors;
- inject headers, log fields, trace attributes, metric labels, SMTP replies,
  filesystem paths, URLs, commands, or generated-client values;
- create stale, tampered, skipped, or cross-snapshot security evidence; and
- turn a local policy PASS into an overclaim of Draft-04 or RFC conformance.

### Explicit Non-Goals

This increment does not:

- change the pinned draft identifiers or semantics;
- invent behavior for Draft-04 `TBA` sections;
- implement Unicode, IDNA, or SMTPUTF8 envelope normalization;
- add DNSSEC policy;
- replace standard cryptography with custom primitives;
- add remote daemon access, a TCP Milter listener, new Milter actions, or
  fail-open defaults;
- add LDAP or SQL providers;
- add a new general-purpose security framework dependency without a reviewed
  necessity;
- perform dynamic attacks against public or production infrastructure;
- claim side-channel resistance beyond the existing explicit constant-time
  comparisons and standard-library cryptography;
- implement, restore, inspect, or execute Exim adapter work; or
- create a release tag, publish an artifact, stage files, or commit from an
  implementation or review prompt.

## Closed Resource Model

Every boundary must satisfy all of these rules:

1. Count, encoded-byte, decoded-byte, depth, work, concurrency, waiter,
   response, and output limits are finite.
2. Limits are charged before allocation or irreversible side effects whenever
   practical.
3. Aggregate limits compose across nested collections and transformations.
4. Arithmetic uses overflow-safe checks.
5. Public/configurable limits may narrow hard limits but cannot widen them.
6. Exact-limit and one-over-limit tests exist for each externally reachable
   dimension.
7. Cancellation and deadlines stop new work and cannot produce success after
   authority becomes indeterminate.
8. Errors expose a closed code and bounded public facts, never hostile raw
   content.
9. No fallback retries an indeterminate mutation or bypasses a saturated
   authority.
10. A limit failure must not partially mutate a message, replay state,
    datasource generation, action plan, output stream, or trusted header.

The cross-boundary audit freezes and tests at least these existing ceiling
families:

| Boundary | Required dimensions |
| --- | --- |
| Raw message | total bytes, header bytes, header fields, physical line bytes, field bytes, body lines, body line bytes |
| DKIM2 fields | field bytes, tags, algorithms, hash/signature sets, sequence facts, recipients, diagnostic facts |
| Recipes | JSON bytes/depth/members, names, steps, ranges, copied items, literals, state bytes, reconstructed bytes, input items, candidates, key bytes, comparisons, work units, history depth |
| Signing and verification | message/envelope bytes, profiles, routes, signatures, algorithms, callbacks, produced fields, output bytes |
| DNS | owner bytes/labels, TXT/RR bytes and count, key bytes, lookups, cache entries, flights, waiters, TTL |
| Datasource | identifiers, labels, profiles, credentials, handles, policies, file/JSON/string/key bytes, records, generations, reload work |
| Replay | identity inputs, key/value bytes, retention, entries, prune budget, in-flight operations, waiters, wire response, audit work |
| HTTP/OpenAPI | header bytes, request bytes, JSON depth/tokens/member names, encoded/decoded message, envelope bytes/count, in-flight operations, waiters, response bytes, timeout |
| Milter | frame/payload bytes, connection count, messages in flight, total buffered bytes, message/header/field/body/recipient bytes, action count/bytes, daemon response bytes, timeouts |
| Config/protected files | file bytes, YAML/JSON nodes/depth/scalars, placeholder bytes/count, path components, PEM blocks, metadata, read attempts |
| Observability | record bytes, event attributes, span attributes, export batch/queue, metric label vocabulary, buckets, diagnostics |
| Conformance/security evidence | manifest/report bytes, artifacts/cases, paths, digests, stdout/stderr capture, retained artifact bytes |

The implementation must derive exact values from the owning package and keep
one source of truth. This document does not authorize a second table of numeric
production constants. A repository-owned hardening inventory may record names,
owners, and proof tests, but any generated numeric view must be checked against
the actual constructors/constants and fail on drift.

Any discovered missing limit receives a cohesive owner, a restrictive default,
a non-widenable hard maximum, typed failure, exact/one-over tests, and
appropriate public/config documentation. Adding a limit may not silently
change Draft-04 success semantics for an input previously within every
documented bound; compatibility impact must be documented.

## Fuzzing Contract

The repository gains one closed, deterministic inventory of every first-party
Go fuzz target outside `vendor/`. The initial inventory must account for all
targets present at the implementation base and every target added by this
increment. Each entry binds:

- exact module and package;
- exact function name;
- owning input boundary;
- primary authority/class;
- stable seed-corpus source;
- properties asserted;
- per-case input cap or early bounding strategy;
- whether external I/O is forbidden or replaced by a deterministic fake;
- focused deterministic regression test ownership; and
- required completion duration.

The inventory cannot supply arbitrary commands, flags, environment variables,
working directories, paths, URLs, network endpoints, or output locations.
Repository code maps closed target identifiers to fixed module/package/function
tuples and rejects inventory drift, duplicate targets, missing targets, and
unexpected first-party fuzz targets.

Every target proves, as applicable:

- no panic, deadlock, data race, unbounded allocation, or uncontrolled I/O;
- deterministic success/error classification for the same injected state;
- output and error bounds;
- immutability and no partial mutation on failure;
- preservation of valid byte-oriented input;
- no secret-marker escape; and
- context cancellation or owned timeout behavior.

Each new or changed target runs individually for at least ten seconds after its
last edit. Before milestone approval, every inventoried target runs
individually for at least ten seconds on the unchanged candidate. A crash,
timeout caused by production behavior, excessive allocation, nondeterminism,
or race is a finding. A useful generated reproducer is minimized where
practical, promoted to a deterministic regression/seed, and fixed at the root.
The final evidence records only target ID, toolchain, bounded duration class,
result, and candidate identity; raw corpus bytes and hostile errors remain out
of reports.

## Recipe Bomb Campaign

Recipe hardening covers parser, applier, generator, history traversal, public
verification, signing/revision, OpenAPI, and Milter-reachable flows.

Required families include:

- maximum JSON depth and one-over depth;
- duplicate and unknown object members at every object level;
- huge numbers, negative numbers, exponent forms, integer overflow, and
  noncanonical numbers where forbidden;
- many case-fold-equivalent header names and duplicate header occurrences;
- many tiny copy ranges, overlapping-looking ranges, zero/negative/overflowing
  indexes, and large copied-item totals;
- many literal strings, single huge literals, escaped-string expansion, and
  aggregate decoded-byte limits;
- body lines with empty, maximum, one-over, binary, and repeated content;
- duplicate-heavy candidate matching intended to maximize comparisons;
- generation inputs that maximize candidates, key bytes, comparisons, steps,
  JSON size, and self-proof work;
- `b:null`, absent body, header-only, and disallowed body-unavailable
  combinations;
- many historical instances, sequence gaps, wrong recipes, and reconstructed
  state exact/one-over limits;
- cancellation before work, during planning, before publication, and at
  callback boundaries; and
- repeated and concurrent evaluation proving deterministic classifications
  and bounded retained memory.

Tests assert charged work rather than fragile wall-clock performance. A small
separate benchmark or stress test may establish practical growth bounds, but
CI correctness cannot depend on machine speed. No recursion may grow with
attacker-controlled recipe/history depth unless an explicit small hard limit
and stack-safety proof exist.

## Datasource, Signing Store, DNS, And Replay Abuse

The provider campaign uses storage-neutral fakes plus the real hermetic Valkey
target. It covers:

- missing, duplicate, ambiguous, inactive, malformed, unauthorized,
  unavailable, degraded, inconsistent, platform-limit, cancellation, and
  invariant states;
- exact and one-over identifiers, labels, rows, records, handles, keys, JSON
  depth, strings, files, and aggregate accounting;
- descriptor confinement, symlink/hard-link/path replacement, owner/mode/link
  changes, special files, short reads, empty-read loops, trailing bytes, and
  metadata changes between checks;
- atomic generation publication, failed reload, concurrent readers, shutdown,
  generation rollover, and no cross-generation policy/profile/key mixing;
- opaque-handle and public/private-key coherence without exposing key material;
- provider callbacks that are slow, context-aware, context-ignoring, panic,
  return contradictory results, or race cancellation;
- DNS multi-RR ambiguity, malformed records, cache/coalescing saturation,
  canceled final waiters, and transport contract failure;
- replay concurrent duplicates with exactly one first-seen result;
- replay unavailable-before-mutation versus indeterminate-after-possible-
  mutation, with no retry, fallback, or success projection;
- Valkey authority, RESP bounds, timeout, lifecycle, audit, revalidation,
  saturation, shutdown, and server-error classification; and
- seeded privacy markers absent from all results and diagnostics.

Provider-specific models remain behind their existing boundaries. A security
fix must not move Valkey, flat-file, filesystem, OpenAPI, or command types into
protocol packages.

## OpenAPI And Generated-Client Abuse Fixtures

The authoritative OpenAPI document changes only if a demonstrated contract
defect requires it. OpenAPI changes precede server/client changes, regenerate
every server and client artifact, and pass stale-output checks.

Abuse coverage includes:

- methods, paths, content types, content encoding, transfer framing, duplicate
  critical headers, capability shape and cross-route capability reuse;
- request-line and header exact/one-over boundaries;
- empty, truncated, trailing, duplicate-member, unknown-member, deep, token-
  heavy, invalid UTF-8, malformed escape, and multiple-value JSON;
- canonical Base64 exact/one-over encoded and decoded message boundaries;
- envelope counts, order, duplicates, null sender, invalid paths, and
  aggregate bytes;
- operation/version/draft/fidelity/context contradictions;
- admission saturation, waiter cancellation, deadline precedence, slow body,
  body read failure, disconnect, shutdown, and no work after rejection;
- generated response shape, version, operation, disposition/result matrix,
  action-plan order/count/value/aggregate bounds, body overflow, malformed
  media type, timeout, redirect, proxy, and ambient credential rejection;
- route-specific capability files and offline fixture validation before
  protected-file/network access; and
- error/report/CLI privacy with marker-bearing request, response, transport,
  path, and protected inputs.

Ordinary positive requests continue through generated DTOs and clients.
Negative raw HTTP construction stays a small closed oracle limited to declared
mutations. No parallel handwritten REST model is introduced.

## Milter Abuse Fixtures And Real Postfix Regression

Portable hostile Milter fixtures cover:

- frame length zero, maximum, one-over, truncation, command-only, unexpected
  command, and disconnect at every byte boundary;
- negotiation flags and protocol-v6 capability contradictions;
- every illegal callback transition, repeated callbacks, abort/reset/reuse,
  close during message, and multiple messages per connection;
- SMTP and Postfix-simulated bare envelope paths, null reverse path, recipient
  duplicates/order/count/bytes, ESMTP argument grammar, and no rejection or
  tempfail of simulated non-SMTP RCPT callbacks;
- duplicate, folded, empty, maximum, one-over, binary, UTF-8, and invalid
  headers; body chunk invariance and aggregate buffering;
- connection, message, byte, waiter, daemon, and shutdown saturation;
- daemon timeout, disconnect, oversized/malformed response, wrong operation,
  invalid result/disposition, contradictory action plan, and forged local
  `Authentication-Results`;
- full-plan validation before the first mutation byte;
- failure before mutation, after serialization, and after each possible write,
  preserving the documented indeterminate partial-mutation classification;
- fail-open eligibility and every condition that disables fail-open;
- Unix-socket path, owner, mode, stale-node, replacement, restart, shutdown,
  and project-scoped cleanup; and
- marker absence from adapter logs, metrics, errors, reports, socket names, and
  SMTP replies.

After portable fixes, the real Postfix qualification runs at least twice on the
unchanged candidate and produces byte-identical normalized reports. It must
continue to prove:

- internal-only topology, loopback daemon, Unix Milter sockets, no host ports,
  and no Milter TCP listener;
- explicit Milter protocol 6 and `tempfail` defaults;
- independent `smtpd_milters` and `non_smtpd_milters` paths;
- real SMTP origin signing, local `sendmail(1)` signing, inbound verification
  and bounded reporting;
- Postfix's hidden-from-Milter but final-queue `Received` behavior;
- stopped daemon and stopped Milter outcomes;
- cryptographic/public verification rather than grep-only header checks; and
- cleanup on success and injected failure.

This campaign preserves the documented Milter reconstruction limitation. It
does not relabel callback reconstruction as original RFC 5322 wire evidence.

## Logging, Tracing, Metrics, And Output Review

Perform both static field/label inventory and dynamic seeded-marker tests.

Forbidden everywhere outside isolated fixture input memory:

- private keys, capabilities, tokens, passwords, protected config and paths;
- raw messages, bodies, header values, signatures, Message-Instance values;
- raw senders, recipients, local parts, message IDs, selectors, domains,
  nonces, DNS TXT, datasource rows/queries, replay keys, Valkey keys;
- raw errors, URLs, LDAP DNs, SQL text, client addresses, backend identities,
  request/session/trace IDs copied as values; and
- unbounded or attacker-selected attribute names, event names, label names,
  label values, filenames, or SMTP reply text.

Allowed telemetry remains the closed vocabulary and buckets from the
observability specification. Metrics tests enumerate every registered
descriptor, reject forbidden or unknown labels, bound possible series from the
label vocabulary, and prove repeated hostile values cannot create new labels.
Tracing tests use an in-memory exporter and inspect every resource, span name,
status, event, and attribute. Logging tests inspect complete serialized records,
including handler failure and panic containment. REST, CLI, conformance,
security evidence, Docker qualification, and test failure outputs receive the
same marker scan.

Telemetry failure never changes protocol, policy, replay, datasource, HTTP, or
Milter results. Debug modules remain explicit, bounded, and secret-safe.

## Race, Lifecycle, And Concurrency Proof

`make race` remains mandatory. Additional repeated race cases target:

- DNS cache/coalescing and final-waiter cancellation;
- datasource immutable generations and reload/shutdown overlap;
- private signing generation acquisition and retirement;
- replay memory and Valkey admission/revalidation/shutdown;
- daemon HTTP admission, readiness, lifecycle, and exporter shutdown;
- Milter connection/message/byte admission, abort/reset/reuse, action writes,
  socket cleanup, and shutdown;
- conformance/security report collection and candidate-snapshot checks; and
- observer callbacks that block, panic, re-enter permitted seams, or race
  cancellation.

Assertions use bounded coordination primitives, not sleeps as correctness
proof. Repetition counts are fixed and reasonable. No race is dismissed as
test-only until ownership and production reachability are proven.

## Vulnerability And Dependency Policy

Completion requires:

- `govulncheck` over every workspace module and the tools module;
- current vulnerability database access, with the database identity or update
  time recorded in ignored evidence when the tool exposes it;
- review of every reachable finding against the exact call path;
- update or root-cause remediation for reachable findings;
- `go work sync`, standalone-module checks, OpenAPI regeneration checks, and
  reproducible vendor checks after any dependency change;
- no unreviewed `replace`, fork, checksum bypass, floating generator, mutable
  image, or new runtime dependency; and
- a clean repeat of tests, race, conformance, and vulnerability gates after a
  dependency fix.

Critical, high, medium, and reachable unscored findings block completion. An
unreachable advisory is recorded as bounded ignored evidence and kept under
the ordinary scanner gate. A maintainer exception must be explicit, durable,
time-bounded, and include reachability evidence, compensating controls, owner,
and removal condition; implementation and review agents cannot invent one.

## Package And Dependency Boundaries

- `lib/` owns protocol, parser, canonicalization, recipe, verification,
  signing, DNS-domain, datasource-domain, replay-domain, and library-safe
  observation fixes. It remains free of daemon, Milter, OpenAPI, Cobra, Viper,
  Fx, Prometheus, OTLP exporter, Valkey-driver, filesystem-provider, and
  CLI-only dependencies.
- `cmd/dkim2d` owns HTTP containment, generated server mapping, config,
  protected files, concrete providers, private signing, Fx lifecycle,
  exporters, metrics, and process admission.
- `cmd/dkim2ctl` owns generated-client fixture and output hardening. It does
  not gain a handwritten REST model.
- `cmd/dkim2-milter` owns Milter wire, callback fidelity, daemon-client,
  action-plan, Unix-socket, failure-policy, and adapter-observability fixes.
- `tools/` and root Make targets may own a closed first-party fuzz/security
  inventory and deterministic orchestration. They do not own protocol
  semantics and must not execute fixture-selected commands.
- `testdata/conformance/` remains the durable case/report authority where new
  deterministic abuse fixtures extend M18. Generated run reports remain
  ignored artifacts.

Use cohesive existing types and narrow interfaces. Add an abstraction only
when it removes real duplicated security logic or protects a durable boundary.
Every changed or introduced handwritten named function and method has a
concise English doc comment.

## Security Evidence Contract

Security evidence binds:

- exact base revision;
- exact candidate-snapshot digest defined by the conformance-suite
  specification for the durable dirty candidate;
- exact pinned draft identifiers;
- Go version, GOOS, GOARCH, race status, vulnerability tool identity, and
  closed profile;
- complete inventoried fuzz target IDs and pass/fail/not-run states;
- deterministic abuse suite IDs and pass/fail states;
- conformance manifest and portable/full report digests;
- two normalized real Postfix report digests;
- vulnerability state by bounded class;
- unresolved finding counts by severity; and
- one overall result.

Evidence contains no timestamps in canonical comparison material, durations
except bounded classes, absolute paths, host/user/container IDs, corpus bytes,
raw commands, raw errors, messages, envelopes, identities, secrets, provider
data, or protected paths. Raw tool output remains ephemeral and receives the
same privacy scan.

Required cases cannot be skipped. Platform exclusions must be declared before
execution. Exim is the sole adapter capability permitted to remain
`deferred_m17`; it has zero security execution cases.

Any durable byte, file mode, path, generated artifact, base revision, or
manifest change invalidates prior reports and approvals. Implementation and
review evidence must refer to one unchanged candidate.

## Delivery Shape

One implementation agent executes these slices sequentially:

1. Freeze the first-party fuzz/resource/security inventory, closed runner,
   threat-model fixtures, deterministic evidence types, and drift tests.
2. Harden protocol-core parsers, canonicalization, verification, signing,
   history, recipes, and exact resource/work accounting.
3. Harden DNS, datasource, protected-file, private-signing, replay-memory, and
   Valkey provider abuse/lifecycle behavior.
4. Harden OpenAPI, daemon HTTP/config/admission, generated clients, protected
   capabilities, and adversarial fixtures.
5. Complete the whole-product observability, privacy-marker, output, and
   metric-cardinality review.
6. Harden portable Milter behavior and repeat the real Postfix qualification
   including failure cleanup.
7. Finish race/stress/fuzz orchestration, `govulncheck`, CI, documentation,
   M18 conformance, full guardrails, and unchanged-snapshot evidence.

One fresh independent reviewer then audits and fixes the cumulative candidate.
There are no slice commits. The orchestrator creates exactly one
project-formatted commit only after all findings are fixed, every required gate
passes, and two approvals bind the same unchanged snapshot.

## Implementation Effort

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 5 to 14 agent-hours, excluding unavailable external vulnerability service or Docker recovery |
| Highest-risk areas | recipe/work amplification, cross-boundary size composition, provider lifecycle, partial Milter mutation, privacy false negatives |
| Expected prompt count | seven implementation prompts plus one independent review/fix prompt |
| Required final gate | full security profile, full M18 conformance including real Postfix, and `make guardrails` |

Measured wall-clock prompt timing, blocked time, focused tests, findings, fixes,
candidate hashes, report hashes, and approvals are recorded only in the ignored
prompt-pack execution ledger until closeout. Durable completion evidence may be
added here only after the final unchanged candidate is accepted.

## Required Tests

### Inventory And Deterministic Tests

- closed inventory equality against every first-party fuzz target;
- duplicate, missing, unexpected, vendor, malformed, and command-injection
  inventory cases;
- exact/one-over tests for every reachable resource dimension;
- overflow, cancellation, deterministic replay, immutability, and no-partial-
  mutation properties;
- authority/classification tests preventing local-policy overclaims;
- security evidence schema, ordering, snapshot, merge, skip, tamper, and
  privacy tests.

### Protocol And Recipe Tests

- all existing Draft-04/DNS-04 vector and conformance cases;
- targeted parser/canonicalization/signature/history/signing negative cases;
- complete recipe bomb families through internal and public boundaries;
- deterministic work-counter tests and bounded stress/benchmark evidence;
- every affected protocol fuzz target for at least ten seconds after its last
  edit and in the final all-target run.

### Provider And Runtime Tests

- datasource/provider state and generation abuse matrix;
- protected-file descriptor and metadata race matrix on supported platforms;
- replay memory concurrency and exact real Valkey integration;
- OpenAPI generated-client positive and hostile raw-boundary fixtures;
- daemon admission/readiness/lifecycle saturation and cancellation;
- telemetry static allowlist and dynamic marker absence;
- portable public-socket Milter hostile-peer fixtures;
- real Postfix qualification twice plus injected failure cleanup.

### Race, Vulnerability, Generated, And Documentation Checks

- focused repeated race schedules and full workspace race;
- every first-party fuzz target individually for at least ten seconds;
- current `govulncheck` over workspace and tools;
- OpenAPI stale output, workspace sync, standalone modules, vendor
  reproducibility, protected-platform builds, formatting, vet, and lint;
- conformance manifest closure, portable report, Valkey, Postfix, and full
  report;
- architecture/README/conformance updates only where implemented status or
  commands change; and
- English doc comments and production naming audit.

## Final Gates

The implementation may add closed Make targets such as:

```text
make check-security
make fuzz-security
make security
```

Names may be refined during implementation, but `check-security` must be
deterministic and network-free, `fuzz-security` must run the exact closed
first-party target inventory, and `security` must fail on any required skipped
or failing case. None may evaluate caller-supplied commands.

On one unchanged candidate, completion requires:

```text
make fmt
make test
make vet
make lint
make race
make check-openapi
make check-workspace
make check-vendor
make check-platform-builds
make test-valkey
make check-conformance
make conformance
make conformance-postfix
make conformance-all
make check-security
make fuzz-security
make security
make govulncheck
make guardrails
git diff --check
```

The real Postfix qualification runs at least twice and produces identical
normalized reports. Every first-party fuzz target runs individually for at
least ten seconds after the last relevant edit. Full reports, security
evidence, reviewer approval, and orchestrator approval must bind the same
candidate snapshot. A failed, skipped, stale, unavailable, or mismatched
required gate is not approval.

## Review Requirements

The independent reviewer:

- reads the actual diff and surrounding ownership code rather than relying on
  implementation summaries;
- independently maps every behavior assertion to the authority matrix;
- independently inventories first-party fuzz targets and resource boundaries;
- reproduces representative exact/one-over, recipe bomb, provider race,
  OpenAPI, telemetry, and Milter attacks;
- inspects full raw tool diagnostics locally for false positives while keeping
  them out of durable evidence;
- repeats race, fuzz, Valkey, vulnerability, portable/full conformance, and
  real Postfix gates as required;
- fixes every finding at the root with a stable reproducer first where
  practical;
- rejects any weakened validation, reduced coverage, skipped target,
  overclaimed conformance, secret leak, arbitrary command runner, or
  dependency-boundary breach; and
- records one explicit approval only after no unresolved findings remain.

The orchestrator performs a separate second review of the unchanged snapshot,
candidate digest, report identities, diff, index, ignored paths, and complete
gate evidence before exact staging.

## Acceptance Criteria

- Every first-party fuzz target is in one closed drift-checked inventory and
  passes the required final run.
- Every untrusted-input and external-I/O boundary has finite, composable,
  exact/one-over-tested limits.
- Recipe bombs remain bounded across parse, apply, generate, history, public,
  OpenAPI, and Milter-reachable paths.
- Datasource, DNS, protected-file, signing-store, replay, and Valkey ambiguity,
  degradation, race, and indeterminate states remain typed and fail closed.
- OpenAPI and generated clients reject all hostile contract, size, capability,
  timeout, and action-plan contradictions without partial work or leakage.
- Milter hostile peers cannot bypass callback, fidelity, admission, action,
  mutation, timeout, or fail-open policy.
- Logs, traces, metrics, REST, CLI, reports, errors, test diagnostics, and
  panic containment pass the complete marker campaign; metrics remain
  low-cardinality.
- Full race and repeated lifecycle evidence passes.
- `govulncheck` reports no reachable unresolved vulnerability and dependency
  metadata is synchronized and reproducible.
- M18 portable, Valkey, and real Postfix/full conformance remain green and
  deterministic.
- Exim remains exactly `deferred_m17`; its stash and deferred work are not
  inspected, restored, changed, or executed.
- All findings are fixed, two approvals bind one unchanged snapshot, `temp/`
  and generated reports remain ignored/unstaged, and exactly one
  project-formatted security-hardening commit is ready for the orchestrator.

## Completion Evidence

Fill after implementation and independent review:

- implementation start/end and measured wall-clock effort;
- deterministic security inventory/report hashes;
- candidate-snapshot hash;
- fuzz target count and all-target result;
- focused abuse and race commands/results;
- Valkey and real Postfix report hashes;
- portable and full conformance report hashes;
- vulnerability tool/database identity and result;
- complete guardrail result;
- reviewer findings and root-cause fixes;
- independent reviewer approval;
- orchestrator approval;
- exact staged durable path inventory; and
- final commit identity.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Authority | Draft/RFC/OpenAPI/interpretation/policy/adapter claims remain separate | pending | pending | |
| Threat model | Every asset, input boundary, failure peer, and abuse goal is exercised | pending | pending | |
| Resource limits | Finite composable limits with exact/one-over and overflow proof | pending | pending | |
| Fuzzing | Closed complete inventory and required per-target run | pending | pending | |
| Recipes | Bombs bounded across internal and public flows | pending | pending | |
| Providers | Datasource, DNS, signing, replay, Valkey abuse and races fail closed | pending | pending | |
| OpenAPI | Generated contract, containment, capabilities, responses, and privacy hold | pending | pending | |
| Observability | Allowlist, redaction, bounded records, and cardinality hold | pending | pending | |
| Milter/Postfix | Hostile-peer and real SMTP/non-SMTP evidence pass | pending | pending | |
| Race | Full and focused repeated race evidence passes | pending | pending | |
| Vulnerabilities | No unresolved reachable finding; metadata reproducible | pending | pending | |
| Exim | Exact deferred state; stash and work untouched | pending | pending | |
| Evidence | Deterministic reports and two approvals bind one unchanged snapshot | pending | pending | |
| Commit | One exact project-formatted commit after approval | pending | pending | |

## Settled Decisions And Deferred Work

- Settled: Draft-04 and historical DNS-04 remain the behavior baseline.
- Settled: Draft-04's `TBA` Security Considerations do not make local hardening
  rules normative DKIM2 requirements.
- Settled: hardening extends existing package owners; it does not create a
  second protocol, limit, provider, REST, Milter, or telemetry model.
- Settled: every first-party fuzz target is inventoried and run individually;
  useful fuzz failures become deterministic regressions.
- Settled: correctness gates use work/accounting assertions rather than
  machine-speed thresholds.
- Settled: real Postfix remains required because Milter abuse behavior is in
  scope.
- Settled: vulnerability findings are release blockers under repository policy
  unless the maintainer supplies a durable explicit exception.
- Deferred: Exim implementation and abuse/live compatibility evidence remain
  deferred until the taint-safe envelope-authority design is resolved.
- Deferred: polished production deployment/operator documentation remains the
  documentation and operator-guide increment.
- Deferred: external-implementation comparison, draft issue closure, API
  cleanup, and release-candidate claims remain the interop/reference-polish
  increment.
