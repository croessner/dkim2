# Test Vectors And Conformance Suite Implementation Specification

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-06 authority is the migration disposition
> and current durable architecture. Its `qualified_linux` evidence does not
> qualify Draft-06.

Status: implementation-ready planning baseline.

Implementation base: `487ad434d106954e72d1cd241de543918c0fd260`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` baseline. The active working-group DNS
document has a different identifier but a normatively identical body; this
increment does not silently migrate identifiers, behavior, or vectors.

## Purpose

This increment turns the repository's existing package-owned vectors,
fixtures, integration tests, and adapter evidence into one versioned,
auditable conformance suite. It adds missing positive, negative, replay,
OpenAPI, and Milter coverage, produces a deterministic machine-readable CI
report, and publishes precise conformance notes.

The suite is evidence about a named implementation snapshot against named
authorities. It is not an IETF certification program, does not make draft
status final, and must not describe project policy or adapter behavior as a
normative DKIM2 requirement.

This increment also delivers a real, reproducible Linux Docker qualification
fixture for the operational Postfix path:

```text
Postfix -> dkim2-milter -> dkim2d
```

The fixture proves both SMTP and non-SMTP Postfix Milter paths with synthetic
test material. It is a qualification asset, not the polished deployment or
operator demo owned by the documentation increment.

The Exim adapter is deliberately deferred. This increment freezes an exact
future Exim fixture and result schema, but it neither depends on an Exim module
nor claims live Exim conformance.

## Later M17 Qualification Addendum (2026-07-31)

The preceding Exim deferral records this earlier conformance milestone and is
not the current capability state. M17 subsequently qualified the source-linked
Exim adapter on Linux across five authenticated upstream, Debian, and Ubuntu
rows, with all 43 cases passing per row and the fail-closed privacy verifier
passing. The candidate-bound run ID remains in generated full-profile evidence.
The active model is `qualified_linux`: portable reports mark Exim execution not
applicable, while full reports require an explicit evidence root and import
only a bounded summary bound to the current manifest, base revision, candidate
snapshot, and verifier digest. See `docs/conformance.md` and
`docs/reports/exim-compatibility-2026-07-27.md`.

## Governing Authority

Authority order is:

1. `draft-ietf-dkim-dkim2-spec-04` for DKIM2 protocol meaning;
2. `draft-chuang-dkim2-dns-04` for the repository's tested DNS behavior;
3. RFC 5321, RFC 5322, RFC 6376, RFC 6531, RFC 6532, and RFC 8601 for SMTP,
   message, DKIM heritage, internationalized mail, and reporting behavior;
4. the authoritative OpenAPI document for HTTP operations and DTOs;
5. the completed implementation specifications for project interpretations,
   service behavior, replay policy, and adapter behavior;
6. the Postfix Milter documentation for Postfix-specific integration facts;
7. this document for suite structure, evidence, reporting, and CI policy.

Fixtures are executable expectations of these authorities. They are never a
new source of protocol semantics. If implementation, fixture, and authority
disagree, work stops until the authority mapping and root cause are reviewed.
Changing an expected result merely to make the implementation pass is
forbidden.

The Postfix-specific baseline is the official
[Postfix MILTER_README](https://www.postfix.org/MILTER_README.html) and
[postconf(5)](https://www.postfix.org/postconf.5.html). Postfix callback and
queue behavior are adapter-fidelity facts, not DKIM2 rules.

## Conformance Classes

Every case belongs to exactly one class:

| Class | Meaning | Examples |
| --- | --- | --- |
| `draft_normative` | Directly tests normative pinned-draft behavior | tag grammar, sequence, canonical input, signature, recipe |
| `rfc_normative` | Directly tests an incorporated mail or reporting RFC rule | RFC 5322 bytes, SMTP envelope syntax, Authentication-Results trust boundary |
| `documented_interpretation` | Tests a durable project interpretation of draft ambiguity | current Draft-04 recipe or custody interpretation |
| `local_security_policy` | Tests fail-closed behavior outside DKIM2 conformance | replay storage, protected files, limits, redaction |
| `openapi_contract` | Tests the authoritative generated HTTP boundary | request/response schema, action plan, status mapping |
| `adapter_contract` | Tests Milter or MTA integration behavior | callback fidelity, action application, Postfix failure mapping |

A report must keep the class visible. An `adapter_contract` or
`local_security_policy` PASS must never be counted as proof of a
`draft_normative` requirement.

## Scope

This increment delivers:

- a strict repository-level conformance manifest with exact artifact digests;
- a bounded, versioned case schema and deterministic loader;
- broader Draft-04 positive vectors for verification, signing, revision,
  recipes, policy, DNS, and public facade behavior;
- negative vectors with typed expected failures and exact mutation provenance;
- replay vectors that separate first-seen, replayed, disabled, and
  indeterminate storage states from protocol verification;
- generated-client OpenAPI fixtures for process, sign, and revise operations,
  plus closed negative-contract cases;
- portable data-driven Milter fixtures for reconstruction, daemon requests,
  action plans, SMTP outcomes, and fidelity limits;
- a real pinned Postfix Docker/Compose qualification fixture covering
  `smtpd_milters` and `non_smtpd_milters` separately;
- an exact future Exim fixture/result schema and an explicit deferred status;
- deterministic JSON and human-readable conformance reports;
- public conformance notes that state supported, partial, deferred, and
  non-normative areas without overclaiming;
- Makefile targets and Linux CI that validate the manifest, run the suite,
  run the Postfix qualification, and retain reports; and
- focused unit, integration, negative, privacy, race, reproducibility, and
  tamper tests.

## Non-Goals

This increment does not:

- change the pinned DKIM2 or DNS behavior baseline;
- invent semantics for draft `TBA` sections;
- add Unicode, local-part, or IDNA normalization;
- claim DNSSEC as a DKIM2 conformance input;
- make Milter reconstruction equivalent to original RFC 5322 wire bytes;
- implement or restore the deferred Exim adapter;
- publish a live Exim compatibility result;
- add production Postfix packaging, production images, Helm charts, service
  units, secret management, upgrade policy, or a polished operator demo;
- test against private messages, production domains, production keys, or
  production credentials;
- allow arbitrary commands, paths, URLs, environment values, or Docker images
  to be selected by a fixture;
- make CI reports a source of protocol truth; or
- permit skipped required cases to count as passing.

## Ownership And Repository Layout

Protocol rules remain in `lib/`. The suite may expose no command, OpenAPI,
Milter, Docker, or report dependency from the library module.

Package-owned fixtures stay close to their implementation:

```text
lib/testdata/vectors/
  draft-ietf-dkim-dkim2-spec-04/
  draft-chuang-dkim2-dns-04/

cmd/dkim2ctl/testdata/fixtures/
  draft-ietf-dkim-dkim2-spec-04/

cmd/dkim2-milter/testdata/conformance/
  draft-ietf-dkim-dkim2-spec-04/
```

Repository-wide indexing, schemas, and report expectations live under:

```text
testdata/conformance/
  manifest.json
  schemas/
  exim/
  report-golden/
```

The real Postfix qualification lives under:

```text
contrib/qualification/postfix-milter/
```

This path is intentionally a test fixture. The later operator-documentation
increment may reuse proven pieces, but must not reclassify qualification
defaults as production guidance without a separate review.

Suite orchestration and report generation belong in `cmd/dkim2ctl` or the
repository `tools` module. They may call closed, compiled-in runners and
Makefile targets. They must not duplicate library protocol rules or generated
OpenAPI DTOs. The Milter module continues to own its wire fixture runner.

## Manifest Contract

The authoritative manifest is UTF-8 JSON with schema
`dkim2.conformance-manifest.v1`. It is bounded to 1 MiB, depth 16, 4,096
artifacts, and 16,384 cases. Duplicate members, unknown members, a BOM,
trailing values, noncanonical integers, invalid UTF-8, and unsorted identifiers
fail closed.

The manifest contains:

- exact message and DNS draft identifiers;
- an exact suite-schema version;
- a stable ordered list of suite identifiers;
- for every artifact, its repository-relative slash path, SHA-256 digest,
  owning module, case class, runner kind, and required platform;
- exact case identifiers and expected outcome classes;
- explicit capability states for library, daemon, Milter, Postfix, and Exim;
  and
- no timestamp, local absolute path, hostname, user identity, network
  endpoint, or secret-bearing value.

Paths must be canonical repository-relative paths without `.` or `..`,
backslashes, NUL, symlinks, hard-link ambiguity, case-fold collisions, or
escape from the repository root. Each referenced regular file is opened,
bounded, hashed, and then decoded from the same descriptor. Hash verification
precedes semantic execution.

The manifest cannot hash itself. A report records the SHA-256 of the exact
manifest bytes it loaded. Artifact order is by stable suite identifier, then
case identifier, then artifact path. Filesystem enumeration order must not
affect execution or output.

Manifest runner kinds are a closed internal enum. The manifest cannot provide
commands, arguments, environment variables, working directories, image names,
mounts, URLs, package patterns, regular expressions, or output paths.

## Common Vector Contract

Every new portable vector uses one strict versioned schema and contains:

- a stable lowercase ASCII case identifier;
- exact message and DNS draft identifiers where applicable;
- one conformance class;
- one closed operation kind;
- exact authority references, including draft/RFC section or durable
  interpretation identifier;
- input bytes encoded as padded RFC 4648 Base64 where bytes are authoritative;
- separately represented SMTP reverse and ordered forward path bytes;
- an injected clock, nonce, key record, and policy only when the operation
  requires them;
- a typed expected result, error, disposition, replay state, or action plan;
- provenance for the expected value; and
- no private production material or raw diagnostics.

Operation schemas are closed rather than one bag of optional fields. Initial
portable kinds are:

- `verify`;
- `sign`;
- `revise`;
- `recipe_apply`;
- `recipe_generate`;
- `dns_record`;
- `policy`;
- `replay`;
- `openapi`;
- `milter`.

Unknown kinds and fields fail closed. Limits apply before Base64 allocation,
and aggregate decoded bytes are bounded. A case may refer only to fixture
objects in its own draft directory or to exact manifest-listed shared
synthetic key material.

Expected outcomes use existing typed domain codes. A fixture must not assert
raw error text, implementation-specific stack traces, or only a boolean. PASS
cases assert the relevant bounded domain facts and, where the protocol is byte
sensitive, exact bytes or SHA-256 of independently frozen exact bytes.

## Expected-Value Provenance

Each expected value names one provenance class:

- `draft_example`: transcribed from a pinned draft example and independently
  checked for transcription;
- `rfc_example`: transcribed from a named RFC example;
- `independent_oracle`: produced by a small test-only oracle that does not call
  the production code under test;
- `cross_primitive`: checked with an independent standard cryptographic
  primitive or parser;
- `manual_derivation`: byte-level derivation documented beside the fixture;
- `regression_reproducer`: retained from a demonstrated defect and linked to a
  durable test description.

A generator that calls production code may prepare candidate bytes but cannot
be the sole oracle. Review must compare the frozen result against draft text,
manual byte derivation, or an independent primitive. Regeneration never
silently overwrites reviewed goldens.

Synthetic private keys needed for deterministic signing are explicitly marked
test-only. They use reserved `.test` names, cannot be selected by production
configuration, and must not appear in logs or reports. Their public portions
and expected signatures are cross-checked through standard-library
cryptographic verification.

## Positive Draft-04 Coverage

The public suite includes at least:

- raw messages with duplicate fields, folded fields, empty bodies, header-only
  messages, binary body octets, and legal SMTPUTF8 bytes where the operation
  supports them;
- Message-Instance parsing, exact hash input, numbering, and formatting;
- DKIM2-Signature parsing, canonical input, RSA-SHA256, Ed25519-SHA256, and
  multiple algorithms;
- current-envelope matching with null and non-null reverse paths, ordered
  recipients, duplicates, and case behavior already defined by the draft;
- exact ordinary custody chains and authorized next-domain transitions;
- header and body recipe application and deterministic generation, including
  no-body state and hash-gated historical reconstruction;
- origin signing, unchanged revision, changed revision, restricted release,
  and complete final insertion;
- DNS key parsing and lookup for the pinned DNS-04 baseline;
- strict, permissive, and testing policy projections kept separate from
  cryptographic verification; and
- public facade results with fixed clock, resolver, policy, signer, route, and
  nonce inputs.

Package-internal byte contracts may retain package-owned goldens. One public
end-to-end case must exercise each already exported root-facade workflow that
the implementation supports, such as verification and the existing signing or
revision entry paths. This requirement does not make internal operation kinds
public, does not require a public recipe/parser/canonicalization API, and does
not authorize any new exported surface solely for conformance. Adapter success
cannot substitute for public library evidence.

## Negative Coverage

Negative cases are frozen inputs, not runtime mutation recipes, unless the
mutation itself is the exact subject of the test. Each negative case identifies
one primary violated rule and its typed expected classification.

Coverage includes:

- malformed RFC 5322 framing, bare LF where rejected, illegal field names,
  overlong fields, invalid continuation, and limit exact/one-over boundaries;
- duplicate, missing, unknown, malformed, or noncanonical tag-value forms;
- malformed padded Base64, numeric overflow, sequence gaps, duplicate
  sequence/instance state, and inconsistent custody;
- Message-Instance header/body hash mismatch;
- signature mismatch, algorithm mismatch, disallowed RSA exponent and size,
  malformed Ed25519 key, revoked/multiple/missing DNS record, and resolver
  temporary failure;
- exact timestamp edge, one-over age/future skew, and deterministic clock
  behavior;
- reverse-path and forward-path mismatch, recipient order/duplicate mismatch,
  and signing use of unsupported SMTPUTF8 envelope bytes;
- recipe syntax, duplicate JSON member, operation limit, expansion limit,
  body-unavailable, historical hash mismatch, and null-body misuse;
- policy prohibitions and ambiguous datasource/profile/route state;
- malformed OpenAPI versions, fidelity, action plans, and media/JSON/body
  boundaries; and
- Milter frame, callback sequence, reconstruction, action, timeout, overload,
  and possible-partial-mutation failures.

Fuzz corpus files may be indexed for provenance, but fuzz success is reported
as robustness evidence and not counted as a normative vector PASS.

## Replay Coverage

Replay detection is a local security policy layered after successful protocol
verification. Reports must not describe it as a Draft-04 cryptographic
requirement.

Deterministic replay cases cover:

- disabled replay with an explicit policy result;
- memory first-seen followed by replayed for the exact same sealed input;
- changed draft, identity-algorithm version, epoch, signature, envelope, or
  retention input producing the documented distinct identity behavior;
- retention exact edge and expiry using an injected clock;
- concurrent duplicate attempts with exactly one first-seen result;
- provider unavailable before mutation;
- indeterminate storage mutation with no retry or fallback;
- standalone Valkey `SET NX PX` first-seen/replayed behavior through the
  existing hermetic Valkey target; and
- privacy evidence proving reports contain no replay key, HMAC input, raw
  signature, sender, recipient, selector, or secret.

The portable report may record Valkey as `not_run` only when the caller
explicitly selected the portable no-external-service profile. The Linux full
CI profile requires Valkey and treats a skip as failure.

## OpenAPI Fixtures

The authoritative OpenAPI document remains the source of HTTP truth. Ordinary
requests use generated clients and DTOs. No handwritten parallel request or
response model is permitted.

`dkim2ctl` fixture support expands to all current operations:

- process;
- sign;
- revise;
- health and readiness; and
- the existing closed negative-contract probes.

Fixture validation remains entirely offline and completes before protected-file
or network access. Operation capabilities are supplied only through distinct
protected process, sign, and revise capability files. Existing process
capability behavior remains compatible; capabilities are never fixture fields,
flag values, environment values, report values, or output.

Positive fixtures assert exact versions, operation, result, disposition, and
closed action-plan order. Sign and changed-revision fixtures assert
`Message-Instance` followed by `DKIM2-Signature`; unchanged revision asserts
only the new signature. Process reporting asserts only the configured
`Authentication-Results` action. The runner validates complete generated
responses, not merely HTTP status.

Negative fixtures cover route/capability separation, version drift, invalid
fidelity, malformed Base64/JSON, unknown or duplicate members, body
exact/one-over, operation/disposition/action contradictions, response
overflow, timeout, and malformed generated response shapes. A raw negative
builder stays closed to declared routes and mutations.

Stable JSON Lines remain content-free. Conformance reporting consumes typed
runner outcomes and never parses human error text.

## Portable Milter Fixtures

The Milter module gains data-driven fixtures that an independent MTA-side
oracle drives through the public Unix socket. Fixture files contain exact
callback frames or typed callback events, expected generated daemon request
facts, expected ordered Milter actions, and expected terminal SMTP/Milter
outcome.

Coverage includes:

- protocol-v6 negotiation and required capability/leading-space flags;
- SMTP reverse and ordered forward path bytes, duplicate recipients, null
  reverse path, and supported SMTPUTF8 inbound bytes;
- duplicate headers, original field-name casing, after-colon whitespace,
  folded fields, empty/header-only messages, binary body bytes, and body chunk
  invariance;
- explicit `milter_reconstructed_crlf` fidelity;
- inbound, originator, and ordinary-transit operation mapping;
- full-plan validation before the first mutation byte;
- Authentication-Results sanitization and insertion order;
- abort/reset/reuse, malformed order, timeout, overload, disconnect, partial
  frame, and possible partial mutation;
- fixed tempfail/reject/accept outcomes; and
- secret/message-marker absence from logs, metrics, reports, and errors.

The fixtures must state that Milter callback reconstruction is not original
raw RFC 5322 wire evidence. Postfix-specific behavior remains in the Docker
qualification rather than being faked in portable wire fixtures.

## Real Postfix Docker Qualification

The qualification is reproducible on a supported Linux Docker Engine with the
Compose v2 plugin. It builds repository source and a pinned Postfix base from
immutable image digests or exact source/package artifacts with verified
checksums. Floating tags, `latest`, mutable package repositories without a
snapshot, host-installed Postfix, and unverified downloads are forbidden.

All images and package versions are recorded in the report. The network is
isolated and internal. No host SMTP, daemon, metrics, or control port is
published. The test driver runs inside the Compose project. Containers use
read-only root filesystems where practical, explicit tmpfs/volumes for runtime
state, bounded resources, no ambient host credentials, and no privileged mode,
host network, Docker socket, or broad capabilities.

The fixture uses only reserved domains such as `origin.example.test`,
`relay.example.test`, and `receiver.example.test`, synthetic mailboxes, a
fixture DNS authority, deterministic test keys, and ephemeral generated
capabilities. Test private material is mounted only into the daemon ownership
boundary and never into Postfix, the Milter process, the test driver, reports,
or logs.

Because `dkim2d` accepts only canonical loopback HTTP and the Milter adapter
listens only on a protected Unix socket, the qualification topology must
preserve those security boundaries. Components that must share the loopback
or protected socket namespace may run in one qualification container under
separate unprivileged process identities. The fixture must not widen a
production listener to make Compose easier.

The test driver records and verifies effective listener topology from inside
the relevant network namespace: daemon HTTP is bound only to canonical
loopback, each Milter endpoint is a Unix socket with the expected ownership and
mode, Postfix references only those Unix sockets, Compose publishes no host
port, and no Milter TCP listener exists. Effective configuration and socket
facts are normalized and content-free; raw protected paths or capabilities do
not enter reports.

Postfix configuration explicitly sets protocol 6 and tempfail behavior. It
must not rely on Postfix defaults:

```text
milter_protocol = 6
milter_default_action = tempfail
```

When per-Milter syntax is used, it also states `protocol=6` and
`default_action=tempfail`. This is required because Postfix 3.11 changed the
global default failure action from `tempfail` to `shutdown`.

The qualification treats these official Postfix facts as adapter evidence:

- `smtpd_milters` applies to mail entering through `smtpd(8)`;
- `non_smtpd_milters` applies to local `sendmail(1)` and QMQP-style intake,
  not the SMTP path;
- Postfix simulates CONNECT, EHLO, MAIL, RCPT, DATA, and disconnect callbacks
  for non-SMTP submission;
- a non-SMTP Milter must not reject or tempfail simulated RCPT callbacks;
- Postfix hides its own prepended `Received` field from Milters while retaining
  it in the queued message; and
- the adapter therefore continues to report reconstructed Milter fidelity,
  never original wire fidelity.

At minimum, the real matrix proves:

1. SMTP originator submission through `smtpd_milters` produces exactly one
   Message-Instance followed by exactly one DKIM2-Signature.
2. Local `sendmail(1)` submission through `non_smtpd_milters` independently
   produces the same permitted field ordering without conflating simulated
   SMTP with a network session.
3. A signed message received through an inbound Postfix/Milter instance is
   processed by `dkim2d` with synthetic DNS and receives only the configured
   bounded Authentication-Results action.
4. Envelope sender and recipient evidence comes from Milter callbacks and is
   not derived from `From`, `To`, `Received`, or other message fields.
5. The Postfix-prepended Received field is absent from the Milter-submitted
   daemon bytes but present in the final queued/captured message.
6. Duplicate/folded headers, an empty body, a binary-safe body, null reverse
   path, and one multi-recipient inbound case preserve the adapter's documented
   fidelity or fail with the documented closed outcome.
7. A stopped/unreachable Milter causes a temporary SMTP failure under the
   explicit policy; the local submission path produces the documented queue
   write/failure behavior without silently accepting an unsigned message.
8. A stopped/unreachable daemon produces the adapter's fixed 451 behavior and
   no mutation.
9. Restart, shutdown, socket cleanup, queue drain, and repeated execution leave
   no stale project state and produce byte-identical normalized report facts.

The test driver verifies final messages through an independent capture/parser
and, where applicable, the public library verifier. It does not accept grep-only
header presence as conformance. It verifies count, order, field grammar,
envelope, disposition, and cryptographic result.

`docker compose down --volumes --remove-orphans` or an equivalent
project-scoped cleanup runs on success and failure. Cleanup must never remove
unrelated images, containers, networks, volumes, or host files.

## Deferred Exim Fixture And Result Schema

The repository adds an adapter-neutral JSON schema
`dkim2.exim-adapter-fixture.v1` under
`testdata/conformance/exim/`. It is durable future authority for portable Exim
case data, not evidence that the adapter exists.

The schema records:

- exact message and DNS draft identifiers;
- fixture identifier and conformance class;
- closed path `local_scan` or `transport_filter`;
- closed operation `process`, `sign`, or `revise`;
- exact raw message and SMTP envelope fixture bytes;
- required Exim-observed facts and documented fidelity;
- expected daemon operation and closed action plan;
- expected Exim acceptance, rejection, or temporary failure;
- required compatibility identity fields for Exim upstream version,
  distribution package version, source/package authentication, build ID,
  module ABI identity, and platform; and
- an evidence object whose artifact digests must be supplied only by a real
  M17 matrix execution.

Fixture data and execution evidence are separate schemas. A portable fixture
cannot self-assert that an Exim binary, package, hook, output message, or SMTP
result was observed.

This increment may add schema-valid examples marked `deferred`, but it must not
add a PASS result, compatibility row, live transcript, or adapter-generated
message. The conformance manifest reports the Exim capability exactly as
`deferred_m17`, with zero executed Exim cases. `not_applicable`, `pass`, or
omission are not substitutes.

When M17 resumes, its real matrix must populate the frozen evidence schema with
authenticated source/package identity, exact producer hashes, case timestamps,
component transcripts, output digests, and cross-component relations. M18
must not read the stashed or absent Exim worktree to complete.

## Report Contract

The machine report schema is `dkim2.conformance-report.v1`. JSON is canonical
for repository purposes: UTF-8, LF, two-space indentation for artifacts,
lexically stable object construction, and stable array ordering. The report
contains:

- exact message and DNS draft identifiers;
- manifest schema and manifest SHA-256;
- base source revision supplied by the trusted runner;
- exact candidate-snapshot digest for the dirty pre-commit durable tree;
- report profile and platform class;
- closed capability states;
- ordered suite and case results;
- counts by conformance class and state;
- normalized tool/build identities;
- exact fixture and executable producer digests where applicable; and
- one overall state.

Case states are exactly:

- `pass`;
- `fail`;
- `not_run`;
- `not_applicable`;
- `deferred`.

Required cases in the selected profile may only be `pass`; `not_run` is a
failing overall report state. `deferred` is permitted only for manifest-declared
future capability, initially Exim. `not_applicable` is permitted only when the
manifest declares a platform exclusion before execution.

The base source revision alone is insufficient before the milestone commit:
HEAD still identifies the previous committed milestone while the candidate is
an intentionally dirty durable worktree. The suite therefore defines
`dkim2.candidate-snapshot.v1`.

The candidate-snapshot producer first requires an empty real index and the
expected base revision. It obtains the exact union of Git-tracked and
non-ignored untracked files, excludes `.git/`, ignored `temp/`, ignored report
output, and other Git-ignored local artifacts, and rejects symlinks, nonregular
files, path collisions, path escape, and a changing file during hashing. It
sorts canonical slash paths by raw byte order and frames:

- the literal snapshot schema identifier;
- the exact base revision; and
- for each file, Git-equivalent regular-file mode (`100644` or `100755`),
  path length and path bytes, content length, and SHA-256 of exact content.

Lengths use fixed-width unsigned big-endian encoding. The SHA-256 of the whole
framed stream is `candidate_snapshot_sha256`. The producer is repository-owned,
has independent golden/framing tests, and its own source is included in the
snapshot it hashes. It never follows links or includes ignored files.

Every machine report records both `base_revision` and
`candidate_snapshot_sha256`. Every suite fragment, report merge, full-profile
result, independent review, and orchestrator approval must match both values.
The reviewer independently reproduces the digest from the same path/mode/byte
inventory. Any durable edit, mode change, added file, removed file, generated
drift, or base revision change invalidates all earlier reports and approvals.

Reports contain no exact wall-clock duration, random run ID, absolute path,
hostname, username, container ID, network address, raw error, raw message,
header value, envelope value, signature, selector, domain from a non-reserved
fixture, capability, private key, replay key, datasource record, or protected
path. Bounded duration and size buckets may be emitted.

Raw runner logs are separate CI diagnostics with the same privacy rules. A
failure report uses stable error classes and artifact/case identifiers. It
does not copy stderr.

The human-readable report is generated from the machine report. It includes:

- baseline and snapshot;
- supported and tested operations;
- exact limits of each claim;
- pass/fail/deferred counts by class;
- Milter reconstruction and Postfix limitations;
- replay's local-policy status;
- Exim's explicit deferral;
- known draft `TBA` areas and interpretations; and
- reproducible commands.

Generated reports are build artifacts, not silently committed current truth.
Checked-in report goldens test deterministic formatting. Public conformance
notes describe the last reviewed capability baseline and link to CI artifacts
without pretending that a historical run proves the current checkout.

## Public Conformance Notes

`docs/conformance.md` is the durable public statement. It must:

- name both pinned draft identifiers;
- distinguish normative, interpreted, policy, OpenAPI, and adapter evidence;
- enumerate operations with `supported`, `partial`, or `deferred` status;
- disclose that Milter messages are callback reconstructions;
- disclose the Postfix Received-header visibility rule and simulated local
  SMTP behavior;
- state that replay is local security policy, not protocol verification;
- mark live Exim conformance deferred until M17;
- state that no mature external interoperability corpus is yet authoritative;
- avoid the words certified, compliant implementation, complete, or final
  unless narrowly qualified by a named report and profile; and
- give exact local commands for portable and Docker qualification.

## CI And Makefile Integration

The root Makefile adds closed targets with no caller-provided command
evaluation:

```text
make check-conformance
make conformance
make conformance-postfix
make conformance-all
```

`check-conformance` validates schemas, manifest closure, digests, ownership,
draft directories, generated report goldens, and the explicit Exim deferral.
It performs no network or Docker work.

`conformance` runs the portable library, replay, OpenAPI, and Milter suites and
writes machine/human reports to an ignored or caller-selected artifact
directory. The path is created safely and may not escape the selected output
root.

`conformance-postfix` builds and runs the real Linux Docker qualification with
project-scoped cleanup. It fails clearly when Docker/Compose is unavailable;
it is never silently skipped.

`conformance-all` requires both portable and Postfix results and merges them
only after verifying matching manifest, base revision, candidate-snapshot
digest, draft, producer, and profile identities.

`make guardrails` includes `check-conformance` and the portable conformance
suite. The full Linux CI job additionally runs `conformance-postfix` and
publishes both report forms as artifacts. A Docker-unavailable developer may
run the portable profile, but cannot claim the full profile.

CI configuration uses least permissions, immutable action references, no
repository secrets, no privileged Docker service, bounded timeouts, and
artifact retention. It verifies a clean generated tree after the run. Pull
requests and the default branch run the same manifest. A report from a
different base revision or candidate-snapshot digest cannot be merged into the
current result.

## Security And Privacy

All fixtures are synthetic and use reserved names. Corpus import validates
that no non-reserved domain, live mailbox, credential marker, production key,
or unreviewed message is introduced.

Loaders are bounded before allocation and reject duplicate/unknown fields,
trailing values, symlinks, path escape, size overflow, count overflow, digest
mismatch, and manifest/artifact draft mismatch. Reports and logs use closed
allowlists and stable error classes.

No test executes fixture-controlled commands or URLs. Docker build inputs are
confined to exact repository paths, use a restrictive `.dockerignore`, and do
not include `.git`, `temp`, developer configuration, environment files, local
caches, or unrelated source trees.

Negative and privacy tests seed unique markers into message, envelope,
signature, key, capability, replay, datasource, path, and raw-error inputs and
prove absence from:

- reports;
- stdout and stderr;
- logs and traces;
- Prometheus labels;
- container names and inspect labels;
- generated filenames; and
- failure strings.

## Implementation Sequence

One implementation agent executes these slices in order:

1. strict schemas, manifest, artifact hashing, capability states, and
   deterministic report types;
2. public positive Draft-04 vectors and independently checked expected values;
3. negative and replay vectors, exact/one-over limits, and privacy cases;
4. generated-client OpenAPI fixtures and deterministic runner integration;
5. portable Milter fixtures and the real Postfix Docker qualification;
6. CI, Makefile integration, public conformance notes, reproducibility,
   fuzz/race evidence, and complete guardrails.

One independent reviewer then audits and fixes the cumulative candidate. The
review must trace every conformance claim to authority, reproduce report
digests, run the full supported profile, and reject any overclaim or skipped
required case.

No implementation slice stages or commits. The orchestrator creates exactly
one project-formatted commit only after all findings are fixed, full gates
pass, and two approvals cover one unchanged candidate.

## Required Tests

Focused unit tests cover:

- strict JSON and schema closure;
- manifest path, ordering, digest, symlink, collision, and bound behavior;
- every case class, kind, state, and capability transition;
- draft and DNS identifier mismatch;
- independent expected-value provenance;
- deterministic report and human-summary rendering;
- report merge identity checks;
- content-free error and privacy marker policy;
- generated-client request/response conversion;
- Milter fixture decoding and independent byte/action oracle;
- Exim schema acceptance plus rejection of any non-deferred result; and
- Docker configuration static policy.

Integration evidence covers:

- public library positive/negative vectors;
- replay memory and Valkey behavior;
- generated-client process/sign/revise fixtures against the real daemon;
- portable public-socket Milter fixtures against the real adapter;
- Postfix SMTP and local-submission qualification against real processes;
- daemon/Milter failure mapping;
- repeated report byte identity after normalization; and
- project-scoped cleanup on success and injected failure.

Fuzz targets cover at least manifest decoding, vector decoding, report merge,
OpenAPI fixture decoding, Milter fixture decoding, and any new byte-oriented
oracle. Each new or affected target runs separately for at least ten seconds
after its last change.

Race tests cover report collection, concurrent vector execution where allowed,
replay duplicate admission, Milter fixture execution, and cleanup ownership.

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
make check-platform-builds
make test-valkey
make check-conformance
make conformance
make conformance-postfix
make conformance-all
make govulncheck
make guardrails
git diff --check
```

Every new fuzz target runs individually for at least ten seconds after the
last implementation or review fix. The final report artifacts must bind to the
same unchanged candidate hash reviewed by both approvers.

If Docker is genuinely unavailable on a developer platform, the portable
profile may be reviewed locally, but milestone completion still requires the
full Linux Docker profile in a trusted environment. An unavailable, skipped,
stale, or mismatched required gate is not approval.

## Completion Conditions

Completion requires:

- all manifest artifacts and cases are digest-bound, versioned, bounded, and
  owned by one clear package or adapter;
- positive values have independent provenance;
- negative expectations remain typed and authority-linked;
- replay evidence remains visibly separate from protocol verification;
- OpenAPI fixtures use generated clients and generated DTOs;
- portable Milter fixtures preserve the documented reconstruction limitation;
- real Postfix qualification passes for SMTP and non-SMTP paths with explicit
  protocol-6/tempfail settings;
- the Postfix Received-header and simulated-SMTP limitations are proven and
  disclosed;
- Exim is exactly `deferred_m17`, with a frozen future schema and no fabricated
  execution result;
- deterministic machine and human reports bind the base revision plus exact
  candidate-snapshot digest and pass privacy and reproducibility checks;
- CI and Makefile targets fail on stale, skipped, tampered, or mismatched
  required evidence;
- all review findings are fixed at their root;
- full gates and all affected fuzz runs pass;
- two independent approvals cover one unchanged snapshot;
- `temp/` remains ignored and unstaged; and
- exactly one project-formatted milestone commit contains only intentional
  durable paths.

## Deferred Work

- The Exim implementation, live release matrix, and evidence population remain
  M17 and must be completed after the taint-safe envelope-authority design is
  resolved.
- Repository-wide hardening beyond this suite's focused robustness evidence
  remains the security-hardening increment.
- Production deployment, operator configuration, upgrades, rollback, and the
  polished Postfix Docker demo remain the documentation/operator increment.
- External implementation comparison, issue-log closure, API polish, and
  release-candidate claims remain the interoperability increment.
