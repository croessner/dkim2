# Specification and Prompt Pack Template

This document defines how DKIM2 implementation specifications and prompt packs
must be written. It is based on the `nauthilus-director` specification style:
durable specs are binding implementation contracts under `docs/`, while prompt
packs are local handoff artifacts under ignored `temp/`.

## Purpose

A DKIM2 spec must make the intended behavior, boundaries, risks, tests and
closeout evidence explicit before implementation starts. A prompt pack must
split that spec into focused, reviewable implementation slices that can be run
one at a time without scope drift.

Specs and prompts are not planning labels for production code. Production
identifiers, comments, file paths, branch names, commit subjects and commit
bodies must describe domain behavior, not prompt IDs, rollout labels or
temporary task names.

## Artifact Placement

Use these locations:

- Durable implementation specs: `docs/specs/implementation/<topic>.md`
- Durable OpenAPI contracts: `docs/specs/openapi/`
- Local prompt packs: `temp/<topic>-prompts/`
- Local one-off security or bug slices: `temp/<topic>-slice.md`
- Scratch notes and handoff material: `temp/`

The root `temp/` directory is ignored and must not be staged. When a local
prompt pack produces durable decisions, move those decisions into the relevant
spec, architecture document, OpenAPI contract, docs, tests or runbook.

## Spec Writing Rules

A spec is the implementation contract. Write it before broad implementation
work starts and update it when evidence proves the contract needs correction.

Every spec must:

- Name the source documents that govern the work.
- State the current gap or problem in concrete terms.
- Define the goal in operator and implementation language.
- Keep in-scope and out-of-scope work explicit.
- Bind behavior to DKIM2 draft versions, architecture decisions or local policy.
- Preserve module boundaries between `lib/`, `cmd/dkim2d`,
  `cmd/dkim2-milter` and `cmd/dkim2ctl`.
- Define security defaults, fail-closed behavior and secret-redaction rules.
- Define observability expectations without creating high-cardinality labels or
  secret-bearing telemetry.
- Define datasource, OpenAPI, Milter, CLI or config boundaries when touched.
- Define required unit, integration, E2E, generated-output and guardrail checks.
- Include acceptance criteria and a final review matrix.
- Include effort estimation before implementation and measured effort after
  closeout.

## Spec Template

Use this structure unless a smaller one-off slice is enough. Keep section names
stable so future prompt packs can quote and reference them reliably.

~~~markdown
# <Feature Or Fix Name>

Status: draft | implementation-ready | in-progress | completed | blocked.

Briefly describe the behavior, defect or follow-up. State why this work exists
and which DKIM2 surface it touches.

## Source Documents

This spec is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/specs/openapi/dkim2d.yaml` if REST behavior is touched
- `<draft section, RFC, architecture decision, prior spec or issue>`
- `Makefile`

If this spec conflicts with a source document, stop and fix the drift before
implementation continues.

## Original Gap

Describe the current behavior, missing behavior or defect. Include concrete
paths, APIs, protocol states, config paths, datastore keys or adapter flows
where possible.

## Goal

Describe the target behavior. Include examples only when they clarify the
contract. Examples must not contain real secrets, raw message bodies, live
recipient lists or protected config values.

## Delivery Shape

Split the work into focused slices. Each slice should be independently
reviewable and should have a clear test or proof target.

1. <Slice one>
2. <Slice two>
3. <Final proof, docs and closeout>

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | small | medium | large |
| Estimated wall-clock effort | <range, for example 2-4 hours> |
| Highest-risk area | <protocol, OpenAPI, datasource, Milter, observability, etc.> |
| Expected prompt count | <number or range> |
| Required final gate | `make guardrails` or justified narrower gate |

Risk notes:

- Low risk: <items>
- Medium risk: <items>
- Highest risk: <items>

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| <prompt file or slice> | <ISO 8601 timestamp with timezone> | <ISO 8601 timestamp with timezone> | <duration> | <optional duration> | <blocked time, skipped work, environment notes> |

The required measurement is wall-clock time from the start of prompt execution
to the final closeout response for that prompt. Active engineering time may be
recorded as an additional estimate, but it does not replace wall-clock time.

## Scope

In scope:

- <specific behavior>

Out of scope:

- <nearby behavior that must not be changed>

## Protocol, Runtime Or Domain Semantics

State the behavior in precise terms. For DKIM2 protocol work, identify whether
each rule comes from the active draft, an RFC, `docs/ARCHITECTURE.md`, or local
policy. Ambiguous draft behavior must be called out and tested so it can be
revised when the draft changes.

## Package Boundaries

State the intended ownership:

- `lib/`: <core DKIM2 semantics only>
- `cmd/dkim2d`: <daemon/runtime/OpenAPI/config/observability work>
- `cmd/dkim2-milter`: <Milter adapter work>
- `cmd/dkim2ctl`: <generated-client/test-client work>

Generated REST DTOs must stay at HTTP boundaries. Core DKIM2 packages must not
import generated OpenAPI types.

## Security And Privacy

Define fail-closed behavior, secret handling and abuse-case limits. Explicitly
state what must not be logged, traced, metric-labeled, emitted through REST or
CLI, or included in test output.

## Observability

Define logs, metrics, traces and debug output only as bounded observation
records. Metrics labels must remain low-cardinality and secret-safe.

## Required Tests

Unit tests:

- <focused unit coverage>

Integration or E2E tests:

- <public-boundary, daemon, Milter, OpenAPI or CLI proof>

Generated and documentation checks:

- <OpenAPI generation/checks, docs checks, manpage checks, etc.>

Final gate:

- `make guardrails`, or list the narrower commands and why they are sufficient.

## Acceptance Criteria

- <observable completion criterion>
- <security criterion>
- <docs/generated artifact criterion>
- <guardrail criterion>

## Completion Evidence

Fill this after implementation:

- Focused tests: <commands and results>
- Generated checks: <commands and results>
- Guardrails: <commands and results>
- `git status --short`: <result summary>
- Skipped checks: <check and reason, if any>

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Work stays inside this spec |  | done/partial/blocked/deferred |  |
| Behavior | Target semantics are implemented |  |  |  |
| Tests | Reproducer and regression coverage exist |  |  |  |
| Security | Fail-closed and secret-safe behavior is preserved |  |  |  |
| Boundaries | Module and generated-code boundaries hold |  |  |  |
| Effort | Prompt timings are measured and recorded |  |  |  |

## Decisions And Open Questions

- Settled: <decision>
- Open: <question, owner, and blocker>
~~~

## One-Off Slice Template

Use a smaller slice document under `temp/` for a narrow bug or security fix
that does not need a full durable spec. Promote it to `docs/` if it becomes an
architecture decision or reusable contract.

~~~markdown
# <Slice Name>

## Scope

Fix only:

- `<finding or bug id>`: <exact behavior>

Do not change:

- <explicit exclusions>

## Expected Behavior

Describe the target behavior and fail-closed condition.

## Reproducer Or Regression Tests

- <failing test to add first, if practical>
- <positive control>
- <negative control>

## Validation Commands

```sh
<focused test command>
make test
make guardrails
git diff --check
git status --short
```

## Time Tracking

| Field | Value |
| --- | --- |
| Started at | <ISO 8601 timestamp with timezone> |
| Completed at | <ISO 8601 timestamp with timezone> |
| Wall-clock duration | <duration from prompt start to final closeout> |
| Active engineering time | <optional duration> |
| Blocked or waiting time | <duration and reason, if any> |
~~~

## Prompt Pack Rules

A prompt pack turns one spec into a queue of bounded implementation prompts.
The index owns shared constraints and order. Each prompt owns one slice.

Every prompt pack must:

- Live under `temp/<topic>-prompts/`.
- Include `index.md`.
- Include numbered prompt files with stable names, for example
  `01-domain-contract.md`.
- Start each prompt with the repo path and branch or state expectation.
- Tell the implementer exactly what to read first.
- Treat the spec as the increment authority.
- Include in-scope and out-of-scope lists.
- List expected files or packages when known.
- Prefer Makefile targets over ad hoc command variants.
- Require reproducer-first work for bug fixes where practical.
- Preserve unrelated dirty worktree changes.
- Forbid commits unless explicitly requested.
- Require exact test commands, skipped-check reasons and `git status --short`.
- Require `Review und Ist/Soll-Abgleich`.
- Require prompt-level time tracking from prompt start to final closeout.

## Prompt Pack Index Template

~~~markdown
# <Topic> Prompt Index

This local prompt pack splits `<spec name>` into focused, reviewable
implementation slices. It lives under `temp/`, is intentionally ignored, and
must not be staged or committed.

## Required Source Documents

Every prompt starts by reading:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/specs/implementation/<spec>.md`
- `<other durable docs, OpenAPI contracts, generated references, tests>`
- `Makefile`
- `.gitignore`

The spec is the increment authority. If it conflicts with code, generated
artifacts, docs or architecture, stop and reconcile the durable artifact before
expanding implementation.

## Shared Hard Constraints

- Work in `/Users/croessner/src/dkim2`.
- Preserve unrelated dirty worktree changes.
- Do not commit unless explicitly asked.
- Keep all scratch and handoff notes under `temp/`.
- Keep durable documentation under `docs/`.
- Use Makefile targets rather than ad hoc command variants where possible.
- Keep the `lib/` module free of daemon, Milter, OpenAPI, Cobra, Viper, Fx,
  Prometheus, OTLP exporter and CLI-only dependencies.
- Keep generated OpenAPI DTOs at REST boundaries.
- Keep logs, traces, metrics, REST output, CLI output, test logs and errors
  free of private keys, tokens, protected config, raw message bodies and raw
  recipient lists.
- Keep metrics labels low-cardinality and secret-safe.
- For bug fixes, add a meaningful reproducer before production changes when
  practical.
- Measure every prompt from execution start to final closeout.

## Prompt Order

1. `01-<slice>.md`
2. `02-<slice>.md`
3. `03-final-proof-docs-closeout.md`

The order is intentional. Later prompts may rely on earlier domain types,
contracts, tests, generated artifacts or proof.

## Settled Decisions

- <decision from the spec>

## Prompt Timing Ledger

Each prompt closeout must update or report this ledger:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Status | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `01-<slice>.md` |  |  |  |  | pending |  |
| `02-<slice>.md` |  |  |  |  | pending |  |
| `03-final-proof-docs-closeout.md` |  |  |  |  | pending |  |

## Required Closeout Pattern

Every implementation prompt must end with:

1. Targeted test results, including skipped checks and why they were skipped.
2. `git status --short`.
3. Time tracking:
   - started timestamp
   - completed timestamp
   - wall-clock duration
   - optional active engineering time
   - blocked or waiting time, if any
4. A `Review und Ist/Soll-Abgleich` table:

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Example | Expected behavior from the prompt/spec | Observed implementation state | done/partial/blocked/deferred | Evidence |

Allowed statuses:

- `done`
- `partial`
- `blocked`
- `deferred`

## Explicit Review Checks

- Re-read the relevant spec sections before finalizing a slice.
- Verify scope stayed inside the prompt.
- Verify no production identifier, comment or path refers to prompts, slices or
  temporary labels.
- Verify generated artifacts are fresh when contracts changed.
- Verify security-sensitive behavior fails closed.
- Verify proof uses public or realistic boundaries where the spec requires it.
- Verify prompt timing was measured and reported.
~~~

## Implementation Prompt Template

~~~markdown
# Prompt NN: <Slice Name>

You are working in `/Users/croessner/src/dkim2` on `<branch or current branch>`.

Implement the `<slice name>` slice from
`docs/specs/implementation/<spec>.md`.

## Time Tracking

Record these values during closeout:

| Field | Value |
| --- | --- |
| Started at | <set when prompt execution begins, ISO 8601 with timezone> |
| Completed at | <set immediately before final response, ISO 8601 with timezone> |
| Wall-clock duration | <completed minus started> |
| Active engineering time | <optional, if separately tracked> |
| Blocked or waiting time | <duration and reason, if any> |

The wall-clock duration is mandatory. It starts when the implementer begins
executing this prompt in the workspace and ends when the final closeout response
for the prompt is complete.

## Read First

1. `AGENTS.md`
2. `POLICY.md`
3. `docs/ARCHITECTURE.md`
4. `docs/specs/implementation/<spec>.md`
5. `<directly touched files, generated contracts, tests, runbooks>`
6. `Makefile`

## Goal

State the single result this prompt must produce.

## In Scope

- <specific work>

## Out of Scope

- <nearby work that must not be touched>
- Committing changes unless explicitly asked.

## Expected Files

```text
<path>
<path>
```

The expected list is guidance, not permission to widen scope. If the real code
requires a different file, explain why in the final closeout.

## Implementation Notes

- <domain, security, boundary or generated-code guidance>
- <test-first requirement when applicable>
- <redaction and observability constraints>

## Required Tests

Run focused checks first:

```text
<focused make or go test command>
```

Run final checks:

```text
make guardrails
git diff --check
git status --short
```

If a required check cannot run, state the exact blocker and the largest
equivalent subset that did run.

## Acceptance

- <criterion>
- <criterion>
- Prompt timing is measured and reported.

## Review und Ist/Soll-Abgleich

Before final response:

1. Re-read the Goal, Scope and Acceptance sections.
2. Verify no out-of-scope files or behaviors were changed.
3. Verify secret-safe diagnostics and low-cardinality observability.
4. Run `git status --short`.
5. Record time tracking.
6. Report:

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Work stays inside this prompt |  |  |  |
| Behavior | Slice behavior matches the spec |  |  |  |
| Tests | Focused and final checks run or blocker documented |  |  |  |
| Security | Fail-closed and secret-safe behavior preserved |  |  |  |
| Time | Started, completed and wall-clock duration recorded |  |  |  |
~~~

## Final Closeout Prompt Requirements

The final prompt in a pack must reconcile the full spec against implementation
evidence. It must:

- Re-read the spec and all completed prompt closeouts.
- Verify every acceptance criterion.
- Verify generated artifacts and docs are current.
- Run `make guardrails` or document a concrete blocker.
- Run `git diff --check` and `git status --short`.
- Update completion evidence in the durable spec when appropriate.
- Roll up all prompt timing into the spec's measured effort table.
- Compare measured wall-clock effort against the planning estimate and call out
  major variance.

The final review matrix must include at least:

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Spec reconciliation | Spec matches implemented behavior and evidence |  |  |  |
| Scope | No prompt drift or unrelated cleanup |  |  |  |
| Tests | Required focused and final gates are green or blocked explicitly |  |  |  |
| Generated artifacts | OpenAPI/docs/generated files are fresh where touched |  |  |  |
| Security | Fail-closed and secret-safe behavior holds |  |  |  |
| Effort | Prompt timing ledger is complete and compared to estimate |  |  |  |

## Timing Measurement Policy

Timing exists so architecture estimates can be checked against real
implementation cost. Record it consistently:

- Use ISO 8601 timestamps with timezone, for example
  `2026-07-03T14:25:00+02:00`.
- Start time is when prompt execution begins in the workspace, not when the
  prompt file was authored.
- Completion time is immediately before the final closeout response for that
  prompt.
- Wall-clock duration is mandatory and includes investigation, coding, test
  runs, docs, review, blocked waits and closeout.
- Active engineering time is optional and may exclude long external waits, but
  it must never replace wall-clock duration.
- If work is interrupted and resumed, record either one wall-clock span with a
  note or multiple spans whose sum is clear.
- If a prompt is blocked, record start, blocked-at time, elapsed duration and
  blocker.
- The final prompt rolls all prompt timings into the durable spec.

Major variance should be explained in plain engineering terms: underestimated
draft ambiguity, missing test seams, generated-code churn, environment
blockers, dependency issues, or architecture mismatch.

## Quality Bar

A spec or prompt pack is ready when another engineer can execute it without
inventing scope, weakening validation, duplicating domain rules, leaking
secrets, or guessing which proof matters. The documents should be concrete
enough to bind behavior and small enough to keep each implementation slice
reviewable.
