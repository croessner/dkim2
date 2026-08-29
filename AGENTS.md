# DKIM2 Development Guidelines

This repository is a Go 1.26 multi-module workspace for a DKIM2 reference
implementation. Keep `go.work`, every module `go.mod`, generated code,
documentation, CI, and local guardrails aligned with Go 1.26 whenever toolchain
details change.

The implementation baseline is `draft-ietf-dkim-dkim2-spec-06` plus
`draft-chuang-dkim2-dns-04`. Treat the draft version as part of the behavior
under test. If a later draft changes semantics, update durable documentation and
test vectors before changing protocol behavior.

## Repo-Local Skills

Repo-local Codex skills live under `.codex/skills/`. Use the relevant skill
before substantial work in its area:

- `dkim2-spec-conformance` for draft/RFC fidelity and normative behavior.
- `dkim2-senior-go-architect` for Go architecture, DRY, OOP-style boundaries,
  and dependency placement.
- `dkim2-mail-domain` for SMTP, RFC 5322, DKIM, EAI, Authentication-Results,
  DNS mail behavior, and Milter fidelity.
- `dkim2-openapi-service` for `dkim2d`, OpenAPI, generated server/client code,
  and `dkim2ctl`.
- `dkim2-datasource-provider` for datasource contracts, Valkey replay storage,
  and flat-file, LDAP, PostgreSQL, MySQL, and MariaDB providers.
- `dkim2-observability` for `slog`, OpenTelemetry, Prometheus, debug modules,
  labels, and redaction.
- `dkim2-milter-adapter` for Milter EOM flow, daemon calls, action plans, and
  fail-closed adapter behavior.
- `dkim2-security-testing` for reproducers, fuzzing, abuse cases, and
  robustness tests.
- `dkim2-review-audit` for review or audit tasks.

## Required Workflow

- Use `make` targets instead of ad hoc command variants whenever possible.
- Run `make guardrails` before every commit or pull request once the touched
  packages have implementation code.
- Use `go.work` for local development, but preserve the product boundary:
  `lib/` is the standalone DKIM2 library module, while command modules under
  `cmd/` are adapters or tools.
- Keep the library free of daemon, Milter, OpenAPI, Cobra, Viper, Fx,
  Prometheus, OTLP exporter, and CLI-only dependencies unless a future
  architecture decision explicitly moves that boundary.
- Design and implement security-by-design and security-by-default. Ambiguous
  authentication, transport, key, datastore, replay, recipe, or message-fidelity
  state must fail closed unless a documented compatibility policy explicitly
  says otherwise.
- Fix root causes, not symptoms. Do not mask a protocol, parser,
  canonicalization, datastore, or adapter defect with weaker validation,
  catch-all fallback behavior, relaxed policy, or test expectation changes.
- Use focused, meaningful reproducer tests before fixing bugs whenever a stable
  reproducer is practical. Keep useful reproducers as regression coverage.
- Prefer unit-driven development for protocol core, parsers, canonicalization,
  recipes, policy, datasource adapters, and observability policy. Write focused
  unit tests first when the behavior can be exercised cleanly at unit level.
- When a test fails, first determine whether the failure exposes a production
  defect. Fix production code when it is wrong. Change the test only when the
  fixture, assertion, or test logic is demonstrably wrong.
- Apply DRY intentionally. Shared protocol rules, parser behavior,
  canonicalization, policy checks, security checks, config validation,
  datasource behavior, generated REST mapping, and observability policy must
  live in one clear abstraction.
- Design with strict object-oriented boundaries in Go: cohesive types own their
  invariants, behavior is exposed through methods and narrow interfaces, and
  composition is preferred over package-level mutable state.
- Keep external dependencies intentional. Prefer the standard library or small
  local code when behavior is simple, security-sensitive, and maintainable.
  Add dependencies only when they clearly reduce risk, complexity, or long-term
  maintenance cost.
- Treat the approved service-layer foundation dependencies as intentional
  architecture choices for command/service modules: Cobra for command surfaces,
  Viper for configuration loading, Uber Fx for application composition,
  `log/slog` for structured logging, OpenTelemetry for traces, Prometheus for
  metrics, and OpenAPI generation for HTTP server/client boundaries.
- Keep OpenAPI as the source of truth for `dkim2d` REST contracts from hour
  zero. Generated server/client code must be reproducible and checked for stale
  output before relying on it.
- Keep generated REST DTOs at HTTP boundaries. Core DKIM2 domain packages must
  not import generated OpenAPI types.
- Build `dkim2ctl` and test-client workflows on the generated OpenAPI client
  SDK. Hand-written code may wrap the SDK for command UX, fixtures, output
  formatting, and diagnostics, but must not duplicate REST DTOs or maintain a
  parallel client model.
- Keep configuration paths stable by declared stability window. Stable paths
  must not be renamed, removed, or semantically inverted without explicit
  breaking-change documentation, migration notes, examples, and tests.
- Support environment-variable placeholders in scalar configuration values once
  the config loader exists. Expansion must run before typed validation, must
  never expand map keys, must fail closed on missing variables, and must keep
  secret metadata and redaction intact.
- Keep all secret material out of logs, traces, metrics, REST output, CLI
  output, test logs, and error strings. This includes private keys, token
  material, SMTP credentials, datasource bind passwords, raw message bodies,
  raw recipients, and protected config values.
- Use `log/slog` through a central logging package or provider. Module-level
  debug switches must be explicit, documented, and secret-safe.
- Use OpenTelemetry through a central observability runtime. Domain packages
  may emit bounded observation events but must not construct exporters,
  providers, or global telemetry state.
- Keep Prometheus labels on a strict low-cardinality allowlist. Do not use raw
  user, recipient, session, request, trace, client IP, backend identifier,
  selector nonce, Valkey key, Redis key, SQL text, LDAP DN, raw error, or
  secret-bearing values as labels.
- Keep datasource access behind interfaces. LDAP, SQL, and flat-file providers
  must satisfy the same domain contracts and must not leak provider-specific
  models into protocol packages.
- Keep local planning, prompt, scratch, and handoff artifacts under `temp/`.
  The root `temp/` directory is ignored and must never be staged. Durable
  project documentation belongs under `docs/`.
- Write code comments and technical documentation in English.
- All hand-written named functions and receiver methods introduced or changed
  by a change must have concise English doc comments, including unexported
  functions and unexported receiver methods. Comments should explain intent,
  invariants, security assumptions, side effects, or protocol behavior.
- Name production code after domain behavior, not planning artifacts. Function
  names, receiver names, identifiers, comments, paths, branches, tags, commit
  subjects, and commit bodies must not refer to prompt IDs, task IDs, rollout
  labels, or transient planning milestones.

## Architecture Boundaries

- `lib/` owns DKIM2 protocol semantics and must remain usable without daemon,
  Milter, OpenAPI, Cobra, Viper, Fx, Prometheus, or OTLP dependencies.
- `cmd/dkim2d` owns daemon runtime concerns: Cobra/Viper configuration, Fx
  composition, HTTP server lifecycle, OpenAPI server adapter, concrete
  observability exporters, metrics endpoint, and concrete datasource wiring.
- `cmd/dkim2-milter` owns SMTP/Milter integration only. It collects SMTP
  envelope and message data, calls the daemon or library through approved
  boundaries, and applies returned actions.
- `cmd/dkim2ctl` owns generated-client workflows and test-client behavior.
- `docs/specs/openapi/dkim2d.yaml` is the authoritative REST contract.
- `lib/internal/rawmsg` is the source of truth for byte-preserving RFC 5322
  message representation.
- `lib/internal/canonical` is the source of truth for hash and signature
  canonicalization.
- `lib/internal/recipe` is the source of truth for recipe parsing,
  application, generation, and resource limits.
- `lib/internal/datasource` defines storage-facing contracts; provider-specific
  LDAP, SQL, and flat-file code belongs in command/service modules or explicit
  provider packages.
- Observability records behavior but must not become a second protocol model,
  datasource, key resolver, policy engine, or message state channel.

## Commit Log Format

Use structured commit messages with a fixed, capitalized prefix and a concise
headline:

```text
Prefix: Summarize the main change

- Detail the most relevant implementation work
- Mention tests, guardrails, generated files, or vectors when relevant
- Call out operator-facing behavior, config, security, or dependency changes
```

Allowed prefixes:

- `Add`: new functionality, files, or supported behavior
- `Change`: behavior changes that are not primarily bug fixes
- `Fix`: bug fixes and regressions
- `Remove`: deleted behavior, files, or obsolete paths
- `Refactor`: internal restructuring without intended behavior changes
- `Test`: test-only changes
- `Docs`: documentation-only changes
- `Build`: Makefile, Docker, packaging, release, or toolchain changes
- `Ci`: GitHub Actions, GitLab CI, or automation changes
- `Vendor`: dependency and vendored module updates
- `Security`: hardening or vulnerability-related changes
- `Chore`: repository maintenance that does not fit the other prefixes

Split unrelated work into separate commits when no single prefix and headline
describe the change cleanly.

## Quality Gates

Use the root Makefile:

```text
make test
make vet
make lint
make race
make guardrails
```

`make guardrails` is the local standard gate and should include formatting,
vet, golangci-lint, tests, race tests, OpenAPI checks, and vulnerability checks
as those targets become available.

Current multi-module direct checks:

```text
go test ./lib/...
go test ./cmd/dkim2d/...
go test ./cmd/dkim2-milter/...
go test ./cmd/dkim2ctl/...
```

## Definition Of Done

- [ ] Meaningful reproducer test added first for bug fixes where practical.
- [ ] Unit tests added or updated for protocol/core behavior where practical.
- [ ] Root cause fixed; no symptomatic weakening of validation, policy, or
      tests.
- [ ] DRY review completed; duplicated rules or logic removed or explicitly
      justified.
- [ ] OOP boundaries verified; domain invariants remain owned by cohesive
      types and narrow interfaces.
- [ ] Security-sensitive behavior preserves restrictive defaults,
      fail-closed ambiguity handling, and secret-safe diagnostics.
- [ ] OpenAPI changes are reflected in generated server/client artifacts and
      stale-output checks.
- [ ] Datasource changes preserve provider abstraction and do not leak LDAP,
      SQL, or flat-file models into protocol packages.
- [ ] Observability changes preserve exporter isolation, low-cardinality
      metrics, and secret-safe logs/traces.
- [ ] `make guardrails` passes, or the exact narrower commands run are listed
      with a reason.
- [ ] `golangci-lint` findings are fixed or intentionally documented.
- [ ] New or changed comments and technical docs are English-only.
- [ ] Commit messages use the approved prefix, headline, and bullet-list body
      format.
