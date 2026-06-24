# Engineering Policy

These rules are mandatory for coding changes in this repository. A task is
incomplete if any mandatory rule is missed.

## Must Rules

- MUST: Keep the project on Go 1.26 across `go.work`, module metadata, CI,
  generated code, Docker or packaging files, and documentation.
- MUST: Preserve the multi-module boundary. `lib/` is the standalone DKIM2
  reference library; service and adapter dependencies belong in command modules.
- MUST: Apply security-by-design and security-by-default. Ambiguous protocol,
  transport, key, datastore, recipe, replay, or message-fidelity state must fail
  closed unless an explicit compatibility policy says otherwise.
- MUST: Fix root causes, not symptoms. Do not weaken validation, policy,
  parser strictness, canonicalization, tests, or guardrails to hide a defect.
- MUST: Use meaningful reproducer tests before bug fixes whenever a stable
  reproducer is practical. Keep useful reproducers as regression coverage.
- MUST: Prefer unit-driven development for core protocol and domain behavior.
  Write or adjust focused unit tests before production code when clean unit
  coverage is practical.
- MUST: Treat failing unit tests as evidence. First decide whether the failure
  exposes production behavior that is wrong; change tests only when the test is
  demonstrably wrong.
- MUST: Apply DRY intentionally. Shared protocol rules, parser behavior,
  security checks, validation logic, datasource behavior, OpenAPI mapping, and
  observability policy must live in one authoritative abstraction.
- MUST: Use strict object-oriented boundaries in Go. State must be encapsulated
  in cohesive types, behavior must be exposed through methods and narrow
  interfaces, and composition is preferred over package-level mutable state.
- MUST: Keep dependencies intentional. Add dependencies only when they clearly
  reduce risk, complexity, or long-term maintenance cost.
- MUST: Keep library consumers free from service-only dependencies. The library
  must not depend on Cobra, Viper, Fx, OpenAPI generated code, Prometheus
  exporters, OTLP exporters, Milter packages, SQL drivers, LDAP drivers, or CLI
  frameworks.
- MUST: Treat Cobra, Viper, Uber Fx, `log/slog`, OpenTelemetry, Prometheus, and
  OpenAPI generation as approved foundation choices for service and adapter
  modules, not as dependencies for the protocol core.
- MUST: Use OpenAPI from hour zero for the `dkim2d` REST API. REST contracts,
  server DTOs, client DTOs, and generated clients must originate from
  `docs/specs/openapi/dkim2d.yaml`.
- MUST: Keep OpenAPI-generated artifacts reproducible by documenting and pinning
  the generator, providing generation/check targets, and failing guardrails on
  stale generated output once generation exists.
- MUST: Keep generated REST types at REST boundaries. Core DKIM2 packages must
  use explicit domain request and response types.
- MUST: Build `dkim2ctl` and OpenAPI test-client workflows on the generated
  OpenAPI client SDK rather than a parallel hand-written REST model.
- MUST: Use Viper/Cobra configuration only in command modules. Config loading
  must decode into typed structs, expand scalar environment placeholders before
  validation, never expand map keys, fail closed on missing variables, and
  preserve redaction metadata.
- MUST: Compose `dkim2d` through Uber Fx or an explicit Fx-compatible provider
  model. Runtime packages must receive dependencies through constructors, not
  global mutable state.
- MUST: Use `log/slog` through a central provider. Debug modules must be
  explicit, documented, bounded, and secret-safe.
- MUST: Integrate OpenTelemetry through a central observability runtime.
  Domain packages may emit observation events but must not construct exporters
  or global telemetry providers.
- MUST: Integrate Prometheus through a process-local registry owned by the
  observability runtime. Do not use high-cardinality or secret-bearing labels.
- MUST: Keep metrics labels on a documented low-cardinality allowlist. Raw
  users, recipients, message IDs, session IDs, request IDs, trace IDs, client
  IPs, backend identifiers, selector nonces, Valkey keys, Redis keys, LDAP DNs,
  SQL text, raw errors, tokens, passwords, and private-key material must not be
  labels.
- MUST: Keep datasource access behind interfaces. LDAP, SQL, and flat-file
  implementations must satisfy the same domain contracts and must not leak
  provider-specific types into protocol packages.
- MUST: Keep datasource reads and mutations context-aware, bounded, observable,
  and fail-closed when required data is ambiguous or unavailable.
- MUST: Never log or expose private keys, tokens, credentials, protected config
  values, raw message bodies, raw recipient lists, or other secret-bearing
  values in logs, traces, metrics, REST output, CLI output, or test logs.
- MUST: Keep REST, CLI, Milter, and datasource adapters thin. They translate
  transport or provider details into domain requests and action plans; they do
  not own DKIM2 protocol rules.
- MUST: Keep Milter fidelity limitations explicit. A reconstructed Milter
  message is not the same evidence as raw RFC 5322 bytes from a vector runner.
- MUST: Keep all local scratch, prompt, planning, and handoff artifacts under
  ignored `temp/`. Durable project documentation belongs under `docs/`.
- MUST: Write code comments and technical documentation in English.
- MUST: Add concise English doc comments for all hand-written named functions
  and receiver methods introduced or changed by a task, including unexported
  functions and methods.
- MUST: Keep production names free of planning-only labels. Do not encode
  prompt IDs, task IDs, rollout labels, or transient milestone numbers in
  source names, docs, branches, tags, commit subjects, or commit bodies.
- MUST: Run Go tests through Makefile targets once the relevant targets exist.
- MUST: Run `make lint` or `make guardrails` so `golangci-lint` participates in
  local validation.
- MUST: Keep `.golangci.yml` aligned with the repository guardrail policy.
- MUST: Treat `govulncheck` findings as publish blockers for `main` and `v*`
  tags unless a documented maintainer exception is made.
- MUST: Write commit messages as `Prefix: Concise headline`, using only the
  approved prefixes `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`,
  `Docs`, `Build`, `Ci`, `Vendor`, `Security`, and `Chore`.
- MUST: Use the commit body as a short bullet list of essential implementation,
  validation, operator-facing, security, generated-file, or dependency details.
- MUST: Split unrelated work into separate commits when no single approved
  prefix and headline describes the change cleanly.

## Definition Of Done

- [ ] Meaningful reproducer test added first for bug fixes where practical.
- [ ] Focused unit tests added or updated for core/domain behavior where
      practical.
- [ ] Root cause fixed; no symptom-only workaround or weakened guardrail.
- [ ] DRY check completed; duplicated rules or logic are removed or explicitly
      justified.
- [ ] OOP boundary check completed; domain state remains encapsulated behind
      cohesive types, methods, and narrow interfaces.
- [ ] Security-sensitive changes preserve restrictive defaults, fail-closed
      ambiguity handling, and secret-safe diagnostics.
- [ ] OpenAPI contract, generated artifacts, and stale-output checks are
      updated together when REST behavior changes.
- [ ] Config changes include typed validation, env expansion behavior,
      redaction, and stable-path documentation where relevant.
- [ ] Datasource changes preserve provider abstraction and bounded
      context-aware operations.
- [ ] Observability changes preserve central providers, low-cardinality metrics,
      and secret-safe logs/traces.
- [ ] `make guardrails` passes, or the narrower commands run are listed with a
      reason.
- [ ] `golangci-lint` findings are fixed or intentionally documented.
- [ ] `govulncheck` is clean before publishing release-sensitive refs, or a
      maintainer exception is documented.
- [ ] New or changed comments and technical documentation are English-only.
- [ ] Commit message uses the approved prefix, headline, and bullet-list body
      format.
