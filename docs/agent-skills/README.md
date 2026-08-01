# Agent Skills

This repository carries repo-local Codex skills under `.codex/skills/`. Use
them as focused operating modes for DKIM2 work, not as replacements for
`AGENTS.md`, `POLICY.md`, or `docs/ARCHITECTURE.md`.

Available skills:

- `dkim2-spec-conformance`: draft/RFC fidelity, normative language, protocol
  interpretation, draft-versioned vectors, and ambiguity handling.
- `dkim2-senior-go-architect`: Go package design, OOP-style boundaries, DRY
  checks, interface placement, module separation, and dependency ownership.
- `dkim2-mail-domain`: SMTP, RFC 5322, MIME/header behavior, DKIM heritage,
  EAI/SMTPUTF8, Authentication-Results, DNS mail records, and Milter fidelity.
- `dkim2-openapi-service`: `dkim2d` OpenAPI contract, generated server/client
  code, REST DTO/domain mapping, and `dkim2ctl` test-client workflows.
- `dkim2-datasource-provider`: datasource interfaces, flat-file, LDAP,
  PostgreSQL, MySQL, and MariaDB providers, Valkey replay storage, provider
  errors, and redaction.
- `dkim2-observability`: `slog`, OpenTelemetry, Prometheus, low-cardinality
  metrics, debug modules, and telemetry redaction.
- `dkim2-milter-adapter`: Milter EOM flow, SMTP envelope capture, raw-message
  fidelity, daemon calls, action-plan application, and fail-closed adapter
  behavior.
- `dkim2-security-testing`: reproducer-first fixes, fuzzing, resource limits,
  abuse cases, negative tests, and guardrail closeout.
- `dkim2-review-audit`: reviewer/auditor stance for correctness, regressions,
  tests, security, boundaries, generated artifacts, and policy compliance.

Skill rules:

- Skills must point agents back to `AGENTS.md`, `POLICY.md`, and relevant
  architecture/spec documents before implementation.
- Skills must keep scratch output under ignored `temp/`.
- Skills must not embed private keys, secrets, protected config values, or raw
  production messages.
- Skills must end with evidence: focused tests, guardrail status, and
  `git status --short`.
