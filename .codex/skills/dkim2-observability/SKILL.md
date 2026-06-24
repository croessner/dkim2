---
name: dkim2-observability
description: Guide DKIM2 logging, OpenTelemetry, Prometheus, debug modules, low-cardinality metrics, redaction, and secret-safe diagnostics. Use when adding or reviewing slog fields, spans, trace attributes, metrics, labels, debug switches, health/readiness signals, or observability configuration.
---

# DKIM2 Observability

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`, especially
`Observability Runtime`.

## Architecture Rules

- Use `log/slog` through a central provider.
- Use OpenTelemetry through a central runtime.
- Use Prometheus through a process-local registry owned by the daemon.
- Let library packages emit bounded observation events through injected
  interfaces; they must not construct exporters or global providers.
- Keep metrics labels on the documented low-cardinality allowlist.

## Telemetry Policy

Default telemetry may carry operational facts such as operation, result class,
verdict, reason class, error class, draft, algorithm family, policy mode,
route, status class, datasource kind/result class, replay state, duration, and
size/count buckets.

Richer diagnostics require explicit debug modules. Identity-like values may
appear only as deployment-local keyed hashes in approved debug modules, never as
Prometheus labels.

Never emit private keys, raw messages, raw body content, raw header values, raw
recipients, raw local parts, raw message IDs, raw signatures, raw
Message-Instance fields, raw replay keys, raw DNS TXT, raw LDAP DNs, raw SQL,
tokens, passwords, protected config, or unbounded errors.

## Review Checks

- Are labels low-cardinality and allowlisted?
- Are debug modules explicit and bounded?
- Does telemetry reveal less than CLI/REST output?
- Are errors typed before being logged?
- Is every sensitive field redacted before formatting?

## Completion Check

Report new fields, labels, debug modules, redaction behavior, and tests or
guardrails run.
