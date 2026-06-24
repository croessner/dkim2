---
name: dkim2-milter-adapter
description: Guide DKIM2 Milter adapter design, EOM processing, SMTP envelope capture, raw RFC 5322 reconstruction fidelity, action-plan application, daemon calls, fail-closed behavior, tempfail handling, and Milter integration tests. Use when working in cmd/dkim2-milter or changing adapter-facing action semantics.
---

# DKIM2 Milter Adapter

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`, especially
`Milter Adapter Design`.

## Adapter Rules

- Keep the Milter adapter as operational glue, not the reference engine.
- Collect SMTP session metadata, envelope sender, recipients, headers, and body
  chunks.
- At EOM, submit raw RFC 5322 input plus envelope metadata to `dkim2d`.
- Apply only daemon-returned action plans using Milter-safe operations.
- Keep Milter-specific structs and callback behavior out of protocol packages.
- Default to fail-closed or tempfail for daemon unavailability, invalid daemon
  responses, unacceptable message fidelity, or ambiguous processing state.
- Fail-open behavior must be explicit, visible in effective config, logs,
  metrics, and docs.

## Fidelity Checks

- Record whether the message came from original bytes or callback
  reconstruction.
- Preserve header order, duplicate fields, body bytes, and line-ending behavior
  as far as the adapter path allows.
- Treat fidelity loss as adapter diagnostics and policy input, not as a second
  daemon message model.

## Test Expectations

Use unit tests for action translation and adapter state, HTTP fixture tests for
daemon calls, and integration tests for EOM flows when a Milter harness exists.
Include negative tests for malformed daemon responses, missing envelope state,
oversized messages, partial body collection, and rejected action plans.

## Completion Check

Report adapter evidence captured, fidelity limitations, fail-open/fail-closed
behavior, and tests run.
