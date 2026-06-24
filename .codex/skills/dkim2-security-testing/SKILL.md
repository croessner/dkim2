---
name: dkim2-security-testing
description: Drive reproducer-first DKIM2 security, robustness, fuzzing, resource-limit, abuse-case, and guardrail work. Use when fixing bugs, hardening parsers, recipes, canonicalization, key resolution, replay detection, datasource handling, OpenAPI inputs, Milter flows, telemetry redaction, or fail-closed policy.
---

# DKIM2 Security Testing

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`. Security-sensitive
ambiguity must fail closed unless an explicit compatibility policy says
otherwise.

## Reproducer-First Workflow

1. Create the smallest meaningful reproducer before changing production code
   whenever practical.
2. Classify the failure as parser, canonicalization, recipe, signature, DNS,
   datasource, replay, OpenAPI, Milter, telemetry, or policy.
3. Fix the root cause, not symptoms. Do not weaken validation, relax parser
   strictness, widen policy, or change expectations to hide a defect.
4. Keep useful reproducers as regression tests.
5. Add negative tests for adjacent cases.

## Fuzz And Abuse Targets

Prioritize raw message parsing, tag-value parsing, Message-Instance parsing,
DKIM2-Signature parsing, recipe JSON parsing/application, DNS key records,
OpenAPI request decoding, action plans, and datasource/replay error states.

Abuse tests should cover resource exhaustion, deep/large recipes, oversized
messages, malformed base64, duplicate/conflicting tags, sequence gaps, stale or
future timestamps, ambiguous datasource results, replay-store degradation, and
telemetry redaction failures.

## Security Review Rules

- Treat secrets and raw message data as toxic by default.
- Keep errors typed and bounded.
- Keep context deadlines and request limits near I/O boundaries.
- Make compatibility switches explicit, documented, tested, and observable.
- Treat `govulncheck`, race failures, and stale generated code as release
  blockers unless a maintainer exception is documented.

## Completion Check

Report the reproducer, the root cause, the fix, negative tests, and guardrails
run. If no reproducer was practical, explain why.
