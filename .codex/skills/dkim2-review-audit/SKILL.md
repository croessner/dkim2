---
name: dkim2-review-audit
description: Perform DKIM2 reviewer and auditor passes focused on defects, regressions, spec conformance, security, tests, policy compliance, generated artifacts, module boundaries, observability safety, and release readiness. Use when asked to review code, architecture, PRs, diffs, tests, guardrails, or implementation plans.
---

# DKIM2 Review Audit

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`. Review from the
actual diff and surrounding code, not from intent alone.

## Review Priority

Lead with findings. Order by severity. Prefer file and line references. Focus
on:

- Draft/RFC conformance regressions.
- Security or fail-closed violations.
- Secret or message-metadata leakage.
- Parser, canonicalization, recipe, signature, DNS, replay, or datasource bugs.
- OpenAPI/generated-code drift.
- Milter fidelity or unsafe action application.
- Module-boundary and dependency leaks.
- Missing meaningful unit, golden, fuzz, integration, or negative tests.
- Guardrail, lint, race, or vulnerability gaps.

## Audit Procedure

1. Inspect changed files and nearby ownership boundaries.
2. Trace behavior from input to output for user-facing or protocol-facing
   changes.
3. Check whether tests prove the important failure modes.
4. Verify generated artifacts, docs, and config examples when contracts change.
5. Run or request the narrowest useful commands, then `make guardrails` when
   appropriate.

## Findings Format

Use this order:

1. Findings, ordered by severity, with file/line references.
2. Open questions or assumptions.
3. Brief change summary only after findings.
4. Test or guardrail status.

If no issues are found, say so clearly and note residual test gaps or risks.

## Completion Check

Report whether the review is complete, what evidence was checked, and any
commands that could not be run.
