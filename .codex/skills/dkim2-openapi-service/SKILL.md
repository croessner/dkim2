---
name: dkim2-openapi-service
description: Guide DKIM2 daemon REST API, OpenAPI contract, generated server/client code, dkim2ctl test-client workflows, request limits, HTTP/domain mapping, and generated-code guardrails. Use when changing docs/specs/openapi, cmd/dkim2d HTTP behavior, cmd/dkim2ctl, OpenAPI generation, API fixtures, or REST DTO boundaries.
---

# DKIM2 OpenAPI Service

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`, especially
`OpenAPI as Contract Authority`. `docs/specs/openapi/dkim2d.yaml` is the REST
source of truth.

## Contract Rules

- Change OpenAPI before changing REST handler behavior.
- Use `oapi-codegen` pinned to
  `github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.7.1`.
- Commit generated artifacts and review generated diffs.
- Keep generated DTOs at HTTP/client boundaries only.
- Map generated request/response objects to explicit domain types.
- Build `dkim2ctl` on the generated client, not a parallel hand-written REST
  model.
- Keep `/v1/process`, `/v1/verify`, `/v1/sign`, `/v1/revise`, `/healthz`, and
  `/readyz` semantics explicit and versioned.

## Implementation Procedure

1. Update the OpenAPI spec and generator config together.
2. Regenerate server/client artifacts through the documented Make target once
   it exists.
3. Add positive and negative API fixtures.
4. Keep request size limits, timeouts, and structured error responses in the
   daemon adapter layer.
5. Add or update `dkim2ctl` fixture workflows when API behavior changes.

## Review Checks

- No domain package imports generated REST types.
- No route bypasses the OpenAPI contract.
- Errors are structured and bounded.
- Raw message bodies are accepted only through approved encoded fields.
- Generated output is reproducible and not stale.

## Completion Check

Report OpenAPI files changed, generated files changed, fixtures added, and the
guardrails or narrower commands run.
