---
name: dkim2-senior-go-architect
description: Apply senior Go architecture judgment to the DKIM2 reference implementation. Use when designing packages, interfaces, abstractions, OOP-style boundaries in Go, DRY refactors, module splits, dependency placement, constructor design, test seams, or public API shape across lib, daemon, Milter, datasource, OpenAPI, and CLI modules.
---

# DKIM2 Senior Go Architect

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md`. Preserve the
multi-module boundary: `lib/` owns protocol semantics; `cmd/*` owns service,
adapter, OpenAPI, Cobra/Viper, Fx, observability exporters, and concrete
providers.

## Architecture Rules

- Keep domain behavior behind cohesive types with narrow methods.
- Prefer constructor injection over package-level mutable state.
- Use interfaces at ownership boundaries, not for every small helper.
- Keep REST DTOs, Milter structs, datasource records, and telemetry exporters
  out of protocol packages.
- Use DRY for protocol rules, parser behavior, canonicalization, security
  checks, config validation, datasource semantics, OpenAPI mapping, and
  observability policy.
- Add abstractions only when they remove real duplication, protect a boundary,
  or encode a durable invariant.
- Keep dependencies intentional. The library must not import command/service
  dependencies.

## Design Procedure

1. Locate the owning package and nearby patterns before proposing new structure.
2. Define invariants in the type that owns the state.
3. Decide whether the seam is a domain seam, transport seam, provider seam, or
   test seam.
4. Keep concrete implementations near the runtime that wires them.
5. Write focused unit tests for domain behavior and narrower adapter tests for
   transport mapping.

## Review Prompts

Ask before finishing:

- Does this duplicate a rule already owned elsewhere?
- Did a service dependency leak into `lib/`?
- Is a provider-specific type visible in protocol code?
- Are errors typed and actionable?
- Can the behavior be tested without the daemon when it is protocol-core work?

## Completion Check

Report the package boundary chosen, the abstraction rationale, and the commands
run. If an abstraction is deferred, say why.
