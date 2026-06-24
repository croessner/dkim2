---
name: dkim2-spec-conformance
description: Enforce DKIM2 draft and RFC fidelity for protocol design, implementation, tests, reviews, and architecture decisions. Use when work touches DKIM2 semantics, RFC 5322 message bytes, SMTP envelope binding, Message-Instance, DKIM2-Signature, recipes, DNS key records, canonicalization, verification results, normative language, or ambiguous draft behavior.
---

# DKIM2 Spec Conformance

## First Moves

Read `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md` before changing
behavior. Treat `draft-ietf-dkim-dkim2-spec-02` and
`draft-chuang-dkim2-dns-04` as the active baseline until the architecture says
otherwise.

When a task depends on exact draft text, verify the draft text directly instead
of relying on memory. If internet access is needed, use primary sources only and
cite them in the final answer.

## Conformance Workflow

1. Identify the protocol surface: raw message parsing, SMTP envelope, DKIM2
   tags, Message-Instance, recipe, DNS key record, signature sequence, policy,
   or output reporting.
2. Extract the relevant normative language. Separate `MUST`, `MUST NOT`,
   `SHOULD`, `SHOULD NOT`, `MAY`, examples, notes, and currently `TBA` areas.
3. Map each behavior change to one of:
   - exact draft requirement,
   - explicit architecture decision,
   - local policy outside protocol conformance,
   - temporary interpretation of an ambiguous draft area.
4. For ambiguous text, document the interpretation and add a test that can be
   revised when the draft changes.
5. Reject invented semantics. Do not add Unicode normalization, DNSSEC policy,
   recipe minimization, trust-boundary reporting, or replay behavior as protocol
   conformance unless the draft or architecture explicitly requires it.

## Test Expectations

Prefer draft-versioned golden vectors and negative vectors. Tests must prove:

- Byte-preserving RFC 5322 handling.
- Correct handling of signature sequence gaps.
- Current-envelope matching for the highest DKIM2 signature.
- Message-Instance hash behavior.
- Recipe parse, apply, generate, null-recipe, and resource-limit behavior.
- DNS key-record state distinctions.
- Structured error states rather than raw string matching.

## Completion Check

End work with the draft section or architecture decision used, the tests run,
and any remaining draft ambiguity. Never soften validation or policy to pass a
test unless the test is demonstrably wrong.
