# DKIM2 Current-Semantics Audit — 2026-08-21

> Historical Draft-04 audit. This dated report records the repository state on
> 2026-08-21 and does not define or qualify the current Draft-06 baseline. See
> [`draft-05-semantics-audit-2026-08-26.md`](draft-05-semantics-audit-2026-08-26.md).

This report checks the protocol changes from `v0.1.6` through `v0.1.9` and
the current multi-instance response correction for accidental support of an
obsolete DKIM2 contract. The normative protocol baseline is
[`draft-ietf-dkim-dkim2-spec-04`](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/).
RFC 3464 is authoritative for the generic delivery-status field grammar.

The result is `passed`: the reviewed paths implement one current Draft-04
contract. No deprecated DKIM2 value, protocol-version fallback, enum alias, or
caller-selectable legacy mode is retained or introduced.

## Normative mapping

Draft-04 requires a verifier to reconstruct preceding Message-Instance states,
validate every relevant Message-Instance and DKIM2-Signature field, and check
all signatures needed for chain-of-custody, exploded-message, feedback, and
reputation decisions. Its verification procedure also evaluates later-hop
evidence for `donotmodify` and `donotexplode`. The local policy projection
therefore legitimately reports a verified multi-instance chain with no such
requests as `not_requested`, and reports contiguous authenticated feedback
history as `complete`. Those values are current semantics, not old-output
compatibility.

The current verifier does not yet mint authenticated positive or negative
modification transitions for reconstructed earlier states. Consequently the
public response schema exposes only the presently reachable modification
states `not_requested`, `indeterminate`, and `not_evaluated`. Internal policy
types may model additional future evidence, but `honored`, `violated`, and
their reasons are intentionally not serialized until the verifier can produce
the required authenticated facts. Unknown, empty, future, and unreachable
wire values fail closed.

## Change-history audit

| Change | Current purpose | Legacy or fallback path | Decision |
| --- | --- | --- | --- |
| `245ba7c` | Carries the closed Postfix DSN origin enum `internal` or `external`; only exact EOH-confirmed `internal` authorizes the bounce route. | None. Missing, malformed, duplicate, wrong-stage, or injected values fail closed. | Retain. |
| `bda5bb0` | Derives the delivery-status signing domain only after verification of the authenticated embedded highest `d=`. | None. Caller-selected outer-envelope or static-domain selection is rejected for this route. | Retain. |
| `1b0150e` | Resolves DKIM2 DNS keys with authoritative TTL semantics and bounded UDP/TCP behavior. | None. There is no serve-stale or old DNS-record interpretation. | Retain. |
| `f0e93be` | Admits the bounded current Postfix bounce(8) delivery-status wire profile behind the dedicated Postfix capability and internal-origin gate. | None. Generic library and Exim paths remain strict RFC 3464; the request body cannot select the Postfix profile. | Retain behavior; use wire-profile rather than compatibility or legacy terminology. |
| `99f5a6b` | Emits a closed, content-free stage for DSN evidence failures without changing the response or disposition. | None. An error is reclassified as context cancellation only when it wraps the active context error; an independent typed failure keeps its own stage and permanence even if cancellation races. | Retain. |
| Current multi-instance correction | Serializes reachable full-chain policy and feedback states through the canonical OpenAPI response. | None. All repository clients are generated from the same source contract; no alias or previous-schema branch exists. | Retain reachable values only. |

The Postfix bounce(8) profile is current MTA interoperability, not support for
an earlier DKIM2 draft. It is selected inside the daemon only after the
dedicated route capability attests the trusted adapter path. Mandatory DSN
structure, recipient linkage, cryptography, bounds, and fail-closed behavior
remain unchanged.

The public Go constructor for this profile necessarily accepts the caller's
provenance assertion; a library cannot prove the caller's process topology.
Its contract therefore requires equivalent trusted Postfix bounce provenance.
This is a documented integrator responsibility and a misuse risk, not a second
wire contract. The daemon never exposes that choice in JSON and remains the
only product caller.

## Executable evidence boundary

The in-repository mapper, strict-handler, adapter, and generated-contract tests
are normative. The optional real-Milter test is additional wire evidence. Its
private source is commit
`a3d5e00ff8cff071f91a485acfc0aaaea81c5feb`, tree
`ba6fa740919c13329ef2842895031924424f08f1`, at
`ssh://git@git.roessner-net.de:2222/croessner/miltertest-go.git`. Remote
`main` and `HEAD` were read back at that exact commit and tree. The
deterministic CGO-disabled Go 1.26.6 Darwin amd64 build from that tree, with
VCS metadata disabled, has SHA-256
`b9caf2d3b6c2fe1d76026e554e2c7b6796e651233b162fdfd0605b9d85198c99`.
The exact build command and the secret-free executed Lua, YAML, and synthetic
body hashes are recorded by the opt-in test; capabilities, sockets, actions,
keys, and production messages are not retained.
