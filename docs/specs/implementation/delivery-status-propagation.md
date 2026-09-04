# Received Delivery-Status Evaluation and DSN Propagation

Status: implementation-ready.

This specification closes the last two Draft-06 Section 12 gaps of the
reference implementation: evaluation of a received DKIM2-signed delivery-status
notification (DSN) as a DSN, and propagation of such a DSN backwards along the
chain of custody by a Forwarder. Both build on the byte-preserving RFC 6522
evidence core that already exists for outgoing initial DSN signing.

The work is deliberately MTA-neutral. The reference deployment uses Postfix,
but nothing in this contract depends on a Postfix patch, a Milter, a Postfix
queue feature, or a particular policy service. Any MTA that can route mail for
the local return-path addresses of forwarded messages to an LMTP endpoint, and
that offers a trusted null-sender submission listener, can operate the
propagation path.

## Source Documents

This specification is governed by:

- `AGENTS.md`
- `POLICY.md`
- `docs/ARCHITECTURE.md`
- `docs/specs/openapi/dkim2d.yaml`
- `draft-ietf-dkim-dkim2-spec-06`, Section 8.5 (`mf=`), Section 8.6 (`rt=`),
  Section 8.7 (`nd=`), Section 9.3 (custody schemes), Section 11.4 (domain
  alignment), and Sections 12 through 12.1.2
- `docs/specs/draft-06-migration-disposition.md`, which records that Section
  12 carries the Draft-05 text forward with RFC 6522 terminology only
- RFC 6522 (`multipart/report`), RFC 3464 (`message/delivery-status`),
  RFC 3461 (`ORCPT`, `ENVID`, xtext), RFC 3834 (automatic responses),
  RFC 2033 (LMTP), RFC 5321 and RFC 5322
- `docs/specs/implementation/delivery-status-signing.md`
- `docs/specs/implementation/postfix-dsn-origin.md`
- `docs/specs/implementation/signing-and-revision.md`
- `docs/specs/implementation/recipe-application.md`
- `docs/specs/implementation/replay-store-valkey.md`
- `docs/specs/implementation/milter-adapter.md`
- `docs/specs/implementation/openapi-daemon-foundation.md`
- `docs/specs/implementation/openapi-test-client.md`
- `docs/specs/implementation/observability-foundation.md`
- `Makefile`

If these sources disagree, implementation stops until the durable authority is
reconciled. The active protocol baseline is `draft-ietf-dkim-dkim2-spec-06`.
Section numbers cited here are the Draft-05 numbers that the Draft-06
migration disposition carried forward unchanged.

The RFC 3464, RFC 3834, and RFC 2033 statements in this specification were
confirmed against the RFC text on 2026-09-04. The confirmed facts are:
RFC 3464 requires `Reporting-MTA`, `Final-Recipient`, `Action`, and `Status`;
`Original-Envelope-Id` SHOULD be supplied when an ENVID accompanied the
message and MUST NOT be supplied otherwise; `Original-Recipient` is included
only when a sender-specified `ORCPT` was present; `Final-Recipient` reports
the exact envelope address without angle brackets; `Action` and `Status` are
independent, so `failed` may carry a `4.X.Y` code; the third part is optional
in RFC 3464 but required by Draft-06 Section 12.1. RFC 3834 Section 5 states
that `auto-generated` MUST NOT label a DSN and that `auto-replied` MAY. RFC
2033 requires `LHLO`, a non-positive reply to `HELO` and `EHLO`, `PIPELINING`,
`ENHANCEDSTATUSCODES`, one reply per accepted recipient after `DATA`, and
treats a positive completion reply as accepting delivery responsibility;
`8BITMIME` is a SHOULD.

## Original Gap

The library and daemon implement outgoing initial DSN signing only. The
library exposes `EvaluateDSNForSigning` and `SignDSN` on the `Signer`; both
require an outer `<>` reverse path and authorize the local signing of a bounce
that the local MTA is generating. The daemon exposes them through the
Postfix-exclusive `POST /v1/dsn/sign` route.

Three things are missing:

1. **Received DSN evaluation.** A DKIM2-signed DSN that arrives from another
   system is processed by `/v1/process` as an ordinary message. The outer
   signature is verified, but the RFC 6522 structure, the embedded original,
   and the Draft-06 Section 12.1.2 linkage between the DSN and a message this
   system previously signed are not evaluated. No structured DSN fact reaches
   the Milter, Rspamd, or any policy consumer. The Section 12.1.2 checks exist
   as internal machinery in `lib/internal/dsn/evidence.go` but are reachable
   only through the outgoing signing facade, which evaluates the outer
   recipient against an *outgoing* envelope.
2. **DSN rebuild.** Draft-06 Section 12.1.1 requires a Forwarder that
   propagates a DSN to remove the signature and Message-Instance it added,
   undo its own modifications through the authenticated recipe, degrade to
   `text/rfc822-headers` when the body cannot be reconstructed, and neutralize
   destination-specific text. The verifier performs a historical descent for
   chain verification (`lib/internal/verify/history.go`) and the recipe
   applier reconstructs previous states, but the descent proves hashes only,
   its public entry point expects a body-known current state, the recipe
   package exports no headers-only state constructor, and no historical
   signature is verified. Nothing serializes a reconstructed previous state into a new
   RFC 6522 report.
3. **Propagation transport.** No component receives a DSN from the MTA,
   obtains the rebuilt and signed DSN, and re-submits it with a null reverse
   path to the previous hop. A Milter cannot do this because a Milter cannot
   create a new message; the outgoing signing route cannot do this because its
   authority model requires the embedded highest signature to be local, which
   is not the case for a rebuilt DSN.

The documented consequence is recorded in
`docs/reference/known-limitations.md`: received-DSN processing and DSN
propagation are deferred. This specification removes that deferral.

## Goal

After this work the product:

1. classifies every applicable inbound null-sender `multipart/report;
   report-type=delivery-status` message as a DSN inside `/v1/process`, and
   returns a bounded structured `delivery_status` fact next to the existing
   verification, authentication, policy, and replay facts;
2. evaluates the Draft-06 Section 12.1.2 checks for such a DSN against the
   embedded original message and reports whether the DSN is linked to a
   message this system signed, without ever using that fact as a signing
   authority;
3. rebuilds a linked DSN according to Section 12.1.1 into a new
   single-signature, single-Message-Instance DSN addressed to the previous
   hop's `mf=`, or reports that propagation is impossible or forbidden;
4. signs that rebuilt DSN with the domain proven by the removed local
   signatures, through a dedicated daemon route, capability, route ticket, and
   replay gate;
5. ships an MTA-neutral propagation adapter that receives DSNs from the MTA
   over LMTP, calls the daemon, and re-submits the rebuilt DSN over SMTP with
   a null reverse path to a trusted, Milter-free re-injection listener; and
6. keeps the inbound Milter contract unchanged except for tolerating the new
   optional response member, and projects the received-DSN facts through the
   existing `contrib/rspamd` module as zero-score symbols.

## Delivery Shape

1. Freeze protocol interpretation, limits, typed errors, closed vocabularies,
   and public library seams with reproducer tests. Confirm the RFC 3464,
   RFC 3834, and RFC 2033 statements against the RFC text. Add the
   received-DSN evaluation facade to the library, including the local-hop-run
   and local-authority rules.
2. Add the Section 12.1.1 rebuild to the library: the one-hop-run descent
   seam in `verify` with historical signature verification, the header-only
   serializer, the unsigned-field policy, deterministic report generation,
   and the propagation signing facade.
3. Change OpenAPI first: the `delivery_status` member of `ProcessResponse`,
   the optional `context.tenant` of `ProcessRequest`, the
   `POST /v1/dsn/propagate` and `POST /v1/dsn/propagate/commit` operations
   with their distinct capability, the `PropagationDisposition` schema, the
   propagation envelope with `smtputf8`, and the `lmtp_delivered_crlf`
   fidelity value. Regenerate all server and client artifacts, including the
   new propagator client.
4. Implement daemon orchestration for received-DSN evaluation inside
   `/v1/process` and for the propagation route, including policy mapping,
   replay gate, route ticket, protected capability, config, and observation
   events.
5. Add the `cmd/dkim2-dsn-propagator` module to `go.work`, the Makefile
   product-module list, workspace sync files, OpenAPI client generation and
   stale-output targets, golangci configuration, CI, and container build.
   Implement the LMTP receiver, daemon client on the generated SDK, SMTP
   re-injection client, protected files, config, observability, and the
   fail-closed matrix.
6. Update `cmd/dkim2ctl` fixtures, the inbound Milter response validator, and
   the `contrib/rspamd` module for the new response member and symbols.
7. Real-MTA qualification with Postfix, operator documentation for Postfix and
   for a generic MTA, architecture, known-limitations, conformance manifest,
   and closeout review.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 4-6 engineering days |
| Highest-risk area | Section 12.1.1 rebuild correctness, historical signature verification, and the propagation authority boundary |
| Expected prompt count | 8-10 |
| Required final gate | `make guardrails` plus the opt-in real Postfix qualification |

Risk notes:

- Low risk: OpenAPI member addition, `dkim2ctl` fixtures, Rspamd symbol
  projection, documentation.
- Medium risk: LMTP receiver and SMTP re-injection client, protected-file and
  socket rules, adapter fail-closed matrix, Postfix qualification, workspace
  and CI wiring for a new module.
- Highest risk: local-hop-run detection across `nd=` and imaginary hops,
  recipe undo with hash and signature re-proof, header-only serialization,
  report regeneration without destination leakage, and the authority that
  derives from *removed* signatures instead of the embedded highest one.

Measured effort is filled during closeout in the ignored prompt ledger and
summarized here:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| | | | | | |

## Scope

In scope:

- library facades `EvaluateReceivedDSN`, `RebuildDSNForPropagation`, and
  `SignPropagatedDSN`, with immutable evidence and typed staged errors;
- received-DSN classification and evaluation inside `/v1/process`, projected
  as the closed `delivery_status` fact;
- policy mapping of received-DSN outcomes in the existing strict, permissive,
  and testing modes;
- the daemon route `POST /v1/dsn/propagate`, its distinct protected
  capability, replay gate, route ticket purpose, and response DTO carrying the
  rebuilt DSN bytes;
- the propagation adapter `cmd/dkim2-dsn-propagator` with LMTP intake and
  SMTP null-sender re-injection, and its workspace, build, and CI wiring;
- generated server and client artifacts, `dkim2ctl` fixtures, inbound Milter
  response tolerance, and `contrib/rspamd` symbols;
- provisioning documentation for `delivery_status` profiles on transit
  domains;
- Postfix deployment guidance and qualification for the propagation path, and
  generic MTA guidance;
- architecture, reference, operator, and limitation documentation.

Out of scope:

- changes to the outgoing initial DSN signing route, the Postfix origin enum,
  or the `postfix_dsn` Milter mode;
- any Postfix patch; the propagation path needs none;
- Milter-side DSN generation or envelope mutation;
- generic Exim integration beyond documenting that Exim can route to the same
  LMTP endpoint; Exim remains `unqualified_draft06`;
- recipient-group signing, Bcc disclosure, and the multi-recipient originator
  path;
- automatic sender-rewriting for forwarded mail; the deployment must already
  produce a local `mf=` on forwarded messages, otherwise no DSN can reach this
  system and there is nothing to propagate;
- propagation of a DSN whose previous hop is itself an `nd=` signature
  without `mf=`, which would require reconstructing an earlier system's
  custody scheme;
- mailbox delivery of DSNs for locally originated messages; that remains the
  MTA's ordinary local delivery;
- any policy-service integration beyond the optional, already existing
  `contrib/rspamd` hooks.

## Protocol, Runtime Or Domain Semantics

### Terminology

- **Received DSN**: an inbound message with reverse path `<>`, a top-level
  `multipart/report` with `report-type=delivery-status`, and at least one
  DKIM2 field family present. Unsigned reports are not DSNs for DKIM2 purposes
  and keep today's `not_applicable` behavior.
- **Embedded original**: the third RFC 6522 part, either `message/rfc822` or
  `text/rfc822-headers`.
- **Local authority domain**: a domain for which the requesting tenant holds
  at least one active signing profile of any use (`originator`,
  `ordinary_transit`, `next_domain_transit`, or `delivery_status`) in the
  datasource. This is the only definition of "ours" this specification uses.
  A verified signature under a foreign domain that merely names a local
  address in `mf=` is never local. Whether a local domain can *sign* a
  propagated DSN is a separate question answered by its `delivery_status`
  profile.
- **Local hop run**: the maximal contiguous suffix of the embedded original's
  DKIM2-Signatures `i=n, n-1, ..., k` created by this system. `i=n` is the
  completion signature: it carries `mf=` and `rt=`, its `d=` is a local
  authority domain, and its `mf=` equals the observed outer DSN recipient
  exactly. An earlier signature `i=j` belongs to the run when either
  (a) it is an `nd=` signature whose `nd=` equals the `d=` of `i=j+1` and
  whose `d=` is a local authority domain, the Section 9.3 `nd=` scheme; or
  (b) it carries `mf=` and `rt=`, the `mf=` of `i=j+1` relaxed-matches one of
  its `rt=` paths under the existing Section 9.4 custody check, its `d=`
  relaxed-matches its own `mf=` domain under Section 11.4, and its `d=`, its
  `mf=` domain, and every `rt=` domain are local authority domains, the
  Section 9.3 imaginary-hop scheme.
  Every run member must verify cryptographically over the state it signed;
  a run member that does not verify makes the projection
  `unsupported_chain`, because the keys are local and a non-verifying local
  signature is either forged or damaged, and Section 12.1 requires all
  relevant signatures to verify. The highest-only reading of Section 12.1
  for the embedded verification in the evaluation is a local interpretation.
  Rule (b) also absorbs a genuine earlier hop between two domains of the
  same tenant; that is intended, because such a hop is indistinguishable
  from an imaginary one and the tenant controls both ends. Draft-06 Section
  8.7 guarantees that an `nd=` run ends in one signature with `mf=` and
  `rt=`. A run therefore has one or more members. Section 12.1.1 requires
  *every* signature that the Forwarder added to be removed, which is the
  whole run.
- **Previous hop**: the DKIM2-Signature `i=k-1`. It must carry `mf=` and
  `rt=`. If `i=k-1` is itself an `nd=` signature, the previous hop used a
  custody scheme whose reconstruction this specification does not qualify, and
  the projection is `unsupported_chain`. If `k = 1`, this system originated
  the message and the projection is `terminal_origin`.
- **Propagation**: building and sending a new DSN to the previous hop's `mf=`.

### Received DSN evaluation (Section 12.1.2)

Evaluation runs only after the ordinary inbound verification of the outer
message. It never replaces it. The outer DSN's own DKIM2 signature, replay
state, and policy remain authoritative for accepting the outer message.

The evaluation proves, in this order, and stops at the first failure:

1. **Structure**: exact three-part RFC 6522 framing under the existing DSN
   parser limits; `message/delivery-status` parses under the strict generic
   RFC 3464 profile. The Postfix bounce wire profile is not selected here
   because the DSN was generated by a foreign system.
2. **Embedded verification**: the embedded original's highest signature and
   instance verify with the existing dedicated embedded verifier.
   Current-envelope comparison is marked not applicable exactly as in the
   outgoing DSN path. For `text/rfc822-headers`, only header evidence is
   available and the result carries the `headers_only` form. An embedded
   original that carries no DKIM2-Signature at all is `embedded = absent`:
   Draft-06 Section 12.1.2 applies only when "the included original message
   is also DKIM2 signed", so evaluation stops with `propagation =
   not_applicable` and every later member `not_evaluated`.
3. **Local hop identity**: this is Section 12.1.2 item 2. The completion
   signature `i=n` must (a) verify, with its Section 8.4 timestamp window
   evaluated against the outer DSN's highest-signature `t=` instead of the
   current clock, because a DSN may legitimately arrive long after the
   forwarding: the completion `t=` must not exceed the outer `t=` plus the
   verifier's skew allowance, and the outer `t=` minus the completion `t=`
   must stay within the verifier's maximum age, (b) have a `d=` that is a
   local authority domain for the tenant, resolved through the datasource
   before the
   projection is emitted, (c) satisfy the Section 11.4 relaxed domain match
   between its `d=` and its `mf=` domain, and (d) have an `mf=` that is
   byte-equal to the observed outer DSN recipient after lowercasing the
   domain part of both, the Section 11.4 comparison rule with a
   case-sensitive local part. Outcomes: `local` when all four
   hold; `not_local` when (b) fails, which is the legitimate state of a relay
   carrying somebody else's DSN; `mismatch` when (b) holds but (c) or (d)
   fails, which is a forged-recipient or misrouted DSN naming a local domain.
   The run is then extended backwards over run members as defined above.
   The datasource lookup in (b) is keyed by a signer-chosen `d=`, so it runs
   only after canonical domain-syntax validation, uses the existing bounded
   read path, and is served from the daemon's bounded negative cache for
   repeated foreign domains. This is the first datasource dependency on the
   `/v1/process` path; readiness and latency documentation must state it,
   and a datasource outage maps to `local_hop = temperror`, never to
   `not_local`.
4. **Outer signer alignment**: this is Section 12.1.2 item 1. The outer DSN
   signer's `d=` relaxed-matches the domain of at least one `rt=` path of
   the completion signature: the outer `d=` is equal to, or a parent domain
   of, that `rt=` domain, so a recipient domain may be signed by its
   organizational domain but not the reverse. Reading "aligned" as this
   directed relaxed domain match is a local interpretation.
5. **Recipient linkage**: at least one RFC 3464 recipient group whose
   `Final-Recipient` address, compared raw, or whose `Original-Recipient`
   address, compared after bounded xtext decoding, matches an authenticated
   completion-signature `rt=` path. Groups that do not link are ignored for
   every later decision. This extends the existing boolean linkage rule so
   that the group parser exposes per-group `Action`, `Status`, and
   `Original-Recipient` facts and the per-message `Original-Envelope-Id`.
6. **Failure class**: among the linked groups, the first in report order with
   `Action: failed` is the propagation group. If no linked group has
   `Action: failed`, the DSN reports a delay, a delivery, a relay, or an
   expansion, and Draft-06 Section 12 gives no reason to send a failure to the
   previous hop; the propagation projection is `not_failure`.
7. **Previous hop**: `i=k-1` is located and classified as defined above.

The result is one closed `delivery_status` projection:

| Member | Closed values |
| --- | --- |
| `structure` | `valid`, `malformed`, `limit_exceeded` |
| `embedded` | `verified`, `verified_headers_only`, `unverified`, `temperror`, `absent` |
| `local_hop` | `local`, `not_local`, `mismatch`, `temperror`, `not_evaluated` |
| `outer_alignment` | `aligned`, `misaligned`, `not_evaluated` |
| `recipient_linkage` | `linked`, `unlinked`, `not_evaluated` |
| `propagation` | `not_applicable`, `eligible`, `terminal_origin`, `not_failure`, `forbidden_null_previous_sender`, `unsupported_chain`, `not_reconstructable`, `not_evaluated` |

`propagation` is informational in `/v1/process`. It tells a policy consumer
whether the propagation adapter would be able to act. It is computed from the
same evidence without building anything, so `not_reconstructable` in
`/v1/process` reflects only the two conditions visible without a rebuild: a
previous hop `rt=` with more than one path, and an unsupported historical
hash tuple at or above the previous hop's instance. A headers-only embedded
original with a header recipe in the run is not one of them, because rebuild
step 5 degrades that case instead of failing it. The propagation route may
still return `not_reconstructable` after an attempted rebuild.

Temporary DNS or key failures map to `embedded = temperror`; a temporary
datasource failure maps to `local_hop = temperror`. Both carry the existing
temporary disposition and never degrade to a permanent state.
`not_evaluated` means only that an earlier stage stopped the evaluation or,
for `local_hop` and `propagation`, that no tenant was available; it never
carries a temporary meaning.

Run-member verification inside `/v1/process` needs no reconstruction: a
DKIM2-Signature covers only the Message-Instance and DKIM2-Signature fields
named by Section 9.6, which are present in the embedded original as is. It
adds bounded key fetches per run member under the existing signature-set
limit, deduplicated by the provider cache. A member is verified across all of
its supported signature sets with the same all-hop semantics as chain
verification: any permanent set failure rejects the member even if another
set passes.

### Policy mapping for received DSNs

Draft-06 Section 12.1.2 says a DSN that fails verification MUST NOT be
propagated and SHOULD be rejected with 550/5.7.x when verification happens
before acceptance. The local policy engine maps the projection as follows.
These rules are local policy, not draft text, except where noted. Rows are
evaluated top-down in stage order and the first matching row decides.

| Condition | strict | permissive | testing |
| --- | --- | --- | --- |
| Outer verification not `pass` | existing outer policy applies unchanged | | |
| `structure` not `valid` | `reject` | `continue` | `continue` |
| `embedded = unverified` | `reject` (draft SHOULD) | `continue` | `continue` |
| `embedded = absent` | `accept` | `accept` | `continue` |
| `embedded = temperror` or `local_hop = temperror` | `tempfail` | `tempfail` | `continue` |
| `local_hop = not_evaluated` because no tenant is available | `accept` | `accept` | `continue` |
| `local_hop = mismatch` or `outer_alignment = misaligned` | `reject` (draft SHOULD) | `continue` | `continue` |
| `local_hop = not_local` | `accept` | `accept` | `continue` |
| `recipient_linkage = unlinked` | `reject` | `continue` | `continue` |
| fully linked, any `propagation` value | `accept` | `accept` | `continue` |

An `accept` row never upgrades the outer verdict: it keeps whatever the
outer message verification and policy already decided, so in `testing` mode
the delivery-neutral `continue` remains the result. Reject, tempfail, and
continue rows replace the outer verdict. The received-DSN outcome is recorded
as a policy finding on the single `PolicyDecision`, which keeps one policy
authority and one action plan.

`local_hop = not_local` is accepted because a DSN in transit through a relay
is valid mail for that relay; the relay is not the party Section 12.1.2 speaks
to. Operators who do not relay may reject it with ordinary MTA policy.

The Authentication-Results reporting action stays exactly as it is. No DSN
fact is encoded into the `dkim2=` result string; consumers read the structured
projection. A follow-up contract in `milter-adapter.md` may add exactly one
RFC 8601 property under the registered `policy` ptype, `policy.dsn=<value>`,
whose closed values are drawn from the `local_hop`, `embedded`, and
`structure` vocabularies above; every value in those vocabularies is
therefore restricted to the RFC 8601 `pvalue` token syntax, in which `_` is
permitted, so that no renaming is needed later. This specification does not
extend the reporting action or the Milter validator.

### Rebuild (Section 12.1.1)

Rebuild is attempted only when the evaluation reached `propagation =
eligible`. It produces a new RFC 6522 report from the embedded original as
follows.

1. **Descend the local hop run.** Starting from the embedded original's
   proven current state, walk the Message-Instance chain downwards until the
   instance referenced by the previous hop `i=k-1` is reached, applying each
   authenticated recipe with the existing applier and re-proving every
   intermediate state against its Message-Instance hashes. The walk uses the
   existing history coordinator through a new internal seam that accepts an
   already-proven current state, so that a headers-only embedded original can
   enter the descent with `body = unavailable`. An unsupported historical hash
   tuple, a limit, a malformed recipe, an unavailable source, or a mismatch is
   `not_reconstructable`; unlike chain verification, the rebuild treats an
   unsupported tuple as failure because it cannot prove the state it would
   emit.
2. **Verify the previous hop.** The previous hop signature `i=k-1` must
   verify cryptographically over the reconstructed state at its instance,
   with the same custody and Section 9.6 rules the current-target verifier
   applies. The verifier's Section 8.4 timestamp window is evaluated with the
   completion signature's `t=`, the moment this system forwarded the message,
   as the reference time instead of the current time, and the previous hop's
   `t=` must not exceed the completion `t=`; a DSN that arrives long after
   the forwarding is still legitimate. This is a local interpretation and is
   recorded as such. The previous hop's public key is fetched at propagation
   time; a key that was rotated away or revoked since forwarding makes the
   DSN `not_reconstructable`, which is recorded as a known limit. The Section
   11.4 relaxed domain match between its `d=`
   and its `mf=` domain must pass. Its `mf=` must be non-null; a null `mf=`
   is `forbidden_null_previous_sender` and Draft-06 Section 12 forbids sending
   any DSN. This step is the only authority for calling the previous hop's
   `mf=` "authenticated". The current-target verifiers cannot do this; a new
   historical-target verification seam is required.
3. **Remove the local hop.** Remove exactly the DKIM2-Signature fields of the
   run and every Message-Instance numbered above the instance referenced by
   `i=k-1`, identified by field and tag value, not by position. All other
   DKIM2-Signature and Message-Instance fields are preserved byte-exact.
4. **Unsigned-field policy.** Header fields that are excluded from the header
   hash by Section 4 cannot be proven either way by the recipe. The rebuild
   removes every Section 4 hash-excluded field positioned above the previous
   hop signature `i=k-1` in the header block; DKIM2-Signature and
   Message-Instance fields are owned by step 3 and are not part of this
   rule. Every field above `i=k-1` was
   prepended by this system or by a later system, because each hop prepends
   its fields; every field below it was present when the previous hop signed.
   Every other unsigned field is preserved byte-exact. This is local policy;
   Section 12.1.1 speaks of "the state the message was in when it was
   forwarded", and fields above `i=k-1` describe our reception and the onward
   path, not that state, and would leak topology to the previous hop. The
   rule is fixed and not configurable: it is a privacy property of the
   reference implementation, not an operator preference, and the operator
   retains the original DSN in the MTA queue and the daemon's staged
   observations for diagnosis. A golden vector with interleaved
   hash-excluded fields above and below `i=k-1` pins the rule so that a
   later change to the Section 4 exclusion list breaks the vector visibly.
5. **Body degradation.** If the embedded original was complete and the body at
   the previous hop's instance is reconstructable, the new third part is
   `message/rfc822` with the reconstructed message. If the embedded original
   was headers-only, or any transition in the run carried a null or
   body-unavailable recipe, the new third part is `text/rfc822-headers` with
   the reconstructed header block. Draft-06 requires this degradation instead
   of failure. Header-only serialization needs a new writer; the recipe
   state's existing materialization is defined only for body-known states.
6. **Machine part.** Generate a fresh `message/delivery-status`:
   - per-message: `Reporting-MTA: dns; <reporting_mta>` from the propagation
     request context, and `Original-Envelope-Id` copied verbatim when the
     received report carries one and it is syntactically valid; RFC 3464
     says it SHOULD be supplied when an ENVID accompanied the message, and it
     belongs to the previous hop's envelope, not to the onward destination.
     `Arrival-Date` is omitted.
   - per-recipient: exactly one group with `Final-Recipient: rfc822;
     <address>` where the address is the previous hop's single `rt=` path
     written as an addr-spec without angle brackets, `Action: failed`, and
     `Status:` copied from the propagation group only when it is a
     syntactically valid `4.X.Y` or `5.X.Y` code, otherwise `5.0.0`. RFC
     3464 keeps `Action` and `Status` independent, and MTAs report an
     abandoned delivery after retries as `failed` with a `4.X.Y` code; that
     class information is preserved for the previous hop.
     `Original-Recipient` is the sender-supplied `ORCPT`, which this system
     does not have; it is emitted only when the propagation group carried an
     `Original-Recipient` whose decoded address equals that same `rt=` path,
     and then copied verbatim. The status code, the ENVID, and that
     conditional `Original-Recipient` are the only upstream-derived bytes in
     the report; Section 12.1.1 targets the human-readable reason, and the
     enhanced status class is needed by the previous hop for its own DSN.
   - no `Remote-MTA`, `Diagnostic-Code`, `Will-Retry-Until`, `Last-Attempt-Date`,
     or extension fields, because they describe the onward destination.
   If the previous hop's `rt=` contains more than one path, the rebuild fails
   and reports `not_reconstructable`; the internal typed error is
   `ambiguous_previous_recipient` and is not a separate wire value.
   Group-signed forwarding is not a case this specification qualifies.
7. **Human part.** A fixed English text produced by the library from one
   closed template that ships with the library and is not configurable. It
   states that a message forwarded by `<reporting_mta>` could not be
   delivered and that the original report was not forwarded. It contains no
   upstream text, address, host, queue identifier, or diagnostic. The part is
   `text/plain; charset=us-ascii` with `Content-Language: en`. The template
   is selected internally through a closed language key so that a later
   revision can add languages without changing the public facade; the first
   implementation registers only `en`. Operator-supplied text is not
   accepted because the part is signed and any free text is a channel for
   destination-specific information. This satisfies the Section 12.1.1
   requirement to remove destination-specific information.
8. **Outer message.** `From: Mail Delivery System <MAILER-DAEMON@<reporting_mta>>`,
   `To:` set to the previous hop's `mf=` addr-spec inside RFC 5322 angle
   brackets, a fixed `Subject`, `Date`
   equal to the signing timestamp, a fresh random `Message-ID` under
   `<reporting_mta>`, `Auto-Submitted: auto-replied`, which RFC 3834 Section
   5 permits for DSNs while forbidding `auto-generated`, and
   `MIME-Version: 1.0`. No `Received` header is generated; the MTA adds its
   own on submission.
9. **DKIM2 fields.** The new DSN carries exactly one Message-Instance `m=1`
   and exactly one DKIM2-Signature `i=1` with `mf=<>` and `rt=` equal to the
   previous hop's `mf=`. Draft-06 Section 12.1.1 requires the propagated DSN to
   be a new message with a single signature.

The rebuild is deterministic for a given input, timestamp, nonce, and
identifier, so it can be covered by golden vectors.

### Propagation signing authority

The rebuilt DSN's embedded highest signature belongs to the previous hop, not
to this system. The outgoing DSN signing authority, which derives the domain
from the embedded highest `d=`, therefore does not apply and must not be
reused. The propagation authority is:

- the signing domain is the canonical `d=` of the completion signature `i=n`
  of the removed local hop run, which was proven local by the datasource
  before evaluation and verified with `mf=` equal to the observed outer
  recipient;
- the new outer recipient is the previous hop's `mf=`, authenticated by the
  rebuild step 2 above, which must be non-null;
- the datasource profile is resolved for tenant and that domain with the
  existing `delivery_status` use. The profile identifies which key signs DSNs
  for that domain; the authority to propagate comes from evidence, the route
  purpose, and the route capability, not from a second profile use. A domain
  that is local but has no active `delivery_status` profile is a permanent
  `permerror` with disposition `discard`, so that an unprovisioned forwarding
  domain surfaces as a counted provisioning error rather than as misrouting
  or as a temporary failure;
- the route ticket purpose is `delivery_status_propagation`, disclosure
  `single`, class `external`, and the ticket is consumed by exactly one
  signing operation.

The library exposes this as a separate request type. A caller cannot pass a
domain, and the daemon cannot preselect one; both remain derived.

Provisioning consequence: every domain that signs as a Forwarder, whether
through the ordinary-transit or the next-domain profile, also needs an active
`delivery_status` profile, otherwise received DSNs for its forwarded mail are
classified `local` but cannot be signed and are discarded with a
`permerror`. The operator and datasource documentation must state this.

### Replay and duplicate handling

`/v1/dsn/propagate` derives a propagation replay coordinate from the outer
DSN's own signature and instance with the existing replay deriver. It shares
the epoch, secret, retention, and store with `/v1/process` but uses a
distinct domain-separation frame, `dkim2-replay-propagation-v1`, in the HMAC
input, so that the two operations keep independent state under storage keys
of the existing shape and the existing `/v1/process` identities are
unchanged. Without that separation a deployment whose inbound path already
ran `/v1/process` on the DSN, which is the ordinary case with an inbound
Milter or Rspamd, would see every propagation request as a replay and never
propagate.

The coordinate is committed in two phases, because the adapter can only
learn after the daemon call whether the re-injection listener accepted the
rebuilt DSN:

1. `/v1/dsn/propagate` reserves the coordinate with state `pending` and a
   lease if it is absent, rebuilds and signs, and returns the DSN together
   with an opaque `commit_token` bound to the coordinate. The lease length
   is the daemon configuration value `dsn_propagation.pending_lease`, default
   120 seconds, which must exceed the adapter's daemon timeout plus its
   re-injection and commit timeouts. If the coordinate is `pending` with a
   live lease, another attempt is in flight or has just failed, and the
   response is `temperror`/`tempfail` so that the MTA retries after its own
   retry interval; this closes the
   window in which N concurrent copies of one DSN could each obtain an
   `accept`. If the coordinate is `pending` with an expired lease, the
   previous attempt did not commit, and the request is served again with a
   fresh lease, a fresh rebuild, and a fresh token. If the coordinate is
   `committed`, the response is `pass`/`discard` and no rebuild happens.
2. `POST /v1/dsn/propagate/commit` with the same capability and the
   `commit_token` moves the coordinate from `pending` to `committed` by a
   compare-and-set on the stored value. The token binds to the coordinate,
   not to one token instance: any token issued for that coordinate within
   the ordinary retention commits it, so a token from a superseded attempt
   still commits correctly. The adapter calls commit after the re-injection
   listener's `250` and before it answers the LMTP transaction. A commit for
   an already committed coordinate answers `200`. A commit whose token is
   unknown, malformed, or belongs to an expired retention answers `409`, and
   the adapter then answers `451` so the MTA retries; a `200` for an
   unresolvable token would let the coordinate expire uncommitted and the
   DSN propagate again later.

A `pending` coordinate whose lease and retention have both expired is
treated as absent. The replay store contract gains, for propagation records
only, a closed stored value of either `pending:<lease-expiry>` or
`committed`, an insert-if-absent reservation, and a compare-and-set
transition from `pending` to `committed`; `/v1/process` records keep their
single first-seen `SET NX` semantics and value. An ambiguous store write
remains fail-closed and maps to `tempfail`.

This gate exists because a generic operator may route DSNs to the adapter
without any inbound pass in front of it, and because a captured genuine DSN
would otherwise let an attacker make this system emit unbounded signed DSNs
to the previous hop. The attacker cannot keep a coordinate `pending`: every
successful re-injection commits it, and an adversary who can make
re-injection fail already controls the local trust boundary.

The adapter therefore provides at-least-once semantics: it answers the LMTP
transaction with `250` only after the re-injection listener accepted the
rebuilt DSN and the commit succeeded. A crash between the listener's `250`
and the commit causes the MTA to retry, the coordinate is still `pending`,
and the previous hop may receive a second propagated DSN for the same outer
DSN. A crash after the commit and before the LMTP `250` causes a retry that
is answered `discard`. The specification states this explicitly; it does not
claim exactly-once. A commit failure after successful re-injection is
answered `451` so that the MTA retries into the same `pending` path.

### Propagation adapter contract

`cmd/dkim2-dsn-propagator` is an MTA-neutral adapter. The MTA routes mail
addressed to the local return-path addresses of forwarded messages to the
adapter's LMTP socket. How the MTA identifies those addresses is a deployment
choice: a reserved address class, a VERP-style local-part encoding, an SRS
scheme, or a per-user forwarding address all satisfy the contract as long as
the routing rule delivers exactly those addresses and only those to the socket.
The adapter:

1. speaks LMTP over a Unix socket: `LHLO`, `MAIL`, `RCPT`, `DATA`, `RSET`,
   `NOOP`, `QUIT`, `PIPELINING`, and `ENHANCEDSTATUSCODES`, the last two
   being RFC 2033 requirements; `HELO` and `EHLO` are answered `500`. After
   `DATA` it returns exactly one reply for the single accepted recipient.
   It advertises `SIZE` with the configured
   message limit, `8BITMIME`, and `SMTPUTF8`, because forwarded mail may be
   EAI mail and its DSN must be able to reach the socket; whether the `MAIL`
   command carried `SMTPUTF8` is recorded and passed to the daemon as
   `outer_smtp.smtputf8`. It
   does not advertise or accept `CHUNKING`, `STARTTLS`, `AUTH`, `XCLIENT`,
   `XFORWARD`, or `DSN`; an unadvertised command or parameter is answered
   `502` or `555`. One transaction is processed at a time per connection.
2. accepts exactly one transaction with `MAIL FROM:<>` and exactly one
   `RCPT TO`. A non-null sender is refused with `550 5.7.1` because the
   address class is reserved for DSNs. A second `RCPT TO` is refused with
   `452 4.5.3`, the RFC 5321 "too many recipients" reply that MTAs answer by
   deferring that recipient to a later transaction; this keeps one DSN per
   daemon request.
3. collects the DATA bytes under the configured limits with exact CRLF and
   dot-unstuffing, and identifies them as `lmtp_delivered_crlf` fidelity. The
   MTA has queued the message, so `Received` fields and MTA-side header
   rewriting may have altered unsigned parts; the outer verification decides
   whether the outer signature survived.
4. calls `POST /v1/dsn/propagate` with the raw bytes, the observed outer
   envelope, the tenant, and the configured `reporting_mta`.
5. on `accept`, opens one SMTP session to the configured re-injection
   endpoint, sends `MAIL FROM:<>`, with the `SMTPUTF8` parameter when the
   response carries `smtputf8_required`, `RCPT TO:<next_hop_recipient>`, and
   the returned message bytes. If `smtputf8_required` is set and the
   listener does not advertise `SMTPUTF8`, the adapter does not attempt
   delivery and answers `451 4.4.1`. After the listener's `250` it calls
   `/v1/dsn/propagate/commit` with the `commit_token`, and only then answers
   the LMTP transaction with `250`. On any re-injection or commit failure
   the LMTP reply is `451 4.4.1` so the MTA retries; the daemon serves the
   retry from the still `pending` coordinate with a fresh rebuild once the
   lease has expired, and answers a retry inside the lease with `tempfail`,
   which the adapter maps to `451` again.
6. on `discard`, answers `250` and does nothing further. RFC 2033 reads a
   positive completion reply as accepting delivery responsibility; the
   adapter accepts that responsibility and discharges it by a deliberate,
   counted, protocol-mandated non-delivery, which is not a frivolous loss.
   This is the disposition for every valid-but-not-propagable state: `terminal_origin`,
   `not_failure`, `forbidden_null_previous_sender`, `unsupported_chain`,
   `not_reconstructable`, and a replayed outer DSN. Each is counted under its
   own closed outcome so misrouting and unsupported chains stay visible.
7. on `reject`, answers `550 5.7.1` with a bounded constant text. This is the
   disposition for verification failures, the draft's SHOULD 550/5.7.x.
   Because the DSN has a null sender, an MTA cannot bounce it: Postfix
   discards it and optionally notifies postmaster under `notify_classes`,
   Exim freezes it until `ignore_bounce_errors_after`, and Sendmail delivers
   it to postmaster. An operator who prefers silence may set
   `permanent_failure_reply: discard`, which is the only policy knob of the
   adapter. It governs every daemon `reject`, that is verification failures
   and the misrouting case `not_local`; it never affects `discard`,
   `tempfail`, or `accept`.
8. on `tempfail` or any transport, validation, or capability error, answers
   `451 4.7.1`.

The adapter never parses DKIM2 fields, never rewrites the message, never
decides a target address itself, and never falls back to the outgoing DSN
signing route or to the originator route.

The re-injection endpoint must be a trusted listener that accepts null-sender
mail from the adapter and relays it outbound without any DKIM2 signing route
attached, and without routing the previous hop's address back to the adapter.
The endpoint is a canonical literal loopback `smtp://127.0.0.1:<port>` or,
with the same rules as the daemon's private-network listener, a TLS 1.3
private-network endpoint. Hostnames, proxies, redirects, and ambient
credentials are rejected. Loop protection is structural: every propagation
descends the chain to the previous hop and stops at `i=1`, at a null previous
sender, and at an unsupported chain; the replay gate bounds repetition; the
verifier's existing signature-count limits bound chain depth.

### Deployment prerequisites, MTA-neutral

- Forwarded mail must leave this system with a local `mf=` whose domain is a
  local authority domain, and that domain must hold a `delivery_status`
  profile. The transit signing path itself is a separate prerequisite
  documented in `signing-and-revision.md` and the Milter and Exim adapter
  specifications.
- The MTA routes mail for those `mf=` addresses, and only that mail, to the
  propagation adapter's LMTP socket with one recipient per transaction, and
  hands the recipient address to LMTP unrewritten, because the daemon
  compares it byte-wise against the signed `mf=` apart from domain case.
- The MTA provides a trusted, internal null-sender submission listener for
  re-injection with no DKIM2 signing route attached and, when the previous
  hop's address is non-ASCII, with `SMTPUTF8` support.
- The MTA's minimum retry interval for the LMTP transport must exceed
  `dsn_propagation.pending_lease`, otherwise a retry lands inside the lease
  and is deferred once more before it can be served.

The concrete Postfix configuration that satisfies these three requirements,
including the LMTP transport entry, the single-recipient limit, and the
dedicated loopback listener without Milters or content filter, lives in the
operator guide `docs/operator/postfix-compose.md` and is qualified in this
work. No Postfix patch is involved. The same guide states the three
requirements for other MTAs without Postfix parameter names.

## Package Boundaries

- `lib/internal/dsn`: gains the received-DSN evaluation stages that differ
  from the outgoing path (local authority classification hook, outer signer
  alignment, local-hop identity against an observed outer recipient, local
  hop run detection, failure-class selection), plus the deterministic RFC 6522
  report generator with closed templates. It keeps byte-preserving parsing and
  bounded immutable evidence.
- `lib/internal/verify`: gains one internal seam for the run descent that
  accepts an already-proven current state with a possibly unavailable body,
  and one historical-target verification seam that verifies a signature over
  a reconstructed state. Both reuse the history coordinator, applier, and
  current-target crypto; neither changes verification semantics for existing
  callers.
- `lib/internal/recipe`: unchanged in application and generation semantics.
  It gains an exported headers-only state constructor, because today only a
  body-known state can be built from outside the package, plus any read-only
  accessors the header-only serializer needs; the serializer itself lives in
  `lib/internal/dsn`.
- `lib/internal/routeplan` and `lib/internal/signing`: add the
  `delivery_status_propagation` route purpose and the propagation signing
  request whose authority is the completion signature's domain.
- `lib`: owns the public facades `Verifier.EvaluateReceivedDSN`,
  `Signer.RebuildDSNForPropagation`, and `Signer.SignPropagatedDSN`, the
  immutable `ReceivedDSNEvaluation`, `DSNPropagationEvidence`, and
  `PropagatedDSN` types, a narrow `LocalAuthority` interface that answers
  whether a domain is a local authority domain for the caller, and typed
  staged errors. No daemon, OpenAPI, LMTP, SMTP, Milter, or datasource
  implementation dependency.
- `cmd/dkim2d/internal/app`: owns received-DSN classification inside the
  process operation, the datasource-backed `LocalAuthority` implementation,
  policy projection, the propagation operation, replay gate, tenant and
  domain policy resolution with the `delivery_status` use, ticket handling,
  and observation events.
- `cmd/dkim2d/internal/httpjson`: owns generated DTO mapping, the distinct
  propagation capability route, request bounds, and the new fidelity value.
- `cmd/dkim2d/internal/config`: owns `server.dsn_propagate_capability` and its
  protected-file role.
- `cmd/dkim2-dsn-propagator`: new command module. Internal packages `lmtp`
  (bounded receiver), `reinject` (SMTP client), `daemon` (generated client
  wrapper, same confinement rules as the Milter), `config`, `securefile`,
  `observability`, and `app` (Fx composition). It depends on the generated
  client, Cobra, Viper, Fx, `slog`, Prometheus, and the standard library. It
  must not import `lib` protocol packages; it is transport glue.
- `cmd/dkim2ctl`: gains propagation fixtures and stable projections over the
  generated client only.
- `cmd/dkim2-milter`: the inbound response validator tolerates the optional
  `delivery_status` member; no behavior change.
- `contrib/rspamd`: publishes the projection as zero-score symbols. Forwarding
  the projection to an external policy service stays inside the module's
  existing optional policy block and is not part of this contract.

Generated REST DTOs stay at HTTP boundaries. Core DKIM2 packages must not
import generated OpenAPI types.

## API Shape

### `/v1/process`

`ProcessResponse` gains one optional member `delivery_status` with the closed
projection defined above. It is present only when the outer message has a
null reverse path, a `multipart/report` delivery-status top level, and at
least one DKIM2 field family, matching the Received DSN definition. Its
presence does not change the existing `verification`, `authentication`,
`replay`, or `actions` semantics. `policy` and `disposition` incorporate the
mapping table above.

`ProcessRequest` gains an optional `context.tenant`, because locality is
tenant-keyed and the process route carried no tenant so far. Precedence is:
the request member when present, otherwise the daemon configuration value
`process.default_tenant` when set, otherwise no tenant. Without a tenant the
`delivery_status` member is still emitted with `local_hop = not_evaluated`
and `propagation = not_evaluated`, and the policy table treats that as
`accept`, so an operator who never configured a tenant keeps today's
behavior. The inbound Milter has no tenant configuration and its request
stays unchanged; it relies on `process.default_tenant`. The optional
`contrib/rspamd` module may pass a configured tenant. Two tenants sharing
one daemon are isolated by
this key: a domain that is local for tenant A is `not_local` for tenant B.

### `POST /v1/dsn/propagate`

Security: new `dsnPropagateCapability` scheme, header
`X-DKIM2-DSN-Propagate-Capability`, backed by its own protected 32-byte file.
The DSN signing capability and the process capability are rejected on this
route, and the propagation capability is rejected on every other route.

`DSNPropagateRequest`:

- `api_version`, `draft`
- `message.raw_rfc5322_base64`: the received DSN bytes
- `message.fidelity`: `lmtp_delivered_crlf` or `raw_rfc5322`
- `outer_smtp`: `mail_from` must be `<>`, `rcpt_to` exactly one path,
  `smtputf8` boolean recording whether the LMTP `MAIL` command carried the
  parameter; this member exists only on this route's envelope schema
- `context.tenant`
- `context.reporting_mta`: canonical lowercase DNS name used only in the
  rebuilt report and outer `From:`

`DSNPropagateResponse`:

- `api_version`, `draft`
- `operation`: `delivery_status_propagation`
- `result`: `pass`, `fail`, `permerror`, `temperror`
- `disposition`: a distinct `PropagationDisposition` schema with `accept`,
  `reject`, `discard`, `tempfail`; the shared `Disposition` schema and its
  generated clients are unchanged
- `delivery_status`: the same closed projection as in `/v1/process`
- `replay`: the existing replay result shape
- `propagation_failure` present only with `permerror`: `not_reconstructable`
  or `unprovisioned_domain`
- `propagation` present only with `accept`: `next_hop_recipient` (exact
  SMTP forward path with angle brackets), `smtputf8_required` (true when
  the previous hop's `mf=` or the rebuilt message needs `SMTPUTF8`),
  `commit_token` (opaque, bounded, bound to the coordinate), and `raw_rfc5322_base64` of
  the complete signed DSN

`POST /v1/dsn/propagate/commit` takes `api_version`, `draft`, and
`commit_token` under the same capability and answers `200` with a bounded
`{state: committed}` body; it is idempotent.

The coherence rule of this operation is its own: `pass` permits `accept` or
`discard`, `permerror` requires `discard`, `fail` requires `reject`, and
`temperror` requires `tempfail`. It is defined per projection so adapters can
be tested against a closed matrix:

| Evaluation outcome | `result` | `disposition` |
| --- | --- | --- |
| outer verification `temperror` | `temperror` | `tempfail` |
| outer verification `fail` or `permerror`, or `structure` not `valid`, or `embedded = unverified`, or `embedded = absent`, or `local_hop = mismatch`, or `outer_alignment = misaligned`, or `recipient_linkage = unlinked` | `fail` | `reject` |
| `local_hop = not_local` | `fail` | `reject` |
| `embedded = temperror`, `local_hop = temperror`, replay store unavailable or ambiguous, datasource unavailable, key unavailable | `temperror` | `tempfail` |
| propagation coordinate `pending` with a live lease | `temperror` | `tempfail` |
| propagation coordinate `committed` | `pass` | `discard` |
| `terminal_origin`, `not_failure`, `forbidden_null_previous_sender`, `unsupported_chain` | `pass` | `discard` |
| `not_reconstructable` | `permerror` | `discard`, `propagation_failure = not_reconstructable` |
| `local` domain without an active `delivery_status` profile | `permerror` | `discard`, `propagation_failure = unprovisioned_domain` |
| malformed request, unsupported fidelity, capability mismatch, missing tenant | HTTP 4xx, no body semantics | |
| rebuilt and signed, coordinate absent or `pending` with an expired lease | `pass` | `accept` |

Rows are evaluated top-down and the first matching row decides. A missing
tenant is a request error on this route, unlike `/v1/process`, because
propagation without locality is meaningless.
`local_hop = not_local` is a `reject` on this route, unlike `/v1/process`,
because a DSN that is not ours has been routed to a socket reserved for our
own return-path addresses; that is misrouting and must surface. The adapter
maps it to `550` unless `permanent_failure_reply: discard` is set. Only `accept`
carries `propagation`. `discard` exists only in `PropagationDisposition` and
does not appear in `OperationResponse`.

### `MessageInput.fidelity`

Adds `lmtp_delivered_crlf`. Daemon admission treats it like
`milter_reconstructed_crlf` for the outer DSN: acceptable for verification and
propagation, not an evidence claim of unmodified raw bytes.

## Security And Privacy

- Every ambiguous structure, embedded state, identity, alignment, linkage,
  recipe, hash, historical signature, profile, key, ticket, replay, or
  capability state fails closed before any rebuild or private-key access. A
  rebuild never emits partial output.
- "Local" is decided by datasource authority over the domain, never by an
  address in `mf=`. A foreign signature that names a local address cannot
  become `local`, cannot link, and cannot reach the propagation signer.
- The received-DSN evaluation is read-only. It can never authorize signing,
  and its projection is never an input to any signing route. The propagation
  route re-runs the evaluation on its own input rather than trusting a prior
  `/v1/process` result.
- The propagation signing domain is derived from a verified, datasource-local,
  removed completion signature only. No request field, adapter configuration,
  tenant default, suffix, alias, or wildcard can select it.
- The previous hop's `mf=` becomes a DSN recipient only after its signature
  verified over the reconstructed state and its `d=` relaxed-matches its
  `mf=` domain. This prevents a hostile upstream from planting an arbitrary
  victim address in `mf=` and having this system sign a DSN to it. The
  adapter cannot override, add, or expand the recipient. A null previous
  sender ends propagation.
- Replay of the outer DSN is bounded by the two-phase propagation coordinate:
  at most one propagated DSN per commit, at most one attempt in flight per
  lease, and duplicates are confined to the crash window between the
  re-injection listener's `250` and the commit and to a lease that expired
  while an attempt was still running. A captured DSN yields no further
  output once its coordinate is committed.
- The rebuilt report carries no upstream diagnostic, remote MTA, queue
  identifier, or free text. Only the enhanced status code and the ENVID
  survive, and only when syntactically valid.
- Raw DSN bytes, embedded messages, addresses, message identifiers,
  signatures, capabilities, keys, and provider data never enter errors, logs,
  traces, metrics, REST error bodies, CLI output, or test diagnostics. The
  propagation response body carries message bytes by design and is confined to
  the loopback or private TLS listener like every other daemon response.
- Size amplification is bounded: the rebuilt DSN is never larger than the
  received one plus the fixed report parts, and headers-only degradation only
  shrinks it.
- The adapter's LMTP socket follows the Milter socket ownership, mode, link,
  and ancestry rules. Its capability file follows the protected-file rules.
  Its re-injection endpoint is validated like the daemon endpoint.
- Abuse limits: outer DSN size, embedded size, MIME depth, part count,
  delivery-status field caps, recipe and history cumulative limits, signature
  count, and one LMTP transaction per connection at a time with a bounded
  connection count.
- Fail-open does not exist for the propagation adapter. The only configurable
  policy is whether a daemon `reject`, that is a verification failure or the
  misrouting case `not_local`, is answered `550` or `250`.

## Observability

Daemon:

- `dsn.received.completed` log event and `dkim2d_dsn_received_total` counter
  with closed labels `stage` (`structure`, `embedded_verification`,
  `local_hop`, `outer_alignment`, `recipient_linkage`, `failure_class`,
  `previous_hop`, `completed`) and `result` (`ok`, `permanent`, `temporary`).
- `dsn.propagation.completed` log event and
  `dkim2d_dsn_propagation_total` counter with closed labels `stage`
  (`evaluation`, `replay`, `rebuild`, `previous_hop_verification`,
  `signing_domain`, `policy`, `signing`, `completed`) and `result` (`accept`,
  `reject`, `discard`, `tempfail`).
- Existing operation latency and error metrics gain the
  `delivery_status_propagation` operation value.

Adapter:

- `dsn_propagator_transactions_total{outcome}` with `outcome` in `accepted`,
  `rejected`, `discarded_terminal_origin`, `discarded_not_failure`,
  `discarded_null_previous_sender`, `discarded_unsupported_chain`,
  `discarded_not_reconstructable`, `discarded_unprovisioned_domain`,
  `discarded_committed`, `deferred`, `contract_failure`.
- `dsn_propagator_reinjection_total{outcome}` with `outcome` in `accepted`,
  `deferred`, `failed`, `smtputf8_unavailable`.
- `dsn_propagator_commit_total{outcome}` with `outcome` in `committed`,
  `deferred`.
- Bounded structured logs with the same closed values and no address, host,
  queue identifier, or message content.

No label may contain a domain, address, tenant value, selector, message
identifier, `i=` value, or raw error.

## Required Tests

Unit tests, library:

- received-DSN evaluation: every stage positive and negative, complete and
  headers-only embedded originals, `not_local` with a foreign domain,
  `mismatch` with a local domain and wrong `mf=`, foreign signature naming a
  local address in `mf=`, `misaligned`, `unlinked`, unlinked group with a
  different status than the linked group, `Action: delayed` and
  `Action: delivered` reports, temporary key and datasource failure,
  cancellation, limits, immutability, and redaction;
- local hop run detection: single completion signature, completion preceded
  by one and by several `nd=` members, an imaginary-hop pair, a previous hop
  that is itself an `nd=` signature (`unsupported_chain`), a run member
  whose signature does not verify (`unsupported_chain`), `k = 1`
  (`terminal_origin`), and an `nd=` member whose `d=` is not local (run
  ends early);
- rebuild: run of one and of several signatures, transitions with header
  recipe, body recipe, null recipe degradation to `text/rfc822-headers`,
  headers-only input, unsupported historical hash tuple as failure,
  hash mismatch during re-proof, history limit exhaustion, previous hop
  signature failing verification, previous hop `d=`/`mf=` domain mismatch,
  null previous sender, multi-path previous `rt=`, unsigned-field removal
  policy with interleaved excluded fields, `4.X.Y` and `5.X.Y` status
  preserved and invalid status code fallback to `5.0.0`, ENVID copy and
  invalid ENVID drop, conditional `Original-Recipient` copy,
  and byte-exact golden vectors under
  `lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/`;
- report generation: closed template output, absence of every forbidden field,
  presence of every RFC 3464 required field, deterministic bytes, CRLF
  discipline, and a test proving the status code and ENVID are the only
  upstream-derived bytes;
- propagation signing: authority derived from the completion signature,
  rejection of caller domains, single Message-Instance and single signature
  invariant, `mf=<>`, `rt=` equal to previous `mf=`, ticket consumption, and a
  round-trip proof that the produced DSN verifies with the generic verifier
  and evaluates as `local_hop = local` at the previous hop's simulated view
  with the previous hop as local authority;
- fuzz seeds for the received-DSN parser path and the rebuild input;
- race and privacy coverage in the existing patterns.

Unit tests, daemon:

- `/v1/process` classification: null sender plus signed delivery-status
  report yields the member; non-null sender, non-report, or input without
  any DKIM2 field family does not; `embedded = absent` for a signed report
  around an unsigned original; tenant precedence between request member,
  `process.default_tenant`, and none; two tenants on one daemon see the same
  domain as `local` and `not_local` respectively;
- policy table in strict, permissive, and testing modes;
- propagation route: capability isolation in both directions, request bounds,
  fidelity admission, the full coherence matrix, two-phase replay: a
  preceding `/v1/process` call on the same DSN does not block the first
  propagation, a second request while `pending` is served with a fresh
  rebuild only after the lease expired and `tempfail` while the lease is
  live, concurrent requests for one DSN yield exactly one `accept`, a
  request after commit is `discard`, commit with a superseded token still
  commits, commit with an unknown token is `409`, commit of a committed
  coordinate is `200`, an expired `pending` past retention is absent,
  `smtputf8_required` for a non-ASCII previous
  hop address, `not_local` as
  `reject`, local domain without `delivery_status` profile as
  `permerror`/`discard`, datasource outage on `/v1/process` as
  `local_hop = temperror`, spies proving invalid input never reaches the
  signer, and generated contract parity.

Adapter tests:

- LMTP state machine with hostile peers, pipelining, `RSET`, unadvertised
  `BDAT`, oversized DATA against `SIZE`, non-null sender, second recipient,
  and connection limits;
- fail-closed matrix for every daemon outcome and transport error, including
  `permanent_failure_reply: discard`;
- re-injection client with refused, deferred, and mid-DATA failures, proving
  the LMTP reply is `451` and nothing is acknowledged before the re-injection
  `250`;
- protected-file, socket, endpoint, and config validation parity with the
  Milter;
- an in-process integration test running the generated test server, the
  adapter, and a fake re-injection listener end to end.

Integration and E2E tests:

- `dkim2ctl` positive and negative propagation fixtures over the generated
  client with the distinct capability;
- Milter inbound response tolerance with and without the new member;
- `contrib/rspamd` unit tests for the new symbols;
- opt-in real Postfix qualification: a forwarded message signed by the transit
  route, a foreign DSN generated by the qualification harness, routing to the
  adapter, re-injection, and verification of the propagated DSN at a simulated
  previous hop. Negative cases are a spoofed DSN, a DSN for a message this
  system did not sign, a foreign signature naming a local address, a null
  previous sender, a replayed DSN, and a re-injection outage.

Generated and documentation checks:

- OpenAPI generation and stale-output checks for server, Milter client, Exim
  client, propagator client, and `dkim2ctl`;
- workspace sync, Makefile product-module list, golangci, and CI include the
  new module;
- conformance manifest update for the new vectors;
- operator, architecture, reference, and README checks.

Final gate:

- `make guardrails`
- `git diff --check`
- the opt-in Postfix qualification with its recorded evidence

## Acceptance Criteria

- A DKIM2-signed inbound DSN produces a closed `delivery_status` projection
  from `/v1/process` and is policed per the mapping table; unsigned or
  non-report messages are unaffected.
- A signature under a domain the tenant does not control can never be
  classified `local`, regardless of its `mf=`.
- No received-DSN fact can authorize any signing operation.
- The propagation route produces a Draft-06 Section 12.1.1 conformant DSN
  whose signing domain is provably the removed completion signature's domain,
  whose recipient is provably the cryptographically verified previous hop's
  `mf=`, whose local hop run is removed completely across `nd=` and imaginary
  hops, and whose report contains no destination-specific data beyond the
  status code and ENVID.
- A null previous sender, a terminal origin, a non-failure report, an
  unsupported chain, an unverifiable DSN, a replayed DSN, and a
  non-reconstructable state never produce output.
- The adapter acknowledges to the MTA only after successful re-injection and
  commit, never falls back to another route, and exposes at-least-once
  semantics bounded by the two-phase replay gate; a failed re-injection is
  retried by the MTA and never silently discarded.
- All REST changes originate in OpenAPI; generated artifacts and fixtures are
  current; the inbound Milter and Rspamd validators accept the new member.
- Postfix qualification passes without any Postfix patch; the operator guide
  documents the routing rule, LMTP transport, and the Milter-free re-injection
  listener for Postfix and states the same requirements generically.
- `docs/reference/known-limitations.md` no longer lists received-DSN
  processing and propagation as deferred; it lists `unsupported_chain` and
  the previous-hop key-rotation limit as known limits; Exim status is
  unchanged.

## Completion Evidence

Fill this after implementation:

- Focused tests:
- Generated checks:
- Guardrails:
- Postfix qualification:
- `git status --short`:
- Skipped checks:

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Scope | Received-DSN evaluation, rebuild, propagation route, adapter, projections, docs | | | |
| Behavior | Draft-06 Sections 8.7, 9.3, 11.4, 12, 12.1.1, 12.1.2 and RFC 6522/3464/3834/2033 semantics are explicit and tested | | | |
| Security | Datasource-defined locality, read-only evaluation, verified previous hop, replay gate, fail-closed rebuild, no destination leakage, secret-safe diagnostics | | | |
| Boundaries | Library, daemon, generated client, adapter, Milter, Rspamd stay purpose-separated | | | |
| Tests | Unit, golden, fuzz, race, privacy, daemon, adapter, client, and real-MTA evidence exist | | | |
| Documentation | Architecture, operator, reference, provisioning, and limitation documents agree | | | |
| Effort | Prompt timings are measured and recorded | | | |

## Decisions And Open Questions

- Settled: "local" means datasource authority over the signing domain. An
  `mf=` value is evidence of routing, never of identity.
- Settled: the local hop is a run, not a single signature, because this
  product itself emits `nd=` and imaginary-hop chains and Section 12.1.1
  requires every added signature to be removed.
- Settled: a previous hop that is an `nd=` signature is out of scope
  (`unsupported_chain`) rather than approximated.
- Settled: only `Action: failed` reports propagate. Delay, delivery, relay,
  and expansion reports are `not_failure` and discarded; propagating them
  would fabricate a failure the downstream MTA never issued.
- Settled: the previous hop signature is verified over the reconstructed
  state before its `mf=` may become a recipient. Hash re-proof alone is not
  authentication of `mf=`. Its timestamp window is evaluated at the
  forwarding moment, the completion signature's `t=`, as a local
  interpretation.
- Settled: locality means any active signing profile use for the domain;
  the `delivery_status` profile decides only whether the local domain can
  sign the propagated DSN. Imaginary-hop members are absorbed into the local
  hop run by the same-tenant rule, which also absorbs a genuine same-tenant
  hop by design.
- Settled: the propagation replay coordinate is operation-scoped so that an
  inbound `/v1/process` pass never blocks the first propagation of the same
  DSN.
- Settled: received-DSN evaluation lives inside `/v1/process` as an
  additional read-only projection rather than a separate route, because every
  inbound consumer already calls `/v1/process` and cannot classify DSNs
  reliably on its own.
- Settled: propagation is a separate route with a separate capability,
  replay gate, and response type. Its authority model differs from outgoing
  DSN signing and must not be reachable through the DSN signing capability.
- Settled: the datasource `delivery_status` profile use is reused for
  propagation signing. The profile identifies the key that signs DSNs for a
  domain; purpose separation is enforced by evidence, route purpose, and
  capability. Adding a fifth profile use would force LDAP and SQL schema
  changes without adding a security property. Transit domains must be
  provisioned with that profile.
- Settled: the adapter speaks LMTP to the MTA and SMTP to the re-injection
  listener. LMTP gives exact bytes, per-recipient status, and is supported by
  Postfix, Exim, and Sendmail without patches. A `pipe(8)` mode is not offered.
- Settled: valid-but-not-propagable states are discarded with a `250` and a
  closed counter, because a `5xx` on a null-sender delivery has MTA-specific
  side effects. Verification failures default to `550` per the draft, with an
  operator opt-out.
- Settled: `Original-Envelope-Id` and `Original-Recipient` are carried
  because they belong to the previous hop's envelope; `Remote-MTA`,
  `Diagnostic-Code`, and free text are removed because they describe the
  onward destination.
- Settled: `Auto-Submitted: auto-replied`. RFC 3834 Section 5 was checked on
  2026-09-04: `auto-generated` MUST NOT label a DSN, `auto-replied` MAY.
- Settled: `Status` is copied for both `4.X.Y` and `5.X.Y` codes because RFC
  3464 keeps `Action` and `Status` independent and abandoned deliveries are
  commonly reported as `failed` with a `4.X.Y` code.
- Settled: the RFC 3464, RFC 3834, and RFC 2033 facts this contract relies on
  were confirmed against the RFC text and are listed under Source Documents;
  no confirmation task remains for the first slice.
- Settled: no Postfix patch is required. The existing `{postfix_dsn_origin}`
  enum remains the authority for locally generated bounces only.
- Settled: the human-readable part is one fixed English template that ships
  with the library, marked `Content-Language: en`, with an internal closed
  language key so that additional languages can be added later without an
  API change. Operator templates are rejected because the part is signed and
  free text is a leak channel for destination-specific information.
- Settled: the received-DSN projection stays JSON-only in this contract. A
  separate follow-up to `milter-adapter.md` may add exactly one
  `Authentication-Results` property `policy.dsn=<value>` under the
  registered `policy` ptype with a closed vocabulary; the projection
  vocabularies are already constrained to RFC 8601 token syntax for that
  purpose. Consumers without daemon access see no DSN fact until that
  follow-up exists.
- Settled: the propagation replay coordinate is committed in two phases,
  reserve with a lease on `/v1/dsn/propagate` and commit on
  `/v1/dsn/propagate/commit` after the re-injection listener's `250`. A
  single-phase gate would turn every failed re-injection into a silent
  discard on retry; a lease-less reservation would let concurrent copies
  each obtain an `accept`. Commit binds to the coordinate and fails closed
  with `409` for an unresolvable token.
- Settled: `/v1/process` gains an optional `context.tenant` with a daemon
  default `process.default_tenant`; without any tenant the DSN member is
  emitted with `not_evaluated` locality and accepted, so unconfigured
  operators keep today's behavior.
- Settled: `SMTPUTF8` is carried explicitly on the propagation envelope and
  in the response, and the adapter fails closed with `451` when the
  re-injection listener cannot take an `SMTPUTF8` message it needs to send.
- Settled: every local hop run member must verify; a non-verifying member is
  `unsupported_chain`. The highest-only embedded verification in the
  evaluation is a recorded interpretation of Section 12.1.
- Settled: `PropagationDisposition` is a distinct schema so that the shared
  `Disposition` enum and every generated client remain unchanged.
- Settled: the unsigned-field removal rule in rebuild step 4 is fixed and not
  configurable. Every hash-excluded field above the previous hop signature is
  removed; a golden vector pins the rule.
