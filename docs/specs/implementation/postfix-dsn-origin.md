# Postfix DSN Origin for the Milter Adapter

> Historical Draft-04 implementation record. The original scope and evidence
> below are preserved; current Draft-05 authority is the migration disposition
> and the 2026-08-26 semantics audit.

Status: implementation baseline. This document defines a local Postfix-to-
DKIM2 adapter contract; it is not a DKIM2 wire-protocol extension.

## Authority and scope

The active baseline is `draft-ietf-dkim-dkim2-spec-04`, Section 12. Postfix
provides one provenance fact through normal negotiated Milter macros:

| Macro | Values | Meaning |
| --- | --- | --- |
| `{postfix_dsn_origin}` | `internal`, `external` | Whether bounce(8) generated the current message. |

The internal Postfix representation is a boolean asserted only by bounce(8).
The Milter-facing value is the closed enum above. No original queue ID,
envelope, recipient list, action, status, or message copy crosses this boundary.

## Authorization contract

The `postfix_dsn` adapter requests `{postfix_dsn_origin}` for `SMFIM_EOH` with
the standard `SMFIR_SETSYMLIST` mechanism. Only exact `internal`, confirmed at
EOH for a transaction whose outer reverse path is `<>` and which has exactly
one outer recipient, authorizes the dedicated `/v1/dsn/sign` call.

`external` and an absent macro are not applicable and continue without daemon
I/O or mutation; `external` does not impose bounce envelope shape on ordinary
mail sharing the Milter chain. A malformed enum, duplicate member in one callback,
conflicting callback replay, wrong callback stage, or invalid outer shape is an
adapter contract failure. None can fall back to originator signing. A null
sender alone is never authority.

## DKIM2 evidence boundary

Postfix provenance proves only that the local MTA generated the outer bounce.
The library still parses the exact three-part RFC 3462 report and verifies the
relevant embedded DKIM2 signatures and Message-Instance evidence required by
Draft-04 Section 12.1. For a complete embedded message it verifies header and
body hashes; for `text/rfc822-headers` it uses the restricted header-only path.
Signature cryptography, timestamps, custody structure, and authenticated
`d=`, `mf=`, and `rt=` values remain mandatory.

The embedded object has no independently observed current SMTP envelope at
bounce time. The dedicated verifier therefore records current-envelope matching
as not applicable instead of copying authenticated `mf=` and `rt=` claims into
an alleged observed envelope. The outer DSN recipient must still equal the
authenticated highest embedded `mf=` exactly. The daemon derives the delivery-
status signing domain from the canonical authenticated highest embedded `d=`
only after verification, and at least
one RFC 3464 `Original-Recipient` or `Final-Recipient` field must match an
authenticated highest embedded `rt=`, before policy or private-key access.
The generic library RFC 3464 parser rejects folded delivery-status fields and
enforces the normative per-message and per-recipient field order, uniqueness,
and extension-field tail. The Postfix-exclusive daemon route first uses
that strict path and then admits only the current wire form emitted by
`bounce_notify_util.c`: `Reporting-MTA` precedes optional
`Original-Envelope-Id`, matching `X-<mail-name>-Queue-ID`/optional `Sender`
extensions precede optional `Arrival-Date`, and `Final-Recipient` precedes
optional `Original-Recipient`. Only Postfix's wrapped `Remote-MTA` and
`Diagnostic-Code` fields are unfolded. Unknown extensions, arbitrary
reordering, duplicate fields, wrong-group fields, and other folding still fail
closed. The daemon selects this parser only after authenticating the dedicated,
non-reusable DSN route capability. Possession of that capability explicitly
attests that the Postfix-only adapter established exact `internal` provenance;
the request schema contains neither fidelity nor a compatibility switch. Public library
integrations must satisfy the same provenance precondition before selecting
the explicitly named Postfix evidence constructor. It decodes bounded RFC 3461 xtext only for the
ORCPT-derived `Original-Recipient`; `Final-Recipient` remains the raw exact
generic-address. Raw or decoded control characters and malformed mailbox
results fail closed, while valid quoted local-parts remain eligible for exact
canonical comparison.
Delivery-status interpretation is additionally capped at 256 KiB, 4096 bytes
per unfolded line, 256 recipient groups, 64 fields per group, and 2048 fields
overall. The generic RFC path accepts extension fields only in the normative
extension tail; the Postfix bounce wire profile accepts only its two matching
`X-<mail-name>-*` fields in the exact positions above.

The OpenAPI DSN request consequently contains the outer message, outer SMTP
envelope, and a tenant-only delivery-status context. It has no caller-selected
domain or `original_smtp` member.

## Configuration and deployment

`postfix_dsn` requires `failure.mode: tempfail`, a dedicated DSN capability,
one tenant, and `signing.domain_source: verified_embedded`; `signing.domain`
must be absent. `envelope_sender` is not valid for this mode because Postfix
does not export the original envelope. Originator mode retains its independent
envelope-sender option.

Qualification requires a real bounce(8) positive case and an externally
injected null-sender negative case. Rollback removes only the DSN Milter from
the non-SMTP chain; ordinary delivery and other signers remain unchanged.
