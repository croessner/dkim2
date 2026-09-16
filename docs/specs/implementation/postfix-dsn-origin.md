# Postfix DSN Origin for the Milter Adapter

Status: active upstream Postfix adapter contract, migrated 2026-09-16.
This is not a DKIM2 wire-protocol extension. The DKIM2 baseline is Draft-06.

## Authority and scope

Wietse Venema introduced `{postfix_internal_origin}` in upstream
`postfix-3.12-20260915`. Unmodified Postfix 3.11.7 does not have this feature.
A qualified backport of the final upstream implementation to 3.11.7 is
supported; the old downstream DSN interface and compatibility fallback are not.

| Upstream value | Adapter behavior |
| --- | --- |
| `bounce` | Candidate for DSN signing only with null outer sender and exactly one recipient; embedded evidence remains mandatory. |
| `notify` | SMTP transcript; leave unchanged. |
| `verify` | Address verification probe; leave unchanged. |
| Empty or absent | No signing authority; leave unchanged. |

Upstream `bounce` includes double bounces and postmaster copies. These have
non-null senders and are outside the dedicated DSN signing route, so they pass
unchanged. No original queue ID, envelope, recipient list, action, status, or
message copy crosses the macro boundary.

## Authorization contract

The `postfix_dsn` adapter requests `{postfix_internal_origin}` for `SMFIM_EOH`
using standard `SMFIR_SETSYMLIST`. Identical header-stage replays are accepted;
the transaction must receive the origin again at EOH. Postfix also sends this
macro at CONNECT by default: the adapter validates it but never retains it as
proof for a later transaction. Operators overriding `milter_connect_macros`
should preserve the upstream macro in that list.

Unknown enum values, duplicate members, conflicting transaction replays, wrong
callback stages, and multiple recipients on a null-sender bounce fail closed.
A null sender alone never authorizes signing. Aborted or completed transactions
clear their evidence; no connection-level fallback or legacy macro is used.

## Migration

Upgrade Postfix, the Milter adapter, and deployment documentation together.
An old Postfix with this adapter cannot authorize local DSN signing. Drain or
stop the DSN route during migration, qualify an actual local bounce and an
externally injected null-sender negative case, then reopen it. Roll back the
complete digest-pinned set if qualification fails. Do not backport or translate
the retired downstream interface.

Upstream references: [announcement](https://www.mail-archive.com/postfix-devel@postfix.org/msg01355.html)
and the snapshot's `MILTER_README` provenance section.

## DKIM2 evidence boundary

Postfix provenance proves only that the local MTA generated the outer bounce.
The library still parses the exact three-part RFC 6522 report and verifies the
relevant embedded DKIM2 signatures and Message-Instance evidence required by
Draft-06 Section 12.1. For a complete embedded message it verifies header and
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
attests that the Postfix-only adapter established exact `bounce` provenance;
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
