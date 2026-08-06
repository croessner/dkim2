# Postfix DSN Evidence for the Milter Adapter

Status: implementation baseline. This document defines a local Postfix-to-
DKIM2 adapter contract; it is not a DKIM2 wire-protocol extension.

## Authority and Scope

The active DKIM2 baseline is `draft-ietf-dkim-dkim2-spec-04`, Section 12. A
locally generated DSN has a null SMTP reverse path and must itself carry
DKIM2 fields. The existing daemon route `POST /v1/dsn/sign` already validates
the RFC 3462 structure, the embedded original, and the DKIM2 DSN rules. It
deliberately rejects Milter-reconstructed input because a generic Milter cannot
prove that a null sender is a Postfix-generated DSN.

This follow-on closes precisely that Postfix-specific provenance gap. It does
not add a configurable trust exception for `localhost`, a socket path, HELO,
Milter client address, `MAIL FROM: <>`, a header, or a configured DSN domain.
Those facts are insufficient and remain insufficient.

## Required Trust Boundary

The only admissible Milter DSN path is:

```text
bounce(8) -> private/dsn_cleanup -> cleanup(8) -> Milter callbacks
          mail_owner-only channel    non-persistent evidence
                                      -> dkim2-milter dedicated DSN capability
                                      -> dkim2d /v1/dsn/sign
```

The Milter accepts the path only when every condition below holds:

1. `bounce(8)` posts the DSN through a dedicated cleanup service in Postfix's
   `private` directory. That directory is owned by `mail_owner` with mode
   `0700`; the ordinary `public/cleanup` socket is not an evidence channel.
2. `cleanup(8)` accepts the evidence records only when invoked for that private
   service and removes them before writing the new queue file.
3. The marker and exact original-envelope record are emitted only as requested
   EOH Milter macros.
4. The Milter receives exactly one complete evidence record immediately before
   EOH, retains it through the body, and decides only at EOM with a null outer
   reverse path and exactly one outer recipient.
5. The Milter uses its separate delivery-status capability on the existing
   delivery-status route. It cannot use the originator capability.
6. The daemon parses and validates the DSN bytes and embedded DKIM2 evidence
   before any policy or private-key access.

If evidence is absent, malformed, duplicated, oversized, unexpected, or from
any other Milter stage, the DSN path is not applicable. It must never fall back
to originator signing.

## Postfix Macro Contract: `postfix-dsn-evidence-v1`

The Milter requests these names at `SMFIM_EOH` with the existing standard
`SMFIR_SETSYMLIST` / `SMFIF_SETSYMLIST` negotiation mechanism:

| Macro | Value | Meaning |
| --- | --- | --- |
| `{postfix_dsn_evidence}` | `postfix-dsn-evidence-v1` | Fixed, exact provenance/version marker. |
| `{postfix_dsn_original_queue_id}` | Postfix queue ID | Original message identity; never logged or exported. |
| `{postfix_dsn_original_envelope}` | unpadded base64url | Exact original SMTP envelope record below. |

The envelope record is a NUL-free transport value after base64url encoding. Its
decoded bytes are:

```text
u8 version (= 1)
u16 sender_length, sender_octets
u16 recipient_count
recipient_count * (u16 recipient_length, recipient_octets)
```

All integer fields are unsigned big-endian. The sender and recipients are the
exact address octets in Postfix's queue records, which omit RFC 5321 path
brackets. The adapter restores exactly one surrounding `<...>` pair and then
applies its strict SMTP-path parser; it performs no other normalization. The
record has no optional fields, padding, duplicate-value rule, action/status
claim, or fallback representation. The DKIM2 daemon parses
the outer DSN's `message/delivery-status` part for per-recipient action and
status; encoding those potentially repeated records in Milter macros would be
lossy and is explicitly forbidden.

The v1 limits are 256 recipients, 254 octets per queue address, and 47 KiB decoded
record size. This leaves room for the Milter macro name and framing below the
standard 65535-octet payload limit. A Postfix DSN above a limit does not emit a
partial record.

## Postfix Changes

The upstream patch must be small and self-contained. A caller-provided cleanup
flag on `public/cleanup` is explicitly insufficient: Postfix creates public
listener endpoints for general submission, and `cleanup_service()` otherwise
accepts the caller's `MAIL_ATTR_FLAGS` value without peer-origin evidence.

1. `conf/master.cf`: add a narrowly named private `dsn_cleanup` service that
   runs the existing `cleanup(8)` command. The existing public `cleanup`
   service and its callers remain unchanged.
2. `src/cleanup/cleanup.c`: retain whether the request arrived through
   `dsn_cleanup` and pass that authority into per-message cleanup state.
3. `src/cleanup/cleanup.h` and `cleanup_state.c`: retain private-service
   authority and transient evidence in per-message cleanup state, and free it
   with that state. No caller-provided cleanup flag represents authority.
4. `src/global/post_mail.[ch]`: add a narrow DSN posting helper that connects
   to `private/dsn_cleanup` and writes the original queue ID and envelope
   evidence before `REC_TYPE_MESG`; ordinary `post_mail_fopen*()` calls cannot
   select this path or set its authority.
5. `src/global/mail_proto.h`: define names for the initial internal evidence
   attributes. These records are an internal handoff, not queue metadata.
6. `src/bounce/bounce_notify_util.[ch]`: retain the exact unquoted original
   sender and all original recipient queue records needed to encode the
   envelope. Do not derive evidence from rendered DSN text or quoted headers.
7. `src/bounce/bounce_notify_service.c`, `bounce_warn_service.c`,
   `bounce_one_service.c`, and `bounce_notify_verp.c`: use the DSN helper only
   for the actual null-sender DSN path. Postmaster notices, double bounces, and
   trace notifications keep the ordinary posting path.
8. `src/cleanup/cleanup_envelope.c`: accept and validate the attributes only
   while private-service authority is present and before `REC_TYPE_MESG`;
   retain them in cleanup state and never call `cleanup_out()` for them.
9. `src/cleanup/cleanup_milter.c`: expose the three macro values only for an
   evidence-bearing transaction and only through the EOH macro list. Existing
   macro names and callbacks remain unchanged.

The patch must not introduce a new Milter protocol version or command. It
extends only Postfix's macro value provider, using a standardized opt-in macro
mechanism that older Milters ignore.

## DKIM2 Changes

`cmd/dkim2-milter` gains a dedicated `postfix_dsn` mode. It requests and
retains only the three macro values above, only for the EOH callback that
belongs to the active message, and consumes them only at EOM. The mode rejects every duplicate, partial,
wrong-stage, or malformed record. It maps the outer callbacks and decoded
original envelope to the generated `DSNSignRequest` and sends them with a
dedicated capability. In multi-domain mode it derives the candidate signing
domain only from the trusted original reverse-path; the daemon must still bind
that candidate to the embedded original's verified highest `d=` before policy
or private-key access.

`cmd/dkim2d` gains one explicitly local fidelity value,
`postfix_dsn_milter_reconstructed_crlf`. It is accepted solely by the
delivery-status operation together with the Postfix evidence shape, never by
generic sign, revise, process, or public fixture routes. This acknowledges the
actual cleanup-to-Milter message representation without relabeling it as
original received wire bytes.

The existing `delivery_status` policy use, private-key isolation, DSN parser,
and action-plan handling stay authoritative. No signing-domain fallback is
added.

## Failure and Deployment Policy

Before the Postfix patch and the complete qualification suite exist, null
senders remain rejected by the originator Milter. The new DSN Milter is not
enabled by configuration alone.

After qualification, absent or invalid Postfix evidence is a local DSN-policy
failure: it is visible through bounded metrics and logs but never produces a
signature. The final delivery disposition (temporary failure versus unchanged
unsigned DSN) is an explicit operator policy selected only after the live
qualification proves Postfix's retry behavior. There is no fail-open signing
mode.

## Required Evidence

- unit tests for binary envelope decoding, strict macro stage ownership,
  duplicates, size limits, and redaction;
- generated OpenAPI and daemon tests that reject the new fidelity anywhere
  except the dedicated DSN path;
- Postfix source tests proving external submission and queue re-entry cannot
  recreate evidence;
- an end-to-end patched-Postfix harness that creates a real `bounce(8)` DSN,
  captures EOH provenance macros, and verifies the resulting DKIM2 DSN at EOM;
- a negative harness case for a null-sender message injected through SMTP or
  `sendmail(1)`;
- an operational rollback that removes only the DSN Milter reference; ordinary
  Postfix delivery and legacy OpenDKIM signing remain intact.
