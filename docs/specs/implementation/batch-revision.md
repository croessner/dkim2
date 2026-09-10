# Complete fanout revision

The authoritative contract is `../openapi/dkim2d.yaml`, operation
`POST /v1/revise/batch` (`reviseBatch`). The service uses the unchanged public
reference library for verification, route sealing, modification facts, recipe
generation and signing. This endpoint revises an existing authenticated message;
it does not create an originator signature for absent or invalid DKIM2 evidence.

## Trust and authorization

`server.batch_revise_capability_file` enables this route explicitly and owns an
independent protected 32-byte credential. The client sends its canonical unpadded
base64url representation in `X-DKIM2-Batch-Revise-Capability`. Existing process,
sign, revise and delivery-status capabilities do not grant batch authority.
Private network access retains the existing native TLS 1.3 listener and exact
server-identity checks. Each external signing context must resolve through the
configured SigningAuthority and one operation-wide generation lease.

The trusted MTA supplies the actual original SMTP envelope, exact original
RFC5322 bytes and complete actual delivery plan, including local copies already
delivered. Queue completeness is an authenticated MTA assertion, not a property
proved by a caller boolean or by DKIM2. Local delivery may stand independently
when external revision fails. The daemon does not deliver, roll back a local
copy, establish downstream TLS, or prove archiving.

## Request and byte contract

The following JSON illustrates the exact DTO shape; each `...` message value is
replaced by canonical standard base64 of the corresponding complete message.

```json
{
  "api_version": "v1",
  "draft": "draft-ietf-dkim-dkim2-spec-06",
  "binding": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "original": {
    "message": {"raw_rfc5322_base64": "...", "fidelity": "raw_rfc5322"},
    "smtp": {"mail_from": "<sender@origin.example>", "rcpt_to": ["<team@forwarder.example>"]}
  },
  "copies": [
    {
      "id": "local-1", "delivery": "local",
      "message": {"raw_rfc5322_base64": "...", "fidelity": "raw_rfc5322"},
      "smtp": {"mail_from": "<sender@origin.example>", "rcpt_to": ["<account@forwarder.example>"]}
    },
    {
      "id": "external-1", "delivery": "external",
      "message": {"raw_rfc5322_base64": "...", "fidelity": "raw_rfc5322"},
      "smtp": {"mail_from": "<prepared-token@return.forwarder.example>", "rcpt_to": ["<first@destination.example>"]},
      "context": {"tenant": "tenant-a", "domain": "forwarder.example"}
    },
    {
      "id": "external-2", "delivery": "external",
      "message": {"raw_rfc5322_base64": "...", "fidelity": "raw_rfc5322"},
      "smtp": {"mail_from": "<another-prepared-token@return.forwarder.example>", "rcpt_to": ["<second@other.example>"]},
      "context": {"tenant": "tenant-a", "domain": "forwarder.example"}
    }
  ]
}
```

SMTP paths retain the existing angle-bracket API representation. The null
reverse path is `<>`, not an empty JSON string. The unchanged reference library
refuses ordinary external `SignExisting` revision with `<>`; the service returns
a permanent mutation-free rejection for that unsupported operation. Valid
received DSNs use the separately authorized propagation route, not an invented
originator or revision signature. The service never calculates or rewrites SRS.
It signs the outgoing reverse path prepared by its trusted MTA. Both its direct
`d`/`mf` alignment and its custody adjacency to the prior signed recipient domain
remain library-enforced. An unrelated fixed return domain is not an exception.
Each copy has exactly one outgoing recipient, its own opaque transaction-local
ID and exact current bytes. Local copies have no signing context; external
copies require one. There must be at least one external copy.

Bounds are 32 actual copies, 33,554,432 aggregate decoded original/current
message bytes and the existing 47,878,316-byte framed JSON request limit. Repeated
byte strings count repeatedly; clients must not omit real copies to fit a bound.
The existing bounded successful response limit also applies. Unsupported or
oversized requests receive no signing output.

## Client workflow

First query `GET /v1/revise/batch/capabilities` using the same dedicated
capability. HTTP 200 requires the enabled service and current readiness. The
response names `protocol: batch_revision_v1`, API/draft, original/current,
complete-fanout and controlled-via support, and the exact copy, hop, aggregate
message, request, response and generated-field bounds. It explicitly reports
`external_null_sender: false`. This read-only operation never signs or looks up
DNS keys. Ordinary `/readyz` alone cannot advertise a new batch capability.
Neither endpoint predicts a particular profile's availability or message's
future cryptographic result. Body, query, content metadata, expectation and
conditional request headers are rejected on the capability route.

1. Freeze original message/envelope, all current variants and the complete plan.
   Prepare each outgoing envelope first, including any independently issued SRS
   sender. Compute an opaque SHA-256 binding over the caller's immutable context
   and plan. Do not log this payload or the credential.
2. Use the generated client with the dedicated capability and verified daemon
   transport. Send one complete batch. No caller-supplied pass result, inherited
   flag set or requested `exploded` value is accepted.
3. Require HTTP 200, matching API/draft/binding/original SHA-256 and coherent
   `pass`/`accept`. Require exactly the requested external IDs once in request
   order. For each output, match `current_sha256` to the frozen current variant.
4. Decode `header_fields_base64` in array order. Concatenate the complete fields
   without whitespace changes or an extra empty line; insert at the returned
   `insertion_offset`, immediately before the existing empty header/body
   separator line. Verify that position against the frozen current message.
   Require the reconstructed SHA-256 to match `result_sha256`.
5. Release only that reconstructed message and its already-bound outgoing
   envelope through the caller's delivery/ledger/TLS/archive enforcement.
   Persist outputs for retries as required by the delivery owner; another HTTP
   invocation can generate a new nonce and is not an SMTP idempotency guarantee.

Only external outputs are returned. Each carries `id`, `current_sha256`,
`result_sha256`, `insertion_offset`, and `header_fields_base64`; the response also carries `binding`,
`original_sha256`, `result`, and `disposition`. No body is returned. The full raw
header form deliberately preserves folding that ordinary add-header DTOs unfold.
The response does not echo recipient lists. The caller owns their binding.

## Received delivery-status workflow

The existing `POST /v1/dsn/propagate` operation remains the authority for an
incoming signed DSN. It has its own `X-DKIM2-DSN-Propagate-Capability`, enabled
by `server.dsn_propagate_capability_file`, and its own replay reservation and
commit contract. Submit the received DSN bytes and its **observed** outer
envelope, before rewriting an SRS recipient:

```json
{
  "api_version": "v1",
  "draft": "draft-ietf-dkim-dkim2-spec-06",
  "message": {"raw_rfc5322_base64": "...", "fidelity": "raw_rfc5322"},
  "outer_smtp": {"mail_from": "<>", "rcpt_to": ["<issued-token@return.forwarder.example>"]},
  "context": {"tenant": "tenant-a", "reporting_mta": "mx.forwarder.example"}
}
```

The outer signature is verified with that envelope. A decoded SRS target is
neither substitute envelope evidence nor independent DSN authorization. The
client independently validates its SRS token and issuance ledger and reconciles
the response's authenticated `propagation.next_hop_recipient` with the expected
return recipient. A mismatch must stop delivery.

Only a coherent accept response carries `propagation`: complete rebuilt and
signed `raw_rfc5322_base64`, authenticated `next_hop_recipient`, explicit
`smtputf8_required` and `eight_bit_mime_required`, and an opaque `commit_token`.
Reinject those bytes with `MAIL FROM:<>` and that recipient while honoring the
declared transport requirements. After a durable SMTP 250 or equivalent queue
commit, call `POST /v1/dsn/propagate/commit` with API/draft and `commit_token`.
Do not commit before durable acceptance. Retain the caller's own delivery state
across crashes; HTTP reservation and SMTP acceptance are not one atomic commit.
Committed coordinates are suppressed on replay, pending coordinates defer.

A signature on an arbitrary null-sender message does not make it a valid DSN.
The propagation service still checks report structure, embedded cryptography,
local hop ownership, outer alignment, recipient linkage and reconstructability.
The batch endpoint never substitutes ordinary revision or a fabricated DSN for
this evaluation. The delivery owner separately handles any explicitly enabled
classic path for fully absent DKIM2, without claiming a DKIM2 pass.

## Native integration test input

The opt-in `TestBatchRevisionIntegrationFixture` helper uses only the production
application services and unchanged public library. It exports fresh actual
signatures and test-only protected material to a new private directory:

```sh
DKIM2_BATCH_FIXTURE_DIR=/absolute/private/new-fixture \
GOEXPERIMENT=runtimesecret go test ./cmd/dkim2d/internal/app \
  -run '^TestBatchRevisionIntegrationFixture$' -count=1
```

The output includes `original.eml`, `original-envelope.json`, `dns-txt.json`
and `dkim2d.yaml`. The protected generation contains only the hosted and
forwarding domains' exact transit/DSN profiles, separate keys for both uses,
three independent route capabilities and a replay key. Its config uses
process-local memory replay and a loopback listener for isolated qualification;
it is not a production deployment recipe. Publish the exact test TXT records
through the isolated daemon's `/etc/resolv.conf` resolver. Preserve protected
file and directory modes and adapt absolute mount paths before loading config.
`dns-txt.json` is an object mapping absolute QNames (including the final dot)
to one complete TXT payload each. Return one TXT RR with NOERROR and a positive
TTL for every known name. TXT character strings within that single RR may be
concatenated; separate RRs would be ambiguous. The existing daemon transport
reports DNSSEC diagnostics as unavailable and does not infer authenticity from
AD. An isolated test resolver need not invent AD; this changes no deployment DNS
policy.
`test-source-keys/` holds the separate originating/remote test authorities and
must not be mounted into the daemon. The domains are `origin.test`,
`hosted.test`, `forwarder.test` and `destination.test`; the original envelope
is stored in its envelope JSON rather than printed by the helper.
The source includes Date and Message-ID before its originator signature, so a
receiving MTA need not repair those fields before its first capture callback.

After the MTA's actual final SMTP output has been recorded, create a private
JSON envelope file with `mail_from` and the single `rcpt_to` in angle brackets.
Generate a remote report from those exact final bytes, including real Received
fields and the actual prepared reverse path:

```sh
DKIM2_BATCH_FIXTURE_DIR=/absolute/private/new-fixture \
DKIM2_BATCH_REMOTE_MESSAGE_FILE=/absolute/private/final.eml \
DKIM2_BATCH_REMOTE_ENVELOPE_FILE=/absolute/private/final-envelope.json \
GOEXPERIMENT=runtimesecret go test ./cmd/dkim2d/internal/app \
  -run '^TestBatchRevisionIntegrationFixture$' -count=1
```

Both input files must be regular private files. The helper generates
`remote-dsn.eml` and `remote-dsn-envelope.json` without overwriting prior
outputs. It records the remote system's own controlled custody hop, creates
its local validated DSN, then runs that remote system's actual propagation
service to the received prepared sender. This is a real signed report derived
from the tested delivery, not a precomputed DSN for different bytes. The helper
logs neither content nor keys. Its ordinary Roundtrip test reloads the exported
keys, passes the real protected config loader and flat-file signing store,
and verifies the resulting report through the receiving propagation service.

Independently verify a recorded final forward or propagated report, without
rewriting the input or creating a new report:

```sh
DKIM2_BATCH_FIXTURE_DIR=/absolute/private/new-fixture \
DKIM2_BATCH_VERIFY_MESSAGE_FILE=/absolute/private/received.eml \
DKIM2_BATCH_VERIFY_ENVELOPE_FILE=/absolute/private/received-envelope.json \
GOEXPERIMENT=runtimesecret go test ./cmd/dkim2d/internal/app \
  -run '^TestBatchRevisionIntegrationFixture$' -count=1
```

This entry invokes the unchanged public `Verifier.Verify` with the exact recorded
DATA and observed SMTP reverse/recipient paths and requires PASS. It also loads
the separate local `return` selectors used by the actual daemon's DSN profiles.
It prints only the test outcome and closed verification classifications on
failure. This is independent cryptographic byte/envelope verification; received
DSN structure, local-hop propagation and replay remain independently enforced by
the production propagation endpoint. Verification and report-generation input
options are mutually exclusive.

## Protocol behavior

An external copy can additionally contain `via: {"smtp": SMTPInput, "context":
SigningContext}`. This optional single controlled intermediate hop implements
Draft 06 section 9.3 when the receiving domain and final return/signing domain
differ. Both contexts must belong to the same tenant. Exact ordinary-transit
profiles for both signing domains and exact local authority over the intermediate
recipient domain are resolved from the same SigningAuthority lease. The MTA
provides the intermediate envelope explicitly; the service invents no mailbox or
domain. The intermediate reverse path is non-null and there is one recipient.

The first sealed fanout still counts every actual local and external copy. Each
external copy with `via` is signed first with that envelope, then the resulting
real signature chain is reverified before a final single-copy continuation signs
the prepared external envelope. Both exact header deltas are returned together.
No intermediate output is released and no extra physical delivery is claimed.
The unchanged library verifies every custody transition; common administrative
control never bypasses alignment or inherited restrictions.

For a received DSN, the existing library evaluates these adjacent same-tenant
controlled domains as one local hop run. Its propagation operation verifies and
removes that complete run, reconstructs the preceding message state and selects
the previous authenticated hop's reverse path. The intermediate imaginary mailbox
is not selected as the final propagated recipient.

The original is verified with the actual incoming envelope via
`Signer.VerifyForRevision`. Its sealed capability binds all route entries.
One `PlanRouteFanout` covers both local and external copies. The reference
library derives multiplicity and `exploded`, creates a private single-recipient
ticket for each external copy and computes actual modification facts. An
authenticated `donotmodify` or `donotexplode` restriction that would limit an
external release to local control is rejected. Local copy descriptors do not
create a global local-delivery veto.

Temporary DNS/key/provider failures produce `temperror`/`tempfail`. Invalid
cryptographic evidence and denied policy produce a permanent rejection, never
the classic no-DKIM2 path. A later copy failure releases no partial external
header set. Original/current protocol evidence cannot be stripped or replaced to
restart a chain. Existing public-library fidelity, recipe and body bounds stay
in force.

Normative baseline: [Draft 06, sections 8.5, 8.6, 8.10, 9 and 11.8](https://datatracker.ietf.org/doc/html/draft-ietf-dkim-dkim2-spec-06).
The server returns the baseline version explicitly; it does not claim an RFC or
a later operational-profile conformance.

Candidate qualification and executable evidence are recorded in the
[2026-09-09 report](../../reports/batch-revision-2026-09-09.md).
