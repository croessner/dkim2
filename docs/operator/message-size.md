# Configurable SMTP message size

The daemon accepts `server.message_bytes` in YAML or
`DKIM2D_SERVER_MESSAGE_BYTES` in the environment. It limits each decoded RFC
5322 input, including each original/copy in a batch, before generated DTOs
and decoded message buffers are allocated. The default remains 33,554,432
bytes. Valid explicit values are 1 through 134,217,728 bytes; zero does not
disable the limit. Exact Base64 padding is accounted for at the boundary.

For a Postfix `message_size_limit = 104857600` deployment, use:

```yaml
# dkim2d, for every role
server:
  message_bytes: 104857600
  max_in_flight: 2
  admission_wait: 30s
```

```yaml
# dkim2-milter, for every role
limits:
  message_bytes: 104857600
server:
  max_buffered_bytes: 1073741824
daemon:
  request_timeout: 90s
```

The DSN propagator uses `limits.message_bytes: 104857600`. Its message
ceiling remains configurable, with a 32 MiB default and 128 MiB hard maximum.
Adapters and daemon must receive the same deployment value as Postfix.
Rspamd and native forwarding adapters have their own configuration and must
be aligned too; the daemon cannot discover their settings automatically.

The library's raw-message, signing, canonicalization, DSN MIME-part and
route-source ceilings are 128 MiB. This allows internally generated protocol
headers above a 100 MiB input. Those remain bounded by the separate 1 MiB
header-block ceiling. The parser permits at most 2,097,152 body lines, enough
for a 100 MiB body with 76-character MIME wrapping. Independent structural,
recipe, cryptographic and recipient limits still apply. This is not a promise
to accept every possible message below the byte ceiling.

HTTP framing permits 361,053,016 bytes at the closed library ceiling. The
transport limit of a deployment follows its own `server.message_bytes`, so a
100 MiB deployment admits 282,759,344 body bytes and answers 413 above that.
Batch original/current snapshots have a 256 MiB aggregate ceiling and still
obey the configured per-message limit.
OpenAPI and all generated wire clients carry the same hard bounds.

## Call deadlines

Byte limits alone do not make an SMTP-sized message deliverable. One 38 MB
message occupies a two-CPU daemon for several seconds of Base64 decoding,
generic JSON validation, canonicalization and signing, and `max_in_flight: 1`
serializes everything else behind it. The adapter's `daemon.request_timeout`
must therefore cover the complete call including the bounded admission wait,
and it must exceed the daemon's `server.request_deadline`, so the daemon's own
503 answer arrives instead of a client-side abort. `dkim2-milter` and the DSN
propagator accept up to 180 seconds; `server.request_deadline`
accepts up to 120 seconds. A 2-second adapter deadline is a small-message
default and rejects SMTP-sized mail as `451 4.7.1 DKIM2 service unavailable`
with `failure_class=indeterminate`, long after every byte limit was accepted.

Concurrency follows the configured size. The daemon reserves one per-request
working-set unit derived from `server.message_bytes` and admits as many
requests as the process budget covers at that unit. A deployment that admits
smaller messages therefore admits more requests:

| `server.message_bytes` | reservation | admitted concurrency |
| --- | --- | --- |
| 1 MiB | 217 MiB | 37 |
| 8 MiB | 488 MiB | 16 |
| 33554432 (default) | 878 MiB | 9 |
| 104857600 | 2.66 GiB | 3 |
| 134217728 (ceiling) | 3.17 GiB | 2 |

`server.max_in_flight` selects a value inside that range and the daemon
refuses a larger one at startup. The reservation is an ownership-accounting
bound, not a startup allocation and not a container memory setting: size the
container for the concurrency actually configured.

`server.admission_wait` accepts up to 120 seconds and never more than
`server.request_deadline`. A waiting request owns no reservation and no
request body, so the wait costs one goroutine and its open connection, bounded
by `server.max_waiters`. Keep it below the adapter's `daemon.request_timeout`,
so a queued request still has time to run. An MTA that splits one message to
several recipients opens that many concurrent transactions; with enough
admitted concurrency they are signed together instead of all but one being
deferred with 503 `service_overloaded`.

## Memory and rollout qualification

Do not apply the larger size to an old binary or retain a 512 MiB container
memory limit. Milter admission requires a complete EOM working set, not only
the retained raw input. The 100 MiB configuration test rejects an insufficient
256 MiB budget and accepts 1 GiB.

HTTP reserves one working-set unit per active request, derived from
`server.message_bytes`, within an 8 GiB process budget. These are
ownership-accounting bounds, not allocations at startup and not container
memory settings. The pinned Go 1.27.0 current-verification inventory peaks at
2,750,757,184 bytes at the closed library ceiling, below the 3,403,988,992-byte
reservation that ceiling derives. The largest phase is generic JSON validation.
The exact ReadAll capacities at that ceiling are 361,054,208 final plus
497,039,680 intermediate bytes; JSON retains 536,870,912 bytes and overlaps
805,306,368 during growth. The modelled bounds cover both: ReadAll by three
times the final body capacity, which its 1.5 growth ratio converges below, and
the JSON overlap exactly by one and a half times the covering power of two.
Regression tests replay both probes at every supported ceiling and require
measured to stay at or below modelled, and exercise the complete maximum HTTP
boundary. Signing and batch/revision load qualification must additionally
cover the selected operation and deployment concurrency before rollout.

The 100 MiB library regression signs a MIME-wrapped message, preserves its
body, revises its Subject header, and verifies the resulting two-instance
cryptographic chain. Recipe reconstruction, generation work and cumulative
history budgets scale with the supported raw size and remain finite. Boundary tests cover exact and
one-byte-over values in all Base64 padding classes. They do not replace a
real deployment SMTP/queue verification after installing new images.

Older implementation milestone tables describing 32 MiB library maxima and
512 MiB HTTP reservations are superseded by this operator contract and the
current source-owned capacity tests.

## Batch revision for SMTP-sized forwarding

A forwarding MTA that revises one message for several recipients sends the
original and every current copy in one `POST /v1/revise/batch` request. By
default that request shares the single-message transport ceiling
`2 * base64(server.message_bytes) + 3,139,072` bytes and the 268,435,456-byte
decoded aggregate, so at a 112 MiB message ceiling it carries only about two
messages. `server.batch_revision.max_aggregate_message_bytes` raises the
decoded aggregate of the original plus all copies up to 536,870,912 bytes and
gives the batch route its own working-set sizing and admission pool:

| Setting | Default | Range |
| --- | --- | --- |
| `server.working_set_bytes` | 8589934592 (8 GiB) | 1 GiB to 64 GiB |
| `server.batch_revision.max_aggregate_message_bytes` | 0 (shared sizing) | `server.message_bytes` to 536870912 |
| `server.batch_revision.max_in_flight` | 1 | 1 to 8, used only with an aggregate |

The batch request limit is then the separately padded Base64 of the
aggregate plus 3,139,072 bytes. `GET /v1/revise/batch/capabilities` advertises
the enforced `max_aggregate_message_bytes` and `max_request_bytes`; clients
must read them instead of pinning constants. Each single message still obeys
`server.message_bytes`.

Every shared permit (`server.max_in_flight` times the shared reservation) and
every batch permit (`server.batch_revision.max_in_flight` times the batch
reservation) must fit `server.working_set_bytes` together, or the daemon
refuses to start. The reservations are ownership-accounting bounds derived by
the same model as above; the largest phase of a batch request is generic JSON
validation of its body:

| `server.message_bytes` | aggregate | batch body | batch reservation |
| --- | --- | --- | --- |
| 33554432 | 268435456 | 361,053,104 | 3.17 GiB |
| 104857600 | 419430400 | 562,379,696 | 5.23 GiB |
| 117440512 | 469762048 (original + 3 copies) | 629,488,560 | 5.67 GiB |
| 117440512 | 536870912 (ceiling) | 718,967,044 | 6.25 GiB |

The shared reservation at `server.message_bytes: 117440512` is 2.88 GiB.

### Recommended values for a 112 MiB message limit

For Postfix `message_size_limit = 117440512` and forwarding with an original
and up to three copies per batch:

```yaml
# dkim2d serving /v1/revise/batch
server:
  message_bytes: 117440512
  max_in_flight: 2
  admission_wait: 30s
  request_deadline: 120s
  working_set_bytes: 12884901888
  batch_revision:
    max_aggregate_message_bytes: 469762048
    max_in_flight: 1
```

This reserves 2 x 2.88 GiB + 5.67 GiB = 11.43 GiB of the 12 GiB budget. Size
the container for that budget plus the process baseline, about 13 GiB; with
`server.max_in_flight: 1` the budget may be 10 GiB (10737418240) and the
container about 11 GiB. A daemon that serves no batch route keeps the 8 GiB
default and leaves the batch keys unset.

```yaml
# dkim2-milter, for every role
limits:
  message_bytes: 117440512
server:
  max_buffered_bytes: 1073741824
daemon:
  request_timeout: 150s
```

```yaml
# dkim2-dsn-propagator
limits:
  message_bytes: 117440512
daemon:
  request_timeout: 150s
  pending_lease: 300s
reinjection:
  data_timeout: 120s
```

The propagator's `daemon.pending_lease` declares the daemon's
`dsn_propagation.pending_lease`, so the daemon that serves propagation sets
`dsn_propagation.pending_lease: 300s` as well; the sum of the propagator's
call, re-injection and commit deadlines (282 seconds here) must stay below it.

The batch client's own call deadline must exceed `server.request_deadline`
(120 seconds), like an adapter's `daemon.request_timeout`, and its reported
limits must come from the capability route. Revising a 112 MiB message for
three external copies decodes, verifies and signs about 450 MiB of message
data in one request; qualify the deployment's CPU time against the 120-second
deadline before rollout. The Exim adapter keeps its separate 32 MiB ceiling.
