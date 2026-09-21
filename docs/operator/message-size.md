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
503 answer arrives instead of a client-side abort. `dkim2-milter` accepts up
to 180 seconds and the DSN propagator up to 30 seconds; `server.request_deadline`
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
