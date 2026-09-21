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
  max_in_flight: 1
```

```yaml
# dkim2-milter, for every role
limits:
  message_bytes: 104857600
server:
  max_buffered_bytes: 1073741824
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

HTTP framing permits 361,053,016 bytes; batch original/current snapshots have
a 256 MiB aggregate ceiling and still obey the configured per-message limit.
OpenAPI and all generated wire clients carry the same hard bounds.

## Memory and rollout qualification

Do not apply the larger size to an old binary or retain a 512 MiB container
memory limit. Milter admission requires a complete EOM working set, not only
the retained raw input. The 100 MiB configuration test rejects an insufficient
256 MiB budget and accepts 1 GiB.

HTTP reserves 4 GiB per active request, at most two reservations/8 GiB per
process. These are ownership-accounting bounds, not allocations at startup
and not container memory settings. The pinned Go 1.27.0 current-verification
inventory peaks at 2,750,757,184 bytes, below its 4 GiB reservation. The
largest phase is now generic JSON validation. The exact ReadAll capacities
are 361,054,208 final plus 497,039,680 intermediate bytes; JSON retains
536,870,912 bytes and overlaps 805,306,368 during growth. Regression tests
derive these capacities from the runtime and exercise the complete maximum
HTTP boundary. Signing and batch/revision load qualification must additionally
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
