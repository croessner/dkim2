# Rspamd DKIM2 verifier module

This contrib module lets Rspamd use the existing authenticated
`dkim2d` `POST /v1/process` operation for inbound DKIM2 verification. It is a
transport adapter only. DKIM2 parsing, cryptography, recipes, DNS, local DKIM2
policy, replay coordination, disposition, and the optional
`Authentication-Results` value remain owned by `dkim2d`.

The supported compatibility floor is Rspamd 4.1.5. A normal asynchronous
filter resolves a privacy-preserving Redis retry result before calling
`dkim2d`. A later postfilter sends the validated verifier projection and
bounded current-scan facts to the existing generic Nauthilus Policy API. A
final idempotent symbol runs after all filters, postfilters, and composites to
arm retryable results or consume terminal results from the effective action.

See [OPERATIONS.md](OPERATIONS.md) for the complete operator runbook, including
configuration reference, staged rollout, acceptance checks, troubleshooting,
credential rotation, Redis operation, rollback, and DSN boundaries.

## Installation

Install the files using the paths compiled into the target Rspamd package:

```text
plugins.d/dkim2.lua
  -> $LOCAL_CONFDIR/plugins.d/dkim2.lua
lualib/dkim2/*.lua
  -> $CONFDIR/lua/dkim2/*.lua
modules.local.d/dkim2.conf
  -> $CONFDIR/modules.local.d/dkim2.conf
local.d/dkim2.conf.example
  -> $LOCAL_CONFDIR/local.d/dkim2.conf
```

Rspamd installation paths vary between operating-system packages, source
builds, appliances, and container images. Check `rspamadm configdump` and the
installation's package metadata, then install `modules.local.d/dkim2.conf` at
the effective `$CONFDIR` path. Do not modify Rspamd's shipped `modules.d`
files.

The process capability file contains exactly 32 nonzero raw bytes and must be
the same generation-bound process capability configured for `dkim2d`. Keep it
in a protected absolute path readable only by the Rspamd service identity.
Never put the bytes or their encoded value in UCL, environment variables,
arguments, logs, traces, metrics, or diagnostic output.

The default `loopback` transport requires a shared host network namespace. The
explicit `tls_private_network` transport uses a canonical service DNS name,
TLS 1.3 with the deployment's internal PKI, and the existing route capability.
Use it only on a dedicated private service network whose only application
participants are the inbound Rspamd and `dkim2d`. The isolation boundary may
be implemented by hosts, VMs, containers, or an equivalent private network.
Configure Rspamd's `ssl_ca_path` with the internal CA, and configure the daemon
with its matching TLS private-network listener. Never publish or proxy the
daemon port. Reload or restart Rspamd whenever the generation-bound capability
or PKI material is rotated.

The retry cache uses a separate protected 32-64 byte binary HMAC key and a
required opaque authority generation. Rotate the generation whenever the
dkim2d verifier build/schema, local policy, replay authority or namespace,
endpoint tenant, or process-capability generation changes. Its Redis
ACL is limited to `dkim2:retry:v1:*` and the script load/execute operations
needed by Rspamd. The generic Nauthilus client uses verified HTTPS and a
Policy-Basic password read from a protected file; neither credential belongs in
UCL, environment variables, logs, or diagnostics.

Run before activation:

```text
rspamadm configtest
rspamadm configdump dkim2
```

The repository-local transport contract test needs only a Lua interpreter and
compiler:

```text
contrib/rspamd/tests/run.sh
```

The digest-pinned Rspamd 4.1.5 loader, UCL, Redis discovery, greylist
dependency, and active-module proof requires Docker:

```text
contrib/rspamd/tests/rspamd-4.1.5/configtest.sh
```

The neutral Nauthilus Policy lane uses real Rspamd, Redis, Nauthilus v4, its
native reputation provider, and `miltertest-go`, but deliberately supplies the
`/v1/process` response from a deterministic stub:

```text
contrib/rspamd/tests/run-policy-e2e.sh
```

That lane proves the adapter, retry, strict Policy request/response, and Milter
boundaries. It does not prove that a live `dkim2d` verifier produced the
upstream response. A bounded isolated attempt started the live daemon and
Rspamd successfully, but the synthetic signed message returned a verifier-side
temporary failure before Policy and therefore is not published as pass
evidence. Qualify the real verifier, DNS, and MTA wire-fidelity path separately
before production activation.

## Behavior and ordering

Messages containing neither `Message-Instance` nor `DKIM2-Signature` continue
without daemon, Redis, or Policy I/O. For an applicable message, the normal
filter derives a keyed versioned identity over the exact SMTP peer, message,
sender path, ordered recipient paths including duplicates, DKIM2 draft,
projection schema, and operator-owned authority generation. Raw values never
appear in the Redis key.

An armed cache hit is atomically claimed with an owner and lease. A miss calls
`dkim2d`; an eligible validated `PASS`/`chain` response is acknowledged in
Redis as `provisional` before Rspamd consumes it. Concurrent provisional or
leased entries fail temporarily instead of reusing first-seen evidence.

The request carries the unchanged Rspamd message buffer plus the original raw
SMTP sender and recipient paths. The module accepts at most 32 MiB of message
data, 2,000 recipients, and 256 bytes per SMTP path, matching the current
daemon contract.

`dkim2d` `accept` and `continue` dispositions allow the rest of the Rspamd scan
to continue. They never force a global Rspamd accept result. `reject` becomes
an Rspamd reject pre-result and `tempfail` becomes a soft-reject pre-result.
Applicable transport, timeout, capability, response-size, JSON, or response
contract failures use `failure_mode`:

- `tempfail` is the secure default.
- `continue` is an explicit fail-open pilot setting and remains visible in
  `configdump`, startup logs, and the `DKIM2_SERVICE_ERROR` symbol.

Only a complete `PASS`/`chain` projection whose daemon policy and disposition
are `accept` or `continue` reaches Nauthilus. The request uses generic
`POST /api/v1/policy/decisions`, target
`dkim2/accept-message-instance`, and local nested `dkim2.*` and `rspamd.*`
attributes. The exact MTA-supplied peer is captured once from
`task:get_from_ip()` and reused for both cache identity and Policy request;
Rspamd
does not submit reputation or provider/plugin facts.

Nauthilus `permit` continues without forcing accept. `deny` and non-retryable
`indeterminate` reject permanently. Retryable `indeterminate`, unexpected
`not_applicable`, malformed responses, HTTP failures, and authentication or
transport failures soft reject with local generic text. A successful response
must use `application/json` and strict RFC 8259 JSON, contain the required
`request_id`, and return exactly the fresh correlation identifier sent by this
scan. Status codes, retryability, and effects must satisfy the closed Nauthilus
taxonomy. The finalizer arms the cache only for an effective soft reject or
greylist action. Every permanent reject or accepted/continued terminal result
consumes the entry.

The module emits only zero-score, option-free symbols. This includes closed
symbols for the daemon's authenticated `donotmodify` and `donotexplode`
compliance states; they are observations, not caller-selectable requests. No
domain, selector, recipient, message identifier, daemon error, response body,
replay key, or provider data is placed in symbol options.

For a cautious rollout, first qualify real MTA envelope and message fidelity on
a non-production listener. `failure_mode = "continue"` is available for a
visible fail-open pilot; production enforcement should use the default
`tempfail` once daemon readiness and retry behavior have been observed.

## Authentication-Results

Reporting is disabled when `authserv_id` is absent. When it is configured, the
module accepts only the exact daemon action:

```text
Authentication-Results: <authserv_id>; dkim2=<pass|fail|permerror|temperror>
```

Before inserting that value, the module uses Rspamd's existing
`lua_auth_results` parser to remove only prior `Authentication-Results` fields
whose authority exactly equals `authserv_id`. Foreign and Rspamd-owned
authorities are preserved. If another Rspamd module creates the deployment's
combined authentication report, order and ownership must still be configured
so it does not replace the daemon-owned DKIM2 result.

## Symbols

The parent symbol is `DKIM2_CHECK`. Virtual symbols cover applicability, the
four final authentication states, replay classes, local policy verdicts,
Nauthilus outcomes, and adapter service failure:

```text
DKIM2_NOT_APPLICABLE
DKIM2_PASS
DKIM2_FAIL
DKIM2_PERMERROR
DKIM2_TEMPERROR
DKIM2_REPLAY_NOT_CHECKED
DKIM2_REPLAY_DISABLED
DKIM2_REPLAY_FIRST_SEEN
DKIM2_REPLAY_EXPLODED
DKIM2_REPLAYED
DKIM2_REPLAY_INDETERMINATE
DKIM2_POLICY_ACCEPT
DKIM2_POLICY_CONTINUE
DKIM2_POLICY_REJECT
DKIM2_POLICY_TEMPFAIL
DKIM2_DONOTMODIFY_NOT_REQUESTED
DKIM2_DONOTMODIFY_INDETERMINATE
DKIM2_DONOTMODIFY_NOT_EVALUATED
DKIM2_DONOTEXPLODE_NOT_REQUESTED
DKIM2_DONOTEXPLODE_VIOLATED
DKIM2_DONOTEXPLODE_INDETERMINATE
DKIM2_DONOTEXPLODE_NOT_EVALUATED
DKIM2_SERVICE_ERROR
DKIM2_NAUTHILUS_PERMIT
DKIM2_NAUTHILUS_DENY
DKIM2_NAUTHILUS_INDETERMINATE
```

`DKIM2_NAUTHILUS_POLICY` is the postfilter execution symbol and
`DKIM2_RETRY_FINALIZE` is the idempotent retry-state finalizer. They are
scheduling internals rather than result symbols and must not receive scores.

Consumers that need verifier results should depend on `DKIM2_CHECK`. Consumers
that need final Nauthilus outcomes must run after or depend on the unscored
`DKIM2_NAUTHILUS_POLICY` postfilter. Do not assign positive or negative scores
to the state symbols merely to reproduce the daemon disposition; the adapter
already enforces terminal reject and temporary-failure outcomes.
Unknown or future compliance values fail closed until the module and the
versioned daemon contract are updated together. The current Draft-06 wire
contract intentionally has no `donotmodify` `honored` or `violated` state,
because dkim2d cannot yet derive the required authenticated modification facts.

## Fidelity boundary

Rspamd 4.1.5 exposes the original SMTP address views through
`task:get_from({'smtp', 'orig'})` and `task:get_recipients({'smtp', 'orig'})`,
including each address's raw representation. `task:get_content()` supplies the
message buffer submitted to filtering. The module preserves CRLF lines and
restores LF-normalized lines to SMTP CRLF, including the mixed CRLF/LF buffer
that Rspamd can produce after MTA and filter fixups. Bare carriage returns fail
through the configured failure mode. A
deployment must still qualify its actual MTA-to-Rspamd integration because
upstream MTA fixups before Rspamd sees the message are outside this module's
control.

## Bounce and DSN boundary

Inbound verification supports the null reverse path `<>` and forwards it with
the original outer recipients. It does not need or interpret Postfix's private
`{postfix_dsn_origin}` macro to verify a received delivery-status message.

This module cannot replace the dedicated `dkim2-milter` `postfix_dsn` mode for
signing a locally generated bounce. Rspamd 4.1.5 accepts Milter macro frames
internally, but it neither requests `{postfix_dsn_origin}` with
`SMFIR_SETSYMLIST` nor exposes arbitrary custom macros to Lua tasks. Its Milter
bridge forwards only a fixed built-in macro allowlist. A null reverse path by
itself is never authority for DSN signing.

Native Rspamd DSN signing would therefore first require an upstream Rspamd
extension that requests the EOH macro and exposes its exact stage-bound value,
or it must retain the separate purpose-specific DKIM2 Milter. Do not tunnel the
origin value through a message header or infer it from MIME structure.

## Retry cache crash boundary

There is no cross-service transaction between the replay mutation in `dkim2d`
and the acknowledged provisional write in Rspamd Redis. A worker or Redis
failure in that narrow interval can make the SMTP retry appear replayed to
`dkim2d`. This is a documented operational watchpoint, not a reason to weaken
replay detection. Monitor daemon success followed by retry-cache write failure,
keep Redis durable for the configured retry window, and preserve evidence when
investigating the condition.
