# Rspamd DKIM2 verifier operator runbook

This runbook covers installation and operation of the pure-Lua Rspamd adapter
in this directory. The adapter verifies inbound DKIM2 messages through the
authenticated `dkim2d` `POST /v1/process` route. It does not implement DKIM2
cryptography, policy, replay detection, reputation, or signing itself.

## Deployment model

The supported request path is:

```text
Postfix or another MTA
        |
        | Milter protocol
        v
Rspamd normal filter: DKIM2_CHECK
        |
        | Redis retry claim or authenticated HTTP POST /v1/process
        v
dkim2d: verify -> policy -> replay gate -> disposition
        |
        v
Rspamd postfilter: DKIM2_NAUTHILUS_POLICY
        |
        | verified HTTPS POST /api/v1/policy/decisions
        v
Nauthilus generic Policy API
        |
        v
Rspamd idempotent finalizer after filters, postfilters, and composites
```

The default `loopback` transport requires one shared host network namespace.
The explicit `tls_private_network` transport instead requires a dedicated
private service network, TLS 1.3, a certificate from the deployment's
internal PKI, exact service-name verification, and the route capability. Only
the inbound Rspamd and `dkim2d` may be application participants. Never publish
or proxy the daemon port or reuse a broad application network. Bind `dkim2d` to
its exact static private IP on that network; wildcard listeners are rejected so
another daemon network cannot gain incidental reachability.

The normal filter owns daemon verification and retry-result lookup. The Policy
postfilter may only narrow an eligible daemon accept/continue result. The
idempotent finalizer runs after filters, postfilters, and composites, observes
the effective Rspamd action, and atomically arms a soft-reject retry or consumes
a terminal result. The Policy symbol retains its hard dependency on the normal
verifier; idempotent-stage ordering and `ignore_passthrough` keep finalization
after the action-setting phases even when another filter has set a pre-result. Custom
idempotent symbols must remain observation/output-only and must not change the
message action after this boundary.

Rspamd 4.1.5 models this as stage ordering, not as cross-stage symbol
dependencies. Its [version-pinned symbol-cache scheduler][rspamd-415-order]
appends every postfilter before every idempotent symbol; the shipped
`GREYLIST_SAVE` and this module's
`DKIM2_NAUTHILUS_POLICY` are postfilters, while `DKIM2_RETRY_FINALIZE` is
idempotent. Cross-stage dependencies are rejected by Rspamd and must not be
used as a substitute. The digest-pinned compatibility test asserts all three
stage contracts against the supported distribution.

[rspamd-415-order]: https://github.com/rspamd/rspamd/blob/4.1.5/src/libserver/symcache/symcache_impl.cxx#L689-L694

## Prerequisites

Before installation, verify all of the following:

- Rspamd is version 4.1.5 or newer.
- `dkim2d` is configured and ready on the authority matching the selected transport.
- Private-network mode has the internal CA in Rspamd's `ssl_ca_path`, exactly
  one service-name DNS SAN without wildcard or alternate identity, and no
  published daemon port.
- The generation-bound process capability is available as exactly 32 nonzero
  raw bytes.
- The Rspamd service identity can read that capability file, but unrelated
  users and processes cannot.
- The MTA supplies the original SMTP sender and recipients to Rspamd.
- The MTA supplies the exact remote SMTP peer exposed by `task:get_from_ip()`.
- Message bytes observed by Rspamd have not been normalized in a way that
  breaks the deployment's required RFC 5322 fidelity.
- A dedicated Redis/Valkey authority and protected retry-HMAC key are ready.
- Nauthilus exposes the generic Policy endpoint through verified HTTPS and the
  admitted Policy-Basic principal can evaluate `dkim2/accept-message-instance`.
- Rspamd `task_timeout` exceeds the maximum configured dependency chain and
  `soft_reject_on_timeout` is enabled; the pinned baseline uses 15 seconds.

The capability is a bearer credential. Never print, encode for inspection,
copy into UCL, export through an environment variable, or include it in logs,
traces, metrics, tickets, or command output.

## Files and installation paths

Install the repository files as follows:

| Repository file | Target |
| --- | --- |
| `plugins.d/dkim2.lua` | `$LOCAL_CONFDIR/plugins.d/dkim2.lua` |
| `lualib/dkim2/*.lua` | `$CONFDIR/lua/dkim2/*.lua` |
| `modules.local.d/dkim2.conf` | `$CONFDIR/modules.local.d/dkim2.conf` |
| `local.d/dkim2.conf.example` | `$LOCAL_CONFDIR/local.d/dkim2.conf` |

Do not edit Rspamd's shipped `modules.d` files. Packages, source builds,
appliances, and container images may use different effective configuration
trees. Use `rspamadm configdump` and the installation's package metadata to
discover the effective paths, then install the module loader at the actual
`$CONFDIR` location.

Keep local configuration and protected capability material in an
operator-owned, access-controlled path outside vendor-managed files. Neither a
package upgrade nor an image replacement may overwrite them.

## Configuration reference

The local configuration is a closed vocabulary. Unknown keys disable the
module instead of being silently ignored.

| Setting | Required | Default | Valid values and purpose |
| --- | --- | --- | --- |
| `enabled` | yes | none | Must be exactly `true`. Remove the module loader to disable the module. |
| `endpoint` | yes | none | Exact loopback HTTP URL, or an HTTPS URL with the exact `server_name` in TLS private-network mode. Other paths, IP endpoints in private mode, userinfo, queries, and fragments are rejected. |
| `transport` | no | `loopback` | `loopback` or `tls_private_network`. There is no plaintext private-network mode. |
| `server_name` | private network | none | Canonical lowercase DNS service identity present in the internal-PKI certificate SAN and identical to the endpoint host. Forbidden in loopback mode. |
| `capability_file` | yes | none | Absolute path to the exact 32-byte process capability. |
| `timeout` | no | `2.0` | HTTP timeout in seconds, greater than zero and at most `10`. |
| `max_response_bytes` | no | `262144` | Integer response limit from `1024` through `262144` bytes. |
| `failure_mode` | no | `tempfail` | `tempfail` or the explicit pilot-only value `continue`. |
| `authserv_id` | no | disabled | Lowercase DNS-style reporting authority. Enables the daemon-owned `Authentication-Results` action. |
| `retry_cache.secret_file` | yes | none | Protected 32-64 byte binary HMAC key, independent from dkim2d replay material. |
| `retry_cache.authority_generation` | yes | none | Opaque ASCII token, 1-128 bytes. Rotate for every dkim2d verifier build/schema, local policy, replay authority/namespace, endpoint tenant, or process-capability generation change. |
| `retry_cache.ttl_ms` | yes | none | Absolute Redis deadline from 60,000 through 604,800,000 ms; it must cover the configured greylist/retry window. |
| `retry_cache.lease_ms` | yes | none | Atomic claim lease from 1,000 through 600,000 ms and shorter than the TTL. |
| `retry_cache.redis` | yes | none | Dedicated Rspamd Redis configuration. Restrict its ACL to the retry prefix and required script operations. |
| `nauthilus.endpoint` | yes | none | Exact verified HTTPS generic Policy URL ending in `/api/v1/policy/decisions`. |
| `nauthilus.server_name` | yes | none | Canonical DNS name identical to the Policy URL authority and certificate identity. |
| `nauthilus.username` | yes | none | Dedicated Policy-Basic principal `rspamd-verifier`; not an application subject. |
| `nauthilus.password_file` | yes | none | Protected password file with no trailing newline. |
| `nauthilus.instance` | yes | none | Admitted stable Rspamd/MX instance identity. |
| `nauthilus.client_class` | yes | none | Listener-scoped `untrusted`, `trusted`, or `local`; authenticated SMTP overrides it per task. |
| `nauthilus.mail_from_class` | yes | none | Listener-scoped non-null sender class. Null MAIL FROM is detected per task. |
| `nauthilus.recipient_classes` | yes | none | Bounded recipient class set for this listener/routing scope. |

Rspamd 4.1.5 uses its global `ssl_ca_path` for the HTTPS client trust store.
That store must contain the issuer for `nauthilus.server_name`; certificate and
hostname verification remain enabled and the module exposes no disable switch.

The secure production baseline is:

```ucl
enabled = true;
endpoint = "http://127.0.0.1:8080/v1/process";
transport = "loopback";
capability_file = "/etc/dkim2/protected/process-capability";
timeout = 2.0;
max_response_bytes = 262144;
failure_mode = "tempfail";
authserv_id = "mx.example.test";
```

The TLS private-network baseline is:

```ucl
enabled = true;
endpoint = "https://dkim2d-inbound:8443/v1/process";
transport = "tls_private_network";
server_name = "dkim2d-inbound";
capability_file = "/etc/dkim2/protected/process-capability";
timeout = 2.0;
max_response_bytes = 262144;
failure_mode = "tempfail";
```

Configure Rspamd's global `ssl_ca_path` to a trust file containing the internal
PKI issuer. TLS verification is always enabled by the module and cannot be
disabled through its configuration.

`authserv_id` is optional. When absent, reporting is disabled and the daemon
must return no reporting action. When present, the module accepts only the
exact daemon action `Authentication-Results: <authserv_id>; dkim2=<result>`.

## Staged rollout

1. Install the Lua plugin, module loader, local configuration, and protected
   capability without reloading Rspamd.
2. Run the repository-local Lua contract test on a build or administration
   host:

   ```text
   contrib/rspamd/tests/run.sh
   ```

3. Validate the target configuration before activation:

   ```text
   rspamadm configtest
   rspamadm configdump dkim2
   rspamadm configdump -m
   ```

   The first command must report valid syntax. The second must show only the
   intended non-secret settings. The module list must show `dkim2` enabled and
   must not list it among failed modules.
4. Start on a non-production listener or with `failure_mode = "continue"`.
   This pilot mode still emits `DKIM2_SERVICE_ERROR`; alert on that symbol and
   treat it as a failed verification dependency, not as a clean result.
5. Exercise unsigned mail, valid applicable mail, daemon rejection, and daemon
   outage through the real MTA-to-Rspamd path.
6. Confirm retry behavior and daemon readiness, then switch production to
   `failure_mode = "tempfail"` and reload Rspamd.

Do not use an SMTP null reverse path, MIME shape, header, client IP, or Rspamd
score as authority to weaken the DKIM2 result.

## Acceptance checks

The following minimum matrix must pass through the actual Milter listener:

| Scenario | Required Rspamd result |
| --- | --- |
| No `Message-Instance` and no `DKIM2-Signature` | `DKIM2_NOT_APPLICABLE`; no daemon request |
| Valid first observation | `DKIM2_PASS`, `DKIM2_REPLAY_FIRST_SEEN`, and the daemon policy/compliance symbols |
| Accepted exploded copy | `DKIM2_PASS`, `DKIM2_REPLAY_EXPLODED` |
| Duplicate without authenticated exploded exemption | `DKIM2_FAIL`, `DKIM2_REPLAYED`, policy reject, SMTP 5xx |
| Replay evidence unavailable | `DKIM2_TEMPERROR`, `DKIM2_REPLAY_INDETERMINATE`, SMTP 4xx |
| Applicable message while daemon is unavailable | `DKIM2_SERVICE_ERROR`; SMTP 4xx in production mode |
| Inbound DSN with reverse path `<>` | Original null sender and outer recipients reach `dkim2d` unchanged |
| Eligible first-seen result followed by greylisting | Provisional cache entry becomes armed only after `GREYLIST_SAVE`; SMTP 4xx |
| Exact SMTP retry after an armed result | One atomic cache claim; no second dkim2d replay mutation; Nauthilus is evaluated again |
| Concurrent retry while claimed | No cached payload reuse and no dkim2d call; SMTP 4xx |
| Nauthilus permit | No forced accept; existing DKIM2/Rspamd result remains authoritative |
| Nauthilus deny or non-retryable indeterminate | SMTP 5xx and retry entry consumed |
| Retryable indeterminate, transport/auth failure, or malformed Policy response | SMTP 4xx and retry entry armed |
| Final accept or unrelated permanent reject | Retry entry consumed; a later identical delivery reaches dkim2d replay handling |

If `authserv_id` is enabled, also prove that an existing field claiming that
same authority is replaced, the exact daemon-owned DKIM2 result is inserted,
and foreign or Rspamd-owned authorities remain unchanged. Coordinate ordering
with any Rspamd module that constructs a combined authentication report.

Inspect symbols only for finite states. The module intentionally does not add
domain, selector, recipient, message ID, response text, or daemon errors as
symbol options.

## Policy and compliance symbols

`donotmodify` and `donotexplode` are authenticated DKIM2 requests carried by
the verified chain. They are not Rspamd configuration switches. The adapter
validates the daemon's closed policy values and publishes one zero-score symbol
for each result so local composites and monitoring can observe them.

Current `donotmodify` values are `not_requested`, `indeterminate`, and
`not_evaluated`. The current verifier cannot yet produce the authenticated
transition facts required to serialize `honored` or `violated`; an unexpected
future value fails closed.

Current `donotexplode` values are `not_requested`, `violated`, `indeterminate`,
and `not_evaluated`. A violation can contribute to a daemon-owned terminal
policy decision. Operators must not recreate or override that decision with a
Rspamd score.

A monitoring composite may group finite states without changing disposition,
for example:

```ucl
composites {
  DKIM2_POLICY_OBSERVE {
    expression = "DKIM2_DONOTMODIFY_INDETERMINATE | DKIM2_DONOTEXPLODE_INDETERMINATE";
    score = 0.0;
  }
}
```

Keep such composites observational. Terminal reject and temporary-failure
outcomes are already applied directly from the authenticated daemon response.

## Normal operation

Monitor at least these conditions:

- `DKIM2_SERVICE_ERROR` rate and duration;
- `DKIM2_TEMPERROR` and `DKIM2_REPLAY_INDETERMINATE` rate;
- daemon readiness, latency, and timeout rate;
- unexpected changes in applicable versus non-applicable volume;
- capability generation mismatch immediately after rotation;
- distribution of finite policy and compliance symbols.
- retry-cache miss, provisional-store failure, busy claim, hit, arm, consume,
  stale finalizer, and deadline expiry counts;
- generic Nauthilus Policy latency, transport failures, and the finite permit,
  deny, retryable indeterminate, and non-retryable indeterminate outcomes.

Do not attach raw messages, addresses, selectors, replay keys, response bodies,
or capability material to metrics. The symbols are designed to be safe,
bounded dimensions.

An `accept` or `continue` DKIM2 disposition does not force Rspamd to accept the
message. All other Rspamd checks continue normally. A daemon `reject` produces
the DKIM2 policy rejection, and `tempfail` produces a soft reject.

## Capability rotation

The capability is generation-bound and loaded once when the Lua module starts.
Rotate it as one coordinated change:

1. Stage the new protected generation for `dkim2d` and Rspamd without exposing
   either capability.
2. Switch `dkim2d` to the new generation using its documented rotation
   procedure.
3. Atomically replace the Rspamd-visible capability file with the matching raw
   32-byte value.
4. Reload or restart Rspamd so the Lua module reads the new value.
5. Send one applicable test message and confirm that `DKIM2_SERVICE_ERROR` is
   absent.

An old in-memory capability after daemon rotation causes applicable messages
to follow `failure_mode`. In production this should be a visible temporary
failure, never a silent bypass.

## Internal-PKI rotation

TLS certificate renewal publishes a new immutable protected TLS generation
for `dkim2d`. It does not require new capability or replay-HMAC values: copy
those exact protected bytes into the new generation through the normal
secret-management path, add the renewed leaf chain, key, and unchanged internal
CA, validate, then restart only the inbound daemon. Keep the Rspamd-readable
capability copy unchanged when its bytes did not rotate. Replace Rspamd's trust
file and reload Rspamd only when the internal trust anchor actually changes.

Never edit certificate files in an active immutable generation. Retain the
previous complete generation and deployed daemon release identifier until
HTTPS, capability, applicable mail, unsigned mail, and rollback checks pass.

## Troubleshooting

### Module is disabled at startup

Check `rspamadm configtest`, `rspamadm configdump dkim2`, and Rspamd startup
logs. Common causes are an unknown configuration key, `enabled` not exactly
`true`, an endpoint inconsistent with its transport, an invalid port or path, an invalid
`authserv_id`, or an unreadable/malformed capability file. The capability must
be exactly 32 raw nonzero bytes; a hexadecimal or Base64 text file is invalid.

### Every applicable message gets `DKIM2_SERVICE_ERROR`

Confirm `dkim2d` readiness, the exact endpoint and service identity, internal
CA trust, network membership, capability generation, timeout, and response-size limit. Do not log the HTTP
request headers or response body while diagnosing. A contract-version mismatch
also fails closed; update the daemon and contrib module as one compatible set.

### Unsigned messages contact the daemon

Verify the exact message presented to Rspamd. The presence of either a
`Message-Instance` or `DKIM2-Signature` field makes the message applicable even
when the field is malformed; parsing belongs to `dkim2d`.

### Envelope fidelity fails

Confirm that Rspamd receives the original SMTP address views and that the MTA
integration has not replaced bracketed raw paths. The module requires exactly
one sender path, at least one recipient, and bounded original raw values. The
null sender `<>` is valid only for `MAIL FROM`; a null recipient is rejected.

### Authentication-Results conflicts with another module

Either omit `authserv_id` and let the deployment's reporting owner handle the
result through a separately reviewed design, or explicitly order the combined
reporting module after the DKIM2 scrub. Never synthesize `dkim2=pass` from an
Rspamd symbol.

## Bounce and DSN boundary

Inbound DSN verification works with `MAIL FROM:<>` and does not require a
Postfix-private macro. Locally generated DSN signing is different: Rspamd 4.1.5
does not request `{postfix_dsn_origin}` with `SMFIR_SETSYMLIST` and does not
expose arbitrary custom Milter macros to Lua. The null reverse path alone is
not trustworthy signing authority.

Keep the dedicated `dkim2-milter` `postfix_dsn` signer for that route. Replacing
it would require an upstream Rspamd extension that requests and exposes the
exact EOH-stage macro. Do not tunnel the value through a message header or
infer internal origin from MIME content.

## Nauthilus Policy and retry-result lifecycle

Rspamd calls only the existing generic Nauthilus
`POST /api/v1/policy/decisions` operation. It submits target
`dkim2/accept-message-instance`, validated verifier-owned local `dkim2.*`
attributes, and bounded Rspamd-owned local `rspamd.*` observations. It never
submits caller-assessed reputation, provider facts, plugin facts, Redis state,
raw addresses, or message content. The exact SMTP peer IP is mandatory request
data but is prohibited from ordinary logs, metrics, traces, and diagnostics.

The Redis entry has one absolute deadline and the states `provisional`,
`armed`, and `claimed`. Every transition is atomic and owner-bound:

- a miss calls dkim2d and writes an eligible validated response provisionally;
- a final soft reject or greylist arms that response for an SMTP retry;
- an armed retry obtains one bounded claim lease and reuses the response;
- another retry while provisional or actively claimed fails temporarily;
- terminal accept/continue and every permanent reject consume the entry;
- an expired claim may be reclaimed before the unchanged absolute deadline.

The dedicated Redis ACL requires only the key pattern
`~dkim2:retry:v1:*`, script loading/execution, and the commands used inside the
script: `TIME`, `EXISTS`, `HMGET`, `HSET`, `DEL`, and `PEXPIREAT`. Confirm the
exact ACL syntax against the deployed Redis/Valkey version and prove script
reload after `SCRIPT FLUSH`; do not grant broad keyspace access.

The cache identity is a versioned HMAC over length-prefixed exact inputs: SMTP
peer, message bytes, sender path, recipient count and original ordered recipient
paths including duplicates, Draft-06 identifier, and verifier projection
schema, plus the immutable configured authority generation. Do not replace it
with the Rspamd task digest or greylist hashes. Rotate the authority generation
before activating any authority change; old entries then become unreachable
without deleting Redis data.

There is an unavoidable crash interval after dkim2d commits replay state and
before Rspamd receives the provisional Redis acknowledgement. Alert on this
condition and preserve evidence. Redis durability, ACLs, capacity, replication
and failover consistency, TTL alignment, backup policy, and monitoring are
operator responsibilities; replay protection must not be weakened to conceal
an infrastructure failure.

## Rollback

Rollback is configuration-only and does not require deleting daemon data:

1. Remove or stop loading `$CONFDIR/modules.local.d/dkim2.conf`.
2. Run `rspamadm configtest`.
3. Reload or restart Rspamd.
4. Send unsigned and DKIM2-bearing probes and confirm that `DKIM2_CHECK` is no
   longer present.
5. Leave replay storage and `dkim2d` state intact for investigation or another
   adapter. Remove protected capability files only through the daemon's normal
   generation-retirement procedure.

Never delete replay data as part of an adapter rollback. Preserve evidence if
the rollback follows a verification or policy incident.

## Security checklist

- Loopback, or TLS 1.3 on a dedicated private service network; no plaintext private
  mode and no published or proxied daemon port.
- Internal-PKI chain and exact service-name verification are active.
- Exact protected process capability; no secret output or copied encoding.
- Separate protected retry-HMAC and Policy-Basic files, plus an explicitly
  rotated non-secret authority generation; no secret in UCL,
  environment variables, logs, traces, metrics, or diagnostics.
- Dedicated Redis ACL/key prefix, bounded absolute TTL, durable capacity, and
  alerting for provisional-store and finalizer failures.
- `failure_mode = "tempfail"` for production enforcement.
- Real MTA envelope and message-fidelity qualification completed.
- Daemon disposition is authoritative; no score-based recreation.
- Nauthilus uses only the generic Policy API and can narrow but never widen the
  eligible daemon result.
- Exact `task:get_from_ip()` evidence is present and redacted from ordinary
  observability output.
- Compliance symbols remain zero-score and option-free.
- Authentication-Results ownership and module ordering are explicit.
- Dedicated `postfix_dsn` signer retained for locally generated bounces.
- Capability rotation and rollback tested without deleting replay state.
