# DKIM2 Rspamd Policy End-to-End Harness

This fixture exercises the real generic Policy boundary without adding a DKIM2
handler to Nauthilus. It runs the current Nauthilus checkout with the native
`dkim2_reputation` decision fact provider, Rspamd 4.1.5 in Milter mode, Redis,
a deterministic `/v1/process` stub, and the local `miltertest-go` checkout.

Run it through `../run-policy-e2e.sh`. The runner creates all credentials and
certificates in a private temporary directory, uses an isolated Compose project,
and removes the stack and runtime material on exit.

By default, the runner discovers `nauthilus` and `miltertest-go` as sibling
checkouts next to the DKIM2 checkout:

```text
workspace/
  dkim2/
  nauthilus/
  miltertest-go/
```

For another neutral workspace layout, set `NAUTHILUS_REPO` and
`MILTERTEST_REPO` to the respective checkout paths. The runner validates both
locations before creating credentials or starting containers. Set
`POLICY_E2E_PREFLIGHT_ONLY=1` to validate checkout discovery without building
images or starting the stack.

## Real integration scenarios

The runner exercises the following behavior through the real Milter boundary:

| Scenario | Expected proof |
| --- | --- |
| Unsigned message | The DKIM2 producer and Policy endpoint are not called. An unrelated Rspamd greylist action may still defer the message. |
| First signed delivery | DKIM2 and Nauthilus are called, Rspamd returns a temporary greylist result, and the retry cache is armed. |
| Identical retry | Nauthilus is called again, the armed DKIM2 result comes from Redis without another producer call, and the matured greylist permits delivery. The terminal outcome consumes the cache entry. |
| Later duplicate | The consumed entry cannot be replayed locally. Rspamd calls DKIM2 again and honors the producer's replay rejection without calling Policy. |
| Malformed DKIM2 response | Rspamd returns a temporary failure and does not call Policy. |
| Malformed Policy response | Rspamd returns a temporary failure instead of accepting the message. |
| Policy timeout | Rspamd returns a temporary failure after its bounded HTTP timeout. |
| Invalid provider input | The real Nauthilus provider rejects the forwarded request and Rspamd returns a temporary failure. |
| Historical-hop rejection | A producer-bound two-hop chain reaches the real native provider. The target hop is trusted, while the unknown historical signer alone makes Nauthilus deny the message. |
| Oversized retry payload | An armed cache document is replaced with syntactically valid JSON beyond the configured payload bound. The retry fails closed without calling DKIM2 or Policy. |
| Retry identity mismatch | An armed result is presented with the same message content but a different envelope recipient. Rspamd does not reuse it, calls DKIM2 again, and leaves the original identity-bound entry intact. |
| Concurrent retry claim | One retry worker claims the armed entry and is held at the Policy observer. A concurrent worker sees the claim as busy and fails closed; only the winner calls Policy, and its induced timeout safely re-arms the entry. |
| Redis unavailable | Rspamd returns a temporary failure before calling DKIM2 or Policy. |
| Corrupt retry entry | Rspamd fails closed, does not call DKIM2 or Policy, and removes the corrupt entry. |
| Policy rejection | An untrusted RFC 5737 peer is rejected. Repeating the message calls DKIM2 and Policy again, proving that a terminal decision consumed the previous entry. |
| Unrelated Rspamd rejection | Policy still sees the final Rspamd reject action, returns permit, and the unrelated reject remains the final Milter result. The retry entry is consumed. |

## Request contract proof

A test-only TLS observer sits between Rspamd and Nauthilus. It records only the
decoded Policy JSON body and never records the Authorization header. Every
forwarded request is sent to the real Nauthilus server with CA validation and
the `nauthilus-policy` server name.

The request assertion checks the exact SMTP CONNECT peer, target, options, all
resource facts, all environment facts, and every field of every verifier hop.
This includes the bounded Recipe descriptor, custody state, modification and
explosion flags, validation status, algorithms, signer domains, and digests. It
also proves that raw Recipe data, selectors, envelope addresses, the Message-ID,
message body, and credentials are excluded from the Policy document.

The two-hop response is not maintained as an independent hash implementation.
Before Docker starts, a Go overlay test compiles inside the repository verifier
package and invokes the producer's canonical Recipe, projection-binding, and
bound-hop functions. It locks the tracked wire fixture to the same private
producer logic used for real responses, including the empty Recipe lists on the
unchanged origin hop. It also proves that the aggregate custody structure agrees
with the projected hop transitions, so an ordinary chain cannot claim evaluated
next-domain links.

The trusted SMTP peer is `203.0.113.25`. The native plugin permits only the
configured `203.0.113.0/24` contract for the target hop. A separate
`198.51.100.25` peer exercises the real deny path. Both addresses are reserved
documentation ranges.

## Test-layer boundaries

This lane covers transport, TLS, Redis, Milter actions, exact serialization,
the native provider with real processes, identity-bound cache corruption, and
real concurrent Redis claim arbitration between two Milter workers. The
observer-induced timeout is the deterministic synchronization point: it proves
that the second worker competes while the first claim is active, without
depending on scheduler timing. The lane intentionally does not force
every possible Policy action through a synthetic live server response.
Hermetic Lua tests cover finalizer behavior for discard, quarantine, header and
subject mutations, action preservation, retryability, and malformed response
variants. Verifier unit tests cover additional upstream no-call classifications
that cannot be produced deterministically by the single shared golden response.

The deterministic `/v1/process` stub is an explicit proof boundary. This lane
does not claim that its PASS projection was produced by a live `dkim2d`
process. A bounded isolated live-daemon attempt reached healthy `dkim2d` and
Rspamd processes, but the generated signed message ended in a verifier-side
temporary failure before the Policy observer received a request. Because the
daemon intentionally exposes only content-free runtime diagnostics, that run
could not safely distinguish DNS-TXT fixture acceptance from message
wire-fidelity mismatch and is not retained as passing evidence.

## Isolation and secrets

The Compose project, ports, network, Redis instance, and temporary runtime
directory are isolated. The runner does not use a host Redis service. It
generates the bearer token, Redis password, certificate authority, and server
certificate for each run, keeps them in the private runtime directory, and
removes them with the stack on exit. No production credential, host name,
domain, or personal checkout path is embedded in the fixture.
