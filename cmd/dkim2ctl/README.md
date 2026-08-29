# dkim2ctl

`dkim2ctl` is the local OpenAPI-based test and conformance client for
`dkim2d`. It deliberately has no operator mutation commands or generic HTTP
sender.

The client accepts only canonical loopback HTTP authorities, disables proxies,
redirects, cookies, compression, retries, and connection reuse, and emits
stable content-free JSON Lines with bounded duration buckets rather than exact
timings. Health, readiness, process, sign, revise, and delivery-status sign calls use the generated
OpenAPI client and DTOs. Negative cases are restricted to a closed
contract-test mutation vocabulary. The authoritative HTTP contract remains
[`docs/specs/openapi/dkim2d.yaml`](../../docs/specs/openapi/dkim2d.yaml), and
the production path starts in
[`docs/operator/postfix-compose.md`](../../docs/operator/postfix-compose.md).

Commands:

```text
dkim2ctl smoke [--expect-ready=true|false]
dkim2ctl fixture validate PATH...
dkim2ctl fixture run PATH...
```

Global options:

```text
--server-url http://127.0.0.1:8080
--timeout 10s
--capability-file /absolute/protected/path
--sign-capability-file /absolute/protected/sign-path
--revise-capability-file /absolute/protected/revise-path
--dsn-sign-capability-file /absolute/protected/dsn-sign-path
--output jsonl
```

`fixture validate` is offline and never reads the capability or opens a
network connection. `fixture run` validates every path and case before doing
either. Authenticated process and negative cases require a regular,
effective-user-owned, single-link 32-byte route capability file with mode
`0400` or `0600`. Sign, revise, and `sign_dsn` fixtures require their corresponding
distinct capability options. A `sign_dsn` fixture contains the byte-preserving
outer DSN message, exact null outer envelope, and tenant; it has no caller-
selected fidelity. The Postfix-exclusive route and its dedicated capability
attest the representation. Its expected response operation is `delivery_status`.
The daemon derives the domain only from verified embedded `d=` evidence.
Credentials, raw messages, envelope values,
paths, URLs, headers, response bodies, and raw errors never enter output.

Checked draft-versioned examples live under
`cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-06/`. Validate the
complete offline set without protected-file or network access:

```text
dkim2ctl fixture validate cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-06/*.json
```

Their expectations are allowlisted typed projections rather than response
snapshots. `dkim2ctl smoke` is the non-mutating live health/readiness check;
authenticated fixture execution is appropriate only after selecting the exact
route capability files for the test deployment.

Stable exits are `0` for a complete match and `2` through `8` for usage,
fixture, capability, transport, response-contract, expectation-mismatch, and
internal-invariant failures respectively.

Build and verify through the repository targets:

```text
go build ./cmd/dkim2ctl
go test ./cmd/dkim2ctl/...
make check-openapi
make guardrails
```
