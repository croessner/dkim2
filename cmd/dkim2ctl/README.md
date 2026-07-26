# dkim2ctl

`dkim2ctl` is the local OpenAPI-based test and conformance client for
`dkim2d`. It deliberately has no operator mutation commands or generic HTTP
sender.

The client accepts only canonical loopback HTTP authorities, disables proxies,
redirects, cookies, compression, retries, and connection reuse, and emits
stable content-free JSON Lines with bounded duration buckets rather than exact
timings. Ordinary health, readiness, and process calls use the generated
OpenAPI client and DTOs. Negative cases are restricted to a closed
contract-test mutation vocabulary.

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
--output jsonl
```

`fixture validate` is offline and never reads the capability or opens a
network connection. `fixture run` validates every path and case before doing
either. Authenticated process and negative cases require a regular,
effective-user-owned, single-link 32-byte capability file with mode `0400` or
`0600`. Credentials, raw messages, envelope values, paths, URLs, headers,
response bodies, and raw errors never enter output.

Checked draft-versioned examples live under
`testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/`. Their expectations are
allowlisted typed projections rather than response snapshots.

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
