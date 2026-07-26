# Observability Foundation Implementation Specification

Status: implemented and independently reviewed.

Implementation base: `9cf158f27609dbe1116aca136a8e7685cff99902`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` baseline. Telemetry is non-normative:
it cannot define, repair, override, or become input to protocol, DNS, policy,
replay, HTTP, health, or readiness truth.

## Scope And Authority

This increment adds one central secret-safe `log/slog` provider, one
instance-owned OpenTelemetry runtime, one process-local Prometheus registry,
`GET /metrics`, explicit debug modules, injected library observation events,
and lifecycle/redaction/cardinality tests to the existing inbound daemon.

Only executable daemon flows are observed: accepted config, lifecycle,
health/readiness, inbound HTTP, verification, DNS public-key lookup, local
policy, replay coordination, and replay-provider authority. Test-client,
signing, revising, general signing datasources, Milter, Exim, and action-plan
telemetry remain deferred.

Authority order is the pinned drafts for protocol meaning, OpenAPI for HTTP,
architecture and the daemon specification for ownership, then this document
for operational telemetry. The implementation and closeout evidence are
recorded in the ignored execution ledger. This document amends the daemon
resource set only with `GET /metrics`.

## Security And Ownership

`lib/internal/observability` owns closed enums, immutable validated events,
panic containment, and a no-op sink. A minimal public facade exposes only an
injected `Observe(context.Context, Event)` seam. The library imports no slog,
OpenTelemetry, Prometheus, Fx, HTTP, exporter, or command dependency.

`cmd/dkim2d/internal/observability` owns handlers, tracer providers, exporters,
collectors, registries, allowlists, and redaction. App and HTTP packages emit
only facts they own. All dependencies are constructor-injected; no global
logger, tracer provider, propagator, Prometheus registerer, or gatherer changes.
Sink failure or panic is contained and never changes operation results.

Telemetry never carries raw or hashed identities, domains, selectors, senders,
recipients, message/session/request IDs, client addresses, backend identifiers,
messages, headers, signatures, DNS TXT, replay keys, hashes, queries, errors,
credentials, protected paths/values, certificates, or private-key material.
OpenTelemetry trace/span IDs remain protocol identifiers only and are never
copied into logs, attributes, metrics, REST, or CLI output.

## Dependencies

The daemon pins `github.com/prometheus/client_golang v1.23.2` and
`go.opentelemetry.io/otel`, `go.opentelemetry.io/otel/sdk`, and
`go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` at `v1.44.0`.
No HTTP auto-instrumentation is used. Workspace sums and vendor output remain
reproducible; no dependency enters `lib/go.mod`.

The exact OTLP HTTP exporter selects `golang.org/x/net v0.55.0`. Under Go 1.26
that workspace graph makes `go work sync` retain Cobra's pruned indirect
requirements and the four-entry `cmd/dkim2ctl/go.sum`. The workspace guardrail
therefore treats that sum as synchronized metadata; it is not optional drift,
a version downgrade, or a replacement directive.

## Configuration

The stable `dkim2d-config-v1` surface gains:

| Path | Default | Contract |
| --- | --- | --- |
| `observability.logging.level` | `info` | `debug`, `info`, `warn`, `error` |
| `observability.debug.message_shape` | `false` | canonical boolean |
| `observability.debug.dns` | `false` | canonical boolean |
| `observability.debug.replay` | `false` | canonical boolean |
| `observability.tracing.exporter` | `none` | `none`, `otlp_http` |
| `observability.tracing.endpoint` | absent | conditional URL |
| `observability.tracing.ca_file` | absent | conditional protected path |
| `observability.tracing.sample_per_million` | `10000` when enabled | 1..1,000,000 |
| `observability.tracing.export_timeout` | `5s` when enabled | 100ms..10s |

Every path has environment name `DKIM2D_` plus its uppercased underscore form.
No new flags exist. Existing strict merge, placeholder, provenance, scalar,
aggregate-size, unknown-key, stable-path, and redacted-error rules apply.

Exporter `none` forbids explicit endpoint, CA, sampling, or timeout leaves and
builds no SDK processor. `otlp_http` requires endpoint and CA. The endpoint is
exactly `https` to canonical `127.0.0.1` or `[::1]`, a canonical nonzero port,
and `/v1/traces`; userinfo, query, fragment, zones, mapped IPv6, hostnames,
proxy, redirects, arbitrary headers, and compression overrides are forbidden.
TLS uses the endpoint IP, supplied CA pool, and TLS 1.3 minimum.

The CA is a direct child of the selected protected generation and inherits
same-generation descriptor ownership, modes 0400/0600, link-count-one, local
filesystem, exact-EOF, metadata-equality, and redaction rules. It is capped at
1 MiB and accepts only nonempty `CERTIFICATE` PEM blocks. Disabled tracing
does not open it. Unknown debug keys fail; identity, network, and datasource
debug modules and keyed-hash configuration do not exist here.

## Structured Logging

One central bounded JSON slog handler writes serialized records to owned
stderr, with UTC RFC3339Nano time, configured level, no source, fixed message
equal to event ID, and 4 KiB record cap. Allowed keys are:

```text
time level msg event_id operation result verdict reason_class error_class
draft policy_mode route method status_class replay_state disposition
lifecycle_state ready tracing_exporter debug_module duration_bucket
message_size_bucket recipient_count_bucket signature_count_bucket
chain_length_bucket dns_result cache_result replay_store_result
```

Unknown keys/groups, `slog.Any`, `LogValuer`, bytes, errors, URLs, paths, and
arbitrary strings are rejected before encoding. Exact event IDs are
`config.accepted`, `lifecycle.transition`, `readiness.transition`,
`http.request.completed`, `process.completed`, `dns.lookup.completed`,
`replay.coordinate.completed`, and `telemetry.export.failed`.

DNS and replay detail events require their debug module. `message_shape` adds
only the four bucket fields to process completion. Exporter error classes are
`timeout`, `transport`, `tls`, `encoding`, `shutdown`, or `internal`; raw
errors are discarded.

## Library Events And Tracing

Library event kinds are exactly `verify.completed` and
`dns.lookup.completed`. Immutable accessors expose only closed operation,
result, reason/error, draft, algorithm-family, cache-result, duration-bucket,
and enabled message-shape bucket facts. There are no maps, variadic
attributes, raw strings/counts/durations, queries, identities, or errors.
The no-op sink is the default.

Context propagates only through existing `context.Context` calls. Inbound
trace headers are ignored and cleared; the daemon creates a fresh server root.
The instance-owned provider uses resource `service.name=dkim2d`,
`service.namespace=dkim2`, and the pinned draft. No environment, host, process,
container, user, or command detector runs.

Exporter `none` injects no-op tracing and performs no network I/O. OTLP uses
parent-based ratio sampling, queue 2,048, batch 256, delay 1s, configured
timeout, no gzip/proxy/redirects, and protected TLS. Overflow drops spans,
increments a bounded drop counter, and never blocks protocol work/readiness.

Exact spans are `dkim2d.http.request`, `dkim2d.process`, `dkim2.verify`,
`dkim2.dns.lookup`, `dkim2.policy.evaluate`, `dkim2.replay.coordinate`, and
`dkim2.replay.store`. Attributes are closed result/policy/replay facts plus
`http.request.method`, `http.route`, and integer
`http.response.status_code`. No exact duration/count/size, endpoint, query,
error description, exception, event payload, or identity attribute exists.

Protocol failures, policy rejection/tempfail, replay detection, and HTTP 4xx
are completed outcomes with unset span status. Internal invariants, required
storage unavailability, construction failure, and HTTP 5xx set Error without
description. Cancellation/deadline use only closed error classes.

## Prometheus

One fresh registry registers only:

| Metric | Type | Labels |
| --- | --- | --- |
| `dkim2d_readiness` | gauge | none |
| `dkim2d_http_requests_total` | counter | operation,status_class |
| `dkim2d_http_request_duration_seconds` | histogram | operation |
| `dkim2d_http_in_flight` | gauge | operation |
| `dkim2d_process_total` | counter | result,verdict,replay_state,disposition |
| `dkim2d_process_duration_seconds` | histogram | result |
| `dkim2d_policy_decisions_total` | counter | verdict,reason_class,policy_mode |
| `dkim2d_dns_lookups_total` | counter | dns_result,cache_result |
| `dkim2d_dns_lookup_duration_seconds` | histogram | dns_result |
| `dkim2d_replay_coordinates_total` | counter | replay_state,result |
| `dkim2d_replay_coordinate_duration_seconds` | histogram | replay_state |
| `dkim2d_observation_dropped_total` | counter | signal,reason_class |

Allowed labels are exactly those named above; all values are literal closed
enums. HTTP/process buckets are `.005,.01,.025,.05,.1,.25,.5,1,2.5,5,10,30,60`
seconds; DNS/replay buckets are
`.001,.0025,.005,.01,.025,.05,.1,.25,.5,1,2,5`. Summaries, exemplars, native
histograms, dynamic names, const labels, exact sizes/counts, and standard
runtime/process collectors are forbidden.

OpenAPI adds operation `getMetrics` for `GET /metrics`. It shares existing
loopback authority, connection, Host, target, protocol, Date, close, and
response-filter rules. It accepts no query, body, Content-Type, conditional,
capability, or trace-context input. HEAD gets 405 with `Allow: GET`.

Success is 200 with
`text/plain; version=0.0.4; charset=utf-8`, `Cache-Control: no-store`, and a
256 KiB cap. Gather/encoding failure uses bounded 500 JSON; overflow cannot
yield partial success. Scrapes are deterministic, untraced, nonrecursive, do
no DNS/replay/policy/protocol work, and do not require readiness.

## Lifecycle, Tests, And Completion

Startup validates config/protected material, constructs logger/registry/tracer
and observer bridges, binds existing providers/listener, starts exporter work,
activates HTTP, then publishes readiness. Invalid config/CA, duplicate
collectors, or exporter construction fails before listener acquisition.
Exporter reachability is never readiness. Readiness gauge starts at 0, becomes
1 only with existing readiness, returns to 0 before stop/fatal admission close,
and never rises again.

Stop rejects requests, drains HTTP, joins operation spans, then shuts the
provider once with a fixed 5s child budget inside existing shutdown bounds.
Telemetry failure never changes a protocol result or serving readiness.

Tests prove exact config/protected behavior; event/field/label/span/metric
allowlists; bucket and cardinality bounds; context parentage; no global state;
panic/exporter isolation; endpoint route precedence; deterministic capped
output; lifecycle/readiness races; dependency direction; and marker
non-disclosure across logs, traces, metrics, responses, formatting, panics,
and test diagnostics.

Fuzz event validation, slog admission, metric labels, and OTLP projection for
at least ten seconds each after the last change. Final unchanged-snapshot gates
are focused normal/race tests, all fuzz targets, OpenAPI/workspace/vendor
checks, test, vet, lint, race, govulncheck, and guardrails.

Independent review must find no unresolved draft/RFC interference, leakage,
cardinality, global-state, dependency, lifecycle, exporter-isolation, or
OpenAPI defect. Completion requires exactly one project-formatted commit,
clean index/worktree, and ignored unstaged `temp/`.
