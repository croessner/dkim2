# dkim2d

`dkim2d` is planned as the HTTP/JSON daemon around the DKIM2 core library.

It should remain a thin transport adapter. Verification, signing,
canonicalization, recipe handling, policy evaluation, and DNS key lookup belong
in the standalone `github.com/croessner/dkim2` library module.

This command has its own Go module so future HTTP, configuration, metrics, and
deployment dependencies do not become dependencies of library consumers.

Planned foundation:

- Cobra for command surfaces.
- Viper for configuration loading.
- Typed config validation after decoding and environment expansion.
- Uber Fx for dependency composition and lifecycle.
- OpenAPI-generated server boundary.
- `log/slog` for structured logging.
- OpenTelemetry for traces.
- Prometheus for metrics.
- Concrete datasource providers wired behind library-facing interfaces.
