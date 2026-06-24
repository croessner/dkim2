# dkim2ctl

`dkim2ctl` is planned as the OpenAPI-based client and test harness for
`dkim2d`.

The client should use generated OpenAPI client code for HTTP transport and DTOs.
Hand-written code may provide command UX, output formatting, fixtures, and
operator-friendly diagnostics, but it must not maintain a parallel hand-written
REST model.

