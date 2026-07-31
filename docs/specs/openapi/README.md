# DKIM2 Daemon OpenAPI Contract

`dkim2d.yaml` is the authoritative REST contract for the daemon. The current
contract exposes metrics, liveness, readiness, inbound verification/policy/replay
processing, originator signing, and ordinary-transit revision. Each authenticated
route uses a distinct generation-bound local capability in the implementation even
though all three share the contract's `X-DKIM2-Capability` header shape.
Adapter-specific message fidelity values describe how message bytes were obtained;
they do not create adapter-specific routes or parallel DTOs.

The repository pins
`github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen` at `v2.7.1`.
Generation must run through the repository-local `tools` module and the root
Makefile:

```text
make generate-openapi
make check-openapi
```

The daemon server, test-client, Milter client/test-server, and Exim
client/test-server configurations intentionally contain no output path.
The Makefile supplies absolute input, configuration, and output paths so a
different working directory cannot redirect generated artifacts.

The daemon server configuration generates models, the embedded specification,
the standard-library HTTP server, and the strict-server boundary. Client
configurations generate models and generated clients for `dkim2ctl`, the
Milter adapter, and the Exim adapter. Independent strict test servers support
the Milter and Exim public integration boundaries. All configurations preserve
the original lower-camel operation identifiers.

The target-specific overlays change only the Go bindings for the protected raw
message, reverse path, and forward paths. Each generated package uses its own
opaque `wire.ProtectedString`; generated DTOs are never shared with or imported
by the protocol library.

Generated server and client code, generated protected-wire wrappers, and their
generation guards are committed. `make check-openapi` must regenerate into a
private temporary directory, compare output byte-for-byte, validate the
embedded contract and exact routes, and reject stale type bindings or forbidden
generated-code imports.

Operator configuration, route ownership, and deployment procedures are not
duplicated here. Start with
[`docs/operator/postfix-compose.md`](../../operator/postfix-compose.md), then
use the daemon, Milter, and generated-client component READMEs for their
respective runtime boundaries.
