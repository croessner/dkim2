# DKIM2 Daemon OpenAPI Contract

`dkim2d.yaml` is the authoritative REST contract for the daemon. The current
contract exposes metrics, liveness, readiness, inbound verification/policy/replay
processing, originator signing, ordinary-transit revision, and authenticated
outgoing delivery-status signing. Each authenticated route uses a distinct
generation-bound local capability in the implementation. Process, originator
signing, and revision share the contract's `X-DKIM2-Capability` header shape;
delivery-status signing uses `X-DKIM2-DSN-Sign-Capability`.
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

The inbound process operation has two success variants. HTTP 200 carries an
applicable DKIM2 verification with one of the four Draft-04 states plus policy,
replay, disposition, and actions. HTTP 204 is bodyless and means both DKIM2
protocol field families were absent, so verification, DNS, policy, replay, and
mutation were not applicable. Generated server and both client boundaries must
retain this distinction.

The originator sign operation also has two success variants, with independent
local-policy semantics. HTTP 200 carries an applicable signing result and its
closed action plan. HTTP 204 is bodyless and means the authoritative exact
signing policy or profile was absent or inactive, so signing was not applicable
and the message continues unchanged. Datasource ambiguity, unavailability,
degradation, malformed active data, and signing failures are never represented
by this 204 variant.

The delivery-status signing operation requires a strict RFC 3462 report and
separate protected outer and original SMTP contexts. It is intentionally not a
general process route: the daemon first authenticates the embedded original
message's highest `mf=` identity, then applies the separate delivery-status
policy and signing profile. It uses the same 200/204 applicability distinction
as originator signing; malformed or unauthenticated delivery status reports are
explicit failures, not 204 results.

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
