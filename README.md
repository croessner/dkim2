# DKIM2 Reference Implementation

This repository is an early project scaffold for a Go reference implementation
of DKIM2 based on `draft-ietf-dkim-dkim2-spec-02`.

The first design goal is precision: the core implementation must work from a
controlled RFC 5322 message representation, preserve wire-significant details,
and keep adapter behavior separate from the protocol engine.

Current contents:

- `docs/ARCHITECTURE.md`: initial architecture and milestone plan.
- `AGENTS.md` and `POLICY.md`: repository development rules and engineering
  policy.
- `Makefile` and `.golangci.yml`: first local guardrail skeleton.
- `go.work`: local development workspace.
- `lib`: standalone DKIM2 library module. The current module path is a local
  placeholder; the intended public namespace is expected to be in the
  `github.com/go-dkim2/...` family, with `github.com/go-dkim2/libdkim2` as the
  likely library path.
- `cmd/dkim2d`: standalone HTTP/JSON daemon module.
- `cmd/dkim2-milter`: standalone Milter adapter module.
- `cmd/dkim2ctl`: standalone OpenAPI-backed client and test-client module.
- `lib/internal/*`: planned internal implementation boundaries for the library.
- `docs/specs/openapi`: planned source-of-truth OpenAPI contract.
- `testdata/vectors`: planned conformance and regression vectors.

The library module path and command module paths are provisional and must be
confirmed before a public release.

Useful verification commands:

```text
go test ./lib/...
go test ./cmd/dkim2d/...
go test ./cmd/dkim2-milter/...
go test ./cmd/dkim2ctl/...
make test
```
