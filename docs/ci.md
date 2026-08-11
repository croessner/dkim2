# Continuous Integration

DKIM2 keeps ordinary validation and trusted publication as separate GitHub
Actions authority domains. Pull requests, branch pushes, schedules, and manual
validation runs never receive package, OIDC, or attestation write permission.

## Ordinary validation lanes

| Workflow | Scope | Repository command |
| --- | --- | --- |
| `Guardrails` | Complete local quality policy, including format, vet, lint, unit, race, generated artifacts, vendor, vulnerability, boundary, datasource, and CI checks | `make guardrails` |
| `Unit tests` | Fast multi-module Go and Exim C harness feedback | `make test` |
| `Conformance` | Portable and real Postfix conformance plus bounded security evidence | focused conformance and security targets |
| `Container evidence verification` | Non-publishing multi-architecture container, SBOM, vulnerability, provenance, runtime, and reproducibility evidence | `make check-container-release` |
| `CodeQL` | Independent GitHub Actions, Go, and Exim C/C++ analysis | CodeQL hosted analysis |

The ordinary workflows run for `main`, `features`, and `release/**` pushes and
pull requests. Each can also be dispatched manually. Concurrency groups cancel
an obsolete run for the same branch or pull request, while unrelated refs keep
their independent evidence.

Every third-party action uses a reviewed full commit SHA. `make check-ci` runs
`actionlint` and enforces the expected action identities, Go 1.26.5 patch level,
branch scope, least-privilege permissions, concurrency policy, and release-gate
wiring. Dependabot proposes weekly GitHub Actions pin updates against
`features`; each update must include the corresponding reviewed CI-contract
change.

## Stable release gate

`make check-container-release` deliberately proves only container evidence and
has no publication authority. `make release-guardrails` combines the complete
repository guardrails, reference closure, and container evidence before the
protected publication workflow may log in to GHCR or request OIDC and
attestation credentials.

The publication workflow remains release-event-only and is additionally scoped
to the `container-release` environment. It does not accept push, pull-request,
manual-dispatch, or reusable-workflow triggers. The immutable tag, digest,
registry readback, SBOM, provenance, and credential-cleanup rules are documented
in [the container supply-chain guide](operator/container-supply-chain.md).

Development-image publication, automatic stable-image refreshes, and a mutable
`latest` alias are intentionally not copied from related repositories. They do
not match DKIM2's candidate-bound and digest-authoritative release model.
