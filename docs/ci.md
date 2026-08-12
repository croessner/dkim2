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
| `CodeQL` | Independent GitHub Actions, Go, and Exim C/C++ analysis | Retained local SARIF artifacts |

The ordinary workflows run for `main`, `features`, and `release/**` pushes and
pull requests. Each can also be dispatched manually. Concurrency groups cancel
an obsolete run for the same branch or pull request, while unrelated refs keep
their independent evidence.

[`build/ci/toolchain.json`](../build/ci/toolchain.json) is the single authority
for the hosted-runner image, Go patch release, every third-party Action identity
and commit, the Go-installed CI tools, and the Valkey conformance fixture.
GitHub requires literal values in `uses:` and `go-version`, so workflow files
contain reviewed mirrors. `make check-ci` runs the manifest-pinned `actionlint`
and rejects every mirror that differs, every unregistered Action repository,
and every reintroduced inline tool version. Workflows install Go tools only
through `scripts/install-ci-tools.sh`.

The content-addressed image and publication binaries retain their narrower
authorities in `build/container/image-tools.json` and
`build/container/publication-tools.json`; the central manifest indexes both
instead of copying their versions or hashes. Their installers read those
allowlists rather than embedding a second version. Dependabot proposes weekly
Action updates against `features` and groups all CodeQL sub-actions so `init`,
`autobuild`, and `analyze` cannot move to different versions. A reviewed update
must change the central manifest and every required literal mirror together.

The conformance, full guardrails, and protected publication lanes build the
same immutable Valkey 9.1.0 source commit through
`scripts/install-valkey-ci.sh`. This keeps the portable conformance dependency
identical wherever `make conformance` can run.

Each Linux job creates one owner-only temporary root directly below the hosted
runner's home directory before executing repository code. This avoids the
group-writable ancestry of the standard Actions workspace and `/tmp` for tests
that intentionally enforce protected-path ownership. The directory is removed
by an exact, fail-closed cleanup step. Artifact uploads use narrow evidence
paths and explicitly include the hidden `.artifacts` ancestor; the entire
working artifact tree is never uploaded.

The CodeQL lane deliberately sets `upload: never` and retains its SARIF through
the ordinary artifact service. It therefore provides analysis on repositories
without GitHub Advanced Security and needs no `security-events: write`
permission. The Exim build keeps its ordinary AddressSanitizer and
UndefinedBehaviorSanitizer run; only the CodeQL-instrumented C build skips that
nested sanitizer sub-run because the two compiler runtimes cannot be safely
preloaded together.

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
