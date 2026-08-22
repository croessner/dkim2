# Continuous Integration

GitHub Actions execute repository-owned Make targets. They do not define a
second build or test system.

## Workflows

| Workflow | Purpose | Command |
| --- | --- | --- |
| `Guardrails` | Go quality, unit/race tests, builds, generated files, direct vendor resolution and boundaries | `make guardrails` |
| `Conformance` | Portable Draft-04 protocol conformance | `make check-conformance`, `make conformance` |
| `Release` | Stable quality gate and exact GHCR publication | `make release-guardrails` |

There is no separate unit-test workflow because Guardrails already owns unit
tests. Postfix and Exim E2E qualification are intentionally not GitHub Actions
jobs and are never hidden inside `make test`. They remain explicit local or
operator commands: `make integration-postfix`, `make integration-exim`, and
`make qualification-exim`. Container publication does not run for ordinary
pushes or pull requests.

## Tool versions and policy

`build/ci/toolchain.json` contains the Go tool and Valkey fixture versions used
by repository scripts. Workflow Actions are pinned directly to reviewed commit
identities. `make check-ci` runs actionlint and enforces only durable policy:

- the three expected workflow concerns;
- immutable Action pins;
- no publication authority outside `release.yml`;
- no `github.ref_protected` release dependency;
- no privileged or repository-specific CI temporary-filesystem lifecycle;
- no Postfix or Exim E2E workflow; and
- no implicit `latest` image tag.

Normal workflows have read-only repository authority. Only the stable Release
publish job receives package write permission.
Historical private module-proof reconstruction is not a normal source-quality
gate; ordinary CI validates the committed vendor tree directly with Go.

## Stable release

The Release workflow accepts only a published, non-draft, non-prerelease
GitHub Release with a stable semantic version. The release name must resolve to
an annotated tag, and that tag must resolve to the exact checked-out commit.

After `make release-guardrails`, standard Docker Actions build and push the
`dkim2d`, `dkim2-milter` and `dkim2ctl` targets from
`build/container/Dockerfile`. Each exact multi-architecture digest receives
registry-bound BuildKit SBOM and maximum provenance attestations, is scanned
for unfixed high/critical vulnerabilities, and is smoke-tested by digest. The
release policy uses the registry-bound BuildKit attestations attached to each
GHCR subject and does not create a second GitHub repository-attestation path.
The workflow publishes the exact stable version only; it does not create
`latest`.
