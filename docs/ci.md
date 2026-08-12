# Continuous Integration

GitHub Actions execute repository-owned Make targets. They do not define a
second build or test system.

## Workflows

| Workflow | Purpose | Command |
| --- | --- | --- |
| `Guardrails` | Go quality, unit/race tests, builds, generated files, vendor and boundaries | `make guardrails` |
| `Conformance` | Portable Draft-04 protocol conformance | `make check-conformance`, `make conformance` |
| `Postfix integration` | Real Postfix/Milter qualification | `make integration-postfix` |
| `Exim integration` | Exim C ABI and supported-version qualification | `make integration-exim` |
| `Release` | Stable quality gate and exact GHCR publication | `make release-guardrails` |

There is no separate unit-test workflow because Guardrails already owns unit
tests. Postfix and Exim integration are independent jobs and are never hidden
inside `make test`. Container publication does not run for ordinary pushes or
pull requests.

## Tool versions and policy

`build/ci/toolchain.json` contains the Go tool and Valkey fixture versions used
by repository scripts. Workflow Actions are pinned directly to reviewed commit
identities. `make check-ci` runs actionlint and enforces only durable policy:

- the five expected workflow concerns;
- immutable Action pins;
- no publication authority outside `release.yml`;
- no `github.ref_protected` release dependency;
- no repository-specific CI temporary-directory lifecycle; and
- no implicit `latest` image tag.

Normal workflows have read-only repository authority. Only the stable Release
publish job receives package, OIDC and attestation write permissions.

## Stable release

The Release workflow accepts only a published, non-draft, non-prerelease
GitHub Release with a stable semantic version. The release name must resolve to
an annotated tag, and that tag must resolve to the exact checked-out commit.

After `make release-guardrails`, standard Docker Actions build and push the
`dkim2d`, `dkim2-milter` and `dkim2ctl` targets from
`build/container/Dockerfile`. Each exact multi-architecture digest receives
BuildKit SBOM/provenance plus GitHub build provenance, is scanned for unfixed
high/critical vulnerabilities, and is smoke-tested by digest. The workflow
publishes the exact stable version only; it does not create `latest`.
