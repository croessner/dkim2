# Continuous Integration

GitHub Actions execute repository-owned Make targets. They do not define a
second build or test system.

## Workflows

| Workflow | Purpose | Command |
| --- | --- | --- |
| `Guardrails` | Go quality, unit/race tests, builds, generated files, direct vendor resolution and boundaries | `make guardrails` |
| `Conformance` | Portable Draft-04 protocol conformance | `make check-conformance`, `make conformance` |
| `Public Mirror` | One-way branch and tag synchronization from the canonical repository | target-scoped GitHub App installation token |
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

- the four expected workflow concerns;
- immutable Action pins;
- no package, attestation, or OIDC publication authority outside `release.yml`;
- no `github.ref_protected` release dependency;
- no privileged or repository-specific CI temporary-filesystem lifecycle;
- no Postfix or Exim E2E workflow; and
- no implicit `latest` image tag.

Normal workflows have read-only repository authority. Only the stable Release
publish job receives package write permission. The Public Mirror workflow is
inert in the canonical repository and disables all permissions on its built-in
`GITHUB_TOKEN`. In `github.com/go-dkim2/dkim2`, it uses the SHA-pinned
`actions/create-github-app-token` Action to create a short-lived installation
token for the private `DKIM2 Public Mirror` GitHub App. The token is explicitly
limited to the single `go-dkim2/dkim2` repository and requests only
`contents: write` plus `workflows: write`; the latter is required because exact
branch and tag synchronization includes reviewed changes below
`.github/workflows/`. GitHub also grants the App its mandatory implicit
`metadata: read` permission. The Action revokes the installation token after
the job, and GitHub otherwise limits its lifetime to one hour.

The App is owned by `go-dkim2`, has no webhook or event subscriptions, and is
installed only on `go-dkim2/dkim2`. Its client ID is the repository variable
`DKIM2_MIRROR_APP_CLIENT_ID`; its private key is the repository secret
`DKIM2_MIRROR_APP_PRIVATE_KEY`. Neither credential exists in the canonical
repository. `make check-ci` enforces the exact Action identity, credential
allowlist, repository scope, permission pair, built-in-token denial, and
post-job token revocation. The workflow clones the public canonical repository
before creating the token and exposes it only to the target-push step. The App
has no package, attestation, OIDC, secret-management, organization, or
canonical-repository authority.

Canonical branch rewrites are synchronized explicitly because Dependabot and
other automation may replace their own branch history. Tags remain
non-forced: published tag identities are immutable and a rewrite must fail
visibly instead of being copied silently.

GitHub's indivisible `contents: write` permission also includes releases and
merges inside the target repository even though this workflow performs only Git
ref pushes. This is an explicit target-only residual permission: the App is not
installed on the canonical repository, has no package authority, and the
public mirror can be reconstructed entirely from canonical refs if the target
credential is ever compromised.

Because App-authenticated pushes are ordinary repository writes, a changed
`main`, `features`, or `release/**` ref may start the mirror repository's own
Guardrails or Conformance workflow. The Public Mirror workflow has no push
trigger, so synchronization cannot recursively invoke itself.

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
