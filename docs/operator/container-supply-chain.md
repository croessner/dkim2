# Container Build And Supply-Chain Verification

Container delivery is product policy. It does not add requirements to the
DKIM2 protocol drafts.

## Build contract

`build/container/Dockerfile` owns the closed `dkim2d`, `dkim2-milter` and
`dkim2ctl` targets. Final images are `scratch` images, run as numeric UID/GID
`2000:2000`, and contain only the selected product binary, the project license
and deterministic third-party notices. They contain no shell, package manager,
compiler, source tree, cache or test material.

Build metadata is limited to:

- a stable version or `0.0.0-dev`;
- the exact 40-character source revision;
- `SOURCE_DATE_EPOCH` and its UTC creation timestamp; and
- clean/dirty source state.

Builds use the checked-in vendor tree, `CGO_ENABLED=0`, `-trimpath`, no embedded
VCS metadata and an empty Go build ID. Linux amd64 and arm64 are the supported
image platforms. Runtime images remain non-root and read-only; deployments add
only explicitly required bounded writable mounts.

The local build and runtime checks are:

```text
make product-binaries
make check-images
make images-multiarch
make container-smoke
```

These commands keep outputs under ignored `.artifacts/` and do not publish.
The individual release-evidence and aggregate validation targets are:

```text
make image-sbom
make image-provenance
make image-vulnerability
make check-container-release
make release-guardrails
```

They remain local validation commands; only the release workflow receives
publication authority.

## Stable publication

`.github/workflows/release.yml` is the only stable GHCR publication path. It is
triggered by a published, non-draft, non-prerelease GitHub Release and requires:

- a stable semantic version;
- an annotated tag;
- the tag, checkout and release to identify the same commit;
- a clean source tree; and
- successful `make release-guardrails`.

The workflow uses pinned standard Docker Actions to build and push each product
for linux/amd64 and linux/arm64. BuildKit emits SBOM and provenance attestations,
bound to the exact registry digest. The pinned Trivy scanner blocks unfixed
high/critical vulnerabilities, and a hardened runtime smoke uses the exact
published digest. Only the exact version tag is published. `latest` is never
created implicitly.

The release job alone receives `packages: write`. Pull requests, branch
pushes, conformance and adapter integration jobs cannot publish packages. The
repository is private and user-owned, so the unavailable GitHub repository
attestation API is not requested; the GHCR subject retains BuildKit SBOM and
maximum provenance attestations.

## Internal development images

The separately approved `publish-dev-images` target remains an internal,
digest-authoritative development path for
`docker.roessner-net.de/mail`. It is not a stable release path and requires an
explicit invocation gate:

```text
DKIM2_DEV_PUBLISH_APPROVED=true make publish-dev-images
```

It publishes no mutable alias and must be deployed by exact digest. Stable
production rollout uses only the GHCR digest produced by the Release workflow.
