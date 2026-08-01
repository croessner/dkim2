# Container Build And Supply-Chain Verification

The container delivery is product policy. It does not add requirements to
`draft-ietf-dkim-dkim2-spec-04` or the tested historical
`draft-chuang-dkim2-dns-04` DNS baseline.

## Build contract

`build/container/Containerfile` has closed `dkim2d`, `dkim2-milter`, and
`dkim2ctl` targets. `build/container/build-inputs.json` is the central closed
policy for the digest-pinned build-only BusyBox metadata validator, Go 1.26.5
builder, and BuildKit executor. The minimal validator rejects hostile build
metadata before source or vendor bytes are copied and emits one `/validated`
dependency consumed by every product build. The final stages are `scratch`,
run as numeric UID/GID `2000:2000`, and contain one product binary plus the
read-only deterministic third-party notice bundle at
`/usr/share/licenses/dkim2/THIRD_PARTY_NOTICES.txt`. The bundle preserves the
pinned Go toolchain license and patent notice as well as license and notice
files from the checked-in vendor tree. Images contain neither the validation
marker nor a shell, package manager, compiler, source, cache, or test material.

Build metadata is accepted only through the closed version, 40-character
lowercase source revision, clean/dirty state, and decimal
`SOURCE_DATE_EPOCH` fields. Builds use the checked-in workspace vendor tree,
include every `go.work` module manifest needed to load that workspace,
`CGO_ENABLED=0`, `-trimpath`, an empty Go build ID, and no VCS embedding. Linux
`amd64` and `arm64` are the only image platforms.

The checked OCI labels are source, revision, version, creation time, vendor,
documentation, license, product title, and product description. Their exact
allowlist and values are enforced by the image policy tool from the
Containerfile and candidate metadata; this guide does not maintain a parallel
label table. The production deployment and lifecycle entry point is
[`docs/operator/postfix-compose.md`](postfix-compose.md).

The repository does not currently declare a root project license. The
`org.opencontainers.image.licenses=NOASSERTION` label is therefore a deliberate
non-assertion, and the third-party bundle must not be interpreted as granting a
license for the DKIM2 project itself.

The byte-reproducibility claim covers the six product binaries and their
notice bundles when source, toolchain, architecture, vendor tree, and metadata
are identical. OCI output is compared semantically by descriptors, config,
filesystem inventory, ownership, modes, entrypoint, user, and labels. OCI
archive byte identity is not claimed because compression and BuildKit
attestation ordering can differ.

Run:

```text
make product-binaries
make check-images
make images-multiarch
```

The OCI layouts remain under ignored `.artifacts/`; these commands neither
push nor sign.

An explicitly approved internal development publication uses the separate
`publish-dev-images` target. It is not a release path and accepts only a clean,
untagged commit whose build metadata version is `0.0.0-dev`. The fixed registry
is `docker.roessner-net.de/mail`; the sole content-bound tag is derived as
`0.0.0-dev-<full-40-hex-commit>`. No mutable alias is written. Before any
registry mutation, the target rebuilds all three products from its private
descriptor-bound candidate context, exercises their runtime policy, validates
every local index and platform descriptor, and preflights all three final tags.
An existing identical tag is an idempotent success; an existing different tag
or an ambiguous registry lookup during the complete preflight fails closed
before any push. This client-side check does not establish server-side tag
immutability or remove the race between preflight and publication. The target
then
publishes `dkim2d`, `dkim2-milter`, and `dkim2ctl` for Linux amd64 and arm64,
compares every pushed index and platform manifest with the preflighted local
OCI evidence, and reads the tag back by digest. Registry publication across
three repositories is not transactional, so a transport failure can require an
idempotent retry; no local or tag-collision preflight failure can cause a
partial push. Both this path and the
protected stable publisher use an explicit registry exporter with OCI media
types and `SOURCE_DATE_EPOCH` timestamp rewriting. These settings are part of
the digest contract: the registry index, platform manifests, configs, and
layers must be byte-identical to the locally inspected OCI subject. The
development path requires existing Docker credentials and the explicit
invocation gate:

```text
DKIM2_DEV_PUBLISH_APPROVED=true make publish-dev-images
```

The resulting ignored `.artifacts/dev-publication-subjects.json` binds the
exact revision, candidate snapshot, content-bound tag, repositories, and index
digests. Internal development publication does not create trusted GitHub OIDC
attestations and must be deployed only by exact digest. Stable releases remain
exclusive to the protected release workflow below.

## SBOM, provenance, and vulnerability evidence

BuildKit's implicit SBOM and provenance exporters are disabled so their
version-dependent ordering cannot be mistaken for reviewed evidence. The
repository-owned targets produce and validate explicit evidence instead:

```text
make image-tools
make image-inspect
make image-runtime
make image-sbom
make image-provenance
make image-vulnerability
make image-reproducibility
make image-evidence
make check-release
```

The local SBOM producer is Syft 1.46.0 and emits SPDX 2.3 JSON. The local
scanner is Trivy 0.72.0. Tool upgrades are explicit reviewed changes. A
vulnerability database update is allowed only as part of the scanner's
documented bounded update step. Each offline scan uses a private copy-on-write
snapshot created from no-follow, owned, one-link descriptors. The scanner
executable, OCI layout, metadata, and database bytes are therefore detached
from mutable workspace paths without copying the 2 GiB-bounded database into
memory or into a second full allocation. The source layout, database
descriptors, tool identity, and candidate are checked before and after every
scan. Scanner execution has a fixed timeout, a minimal credential-free
environment, bounded output and diagnostics, and no network update path.

Ignored release evidence contains only the portable projection: candidate and
tool identity, the fixed database limit, metadata/database sizes and SHA-256
digests, the shared scan time, and the validated database schema and update
timestamps. The guard rejects a database that is expired at scan or evidence
verification time, more than 48 hours behind its update time, or implausibly
future-dated beyond five minutes. Device, inode, owner, mode, and filesystem
timestamps remain private guard state and are never serialized. Every
reported vulnerability fails the target irrespective of its severity label;
`govulncheck` remains an independent required Go reachability gate.

The daemon keeps the upstream, replacement-free go-ldap v3.4.14 module
contract. A repository-owned, deterministic vendor hardening step relocates
the sole required `golang.org/x/crypto/md4` package, including its BSD license
and patent notice, under go-ldap's `internal` boundary. It removes the package
and source tree while retaining only the explicit module requirement metadata
needed for Go's vendor-consistency check. The transform accepts only the exact
reviewed source-tree, import, and module-manifest shape; unexpected files or
metadata fail closed. Both `make vendor` and
`make check-vendor` apply the same transform, so the checked-in delta remains
reproducible without a local module fork or `replace` directive. This keeps
optional upstream NTLM helpers source-compatible without placing the
unmaintained OpenPGP packages covered by `GO-2026-5932` in any product image.
DKIM2 exposes only simple LDAP bind over verified TLS; it does not expose NTLM
configuration.

The daemon's MySQL/MariaDB adapter uses the upstream
`github.com/go-sql-driver/mysql` v1.10.0 module and its Ed25519 helper
dependency. The connector is built from typed fields only: verified TLS is
mandatory, while DSN input, local infile, multi-statements, plaintext and old
password fallbacks, and interpolated parameters remain disabled. Both modules
are included in the reproducible workspace vendor check and image SBOM.

Provenance uses an in-toto Statement v1 with the SLSA provenance v1 predicate
and binds the exact local OCI archive subject, platform descriptors, source
revision, metadata-validator image, builder image, and BuildKit image from the
central input policy. Local and ordinary-CI provenance is explicitly
`local-test`, demonstrates only the data contract, and is never trusted
publication evidence.

Pull requests and ordinary pushes have `contents: read` only. They receive no
package write, OIDC, registry credential, or signing authority.
`.github/workflows/container-publish.yml` is the separately authorized
publication route. It is triggered only by a published, non-draft,
non-prerelease protected release tag, is additionally gated by the
`container-release` environment, and fixes the GHCR namespace. The workflow
repeats the complete local release verification, builds from a private
descriptor-bound candidate context, compares both published platform
manifests with the reviewed local subjects, and reads the pushed index and
every version alias back by digest. The pinned `actions/attest` producer then
uses release-job-only OIDC and attestation permission to sign provenance for
each exact image-index digest and SPDX evidence for each exact platform
manifest. The workflow verifies repository, signer-workflow, source revision,
source ref, hosted-runner policy, subject digest, and predicate type with
the SHA-256-pinned GitHub CLI 2.94.0 verifier. The exact attestation action,
archive, extracted verifier binary, and SPDX predicate identities live in
`build/container/publication-tools.json`; the preinstalled runner `gh` is not
trusted. `latest` is never produced or used as deployment authority. Defining
this route does not publish anything; publication occurs only when maintainers
separately create the protected release and approve its environment gate.
