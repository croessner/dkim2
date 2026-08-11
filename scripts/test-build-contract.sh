#!/bin/sh
set -eu

test_root=.artifacts/build-contract-negative
test ! -e "$test_root"
test ! -L "$test_root"
mkdir -m 0700 "$test_root"
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM
build_context_marker=privacy-build-context-7f3c9a2d
printf '%s\n' "$build_context_marker" >"$test_root/private-marker"

if scripts/build-products.sh .artifacts/escape >/dev/null 2>&1; then
	exit 1
fi
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. >"$test_root/metadata-a.json"
VERSION='v9.9.9/../../escape' \
REVISION=ffffffffffffffffffffffffffffffffffffffff \
SOURCE_DATE_EPOCH=0 \
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. >"$test_root/metadata-b.json"
cmp "$test_root/metadata-a.json" "$test_root/metadata-b.json"
expected_candidate=$(jq -er .candidate_snapshot_sha256 "$test_root/metadata-a.json")
actual_candidate=$(sed -n \
  's/^candidate_snapshot_sha256=\([0-9a-f][0-9a-f]*\)$/\1/p' \
  .artifacts/product-binaries/build-info)
test "$actual_candidate" = "$expected_candidate"
DKIM2_REVISION=hostile-revision \
SOURCE_DATE_EPOCH=hostile-epoch \
DKIM2_CREATED=hostile-created \
  scripts/check-images.sh
if GITHUB_EVENT_NAME=pull_request \
  GITHUB_REF_TYPE=branch \
  GITHUB_REF_PROTECTED=false \
  GITHUB_REPOSITORY=croessner/dkim2 \
  GITHUB_REF_NAME=main \
  GITHUB_TOKEN=untrusted \
  scripts/publish-images.sh >/dev/null 2>&1; then
	exit 1
fi
if DKIM2_DEV_PUBLISH_APPROVED=false \
  DKIM2_DEV_REGISTRY=docker.roessner-net.de/mail \
  scripts/publish-dev-images.sh >/dev/null 2>&1; then
	exit 1
fi
grep -Fq 'registry=docker.roessner-net.de/mail' scripts/publish-dev-images.sh
grep -Fq 'test "${DKIM2_DEV_PUBLISH_APPROVED:-}" = true' \
  scripts/publish-dev-images.sh
grep -Fq 'test -z "$(git status --porcelain --untracked-files=all)"' \
  scripts/publish-dev-images.sh
grep -Fq 'test "${#revision}" -eq 40' scripts/publish-dev-images.sh
grep -Fq 'case "$revision" in *[!0-9a-f]*) exit 2 ;; esac' \
  scripts/publish-dev-images.sh
grep -Fq 'tag="$version-$revision"' scripts/publish-dev-images.sh
! grep -Fq 'short_revision' scripts/publish-dev-images.sh
grep -Fq 'scripts/build-images.sh' scripts/publish-dev-images.sh
grep -Fq 'scripts/inspect-images.sh check' scripts/publish-dev-images.sh
grep -Fq 'scripts/test-image-runtime.sh' scripts/publish-dev-images.sh
test "$(grep -Fc 'for product in dkim2d dkim2-milter dkim2ctl; do' \
  scripts/publish-dev-images.sh)" -eq 3
grep -Fq 'remote_states="$work/remote-states.jsonl"' \
  scripts/publish-dev-images.sh
grep -Fq 'state=present_identical' scripts/publish-dev-images.sh
grep -Fq "LC_ALL=C grep -Eiq '(manifest unknown|not found)'" \
  scripts/publish-dev-images.sh
local_preflight_line=$(grep -nF 'remote_states="$work/remote-states.jsonl"' \
  scripts/publish-dev-images.sh | cut -d: -f1)
registry_export_line=$(grep -nF -- \
  '--output "type=registry,name=$repository:$tag,oci-mediatypes=true,rewrite-timestamp=true"' \
  scripts/publish-dev-images.sh | cut -d: -f1)
test "$local_preflight_line" -lt "$registry_export_line"
remote_preflight_complete_line=$(awk \
  -v start="$local_preflight_line" -v finish="$registry_export_line" \
  'NR > start && NR < finish && $0 ~ /^[[:space:]]*assert_candidate$/ { line = NR }
   END { print line }' scripts/publish-dev-images.sh)
test -n "$remote_preflight_complete_line"
test "$remote_preflight_complete_line" -lt "$registry_export_line"
grep -Fq -- '--platform linux/amd64,linux/arm64' scripts/publish-dev-images.sh
grep -Fq -- '--output "type=registry,name=$repository:$tag,oci-mediatypes=true,rewrite-timestamp=true"' \
  scripts/publish-dev-images.sh
! grep -Fq -- '--tag ' scripts/publish-dev-images.sh
! grep -Fq -- '--push' scripts/publish-dev-images.sh
grep -Fq -- '--output "type=registry,oci-mediatypes=true,rewrite-timestamp=true"' \
  scripts/publish-images.sh
grep -Fq -- '--tag "$repository:$version"' scripts/publish-images.sh
grep -Fq -- '--tag "$repository:$minor"' scripts/publish-images.sh
grep -Fq -- '--tag "$repository:$major"' scripts/publish-images.sh
! grep -Fq -- '--push' scripts/publish-images.sh
! grep -Eq '(^|[^[:alnum:]_-])latest([^[:alnum:]_-]|$)' \
  scripts/publish-dev-images.sh
grep -Fq 'release:' .github/workflows/container-publish.yml
grep -Fq 'types:' .github/workflows/container-publish.yml
grep -Fq -- '- published' .github/workflows/container-publish.yml
grep -Fq 'environment: container-release' .github/workflows/container-publish.yml
! grep -Fq 'github.ref_protected' .github/workflows/container-publish.yml
grep -Fq 'packages: write' .github/workflows/container-publish.yml
grep -Fq 'id-token: write' .github/workflows/container-publish.yml
grep -Fq 'attestations: write' .github/workflows/container-publish.yml
test "$(grep -Ec \
  'uses: actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6$' \
  .github/workflows/container-publish.yml)" -eq 9
grep -Fq -- '--signer-workflow "$workflow"' \
  .github/workflows/container-publish.yml
grep -Fq -- '--source-digest "$GITHUB_SHA"' \
  .github/workflows/container-publish.yml
! grep -Eq '(^|[[:space:]])(pull_request|push|workflow_dispatch|workflow_call):' \
  .github/workflows/container-publish.yml
! grep -Eq 'artifact-metadata:[[:space:]]*write' \
  .github/workflows/container-publish.yml
grep -Fq 'test "$(git cat-file -t "$GITHUB_REF_NAME")" = tag' \
  scripts/publish-images.sh
grep -Fq 'test "$(git rev-parse "$GITHUB_REF_NAME^{commit}")" = "$(git rev-parse HEAD)"' \
  scripts/publish-images.sh
grep -Fq '.artifacts/publication-tools/gh attestation verify' \
  .github/workflows/container-publish.yml
! grep -Eq '^[[:space:]]*gh[[:space:]]+attestation[[:space:]]+verify' \
  .github/workflows/container-publish.yml
jq -e '
  . == {
    schema:"dkim2-publication-tool-allowlist-v1",
    attestation_action:{
      repository:"actions/attest",
      commit:"f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
      spdx_predicate_type:"https://spdx.dev/Document/v2.3"
    },
    verifier:{
      name:"gh",
      version:"2.94.0",
      goos:"linux",
      goarch:"amd64",
      asset:"gh_2.94.0_linux_amd64.tar.gz",
      archive_sha256:
        "a757f1ba6db18f4de8cbadb244843a5f89bc75b5e7c6fc127d2bd77fbd12ed62",
      member:"gh_2.94.0_linux_amd64/bin/gh",
      binary_sha256:
        "c2033c14259a3a3b7518a47535e57385a6d3faaba1759e9cf8c1c10dd21d3de9"
    }
  }
' build/container/publication-tools.json >/dev/null
grep -Fq -- '--predicate-type https://spdx.dev/Document/v2.3' \
  .github/workflows/container-publish.yml
! grep -Eq '(^|[^[:alnum:]_-])latest([^[:alnum:]_-]|$)' \
  scripts/publish-images.sh .github/workflows/container-publish.yml

context="$test_root/context"
docker buildx build --file build/container/Containerfile \
  --target context-audit --output "type=local,dest=$context" . >/dev/null
test -f "$context/context/go.work"
test -f "$context/context/cmd/dkim2d/main.go"
test -f "$context/context/cmd/dkim2-exim/go.mod"
test -f "$context/context/cmd/dkim2-exim/go.sum"
! grep -aFRq -- "$build_context_marker" "$context"
(
	cd "$context/context"
	find . -type f -print | LC_ALL=C sort
) >"$test_root/context-inventory"
if grep -E '(^|/)(\.env($|\.)|\.netrc$|\.npmrc$|\.pypirc$|credentials\.json$|secrets\.(json|ya?ml)$)|(\.pem|\.key|\.p12|\.pfx)$' \
	"$test_root/context-inventory"; then
	exit 1
fi
for forbidden in \
  'lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-04/signing-test-rsa.pem' \
  'cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-04/sign.json' \
  'cmd/dkim2-milter/internal/integration/milter_fixture_test.go'; do
  test ! -e "$context/context/$forbidden"
done
