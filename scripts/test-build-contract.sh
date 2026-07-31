#!/bin/sh
set -eu

test_root=.artifacts/build-contract-negative
for path in "$test_root"; do
	test ! -e "$path"
	test ! -L "$path"
done
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
grep -Fq 'release:' .github/workflows/container-publish.yml
grep -Fq 'types:' .github/workflows/container-publish.yml
grep -Fq -- '- published' .github/workflows/container-publish.yml
grep -Fq 'environment: container-release' .github/workflows/container-publish.yml
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
