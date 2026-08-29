#!/bin/sh
set -eu

test_root=.artifacts/build-contract
test ! -e "$test_root"
test ! -L "$test_root"
mkdir -m 0700 "$test_root"
trap 'rm -rf -- "$test_root"' EXIT HUP INT TERM

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. >"$test_root/metadata-a.json"
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. >"$test_root/metadata-b.json"
cmp "$test_root/metadata-a.json" "$test_root/metadata-b.json"

expected_candidate=$(jq -er .candidate_snapshot_sha256 "$test_root/metadata-a.json")
actual_candidate=$(sed -n \
  's/^candidate_snapshot_sha256=\([0-9a-f][0-9a-f]*\)$/\1/p' \
  .artifacts/product-binaries/build-info)
test "$actual_candidate" = "$expected_candidate"

marker=privacy-build-context-7f3c9a2d
printf '%s\n' "$marker" >"$test_root/private-marker"
context="$test_root/context"
docker buildx build --file build/container/Dockerfile \
  --target context-audit --output "type=local,dest=$context" . >/dev/null

test -f "$context/context/go.work"
test -f "$context/context/cmd/dkim2d/main.go"
test -f "$context/context/cmd/dkim2-exim/go.mod"
test -f "$context/context/cmd/dkim2-exim/go.sum"
! grep -aFRq -- "$marker" "$context"

(
  cd "$context/context"
  find . -type f -print | LC_ALL=C sort
) >"$test_root/context-inventory"
if grep -E '(^|/)([.]env($|[.])|[.]netrc$|[.]npmrc$|[.]pypirc$|credentials[.]json$|secrets[.](json|ya?ml)$)|([.]pem|[.]key|[.]p12|[.]pfx)$' \
  "$test_root/context-inventory"; then
  exit 1
fi

for forbidden in \
  'lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/signing-test-rsa.pem' \
  'cmd/dkim2ctl/testdata/fixtures/draft-ietf-dkim-dkim2-spec-06/sign.json' \
  'cmd/dkim2-milter/internal/integration/milter_fixture_test.go'; do
  test ! -e "$context/context/$forbidden"
done
