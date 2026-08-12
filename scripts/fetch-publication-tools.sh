#!/bin/sh
set -eu
umask 077

test "$#" -eq 0
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64

directory=.artifacts/publication-tools
allowlist=build/container/publication-tools.json
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory "$directory"
work=$(mktemp -d .artifacts/.publication-tools-work.XXXXXX)

# cleanup removes only the invocation-owned download workspace.
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

jq -e '
  (keys == ["attestation_policy","schema","verifier"]) and
  .schema == "dkim2-publication-tool-allowlist-v2" and
  .attestation_policy == {
    spdx_predicate_type:"https://spdx.dev/Document/v2.3"
  } and
  (.verifier | keys == [
    "archive_sha256", "asset", "binary_sha256", "goarch", "goos",
    "member", "name", "version"
  ]) and
  .verifier.name == "gh" and
  .verifier.goos == "linux" and
  .verifier.goarch == "amd64" and
  (.verifier.version | test("^[0-9]+[.][0-9]+[.][0-9]+$")) and
  .verifier.asset ==
    ("gh_" + .verifier.version + "_linux_amd64.tar.gz") and
  .verifier.member ==
    ("gh_" + .verifier.version + "_linux_amd64/bin/gh") and
  (.verifier.archive_sha256 | test("^[0-9a-f]{64}$")) and
  (.verifier.binary_sha256 | test("^[0-9a-f]{64}$"))
' "$allowlist" >/dev/null
version=$(jq -er .verifier.version "$allowlist")
asset=$(jq -er .verifier.asset "$allowlist")
archive_sha=$(jq -er .verifier.archive_sha256 "$allowlist")
member=$(jq -er .verifier.member "$allowlist")
binary_sha=$(jq -er .verifier.binary_sha256 "$allowlist")
archive="$work/$asset"
binary="$work/gh"
curl --fail --silent --show-error --location \
  --connect-timeout 10 --max-time 120 --retry 2 \
  "https://github.com/cli/cli/releases/download/v$version/$asset" \
  -o "$archive"
test "$(shasum -a 256 "$archive" | cut -d' ' -f1)" = "$archive_sha"
tar -xOf "$archive" "$member" >"$binary"
test "$(shasum -a 256 "$binary" | cut -d' ' -f1)" = "$binary_sha"
chmod 0500 "$binary"
"$binary" --version | sed -n '1p' | grep -Fq "gh version $version "
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -install "$binary" -target "$directory/gh" -executable -replace
