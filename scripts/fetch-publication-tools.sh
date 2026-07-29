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
  .schema == "dkim2-publication-tool-allowlist-v1" and
  .verifier == {
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
' "$allowlist" >/dev/null
asset=$(jq -er .verifier.asset "$allowlist")
archive_sha=$(jq -er .verifier.archive_sha256 "$allowlist")
member=$(jq -er .verifier.member "$allowlist")
binary_sha=$(jq -er .verifier.binary_sha256 "$allowlist")
archive="$work/$asset"
binary="$work/gh"
curl --fail --silent --show-error --location \
  --connect-timeout 10 --max-time 120 --retry 2 \
  "https://github.com/cli/cli/releases/download/v2.94.0/$asset" \
  -o "$archive"
test "$(shasum -a 256 "$archive" | cut -d' ' -f1)" = "$archive_sha"
tar -xOf "$archive" "$member" >"$binary"
test "$(shasum -a 256 "$binary" | cut -d' ' -f1)" = "$binary_sha"
chmod 0500 "$binary"
"$binary" --version | sed -n '1p' | grep -Eq '^gh version 2[.]94[.]0 '
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. \
    -install "$binary" -target "$directory/gh" -executable -replace
