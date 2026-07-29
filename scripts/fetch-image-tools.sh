#!/bin/sh
set -eu
umask 077

GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory .artifacts/image-tools
work=$(mktemp -d .artifacts/.image-tools-work.XXXXXX)
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

case "$(uname -s)" in
  Darwin) goos=darwin ;;
  Linux) goos=linux ;;
  *) exit 2 ;;
esac
case "$(uname -m)" in
  x86_64) goarch=amd64 ;;
  aarch64|arm64) goarch=arm64 ;;
  *) exit 2 ;;
esac

# fetch_tool downloads and installs one tool only when both archive and binary match the durable allowlist.
fetch_tool() {
  name=$1
  version=$2
  release_base=$3
  entry=$(jq -ec \
    --arg name "$name" --arg version "$version" \
    --arg goos "$goos" --arg goarch "$goarch" '
      (if .schema == "dkim2-image-tool-allowlist-v1" then . else halt_error(1) end) |
      [.tools[] |
        select(.name == $name and .version == $version) |
        .platforms[] |
        select(.goos == $goos and .goarch == $goarch)] |
      if length == 1 then .[0] else halt_error(1) end
    ' build/container/image-tools.json)
  asset=$(printf '%s' "$entry" | jq -er .asset)
  archive_sha=$(printf '%s' "$entry" | jq -er .archive_sha256)
  expected_binary_sha=$(printf '%s' "$entry" | jq -er .binary_sha256)
  url="$release_base/$asset"
  installed=".artifacts/image-tools/$name"
  installed_identity="$installed.identity.json"
  if test -e "$installed" || test -L "$installed" ||
    test -e "$installed_identity" || test -L "$installed_identity"; then
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/safepath -root .. -file "$installed"
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/safepath -root .. -file "$installed_identity"
    test "$(shasum -a 256 "$installed" | cut -d' ' -f1)" = "$expected_binary_sha"
    jq -e \
      --arg name "$name" --arg version "$version" \
      --arg asset "$asset" \
      --arg archive_sha256 "$archive_sha" \
      --arg binary_sha256 "$expected_binary_sha" '
        . == {
          schema:"dkim2-image-tool-v1",
          name:$name,
          version:$version,
          asset:$asset,
          archive_sha256:$archive_sha256,
          binary_sha256:$binary_sha256
        }
      ' "$installed_identity" >/dev/null
    return
  fi
  archive="$work/$name.tar.gz"
  binary="$work/$name"
  curl --fail --silent --show-error --location \
    --connect-timeout 10 --max-time 120 --retry 2 \
    "$url" -o "$archive"
  actual=$(shasum -a 256 "$archive" | cut -d' ' -f1)
  test "$actual" = "$archive_sha"
  tar -xOf "$archive" "$name" >"$binary"
  chmod 0500 "$binary"
  "$binary" version >/dev/null 2>&1 || "$binary" --version >/dev/null
  binary_sha=$(shasum -a 256 "$binary" | cut -d' ' -f1)
  test "$binary_sha" = "$expected_binary_sha"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. \
      -install "$binary" -target ".artifacts/image-tools/$name" -executable
  jq -S -n \
    --arg name "$name" \
    --arg version "$version" \
    --arg asset "$asset" \
    --arg archive_sha256 "$archive_sha" \
    --arg binary_sha256 "$binary_sha" \
    '{schema:"dkim2-image-tool-v1",name:$name,version:$version,asset:$asset,archive_sha256:$archive_sha256,binary_sha256:$binary_sha256}' \
    >"$work/$name.identity.json"
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. \
      -install "$work/$name.identity.json" \
      -target ".artifacts/image-tools/$name.identity.json"
}

fetch_tool syft 1.46.0 \
  "https://github.com/anchore/syft/releases/download/v1.46.0"
fetch_tool trivy 0.72.0 \
  "https://github.com/aquasecurity/trivy/releases/download/v0.72.0"
