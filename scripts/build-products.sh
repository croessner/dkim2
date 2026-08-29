#!/bin/sh
set -eu
umask 077

test "$#" -eq 0
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/safepath -root .. -directory .artifacts
work=$(mktemp -d .artifacts/.product-build-work.XXXXXX)

# cleanup removes only invocation-owned private source and build state.
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM
mkdir -m 0700 "$work/context"
GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
  go -C tools run ./cmd/buildmeta -root .. \
    -materialize "$work/context" >"$work/metadata.json"

assert_candidate() {
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/buildmeta -root .. >"$work/metadata-current.json"
  cmp "$work/metadata.json" "$work/metadata-current.json"
}

version=$(jq -er .version "$work/metadata.json")
revision=$(jq -er .revision "$work/metadata.json")
source_date_epoch=$(jq -er .source_date_epoch "$work/metadata.json")
dirty=$(jq -er .dirty "$work/metadata.json")
candidate=$(jq -er .candidate_snapshot_sha256 "$work/metadata.json")
repository=$(pwd -P)
context="$repository/$work/context"

build_once() {
  destination=$1
  cache=$2
  absolute_destination="$repository/$destination"
  absolute_cache="$repository/$cache"
  mkdir -m 0700 "$cache"
  mkdir -m 0700 "$destination"
  for arch in amd64 arm64; do
    mkdir -m 0700 "$destination/$arch"
    for product in dkim2d dkim2-milter dkim2ctl; do
      module="./cmd/$product"
      flags="-buildid="
      case "$product" in
        dkim2d) package=github.com/croessner/dkim2/cmd/dkim2d/internal/command ;;
        dkim2-milter) package=github.com/croessner/dkim2/cmd/dkim2-milter/internal/command ;;
        dkim2ctl) package=github.com/croessner/dkim2/cmd/dkim2ctl/internal/command ;;
      esac
      flags="$flags -X $package.buildVersion=$version"
      (
        cd "$context"
        GOCACHE="$absolute_cache" GOFLAGS=-mod=vendor \
          CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
          go build -buildvcs=false -trimpath -ldflags="$flags" \
            -o "$absolute_destination/$arch/$product" "$module"
      )
    done
  done
}

build_once "$work/first" "$work/cache-first"
assert_candidate
build_once "$work/second" "$work/cache-second"
assert_candidate
for arch in amd64 arm64; do
  for product in dkim2d dkim2-milter dkim2ctl; do
    cmp "$work/first/$arch/$product" "$work/second/$arch/$product"
    GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
      go -C tools run ./cmd/safepath -root .. \
        -install "$work/first/$arch/$product" \
        -target ".artifacts/product-binaries/$arch/$product" \
        -executable -replace
  done
done
assert_candidate
(
  cd "$work/first"
  find amd64 arm64 -type f -print | LC_ALL=C sort | xargs shasum -a 256
) >"$work/SHA256SUMS"
printf '%s\n' \
  "schema=dkim2.product-build.v1" \
  "version=$version" \
  "revision=$revision" \
  "dirty=$dirty" \
  "candidate_snapshot_sha256=$candidate" \
  "source_date_epoch=$source_date_epoch" \
  "message_draft=draft-ietf-dkim-dkim2-spec-06" \
  "dns_draft=draft-chuang-dkim2-dns-04" >"$work/build-info"
for evidence in SHA256SUMS build-info; do
  GOCACHE="${GOCACHE:-/tmp/dkim2-go-build-cache}" \
    go -C tools run ./cmd/safepath -root .. \
      -install "$work/$evidence" \
      -target ".artifacts/product-binaries/$evidence" \
      -replace
done
