#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
exim="$root/cmd/dkim2-exim/exim"
source_directory=${EXIM_UPSTREAM_SOURCE:?EXIM_UPSTREAM_SOURCE must name pristine Exim source}
manifest="$exim/fixtures/upstream-4.99.5/source-manifest-v1.txt"
patch_file="$exim/fixtures/upstream-4.99.5/local_scan-expand-string.patch"
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-upstream-patch.XXXXXX")
trap 'rm -rf "$work"' 0 1 2 15

# digest emits a portable lowercase SHA-256 digest for a regular file.
digest()
{
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# field reads one required immutable manifest value.
field()
{
  key=$1
  value=$(awk -F= -v key="$key" '$1 == key { print $2 }' "$manifest")
  test -n "$value"
  printf '%s\n' "$value"
}

test -f "$source_directory/src/local_scan.h"
test -f "$source_directory/src/functions.h"
test "$(digest "$source_directory/src/local_scan.h")" = \
  "$(field local_scan_header_pristine_sha256)"
test "$(digest "$source_directory/src/functions.h")" = \
  "$(field functions_header_pristine_sha256)"
test "$(digest "$patch_file")" = "$(field local_scan_header_patch_sha256)"

mkdir "$work/src"
cp "$source_directory/src/local_scan.h" "$work/src/local_scan.h"
cp "$source_directory/src/functions.h" "$work/src/functions.h"
(cd "$work/src" && git apply --check "$patch_file" && git apply "$patch_file")

test "$(digest "$work/src/local_scan.h")" = "$(field local_scan_header_sha256)"
test "$(digest "$work/src/functions.h")" = "$(field functions_header_sha256)"
printf '%s\n' 'upstream patch regression: passed'
