#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
exim="$root/cmd/dkim2-exim/exim"
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-c-cross.XXXXXX")
trap 'rm -rf "$work"' 0 1 2 15
export ZIG_GLOBAL_CACHE_DIR="$work/zig-global-cache"
export ZIG_LOCAL_CACHE_DIR="$work/zig-local-cache"

zig=${ZIG:-zig}
command -v "$zig" >/dev/null 2>&1 || {
  printf '%s\n' "missing pinned-compatible Zig C cross compiler" >&2
  exit 2
}
test "$("$zig" version)" = "0.16.0" || {
  printf '%s\n' "unsupported Zig version; require exact 0.16.0" >&2
  exit 2
}

# compile builds the exact prepared local_scan layout for one Linux architecture.
compile()
{
  architecture=$1
  target=$2
  local_dir="$work/$architecture/Local"
  mkdir -p "$local_dir"
  cp "$exim/dkim2_local_scan.c" "$local_dir/dkim2_local_scan.c"
  cp "$exim/generated/build-id-v1.h" "$local_dir/build-id-v1.h"
  "$zig" cc -target "$target" -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
    -Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow -Wstrict-prototypes \
    -I"$exim/fixtures/include" -I"$exim/fixtures/upstream-4.99.5" \
    -c "$local_dir/dkim2_local_scan.c" -o "$work/$architecture/dkim2_local_scan.o"
  test -s "$work/$architecture/dkim2_local_scan.o"
}

compile amd64 x86_64-linux-gnu
compile arm64 aarch64-linux-gnu
