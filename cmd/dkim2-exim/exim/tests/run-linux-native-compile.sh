#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
exim="$root/cmd/dkim2-exim/exim"
work=$(mktemp -d "${TMPDIR:-/tmp}/dkim2-exim-c-native.XXXXXX")
trap 'rm -rf "$work"' 0 1 2 15

cc=${CC:-cc}
command -v "$cc" >/dev/null 2>&1 || {
  printf '%s\n' "missing C compiler" >&2
  exit 2
}

mkdir -p "$work/Local"
cp "$exim/dkim2_local_scan.c" "$work/Local/dkim2_local_scan.c"
cp "$exim/generated/build-id-v1.h" "$work/Local/build-id-v1.h"
set -- -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L
if test "$(uname -s)" = Darwin; then
  set -- "$@" -D_DARWIN_C_SOURCE
fi
"$cc" "$@" \
  -Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow -Wstrict-prototypes \
  -I"$exim/fixtures/include" -I"$exim/fixtures/upstream-4.99.5" \
  -c "$work/Local/dkim2_local_scan.c" -o "$work/dkim2_local_scan.o"
test -s "$work/dkim2_local_scan.o"
