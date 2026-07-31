#!/bin/sh
# Verifies the narrow SMTP transport-filter patch against exact unpacked sources.
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../../../.." && pwd)
source_root=${DKIM2_EXIM_TRANSPORT_FILTER_PATCH_SOURCE_ROOT:-}
patch_file=$root/cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch

if [ -z "$source_root" ] || [ "${source_root#/}" = "$source_root" ] ||
  [ -L "$source_root" ] || [ ! -d "$source_root" ] || [ ! -s "$patch_file" ]; then
  printf '%s\n' 'Exim transport-filter source patch check requires a direct absolute source root' >&2
  exit 2
fi

for version in exim-4.98.2 exim-4.99.1 exim-4.99.5; do
  source=$source_root/$version
  if [ -L "$source" ] || [ ! -d "$source" ] || [ ! -f "$source/src/transport.c" ] ||
    [ ! -f "$source/src/transports/smtp.c" ] || [ ! -f "$source/src/macros.h" ]; then
    printf '%s\n' 'Exim transport-filter source patch check has an incomplete source baseline' >&2
    exit 1
  fi
  patch --dry-run --fuzz=0 -s -p1 -d "$source" <"$patch_file"
done
