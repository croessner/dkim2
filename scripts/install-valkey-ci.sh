#!/bin/sh
set -eu
umask 077

manifest=build/ci/toolchain.json
source_directory=.artifacts/valkey-src
expected_commit=$(jq -er '.fixtures.valkey.commit' "$manifest")
expected_version=$(jq -er '.fixtures.valkey.version' "$manifest")
test -d "$source_directory"
test ! -L "$source_directory"
test "$(git -C "$source_directory" rev-parse HEAD)" = "$expected_commit"

make -C "$source_directory" -j2 BUILD_TLS=no
sudo install -o root -g root -m 0755 \
  "$source_directory/src/valkey-server" /usr/local/bin/valkey-server
rm -rf -- "$source_directory"

version=$(valkey-server --version)
case "$version" in
  *"v=$expected_version"*) ;;
  *)
    printf 'installed Valkey server is not version %s\n' \
      "$expected_version" >&2
    exit 1
    ;;
esac
printf '%s\n' "$version"
