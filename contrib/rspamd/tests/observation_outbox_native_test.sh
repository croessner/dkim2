#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0

set -eu
image=${1:?the canonical Rspamd image is required}
test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
contrib_dir=$(CDPATH='' cd -- "$test_dir/.." && pwd)
log_file=$(mktemp "${TMPDIR:-/tmp}/dkim2-outbox-native.XXXXXX")
trap 'rm -f "$log_file"' EXIT INT TERM

if ! docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --tmpfs /tmp:rw,nosuid,noexec \
  --mount "type=bind,src=$contrib_dir,dst=/fixture,readonly" --entrypoint sh "$image" \
  -c 'umask 077; exec rspamadm lua --exec '\''dofile("/fixture/tests/observation_outbox_crypto_test.lua")'\''' \
  </dev/null >"$log_file" 2>&1; then
  cat "$log_file" >&2
  exit 1
fi
# rspamadm may exit zero after a Lua assertion failure; require the final native test marker.
if ! grep -q '^native encrypted outbox identity, rotation and tamper tests: PASS$' "$log_file"; then
  cat "$log_file" >&2
  exit 1
fi
printf '%s\n' 'Rspamd native encrypted observation outbox contract: PASS'
