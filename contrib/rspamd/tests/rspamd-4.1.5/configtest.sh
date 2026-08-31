#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0

set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
contrib_dir=$(CDPATH='' cd -- "$test_dir/../.." && pwd)
image='rspamd/rspamd:4.1.5@sha256:c307774c4c83bc445f0ae6696fd1798c92b0b89355ae1d87c9c39694c875e51e'
fixture_dir=$(mktemp -d)

cleanup() {
  rm -f "$fixture_dir/process-capability" "$fixture_dir/retry-hmac" \
    "$fixture_dir/policy-password"
  rmdir "$fixture_dir"
}
trap cleanup EXIT INT TERM

openssl rand -out "$fixture_dir/process-capability" 32
openssl rand -out "$fixture_dir/retry-hmac" 32
openssl rand -hex -out "$fixture_dir/policy-password" 16
truncate -s 32 "$fixture_dir/policy-password"
chmod 0444 "$fixture_dir/process-capability" "$fixture_dir/retry-hmac" \
  "$fixture_dir/policy-password"

run_rspamadm() {
  docker run --rm --entrypoint rspamadm \
    -v "$contrib_dir/plugins.d/dkim2.lua:/etc/rspamd/plugins.d/dkim2.lua:ro" \
    -v "$contrib_dir/modules.local.d/dkim2.conf:/usr/share/rspamd/config/modules.local.d/dkim2.conf:ro" \
    -v "$contrib_dir/local.d/dkim2.conf.example:/etc/rspamd/local.d/dkim2.conf:ro" \
    -v "$test_dir/redis.conf:/etc/rspamd/local.d/redis.conf:ro" \
    -v "$test_dir/options.inc:/etc/rspamd/override.d/options.inc:ro" \
    -v "$contrib_dir/lualib/dkim2:/usr/share/rspamd/config/lua/dkim2:ro" \
    -v "$fixture_dir/process-capability:/etc/dkim2/protected/process-capability:ro" \
    -v "$fixture_dir/retry-hmac:/etc/dkim2/protected/rspamd-retry-hmac:ro" \
    -v "$fixture_dir/policy-password:/etc/dkim2/protected/nauthilus-policy-password:ro" \
    "$image" "$@"
}

config_output=$(run_rspamadm configtest 2>&1)
printf '%s\n' "$config_output"
printf '%s\n' "$config_output" | grep 'syntax OK' >/dev/null
if printf '%s\n' "$config_output" | grep -E 'cannot add dependency|module disabled' >/dev/null; then
  echo 'dkim2 emitted a loader or dependency failure' >&2
  exit 1
fi
module_output=$(run_rspamadm configdump -m)
printf '%s\n' "$module_output" | grep 'Modules enabled:.*dkim2' >/dev/null
if printf '%s\n' "$module_output" | grep 'Modules disabled (failed):.*dkim2' >/dev/null; then
  echo 'dkim2 unexpectedly appears in the failed module set' >&2
  exit 1
fi

symbol_output=$(run_rspamadm configdump -d)
for symbol in DKIM2_CHECK DKIM2_NAUTHILUS_POLICY DKIM2_RETRY_FINALIZE; do
  printf '%s\n' "$symbol_output" | grep "${symbol}" >/dev/null || {
    echo "missing registered symbol: ${symbol}" >&2
    exit 1
  }
done

echo 'dkim2 Rspamd 4.1.5 config/dependency test: PASS'
