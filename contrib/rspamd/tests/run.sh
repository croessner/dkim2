#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0

set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
contrib_dir=$(CDPATH='' cd -- "$test_dir/.." && pwd)

find "$contrib_dir" -name '*.lua' -type f -exec luac -p {} \;
lua "$test_dir/dkim2_test.lua" "$contrib_dir/lualib/dkim2/verifier.lua"
lua "$test_dir/dkim2_test.lua" "$contrib_dir/lualib/dkim2/verifier.lua" \
  "https://dkim2d-inbound:8443/v1/process" "tls_private_network" "dkim2d-inbound"
lua "$test_dir/retry_cache_test.lua" "$contrib_dir/lualib/dkim2/retry_cache.lua"
lua "$test_dir/nauthilus_policy_test.lua" "$contrib_dir/lualib/dkim2/nauthilus_policy.lua" \
  "$contrib_dir/lualib/dkim2/strict_json.lua"
lua "$test_dir/plugin_flow_test.lua" "$contrib_dir/plugins.d/dkim2.lua"
sh "$test_dir/retry_cache_redis_test.sh" "$contrib_dir/lualib/dkim2/retry_cache.lua"
