#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0

set -eu

test_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
contrib_dir=$(CDPATH='' cd -- "$test_dir/.." && pwd)

luac -p "$contrib_dir/plugins.d/dkim2.lua"
lua "$test_dir/dkim2_test.lua" "$contrib_dir/plugins.d/dkim2.lua"
lua "$test_dir/dkim2_test.lua" "$contrib_dir/plugins.d/dkim2.lua" \
  "https://dkim2d-inbound:8443/v1/process" "tls_private_network" "dkim2d-inbound"
