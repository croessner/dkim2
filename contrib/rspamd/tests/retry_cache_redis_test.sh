#!/bin/sh
# Copyright 2026 Christian Roessner
# SPDX-License-Identifier: Apache-2.0

set -eu

module_path=$1
test_dir=$(mktemp -d)
socket_path="$test_dir/redis.sock"
script_path="$test_dir/retry.lua"

cleanup() {
  redis-cli -s "$socket_path" shutdown nosave >/dev/null 2>&1 || true
  rm -f "$script_path" "$socket_path" "$test_dir/redis.pid"
  rmdir "$test_dir"
}
trap cleanup EXIT INT TERM

lua - "$module_path" "$script_path" <<'LUA'
local module = assert(loadfile(assert(arg[1])))()
local handle = assert(io.open(assert(arg[2]), 'wb'))
assert(handle:write(module.redis_script))
assert(handle:close())
LUA

redis-server --port 0 --unixsocket "$socket_path" --unixsocketperm 700 \
  --daemonize yes --dir "$test_dir" --pidfile "$test_dir/redis.pid"

attempt=0
while ! redis-cli -s "$socket_path" ping >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 100 ]; then
    echo 'retry cache Redis test server did not become ready' >&2
    exit 1
  fi
  sleep 0.05
done

key='dkim2:retry:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
owner_one='1111111111111111'
owner_two='2222222222222222'

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  store "$owner_one" 1000 60000 '{"validated":true}')
test "$result" = 'STORED'

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  claim "$owner_two" 1000 60000 '')
test "$result" = 'BUSY'

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  arm "$owner_one" 1000 60000 '')
test "$result" = 'ARMED'

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  claim "$owner_two" 1000 60000 '')
test "$result" = "HIT
{\"validated\":true}"

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  claim "$owner_one" 1000 60000 '')
test "$result" = 'BUSY'

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  consume "$owner_one" 1000 60000 '')
test "$result" = 'STALE'

sleep 1.1
result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  claim "$owner_one" 1000 60000 '')
test "$result" = "HIT
{\"validated\":true}"

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  consume "$owner_two" 1000 60000 '')
test "$result" = 'STALE'

result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$key" , \
  consume "$owner_one" 1000 60000 '')
test "$result" = 'CONSUMED'
test "$(redis-cli --raw -s "$socket_path" exists "$key")" = '0'

corrupt_key='dkim2:retry:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
redis-cli --raw -s "$socket_path" hset "$corrupt_key" state broken owner '' \
  lease_until 0 deadline 9999999999999 payload '{}' >/dev/null
result=$(redis-cli --raw -s "$socket_path" --eval "$script_path" "$corrupt_key" , \
  claim "$owner_one" 1000 60000 '')
test "$result" = 'CORRUPT'
test "$(redis-cli --raw -s "$socket_path" exists "$corrupt_key")" = '0'

echo 'dkim2 retry cache real Redis state-machine test: PASS'
