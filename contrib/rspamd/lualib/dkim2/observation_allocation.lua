-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
M.metadata_key = 'dkim2:observation:v1:{meta}:allocation'
M.redis_script = [==[
-- integer validates exact bounded allocation metadata before any write.
local function integer(value, minimum, maximum)
  local number = tonumber(value)
  if not number or number % 1 ~= 0 or number < minimum or number > maximum then
    return nil
  end
  return number
end

if #KEYS ~= 1 or KEYS[1] ~= 'dkim2:observation:v1:{meta}:allocation' or #ARGV ~= 3 then
  return {'INVALID'}
end
local id, shards, generation = ARGV[1], integer(ARGV[2], 1, 64), integer(ARGV[3], 0, 2147483647)
if #id ~= 64 or id:find('[^0-9a-f]') or not shards or not generation then
  return {'INVALID'}
end
local divisor = shards
while divisor > 1 do
  if divisor % 2 ~= 0 then
    return {'INVALID'}
  end
  divisor = divisor / 2
end
local kind = redis.call('TYPE', KEYS[1]).ok
if kind == 'none' then
  -- Only a fresh installation may initialize metadata; workers never perform allocation-key replacement.
  if generation ~= 0 then
    return {'ALLOCATION_MISMATCH'}
  end
  local clock = redis.call('TIME')
  local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
  redis.call('HSET', KEYS[1], 'schema_version', '1', 'allocation_key_id', id,
    'shard_count', shards, 'drain_generation', generation, 'activated_at', now)
  return {'READY'}
end
if kind ~= 'hash' or redis.call('HLEN', KEYS[1]) ~= 5 or redis.call('PTTL', KEYS[1]) ~= -1 then
  return {'CORRUPT'}
end
local metadata = redis.call('HMGET', KEYS[1], 'schema_version', 'allocation_key_id',
  'shard_count', 'drain_generation', 'activated_at')
if metadata[1] ~= '1' or not metadata[2] or #metadata[2] ~= 64 or metadata[2]:find('[^0-9a-f]') or
    not integer(metadata[3], 1, 64) or not integer(metadata[4], 0, 2147483647) or
    not integer(metadata[5], 1, 9007199254740991) then
  return {'CORRUPT'}
end
if metadata[2] ~= id or tonumber(metadata[3]) ~= shards or tonumber(metadata[4]) ~= generation then
  return {'ALLOCATION_MISMATCH'}
end
return {'READY'}
]==]

-- integer validates exact bounded configuration quantities without string coercion.
local function integer(value, minimum, maximum)
  return type(value) == 'number' and value % 1 == 0 and value >= minimum and value <= maximum
end

-- power_of_two admits only the fixed bounded shard counts supported by the crypto owner.
local function power_of_two(value)
  if not integer(value, 1, 64) then
    return false
  end
  while value > 1 do
    if value % 2 ~= 0 then
      return false
    end
    value = value / 2
  end
  return true
end

-- partition allocates a deterministic quotient and remainder without exceeding the global sum.
local function partition(total, shards, shard)
  return math.floor(total / shards) + (shard < total % shards and 1 or 0)
end

-- M.new freezes fixed allocation limits shared by all worker generations.
function M.new(options)
  if type(options) ~= 'table' or not power_of_two(options.shard_count) or
      not integer(options.max_records, options.shard_count, 4096 * options.shard_count) or
      not integer(options.max_bytes, 128 * options.shard_count, 268435456) or
      not integer(options.tombstone_limit, options.shard_count, 4096 * options.shard_count) or
      not integer(options.drain_generation, 0, 2147483647) then
    return nil
  end
  local allowed = {shard_count=true, max_records=true, max_bytes=true, tombstone_limit=true, drain_generation=true}
  for key in pairs(options) do
    if not allowed[key] then
      return nil
    end
  end
  return setmetatable({shards=options.shard_count, records=options.max_records,
    bytes=options.max_bytes, tombstones=options.tombstone_limit, generation=options.drain_generation}, {__index=M})
end

-- M.partition returns only this shard's immutable share of global storage limits.
function M:partition(shard)
  if not integer(shard, 0, self.shards - 1) then
    return nil
  end
  return {max_records=partition(self.records, self.shards, shard),
    max_bytes=partition(self.bytes, self.shards, shard),
    tombstone_limit=partition(self.tombstones, self.shards, shard)}
end

-- M.keys keeps every event transition within one explicit Redis Cluster hash tag.
function M:keys(shard)
  if not integer(shard, 0, self.shards - 1) then
    return nil
  end
  local prefix = 'dkim2:observation:v1:{' .. tostring(shard) .. '}:'
  return {prefix .. 'due', prefix .. 'capacity', prefix .. 'record:',
    prefix .. 'tombstone_due', prefix .. 'tombstone_reason'}
end

return M
