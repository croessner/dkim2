-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
local OPERATIONS = {'ack','claim','dead','enqueue','initialize','retry','sweep'}
local OUTCOMES = {'ACKED','ALLOCATION_MISMATCH','CONFLICT','CORRUPT','DEAD','DUPLICATE','EMPTY',
  'ENQUEUED','EXPIRED','FULL','INVALID','LEASED','MISSING','READY','RETRY','STALE','SWEPT','UNAVAILABLE'}
local MAXIMUM_COUNT = 1000000000
local DETAILS = {'expired','missing','reclaimed','tombstone_expired','tombstone_evicted'}
local SNAPSHOT_BOUNDS = {observed_at=9007199254740991,live_records=4096,live_bytes=268435456,
  due_records=4096,tombstones=4096,expired=8192,missing=8192,reclaimed=8192,
  tombstone_expired=8192,tombstone_evicted=8192}

-- M.snapshot detaches only a complete closed numeric diagnostic record.
function M.snapshot(value)
  if type(value) ~= 'table' then return nil end
  local result = {}
  for field, maximum in pairs(SNAPSHOT_BOUNDS) do
    local number = value[field]
    if type(number) ~= 'number' or number ~= number or number % 1 ~= 0 or number < 0 or number > maximum then
      return nil
    end
    result[field] = number
  end
  for field in pairs(value) do
    if not SNAPSHOT_BOUNDS[field] then return nil end
  end
  return result
end

-- M.new allocates fixed operation/outcome dimensions and at most 64 configured shard snapshots.
function M.new(sink, snapshot_sink, shards)
  if type(sink) ~= 'function' or (snapshot_sink ~= nil and type(snapshot_sink) ~= 'function') then return nil end
  shards = shards or 0
  if type(shards) ~= 'number' or shards % 1 ~= 0 or shards < 0 or shards > 64 then return nil end
  local counts = {}
  for _, operation in ipairs(OPERATIONS) do
    counts[operation] = {}
    for _, outcome in ipairs(OUTCOMES) do counts[operation][outcome] = 0 end
  end
  return setmetatable({counts=counts,sink=sink,snapshot_sink=snapshot_sink,shards=shards,
    snapshots={},details={},dirty={}}, {__index=M})
end

-- M.observe counts one completion and retains no event identifiers or Redis material.
function M:observe(operation, outcome, shard, snapshot)
  local counters = self.counts[operation]
  if not counters or not counters[outcome] then return end
  counters[outcome] = math.min(MAXIMUM_COUNT, counters[outcome] + 1)
  if type(shard) ~= 'number' or shard % 1 ~= 0 or shard < 0 or shard >= self.shards then return end
  local detached = M.snapshot(snapshot)
  if not detached then return end
  local previous = self.snapshots[shard]
  if not previous or detached.observed_at >= previous.observed_at then self.snapshots[shard] = detached end
  local details = self.details[shard] or {}
  for _, name in ipairs(DETAILS) do
    details[name] = math.min(MAXIMUM_COUNT, (details[name] or 0) + detached[name])
  end
  self.details[shard], self.dirty[shard] = details, true
end

-- flush_snapshots emits last-observed capacity and process-local cleanup deltas without summing gauges.
local function flush_snapshots(self)
  for shard = 0, self.shards - 1 do
    if self.dirty[shard] then
      local snapshot = M.snapshot(self.snapshots[shard])
      for _, name in ipairs(DETAILS) do snapshot[name] = self.details[shard][name] end
      self.details[shard], self.dirty[shard] = {}, nil
      if self.snapshot_sink then pcall(self.snapshot_sink, shard, snapshot) end
    end
  end
end

-- M.flush emits bounded diagnostic deltas; exporter failure never changes delivery authority.
function M:flush()
  for _, operation in ipairs(OPERATIONS) do
    for _, outcome in ipairs(OUTCOMES) do
      local count = self.counts[operation][outcome]
      if count > 0 then
        self.counts[operation][outcome] = 0
        pcall(self.sink, operation, outcome, count)
      end
    end
  end
  flush_snapshots(self)
end

return M
