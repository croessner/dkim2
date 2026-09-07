-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local allocation_module = require 'dkim2.observation_allocation'
local state_module = require 'dkim2.observation_outbox_state'
local M = {}
local REPLIES = {
  ENQUEUED=true, DUPLICATE=true, CONFLICT=true, FULL=true, CORRUPT=true, INVALID=true,
  EMPTY=true, MISSING=true, EXPIRED=true, LEASED=true, RETRY=true, ACKED=true, DEAD=true,
  STALE=true, SWEPT=true, READY=true, ALLOCATION_MISMATCH=true,
}

-- M.new composes allocation, crypto, persistence and transport without storing a plaintext queue.
function M.new(options)
  if type(options) ~= 'table' or not state_module.valid_limits(options.limits) or type(options.redis) ~= 'table' or
      type(options.redis.add_redis_script) ~= 'function' or type(options.redis.exec_redis_script) ~= 'function' or
      type(options.crypto) ~= 'table' or type(options.transport) ~= 'table' or
      type(options.encode) ~= 'function' or type(options.decode) ~= 'function' or type(options.random_hex) ~= 'function' then
    return nil
  end
  local allocation = allocation_module.new(options.allocation)
  if not allocation then
    return nil
  end
  local configurations = {}
  for shard = 0, allocation.shards - 1 do
    local limits = allocation:partition(shard)
    for key, value in pairs(options.limits) do
      limits[key] = value
    end
    configurations[shard] = limits
  end
  local state_id = options.redis.add_redis_script(state_module.redis_script, options.redis_params)
  local allocation_id = options.redis.add_redis_script(allocation_module.redis_script, options.redis_params)
  if not state_id or not allocation_id then
    return nil
  end
  return setmetatable({allocation=allocation, configurations=configurations, redis=options.redis,
    crypto=options.crypto, transport=options.transport, encode=options.encode, decode=options.decode,
    random=options.random_hex, state_id=state_id, allocation_id=allocation_id,
    ready=false, busy={}, sweeping={}, observer=options.observer}, {__index=M})
end

-- execute translates transport errors to closed status and invokes its completion at most once.
local function execute(self, script, context, keys, args, callback)
  local completed = false
  -- finish prevents a scheduling error or duplicate callback from completing one operation twice.
  local function finish(err, value)
    if completed then
      return
    end
    completed = true
    if err or type(value) ~= 'table' or not REPLIES[value[1]] or
        (#value ~= 1 and not (value[1] == 'LEASED' and #value == 2 and type(value[2]) == 'string' and #value[2] <= 100000)) then
      value = {'UNAVAILABLE'}
    end
    if type(self.observer) == 'function' then
      local operation = script == self.allocation_id and 'initialize' or args[1]
      pcall(self.observer, operation, value[1])
    end
    callback(value[1], value[2])
  end
  local started = self.redis.exec_redis_script(script, {task=context.task, ev_base=context.ev_base,
    key=keys[1], is_write=true}, finish, keys, args)
  if not started then
    finish(true)
  end
  return started
end

-- M.initialize pins the material identity before this worker may enqueue or decrypt anything.
function M:initialize(ev_base, callback)
  self.ready = false
  local owner = self.random(32)
  if type(owner) ~= 'string' or #owner ~= 32 or owner:find('[^0-9a-f]') then
    callback('INVALID')
    return false
  end
  self.owner = owner
  return execute(self, self.allocation_id, {ev_base=ev_base}, {allocation_module.metadata_key},
    {self.crypto:allocation_id(), tostring(self.allocation.shards), tostring(self.allocation.generation)},
    function(status)
      self.ready = status == 'READY'
      callback(status)
    end)
end

-- transition sends one closed same-slot operation using its deterministic capacity share.
local function transition(self, context, shard, operation, input, callback)
  local keys = self.allocation:keys(shard)
  if not self.ready or not keys then
    callback('UNAVAILABLE')
    return false
  end
  return execute(self, self.state_id, context, keys,
    {operation, self.encode(self.configurations[shard]), self.encode(input)}, callback)
end

-- M.enqueue acknowledges only atomic persistence of one sealed event before SMTP completion.
function M:enqueue(task, event, callback)
  if not self.ready then
    callback('UNAVAILABLE')
    return false
  end
  local record, shard = self.crypto:seal(event)
  if not record then
    callback('INVALID')
    return false
  end
  return transition(self, {task=task}, shard, 'enqueue', record, callback)
end

-- lease_identity selects only the fencing fields from the claimed encrypted record.
local function lease_identity(record)
  return {allocation_tag=record.allocation_tag, lease_owner=record.lease_owner,
    lease_token=record.lease_token, lease_generation=record.lease_generation}
end

-- finish_delivery retains the lease until the fenced Redis completion has finished or failed.
local function finish_delivery(self, ev_base, shard, operation, record, reason)
  local input = lease_identity(record)
  if operation == 'retry' then
    local random = self.random(8)
    if type(random) ~= 'string' or #random ~= 8 or random:find('[^0-9a-f]') then
      self.busy[shard] = nil
      return
    end
    input.jitter_ms = tonumber(random, 16) % (self.configurations[shard].jitter_ms + 1)
  elseif operation == 'dead' then
    input.reason = reason
  end
  transition(self, {ev_base=ev_base}, shard, operation, input, function()
    self.busy[shard] = nil
  end)
end

-- deliver releases decrypted bytes only for one current claim and replays exactly those bytes on uncertainty.
local function deliver(self, ev_base, shard, record)
  local body, request_id = self.crypto:open(record)
  if not body then
    finish_delivery(self, ev_base, shard, 'dead', record, 'corrupt')
    return
  end
  local completed = false
  -- respond maps the already validated Policy result without interpreting diagnostics or mutable scan state.
  local function respond(result, transport_status)
    if completed then
      return
    end
    completed = true
    if transport_status ~= 'rejected' and result and result.effect == 'permit' and result.status.code == 'permit' then
      finish_delivery(self, ev_base, shard, 'ack', record)
    elseif transport_status ~= 'rejected' and (not result or result.status.retryable) then
      finish_delivery(self, ev_base, shard, 'retry', record)
    else
      finish_delivery(self, ev_base, shard, 'dead', record, 'rejected')
    end
  end
  if not self.transport:send_background(ev_base, body, request_id, respond) then
    respond(nil)
  end
end

-- M.work permits at most one outstanding delivery per shard in this worker process.
function M:work(ev_base, shard)
  if self.busy[shard] or not self.ready or not self.allocation:keys(shard) then
    return false
  end
  local token = self.random(32)
  if type(token) ~= 'string' or #token ~= 32 or token:find('[^0-9a-f]') then
    return false
  end
  self.busy[shard] = true
  return transition(self, {ev_base=ev_base}, shard, 'claim', {lease_owner=self.owner, lease_token=token},
    function(status, payload)
      if status ~= 'LEASED' then
        self.busy[shard] = nil
        return
      end
      local ok, record = pcall(self.decode, payload)
      if not ok or type(record) ~= 'table' then
        self.busy[shard] = nil
        return
      end
      deliver(self, ev_base, shard, record)
    end)
end

-- M.sweep schedules independent bounded cleanup even when all deliveries are idle or waiting for HTTP.
function M:sweep(ev_base, shard)
  if self.sweeping[shard] or not self.ready or not self.allocation:keys(shard) then
    return false
  end
  self.sweeping[shard] = true
  return transition(self, {ev_base=ev_base}, shard, 'sweep', {}, function()
    self.sweeping[shard] = nil
  end)
end

return M
