-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}

local IDENTITY_FRAME = 'dkim2-rspamd-retry-identity-v1'
local KEY_PREFIX = 'dkim2:retry:v1:'
local MAX_SECRET_BYTES = 64

local non_delivery_actions = {
  reject = true, discard = true, quarantine = true, greylist = true, ['soft reject'] = true,
}

-- M.preserves_non_delivery reports actions that a technical failure must not widen.
function M.preserves_non_delivery(action)
  return type(action) == 'string' and non_delivery_actions[action] == true
end

-- M.is_retryable_action reports final actions that authorize one cached SMTP retry.
function M.is_retryable_action(action)
  return action == 'soft reject' or action == 'greylist'
end
local MIN_SECRET_BYTES = 32

local SCRIPT = [[
local function now_ms()
  local value = redis.call('TIME')
  return tonumber(value[1]) * 1000 + math.floor(tonumber(value[2]) / 1000)
end

local operation = ARGV[1]
local owner = ARGV[2]
local now = now_ms()

if operation == 'claim' then
  if redis.call('EXISTS', KEYS[1]) == 0 then
    return { 'MISS' }
  end
  local values = redis.call('HMGET', KEYS[1], 'state', 'owner', 'lease_until', 'deadline', 'payload')
  local state = values[1]
  local lease_until = tonumber(values[3]) or 0
  local deadline = tonumber(values[4]) or 0
  if deadline <= now then
    redis.call('DEL', KEYS[1])
    return { 'MISS' }
  end
  if state == 'provisional' then
    return { 'BUSY' }
  end
  if state == 'claimed' and lease_until > now then
    return { 'BUSY' }
  end
  if state ~= 'armed' and state ~= 'claimed' then
    redis.call('DEL', KEYS[1])
    return { 'CORRUPT' }
  end
  local lease = tonumber(ARGV[3])
  redis.call('HSET', KEYS[1], 'state', 'claimed', 'owner', owner, 'lease_until', now + lease)
  return { 'HIT', values[5] }
end

if operation == 'store' then
  if redis.call('EXISTS', KEYS[1]) ~= 0 then
    return { 'EXISTS' }
  end
  local ttl = tonumber(ARGV[4])
  local deadline = now + ttl
  redis.call('HSET', KEYS[1], 'state', 'provisional', 'owner', owner,
    'lease_until', 0, 'deadline', deadline, 'payload', ARGV[5])
  redis.call('PEXPIREAT', KEYS[1], deadline)
  return { 'STORED' }
end

if operation == 'arm' or operation == 'consume' then
  if redis.call('EXISTS', KEYS[1]) == 0 then
    return { 'STALE' }
  end
  local values = redis.call('HMGET', KEYS[1], 'state', 'owner', 'deadline')
  if values[2] ~= owner or (values[1] ~= 'provisional' and values[1] ~= 'claimed') then
    return { 'STALE' }
  end
  if tonumber(values[3]) <= now then
    redis.call('DEL', KEYS[1])
    return { 'STALE' }
  end
  if operation == 'consume' then
    redis.call('DEL', KEYS[1])
    return { 'CONSUMED' }
  end
  redis.call('HSET', KEYS[1], 'state', 'armed', 'owner', '', 'lease_until', 0)
  return { 'ARMED' }
end

return { 'INVALID' }
]]

-- frame_part appends one unambiguous length-prefixed identity component.
local function frame_part(parts, name, value)
  local encoded = tostring(value)
  parts[#parts + 1] = string.format('%08x', #name) .. name
  parts[#parts + 1] = string.format('%08x', #encoded) .. encoded
end

-- read_secret reads one bounded binary cache-identity key without exposing it.
local function read_secret(path)
  if type(path) ~= 'string' or path:sub(1, 1) ~= '/' or path:find('\0', 1, true) then
    return nil
  end
  local handle = io.open(path, 'rb')
  if not handle then
    return nil
  end
  local secret = handle:read(MAX_SECRET_BYTES + 1)
  handle:close()
  if type(secret) ~= 'string' or #secret < MIN_SECRET_BYTES or #secret > MAX_SECRET_BYTES then
    return nil
  end
  return secret
end

-- validate_result accepts only the finite reply vocabulary of the cache script.
local function validate_result(value)
  if type(value) ~= 'table' or type(value[1]) ~= 'string' then
    return nil
  end
  local status = value[1]
  local allowed = {
    MISS = true, BUSY = true, CORRUPT = true, HIT = true, EXISTS = true,
    STORED = true, STALE = true, CONSUMED = true, ARMED = true,
  }
  if not allowed[status] or status == 'HIT' and type(value[2]) ~= 'string' then
    return nil
  end
  return status, value[2]
end

-- M.new constructs one Redis-backed retry-result cache with injected boundaries.
function M.new(options)
  if type(options) ~= 'table' or type(options.redis) ~= 'table' or
      type(options.redis.add_redis_script) ~= 'function' or
      type(options.redis.exec_redis_script) ~= 'function' or
      type(options.hash) ~= 'table' or type(options.hash.create_specific_keyed) ~= 'function' then
    return nil
  end
  local secret = options.secret or read_secret(options.secret_file)
  local ttl_ms = tonumber(options.ttl_ms)
  local lease_ms = tonumber(options.lease_ms)
  local authority_generation = options.authority_generation
  if type(secret) ~= 'string' or #secret < MIN_SECRET_BYTES or #secret > MAX_SECRET_BYTES or
      type(authority_generation) ~= 'string' or #authority_generation == 0 or
      #authority_generation > 128 or
      not authority_generation:match('^[A-Za-z0-9][A-Za-z0-9._:-]*$') or
      not ttl_ms or ttl_ms < 60000 or ttl_ms > 604800000 or ttl_ms % 1 ~= 0 or
      not lease_ms or lease_ms < 1000 or lease_ms > 600000 or lease_ms % 1 ~= 0 or
      lease_ms >= ttl_ms then
    return nil
  end
  local script_id = options.redis.add_redis_script(SCRIPT, options.redis_params)
  if not script_id then
    return nil
  end
  return setmetatable({
    redis = options.redis,
    hash = options.hash,
    secret = secret,
    ttl_ms = ttl_ms,
    lease_ms = lease_ms,
    authority_generation = authority_generation,
    script_id = script_id,
  }, { __index = M })
end

-- M.identity derives one privacy-preserving key from exact ordered SMTP evidence.
function M:identity(input)
  if type(input) ~= 'table' or type(input.peer_ip) ~= 'string' or
      type(input.content) ~= 'string' or type(input.mail_from) ~= 'string' or
      type(input.rcpt_to) ~= 'table' or type(input.draft) ~= 'string' or
      type(input.projection_schema) ~= 'string' then
    return nil
  end
  local parts = {}
  frame_part(parts, 'frame', IDENTITY_FRAME)
  frame_part(parts, 'peer_ip', input.peer_ip)
  frame_part(parts, 'draft', input.draft)
  frame_part(parts, 'projection_schema', input.projection_schema)
  frame_part(parts, 'authority_generation', self.authority_generation)
  frame_part(parts, 'mail_from', input.mail_from)
  frame_part(parts, 'recipient_count', #input.rcpt_to)
  for index, recipient in ipairs(input.rcpt_to) do
    if type(recipient) ~= 'string' then
      return nil
    end
    frame_part(parts, 'recipient_' .. index, recipient)
  end
  frame_part(parts, 'message', input.content)
  local digest = self.hash.create_specific_keyed(self.secret, 'sha256', table.concat(parts))
  if not digest or type(digest.hex) ~= 'function' then
    return nil
  end
  return KEY_PREFIX .. digest:hex()
end

-- M.execute invokes one state-machine transition and validates its reply.
function M:execute(task, key, operation, owner, payload, callback)
  if type(key) ~= 'string' or type(owner) ~= 'string' or #owner < 16 or #owner > 128 or
      type(callback) ~= 'function' then
    return false
  end
  local args = { operation, owner, tostring(self.lease_ms), tostring(self.ttl_ms), payload or '' }
  return self.redis.exec_redis_script(self.script_id, {
    task = task, key = key, is_write = true,
  }, function(err, value)
    if err then
      callback(nil, nil)
      return
    end
    local status, result_payload = validate_result(value)
    callback(status, result_payload)
  end, { key }, args)
end

-- M.claim atomically leases one retry result or reports a cache miss/busy state.
function M:claim(task, key, owner, callback)
  return self:execute(task, key, 'claim', owner, nil, callback)
end

-- M.store persists one validated result provisionally before downstream policy.
function M:store(task, key, owner, payload, callback)
  if type(payload) ~= 'string' or #payload == 0 then
    return false
  end
  return self:execute(task, key, 'store', owner, payload, callback)
end

-- M.finalize arms a retryable result or consumes one terminal result.
function M:finalize(task, key, owner, retryable, callback)
  return self:execute(task, key, retryable and 'arm' or 'consume', owner, nil, callback)
end

M.redis_script = SCRIPT

return M
