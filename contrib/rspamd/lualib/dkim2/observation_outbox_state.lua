-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
local bounds = {max_records={1,4096},max_bytes={128,268435456},max_age_ms={100,604800000},lease_ms={10,3600000},
  max_attempts={1,100},backoff_min_ms={1,3600000},backoff_max_ms={1,86400000},jitter_ms={0,60000},
  tombstone_limit={1,4096},tombstone_ttl_ms={1,604800000}}
local capacities = {max_records=true, max_bytes=true, tombstone_limit=true}

-- redis_bounds renders the single authoritative bounds table into the trusted Redis program.
local function redis_bounds()
  local names, values = {}, {}
  for name in pairs(bounds) do
    names[#names + 1] = name
  end
  table.sort(names)
  for _, name in ipairs(names) do
    values[#values + 1] = name .. '={' .. bounds[name][1] .. ',' .. bounds[name][2] .. '}'
  end
  return '{' .. table.concat(values, ',') .. '}'
end

-- M.valid_limits validates timing configuration against the same bounds enforced inside Redis.
function M.valid_limits(limits)
  if type(limits) ~= 'table' then
    return false
  end
  for name in pairs(limits) do
    if not bounds[name] or capacities[name] then
      return false
    end
  end
  for name, bound in pairs(bounds) do
    if not capacities[name] then
      local value = limits[name]
      if type(value) ~= 'number' or value % 1 ~= 0 or value < bound[1] or value > bound[2] then
        return false
      end
    end
  end
  return limits.lease_ms <= limits.max_age_ms and limits.backoff_min_ms <= limits.backoff_max_ms
end

M.redis_script = [==[
-- integer validates bounded exact Redis numbers before any state mutation.
local function integer(value, minimum, maximum)
  local n = tonumber(value)
  if not n or n ~= n or n % 1 ~= 0 or n < minimum or n > maximum then return nil end
  return n
end

-- hex validates opaque tags and lease tokens without accepting key syntax.
local function hex(value, length)
  return type(value) == 'string' and #value == length and not value:find('[^0-9a-f]')
end

-- identity restricts key versions and worker owners to bounded local identities.
local function identity(value)
  return type(value) == 'string' and #value > 0 and #value <= 64 and value:match('^[A-Za-z0-9_.-]+$') ~= nil
end

-- typed permits only the expected Redis representation or an absent key.
local function typed(key, expected)
  local kind = redis.call('TYPE', key).ok
  return kind == 'none' or kind == expected
end

if #ARGV ~= 3 or #ARGV[2] > 2048 or #ARGV[3] > 100000 then return {'INVALID'} end
local ok, cfg = pcall(cjson.decode, ARGV[2] or '')
local decoded, input = pcall(cjson.decode, ARGV[3] or '')
if not ok or not decoded or type(cfg) ~= 'table' or type(input) ~= 'table' or #KEYS ~= 5 then return {'INVALID'} end
local bounds = ]==] .. redis_bounds() .. [==[
for name in pairs(cfg) do if not bounds[name] then return {'INVALID'} end end
for name, bound in pairs(bounds) do
  cfg[name] = integer(cfg[name],bound[1],bound[2])
  if not cfg[name] then return {'INVALID'} end
end
if cfg.lease_ms > cfg.max_age_ms or cfg.backoff_min_ms > cfg.backoff_max_ms then return {'INVALID'} end
local operation = ARGV[1]
local input_fields = {
  enqueue = {allocation_tag=true,payload_fingerprint=true,key_id=true,nonce=true,ciphertext=true},
  claim = {lease_owner=true,lease_token=true},
  retry = {allocation_tag=true,lease_owner=true,lease_token=true,lease_generation=true,jitter_ms=true},
  ack = {allocation_tag=true,lease_owner=true,lease_token=true,lease_generation=true},
  dead = {allocation_tag=true,lease_owner=true,lease_token=true,lease_generation=true,reason=true},
  sweep = {},
}
if not input_fields[operation] then
  return {'INVALID'}
end
for name in pairs(input) do
  if not input_fields[operation][name] then
    return {'INVALID'}
  end
end
if operation == 'retry' or operation == 'ack' or operation == 'dead' then
  if not hex(input.allocation_tag, 64) or not identity(input.lease_owner) or
      not hex(input.lease_token, 32) or type(input.lease_generation) ~= 'number' or
      not integer(input.lease_generation, 1, 9007199254740991) then
    return {'INVALID'}
  end
end
local prefix = KEYS[1]:match('^(dkim2:observation:v1:{%d+}:)due$')
if not prefix or KEYS[2] ~= prefix..'capacity' or KEYS[3] ~= prefix..'record:' or
  KEYS[4] ~= prefix..'tombstone_due' or KEYS[5] ~= prefix..'tombstone_reason' or
  not typed(KEYS[1],'zset') or not typed(KEYS[2],'hash') or not typed(KEYS[4],'zset') or not typed(KEYS[5],'hash') then
  return {'INVALID'}
end
if redis.call('ZCARD',KEYS[4]) > 4096 or redis.call('HLEN',KEYS[5]) > 4096 then return {'CORRUPT'} end
local clock = redis.call('TIME')
local now = tonumber(clock[1])*1000 + math.floor(tonumber(clock[2])/1000)

-- ledger proves exact aggregate capacity against the bounded authoritative per-record charges.
local function ledger()
  local rows = redis.call('HGETALL',KEYS[2])
  if #rows == 0 then return {total=0,count=0,charges={}} end
  if #rows > 8194 then return nil end
  local result = {total=0,count=0,charges={}}
  local claimed
  for i=1,#rows,2 do
    if rows[i] == 'total_encrypted_bytes' then
      claimed = integer(rows[i+1],0,268435456)
      if not claimed then return nil end
    else
      local tag = rows[i]:match('^record:([0-9a-f]+)$')
      local size = integer(rows[i+1],1,65536)
      if not hex(tag,64) or not size then return nil end
      result.charges[tag]=size
      result.total=result.total+size
      result.count=result.count+1
    end
  end
  if claimed ~= result.total then return nil end
  return result
end
local capacity = ledger()
if not capacity then return {'CORRUPT'} end
local telemetry = {expired=0,missing=0,reclaimed=0,tombstone_expired=0,tombstone_evicted=0}
local fields = {schema_version=true,state=true,allocation_tag=true,payload_fingerprint=true,key_id=true,nonce=true,ciphertext=true,
  created_at=true,expires_at=true,next_attempt_at=true,attempt_count=true,lease_owner=true,lease_token=true,lease_generation=true,lease_until=true}
local numbers = {'created_at','expires_at','next_attempt_at','attempt_count','lease_generation','lease_until'}

-- record reads and validates one complete encrypted record and its exact schedule/ledger ownership.
local function record(tag)
  if not hex(tag,64) or not typed(KEYS[3]..tag,'hash') then return nil,'CORRUPT' end
  local rows=redis.call('HGETALL',KEYS[3]..tag)
  if #rows==0 then return nil,'MISSING' end
  if #rows~=30 then return nil,'CORRUPT' end
  local r={}
  for i=1,#rows,2 do
    if not fields[rows[i]] then return nil,'CORRUPT' end
    r[rows[i]]=rows[i+1]
  end
  for _,name in ipairs(numbers) do
    r[name]=integer(r[name],0,9007199254740991)
    if not r[name] then return nil,'CORRUPT' end
  end
  if r.schema_version~='1' or r.allocation_tag~=tag or not hex(r.payload_fingerprint,64) or not identity(r.key_id) or
    not hex(r.nonce,48) or #r.ciphertext<1 or #r.ciphertext>65536 or r.expires_at<=r.created_at or
    r.created_at>now or r.expires_at-r.created_at>bounds.max_age_ms[2] or
    r.next_attempt_at<r.created_at or r.next_attempt_at-r.created_at>bounds.max_age_ms[2]+bounds.backoff_max_ms[2] or
    r.attempt_count>100 or r.lease_generation~=r.attempt_count or capacity.charges[tag]~=#r.ciphertext or
    redis.call('PTTL',KEYS[3]..tag)~=-1 then return nil,'CORRUPT' end
  local due
  if r.state=='pending' and r.lease_owner=='' and r.lease_token=='' and r.lease_until==0 then
    due=math.min(r.next_attempt_at,r.expires_at)
  elseif r.state=='leased' and identity(r.lease_owner) and hex(r.lease_token,32) and r.lease_generation>0 and
    r.lease_until>=r.created_at and r.lease_until-r.created_at<=bounds.max_age_ms[2]+bounds.lease_ms[2] then
    due=math.min(r.lease_until,r.expires_at)
  else return nil,'CORRUPT' end
  if tonumber(redis.call('ZSCORE',KEYS[1],tag))~=due then return nil,'CORRUPT' end
  return r
end

-- prune_tombstones expires redacted history independently from live activity.
local function prune_tombstones()
  local expired=redis.call('ZRANGEBYSCORE',KEYS[4],'-inf',now)
  for _,tag in ipairs(expired) do
    telemetry.tombstone_expired=telemetry.tombstone_expired+1
    redis.call('ZREM',KEYS[4],tag)
    redis.call('HDEL',KEYS[5],tag)
  end
end

-- tombstone evicts oldest bounded history before adding one closed reason, never charging live capacity.
local function tombstone(tag,reason)
  prune_tombstones()
  while redis.call('ZCARD',KEYS[4])>=cfg.tombstone_limit do
    local oldest=redis.call('ZRANGE',KEYS[4],0,0)[1]
    telemetry.tombstone_evicted=telemetry.tombstone_evicted+1
    redis.call('ZREM',KEYS[4],oldest)
    redis.call('HDEL',KEYS[5],oldest)
  end
  redis.call('ZADD',KEYS[4],now+cfg.tombstone_ttl_ms,tag)
  redis.call('HSET',KEYS[5],tag,reason)
end

-- remove releases the exact ledger charge, record and due member in the same slot.
local function remove(tag,reason)
  if reason=='expired' or reason=='missing' then telemetry[reason]=telemetry[reason]+1 end
  local size=capacity.charges[tag] or 0
  capacity.total=capacity.total-size
  capacity.count=capacity.count-(size>0 and 1 or 0)
  capacity.charges[tag]=nil
  redis.call('HDEL',KEYS[2],'record:'..tag)
  redis.call('HSET',KEYS[2],'total_encrypted_bytes',capacity.total)
  redis.call('ZREM',KEYS[1],tag)
  redis.call('DEL',KEYS[3]..tag)
  if reason then tombstone(tag,reason) end
end

-- enqueue allocates one immutable event and refuses conflicting fingerprints or incoherent duplicates.
local function enqueue()
  local tag=input.allocation_tag
  if not hex(tag,64) or not hex(input.payload_fingerprint,64) or not identity(input.key_id) or
    not hex(input.nonce,48) or type(input.ciphertext)~='string' or #input.ciphertext<1 or #input.ciphertext>65536 then return {'INVALID'} end
  local existing,state=record(tag)
  if existing then
    if existing.payload_fingerprint~=input.payload_fingerprint then return {'CONFLICT'} end
    return {'DUPLICATE'}
  end
  if state~='MISSING' or capacity.charges[tag] or redis.call('ZSCORE',KEYS[1],tag) then return {'CORRUPT'} end
  prune_tombstones()
  if redis.call('ZSCORE',KEYS[4],tag) then return {'DEAD'} end
  local size=#input.ciphertext
  if capacity.count>=cfg.max_records or capacity.total+size>cfg.max_bytes then return {'FULL'} end
  redis.call('HSET',KEYS[3]..tag,'schema_version','1','state','pending','allocation_tag',tag,
    'payload_fingerprint',input.payload_fingerprint,'key_id',input.key_id,'nonce',input.nonce,'ciphertext',input.ciphertext,
    'created_at',now,'expires_at',now+cfg.max_age_ms,'next_attempt_at',now,'attempt_count',0,
    'lease_owner','','lease_token','','lease_generation',0,'lease_until',0)
  redis.call('HSET',KEYS[2],'record:'..tag,size,'total_encrypted_bytes',capacity.total+size)
  redis.call('ZADD',KEYS[1],now,tag)
  return {'ENQUEUED'}
end

-- claim leases one due record with a new token and monotonically increasing generation.
local function claim()
  if not identity(input.lease_owner) or not hex(input.lease_token,32) then return {'INVALID'} end
  local tag=redis.call('ZRANGEBYSCORE',KEYS[1],'-inf',now,'LIMIT',0,1)[1]
  if not tag then return {'EMPTY'} end
  local r,state=record(tag)
  if not r then return {state} end
  if r.expires_at<=now then remove(tag,'expired');return {'EXPIRED'} end
  if r.attempt_count>=cfg.max_attempts then remove(tag,'attempts');return {'DEAD'} end
  if r.lease_generation>=9007199254740990 then return {'CORRUPT'} end
  if r.state=='leased' then telemetry.reclaimed=telemetry.reclaimed+1 end
  r.state='leased';r.lease_owner=input.lease_owner;r.lease_token=input.lease_token
  r.lease_generation=r.lease_generation+1;r.lease_until=now+cfg.lease_ms;r.attempt_count=r.attempt_count+1
  redis.call('HSET',KEYS[3]..tag,'state',r.state,'lease_owner',r.lease_owner,'lease_token',r.lease_token,
    'lease_generation',r.lease_generation,'lease_until',r.lease_until,'attempt_count',r.attempt_count)
  redis.call('ZADD',KEYS[1],math.min(r.lease_until,r.expires_at),tag)
  return {'LEASED',cjson.encode(r)}
end

-- owned requires an exact current unexpired fenced lease for every worker completion.
local function owned()
  local r,state=record(input.allocation_tag)
  if not r then return nil,state end
  if r.state~='leased' or r.expires_at<=now or r.lease_until<=now or r.lease_owner~=input.lease_owner or
    r.lease_token~=input.lease_token or r.lease_generation~=tonumber(input.lease_generation) then return nil,'STALE' end
  return r
end

-- retry keeps the same ciphertext and schedules capped backoff no later than logical expiry in the due index.
local function retry()
  local r,state=owned()
  if not r then return {state} end
  local jitter=integer(input.jitter_ms or 0,0,cfg.jitter_ms)
  if not jitter then return {'INVALID'} end
  if r.attempt_count>=cfg.max_attempts then remove(r.allocation_tag,'attempts');return {'DEAD'} end
  local delay=math.min(cfg.backoff_max_ms,cfg.backoff_min_ms*2^math.min(30,r.attempt_count-1)+jitter)
  local next_at=now+delay
  redis.call('HSET',KEYS[3]..r.allocation_tag,'state','pending','next_attempt_at',next_at,
    'lease_owner','','lease_token','','lease_until',0)
  redis.call('ZADD',KEYS[1],math.min(next_at,r.expires_at),r.allocation_tag)
  return {'RETRY'}
end

-- complete removes only the current owner's event after acknowledgement or a closed terminal reason.
local function complete(dead)
  local r,state=owned()
  if not r then return {state} end
  local reason=dead and (input.reason or 'rejected') or nil
  if reason and not ({rejected=true,corrupt=true,attempts=true})[reason] then return {'INVALID'} end
  remove(r.allocation_tag,reason)
  return {dead and 'DEAD' or 'ACKED'}
end

-- sweep independently reconciles logical expiry, missing records and expired leases with exact capacity cleanup.
local function sweep()
  local tags = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now, 'LIMIT', 0, 4097)
  if #tags > 4096 then
    return {'CORRUPT'}
  end
  local records, seen = {}, {}
  for _, tag in ipairs(tags) do
    local r, state = record(tag)
    if not r and state ~= 'MISSING' then
      return {state}
    end
    records[#records + 1] = {tag = tag, state = r and r.state,
      expires_at = r and r.expires_at, lease_until = r and r.lease_until}
    seen[tag] = true
  end
  for tag in pairs(capacity.charges) do
    if not seen[tag] then
      local r, state = record(tag)
      if not r and state ~= 'MISSING' then
        return {state}
      end
      if not r then
        records[#records + 1] = {tag = tag}
      end
    end
  end
  prune_tombstones()
  for _, entry in ipairs(records) do
    if not entry.state then
      remove(entry.tag, 'missing')
    elseif entry.expires_at <= now then
      remove(entry.tag, 'expired')
    elseif entry.state == 'leased' and entry.lease_until <= now then
      telemetry.reclaimed=telemetry.reclaimed+1
      redis.call('HSET', KEYS[3] .. entry.tag, 'state', 'pending', 'next_attempt_at', now,
        'lease_owner', '', 'lease_token', '', 'lease_until', 0)
      redis.call('ZADD', KEYS[1], math.min(now, entry.expires_at), entry.tag)
    end
  end
  return {'SWEPT'}
end

local result
if operation=='enqueue' then result=enqueue()
elseif operation=='claim' then result=claim()
elseif operation=='retry' then result=retry()
elseif operation=='ack' then result=complete(false)
elseif operation=='dead' then result=complete(true)
elseif operation=='sweep' then result=sweep()
else return {'INVALID'} end
if result[1]=='INVALID' or result[1]=='CORRUPT' then return result end
-- Optional diagnostics cannot turn a committed transition into a failed acknowledgement.
local function snapshot()
  telemetry.observed_at=now
  telemetry.live_records=math.max(0,redis.call('HLEN',KEYS[2])-1)
  telemetry.live_bytes=tonumber(redis.call('HGET',KEYS[2],'total_encrypted_bytes')) or 0
  telemetry.due_records=redis.call('ZCARD',KEYS[1])
  telemetry.tombstones=redis.call('ZCARD',KEYS[4])
  return cjson.encode(telemetry)
end
local measured, encoded = pcall(snapshot)
if not measured then return result end
return {result[1],result[2] or '',encoded}
]==]
return M
