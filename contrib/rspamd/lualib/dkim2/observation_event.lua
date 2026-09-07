-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
local issued = setmetatable({}, {__mode = 'k'})
local ACTIONS = {
  ['no action'] = true, accept = true, ['add header'] = true,
  ['rewrite subject'] = true, greylist = true, ['soft reject'] = true,
  reject = true, discard = true, quarantine = true,
}

-- finite bounds numeric input before comparison or canonical JSON rendering.
local function finite(value)
  return type(value) == 'number' and value == value and value > -math.huge and value < math.huge
end

-- identity accepts only bounded ASCII configuration identities requiring no JSON escaping.
local function identity(value, maximum)
  return type(value) == 'string' and #value > 0 and #value <= maximum and
    value:match('^[A-Za-z][A-Za-z0-9_.-]*$') ~= nil
end

-- random_id requires the exact unpredictable lowercase hexadecimal length requested from the runtime.
local function random_id(random, bytes)
  local value = random(bytes * 2)
  if type(value) ~= 'string' or #value ~= bytes * 2 or value:find('[^0-9a-f]') then
    return nil
  end
  return value
end

-- canonical_peer admits only the bounded native IP rendering without JSON-sensitive bytes or scope zones.
local function canonical_peer(value)
  return type(value) == 'string' and #value > 0 and #value <= 45 and not value:find('[^0-9a-fA-F:.]')
end

-- current_peer uses only the native SMTP peer object and its canonical rendering.
local function current_peer(task)
  local ip = task:get_from_ip()
  if not ip or not ip:is_valid() then
    return nil
  end
  local value = ip:to_string()
  return canonical_peer(value) and value or nil
end

-- signal derives independent bounded evidence from the normal scan and its configured thresholds.
local function signal(task)
  local metric = task:get_metric_result()
  local greylist, reject = task:get_metric_threshold('greylist'), task:get_metric_threshold('reject')
  if type(metric) ~= 'table' or not ACTIONS[metric.action] or not finite(metric.score) or
      not finite(greylist) or not finite(reject) or greylist < 0 or reject <= 0 or reject <= greylist then
    return nil
  end
  if metric.score >= reject then
    return 'mail.rspamd.reject', 1
  end
  if metric.score > 0 and metric.score >= greylist then
    return 'mail.rspamd.spam', math.min(1, metric.score / reject)
  end
  -- A zero greylist threshold delays clean mail without supplying positive spam evidence.
  local clean = greylist > 0 and 1 - metric.score / greylist or 1
  return 'mail.rspamd.clean', math.max(0, math.min(1, clean))
end

-- canonical_body serializes the closed observation contract in one fixed order with no caller extensions.
local function canonical_body(instance, event_id, request_id, timestamp, peer, code, magnitude)
  return '{"version":"1","request_id":"' .. request_id ..
    '","target":{"namespace":"reputation","action":"observe"},' ..
    '"resource":{"type":"reputation-observation","attributes":{' ..
    '"reputation.event_id":{"string":"' .. event_id .. '"},' ..
    '"reputation.observed_at":{"timestamp":"' .. timestamp .. '"},' ..
    '"reputation.signal":{"string":"' .. code .. '"},' ..
    '"reputation.magnitude":{"double":' .. string.format('%.17g', magnitude) .. '},' ..
    '"reputation.subjects":{"records":[{"fields":[' ..
    '{"name":"role","value":{"string":"smtp_peer"}},' ..
    '{"name":"kind","value":{"string":"ip"}},' ..
    '{"name":"value","value":{"string":"' .. peer .. '"}}]}]}}},' ..
    '"environment":{"service":"rspamd","instance":"' .. instance .. '","protocol":"milter"},' ..
    '"options":{"include_diagnostics":false}}'
end

-- sealed_event retains immutable canonical bytes independently of every mutable task or caller table.
local function sealed_event(id, request_id, body)
  local event = setmetatable({}, {
    __index = {
      id = function() return id end,
      request_id = function() return request_id end,
      body = function() return body end,
    },
    __newindex = function() error('observation event is immutable') end,
    __metatable = false,
  })
  issued[event] = true
  return event
end

-- M.new captures a bounded source identity and native clock/random providers without network or storage authority.
function M.new(options)
  if type(options) ~= 'table' or not identity(options.source, 32) or not identity(options.instance, 64) or
      type(options.now) ~= 'function' or type(options.random_hex) ~= 'function' then
    return nil
  end
  for key in pairs(options) do
    if not ({source = true, instance = true, now = true, random_hex = true})[key] then
      return nil
    end
  end
  return setmetatable({source = options.source, instance = options.instance,
    now = options.now, random = options.random_hex}, {__index = M})
end

-- M.capture freezes one independent pre-policy observation; delivery retries reuse this exact sealed event.
function M:capture(task)
  local peer = current_peer(task)
  local code, magnitude = signal(task)
  local now = self.now()
  if not peer or not code or not finite(now) or now < 0 or now > 4102444800 then
    return nil
  end
  local event_id, request_id = random_id(self.random, 32), random_id(self.random, 16)
  if not event_id or not request_id then
    return nil
  end
  event_id = self.source .. '.' .. event_id
  local timestamp = os.date('!%Y-%m-%dT%H:%M:%SZ', math.floor(now))
  local body = canonical_body(self.instance, event_id, request_id, timestamp, peer, code, magnitude)
  if #body > 32768 then
    return nil
  end
  return sealed_event(event_id, request_id, body)
end

-- attribute reads one typed scalar without trusting arbitrary decoder coercion.
local function attribute(attributes, name, kind)
  local value = attributes[name]
  return type(value) == 'table' and value[kind] or nil
end

-- subject_field reads one exact positional subject field from the canonical wire record.
local function subject_field(fields, index, name)
  local field = fields[index]
  if type(field) ~= 'table' or field.name ~= name or type(field.value) ~= 'table' then
    return nil
  end
  return field.value.string
end

-- M.inspect verifies decrypted canonical bytes by reconstructing the sole closed event representation.
function M.inspect(body, decode)
  if type(body) ~= 'string' or #body == 0 or #body > 32768 or type(decode) ~= 'function' then
    return nil
  end
  local ok, value = pcall(decode, body)
  if not ok or type(value) ~= 'table' or type(value.resource) ~= 'table' or
      type(value.resource.attributes) ~= 'table' or type(value.environment) ~= 'table' then
    return nil
  end
  local attrs = value.resource.attributes
  local event_id = attribute(attrs, 'reputation.event_id', 'string')
  local timestamp = attribute(attrs, 'reputation.observed_at', 'timestamp')
  local code = attribute(attrs, 'reputation.signal', 'string')
  local magnitude = attribute(attrs, 'reputation.magnitude', 'double')
  local subjects = attribute(attrs, 'reputation.subjects', 'records')
  if type(subjects) ~= 'table' or #subjects ~= 1 or type(subjects[1]) ~= 'table' or
      type(subjects[1].fields) ~= 'table' or #subjects[1].fields ~= 3 then
    return nil
  end
  local fields = subjects[1].fields
  local peer = subject_field(fields, 3, 'value')
  if subject_field(fields, 1, 'role') ~= 'smtp_peer' or subject_field(fields, 2, 'kind') ~= 'ip' or
      not canonical_peer(peer) or not identity(value.environment.instance, 64) or
      type(event_id) ~= 'string' or type(timestamp) ~= 'string' or
      not timestamp:match('^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%dZ$') or
      not ({['mail.rspamd.clean']=true,['mail.rspamd.spam']=true,['mail.rspamd.reject']=true})[code] or
      not finite(magnitude) or magnitude < 0 or magnitude > 1 then
    return nil
  end
  local source, opaque = event_id:match('^([A-Za-z][A-Za-z0-9_.-]*)%.([0-9a-f]+)$')
  local request_id = value.request_id
  if not identity(source, 32) or not opaque or #opaque ~= 64 or type(request_id) ~= 'string' or
      #request_id ~= 32 or request_id:find('[^0-9a-f]') then
    return nil
  end
  if canonical_body(value.environment.instance, event_id, request_id, timestamp, peer, code, magnitude) ~= body then
    return nil
  end
  return event_id, request_id, source
end

-- M.is_sealed accepts only events issued by this owner, never caller-shaped request tables.
function M.is_sealed(event)
  return issued[event] == true
end

return M
