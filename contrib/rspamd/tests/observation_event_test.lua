-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local event = assert(loadfile(assert(arg[1])))()
local strict = assert(loadfile((arg[1]:gsub('observation_event.lua$', 'strict_json.lua'))))()
local score, action = 2, 'no action'
local peer = '192.0.2.20'
local calls = 0
local task = {
  get_from_ip = function()
    return { is_valid = function() return peer ~= nil end, to_string = function() return peer end }
  end,
  get_client_ip = function() error('forwarded identity must never be read') end,
  get_metric_result = function() return { score = score, action = action } end,
  get_metric_threshold = function(_, kind) return kind == 'reject' and 15 or 4 end,
  has_symbol = function() error('arbitrary symbols must not enter observations') end,
}
local producer = assert(event.new({
  source = 'scan', instance = 'fixture', now = function() return 1800000000 end,
  random_hex = function(characters) calls = calls + 1 return string.rep(calls == 1 and 'a' or 'b',characters) end,
}))
local sealed = assert(producer:capture(task))
assert(event.is_sealed(sealed) and not event.is_sealed({}))
local body, id = sealed:body(), sealed:id()
assert(strict.valid(body))
assert(not pcall(function() sealed.body = function() return "forged" end end))
assert(id == 'scan.'..string.rep('a',64))
assert(body:find('"namespace":"reputation","action":"observe"',1,true))
assert(body:find('"mail.rspamd.clean"',1,true))
assert(body:find('"double":0.5',1,true))
assert(body:find('"192.0.2.20"',1,true))
assert(not body:find('causality',1,true) and not body:find('evidence_origin',1,true))
assert(not body:find('network',1,true) and not body:find('asn',1,true))
score, action, peer = 100, 'reject', '198.51.100.8'
assert(sealed:body() == body and sealed:id() == id and calls == 2)
local changed = assert(producer:capture(task)):body()
assert(changed:find('"mail.rspamd.reject"',1,true))
score, action = 6, 'greylist'
assert(producer:capture(task):body():find('"mail.rspamd.spam"',1,true))
for _, invalid in ipairs({0/0, math.huge, -math.huge}) do
  score = invalid
  assert(producer:capture(task) == nil)
end
score, peer = 6, nil
assert(producer:capture(task) == nil)
peer, action = '192.0.2.20', 'invented'
assert(producer:capture(task) == nil)
assert(event.new({source='bad source',instance='fixture'}) == nil)
print('immutable observation event and exact peer contract: PASS')

-- A zero greylist threshold is a legitimate delay configuration and must not divide by zero or invent spam at score zero.
local zero_greylist = setmetatable({
  get_metric_threshold=function(_,kind) return kind=='reject' and 15 or 0 end,
}, {__index=task})
score,action,peer=0,'greylist','192.0.2.20'
local zero_body=assert(producer:capture(zero_greylist)):body()
assert(zero_body:find('"mail.rspamd.clean"',1,true) and zero_body:find('"double":1',1,true))
score=3
assert(producer:capture(zero_greylist):body():find('"mail.rspamd.spam"',1,true))
