-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

package.path = '/fixture/lualib/?.lua;' .. package.path
local crypto = require 'dkim2.observation_outbox_crypto'
local events = require 'dkim2.observation_event'
local hash = require 'rspamd_cryptobox_hash'
local secretbox = require 'rspamd_cryptobox_secretbox'
local util = require 'rspamd_util'
local ucl = require 'ucl'

-- write_fixture creates synthetic keys only inside the isolated container's private temporary filesystem.
local function write_fixture(name,value)
  local file = assert(io.open('/tmp/'..name,'wb'))
  assert(file:write(value))
  assert(file:close())
  return {file='/tmp/'..name}
end

local allocation = write_fixture('allocation',string.rep('a',32))
local active = write_fixture('active',string.rep('e',32))
local next_key = write_fixture('next',string.rep('f',32))

-- decode uses the real Rspamd JSON parser behind the canonical event contract.
local function decode(body)
  local parser = ucl.parser()
  assert(parser:parse_string(body))
  return parser:get_object()
end

local options = {allocation_key=allocation,active_key=active,source='scan',shard_count=4,
  hash=hash,secretbox=secretbox,util=util,decode=decode}
local current = assert(crypto.new(options))
local producer = assert(events.new({source='scan',instance='fixture',now=function() return 1800000000 end,random_hex=util.random_hex}))
local task = {
  get_from_ip=function() return {is_valid=function() return true end,to_string=function() return '192.0.2.8' end} end,
  get_metric_result=function() return {score=2,action='no action'} end,
  get_metric_threshold=function(_,kind) return kind=='reject' and 15 or 4 end,
}
local event = assert(producer:capture(task))
local record, shard = current:seal(event)
assert(record and shard>=0 and shard<4)
assert(not record.ciphertext:find('192.0.2.8',1,true))
local body, request_id = current:open(record)
assert(body==event:body() and request_id==event:request_id())
assert(current:seal({body=function() return event:body() end})==nil)
options.active_key, options.previous_key = next_key, active
local rotated = assert(crypto.new(options))
assert(rotated:allocation_id()==current:allocation_id())
local next_record,next_shard = rotated:seal(event)
assert(next_record.allocation_tag==record.allocation_tag and next_shard==shard)
assert(next_record.payload_fingerprint==record.payload_fingerprint and next_record.key_id~=record.key_id)
assert(rotated:open(record)==event:body())
for _, field in ipairs({'allocation_tag','payload_fingerprint','nonce','ciphertext','key_id'}) do
  local altered={}
  for key,value in pairs(record) do altered[key]=value end
  altered[field]=(altered[field]:sub(1,1)=='a' and 'b' or 'a')..altered[field]:sub(2)
  assert(rotated:open(altered)==nil,'altered encrypted envelope accepted')
end
options.allocation_key=write_fixture('other-allocation',string.rep('b',32))
assert(crypto.new(options):allocation_id()~=current:allocation_id())
options.allocation_key=active
assert(crypto.new(options)==nil,'allocation and encryption key material must stay separate')
options.allocation_key=allocation
options.active_key=next_key
options.previous_key=active
options.authority_files={write_fixture('policy-password',string.rep('f',32))}
assert(crypto.new(options)==nil,'encryption material must not equal another authority secret')
options.authority_files={write_fixture('independent-password','different-policy-password')}
assert(crypto.new(options))
for _, reference in ipairs({{file='/tmp/absent'}, {value='inline-secret'},
    write_fixture('short-key',string.rep('s',31)),write_fixture('long-key',string.rep('l',65))}) do
  options.active_key=reference
  assert(crypto.new(options)==nil,'malformed key reference accepted')
end
print('native encrypted outbox identity, rotation and tamper tests: PASS')
