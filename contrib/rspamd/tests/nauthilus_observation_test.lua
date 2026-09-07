-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

package.path = assert(arg[1]) .. '/?.lua;' .. package.path
local module = require 'dkim2.nauthilus_observation'
local events = require 'dkim2.observation_event'
local producer = assert(events.new({source='scan',instance='fixture',now=function() return 1800000000 end,
  random_hex=function(length) return string.rep('a',length) end}))
local task = {
  get_from_ip=function() return {is_valid=function() return true end,to_string=function() return '192.0.2.8' end} end,
  get_metric_result=function() return {score=2,action='no action'} end,
  get_metric_threshold=function(_,kind) return kind=='reject' and 15 or 4 end,
}
local pending, queued, result, started = nil,nil,nil,true
local transport = {send=function(_,value,body,id,callback)
  assert(value==task)
  pending=callback
  queued={body=body,id=id}
  return started
end}
local synchronous = assert(module.new({mode='synchronous',producer=producer,transport=transport}))
local sealed = assert(synchronous:capture(task))
synchronous:deliver(task,sealed,function(status) result=status end)
assert(result==nil and queued.body==sealed:body() and queued.id==sealed:request_id())
pending({effect='permit',status={code='permit',retryable=false}})
assert(result=='ACKNOWLEDGED')
for _, reply in ipairs({{effect='deny',status={code='policy_denied',retryable=false}},
  {effect='indeterminate',status={code='effect_outcome_unknown_replay_safe',retryable=true}}}) do
  result=nil
  synchronous:deliver(task,sealed,function(status) result=status end)
  pending(reply)
  assert(result=='UNAVAILABLE')
end
started=false
synchronous:deliver(task,sealed,function(status) result=status end)
assert(result=='UNAVAILABLE')
local outbox = {enqueue=function(_,value,event,callback)
  assert(value==task and event==sealed)
  pending=callback
  return true
end}
local asynchronous = assert(module.new({mode='asynchronous',producer=producer,outbox=outbox}))
for _, status in ipairs({'ENQUEUED','DUPLICATE','FULL','UNAVAILABLE','CONFLICT','DEAD'}) do
  result=nil
  asynchronous:deliver(task,sealed,function(value) result=value end)
  assert(result==nil)
  pending(status)
  assert(result==((status=='ENQUEUED' or status=='DUPLICATE') and 'PERSISTED' or 'UNAVAILABLE'))
end
assert(not module.new({mode='fire-and-forget',producer=producer,transport=transport}))
assert(not module.new({mode='asynchronous',producer=producer}))
print('observation synchronous acknowledgement and durable enqueue boundary: PASS')
