-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local path = assert(arg[1])
package.path = path .. '/?.lua;' .. package.path
local module = require 'dkim2.observation_outbox'
local calls, response, pending = {}, {'READY'}, nil
local observed = {}
local random_calls = 0
local redis = {
  add_redis_script = function(script) return script:find('ALLOCATION_MISMATCH',1,true) and 'allocation' or 'state' end,
  exec_redis_script = function(id, context, callback, keys, args)
    calls[#calls+1] = {id=id, context=context, keys=keys, args=args}
    callback(nil,response)
    callback(nil,response)
    return true
  end,
}
local body, request_id = 'sealed-body', string.rep('1',32)
local envelope = {allocation_tag=string.rep('a',64),payload_fingerprint=string.rep('b',64),
  key_id=string.rep('c',64),nonce=string.rep('d',48),ciphertext='opaque'}
local crypto = {
  allocation_id = function() return string.rep('a',64) end,
  seal = function() return envelope,0 end,
  open = function() return body,request_id end,
}
local claimed = {allocation_tag=envelope.allocation_tag,lease_owner='worker',lease_token=string.rep('1',32),lease_generation=1}
local encoded = {}
local options = {redis=redis,redis_params={},crypto=crypto,
  observer=function(operation,outcome,shard,snapshot)
    observed[#observed+1]={operation,outcome,shard,snapshot}
  end,
  encode=function(value) encoded[#encoded+1]=value; return '{}' end,
  decode=function(value)
    if value=='numeric-snapshot' then return {observed_at=1000,live_records=1,live_bytes=128,due_records=1,tombstones=0,expired=0,missing=0,reclaimed=0,tombstone_expired=0,tombstone_evicted=0} end
    return claimed
  end, random_hex=function(length) random_calls=random_calls+1;return string.rep(string.format('%x',random_calls%16),length) end,
  transport={send_background=function(_,ev_base,payload,id,callback)
    assert(ev_base=='event-loop' and payload==body and id==request_id)
    pending=callback
    return true
  end},
  allocation={shard_count=2,max_records=5,max_bytes=1025,tombstone_limit=3,drain_generation=0},
  limits={max_age_ms=60000,lease_ms=1000,max_attempts=3,backoff_min_ms=100,backoff_max_ms=1000,jitter_ms=20,tombstone_ttl_ms=1000},
}
local queue = assert(module.new(options))
local status
queue:enqueue({}, {}, function(value) status=value end)
assert(status=='UNAVAILABLE' and #calls==0)
local constructor_owner=queue.owner
queue:initialize('event-loop',function(value) status=value end)
assert(queue.owner~=constructor_owner,'forked workers must acquire their own owner at initialization')
assert(status=='READY' and calls[#calls].keys[1]=='dkim2:observation:v1:{meta}:allocation')
response={'ENQUEUED'}
queue:enqueue({}, {}, function(value) status=value end)
assert(status=='ENQUEUED' and calls[#calls].args[1]=='enqueue')
assert(encoded[#encoded-1].max_records==3 and encoded[#encoded-1].max_bytes==513)
response={'LEASED','encoded-record'}
assert(queue:work('event-loop',0))
assert(pending and calls[#calls].args[1]=='claim')
local before=#calls
assert(not queue:work('event-loop',0) and #calls==before)
response={'ACKED'}
pending({effect='permit',status={code='permit',retryable=false}})
assert(calls[#calls].args[1]=='ack')
response={'LEASED','encoded-record'}
queue:work('event-loop',0)
response={'RETRY'}
pending({effect='indeterminate',status={code='effect_outcome_unknown_replay_safe',retryable=true}})
assert(calls[#calls].args[1]=='retry')
response={'LEASED','encoded-record'}
queue:work('event-loop',0)
response={'DEAD'}
pending({effect='deny',status={code='policy_denied',retryable=false}})
assert(calls[#calls].args[1]=='dead')
response={'LEASED','encoded-record'}
queue:work('event-loop',0)
response={'DEAD'}
pending(nil,'rejected')
assert(calls[#calls].args[1]=='dead' and encoded[#encoded].reason=='rejected')
response={'SWEPT'}
queue:sweep('event-loop',1)
assert(calls[#calls].args[1]=='sweep')
assert(#observed==#calls,'duplicate callbacks must not inflate operation counters')
assert(observed[1][1]=='initialize' and observed[1][2]=='READY')
response={'ENQUEUED','','numeric-snapshot'}
queue:enqueue({}, {}, function(value) status=value end)
assert(status=='ENQUEUED' and observed[#observed][3]==0 and observed[#observed][4].live_records==1)
for _, invalid in ipairs({'invalid-json',string.rep('x',1025),false}) do
  response={'ENQUEUED','',invalid}
  queue:enqueue({}, {}, function(value) status=value end)
  assert(status=='ENQUEUED' and observed[#observed][4]==nil,'optional diagnostics must not change authority')
end
for _, invalid in ipairs({{'ENQUEUED','unexpected','numeric-snapshot'},{'ENQUEUED','','numeric-snapshot','extra'},{'LEASED'},{'LEASED',false,'numeric-snapshot'}}) do
  response=invalid
  queue:enqueue({}, {}, function(value) status=value end)
  assert(status=='UNAVAILABLE','malformed authority reply was accepted')
end
queue.observer=function() error('synthetic observer failure') end
response={'ALLOCATION_MISMATCH'}
queue:initialize('event-loop',function(value) status=value end)
assert(status=='ALLOCATION_MISMATCH')
before=#calls
queue:enqueue({}, {}, function(value) status=value end)
assert(status=='UNAVAILABLE' and #calls==before)
print('outbox startup, bounded worker, replay-safe delivery and capacity partition: PASS')
