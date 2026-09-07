-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

package.path = assert(arg[1]) .. '/?.lua;' .. package.path
local module = require 'dkim2.observation_redis'
local parameters={ssl=true,no_ssl_verify=false,sni='redis.fixture',username='outbox',password='synthetic'}
local calls, replies, result = {}, {}, nil
-- request models the shipped TLS-aware request entrypoints, including duplicate callback defense.
local function request(params, key, write, callback, command, args)
  assert(params==parameters and params.ssl and params.no_ssl_verify==false and key=='slot' and write)
  calls[#calls+1]=command
  local reply=table.remove(replies,1)
  assert(reply,'unexpected extra Redis request')
  if reply.started==false then return false end
  callback(reply.err,reply.value)
  callback(reply.err,reply.value)
  return true
end
local client = assert(module.new({
  redis_make_request=function(task,...) assert(task=='task');return request(...) end,
  redis_make_request_taskless=function(ev,cfg,...) assert(ev=='loop' and cfg=='config');return request(...) end,
},'config'))
local id=assert(client.add_redis_script('return {"READY"}',parameters))
local completed=0
local function finish(err,value) completed=completed+1;result=err and 'UNAVAILABLE' or value[1] end
replies={{value=string.rep('a',40)},{value={'READY'}}}
assert(client.exec_redis_script(id,{task='task',key='slot',is_write=true},finish,{'slot'},{}))
assert(result=='READY' and completed==1 and table.concat(calls,',')=='SCRIPT,EVALSHA')
replies={{err='NOSCRIPT No matching script'},{value=string.rep('a',40)},{value={'READY'}}}
calls={}
client.exec_redis_script(id,{ev_base='loop',key='slot',is_write=true},finish,{'slot'},{})
assert(result=='READY' and completed==2 and table.concat(calls,',')=='EVALSHA,SCRIPT,EVALSHA')
replies={{err='NOSCRIPT No matching script'},{value=string.rep('a',40)},{err='NOSCRIPT No matching script'}}
client.exec_redis_script(id,{task='task',key='slot',is_write=true},finish,{'slot'},{})
assert(result=='UNAVAILABLE' and completed==3 and #replies==0,'reload retries must be bounded')
replies={{started=false}}
client.exec_redis_script(id,{task='task',key='slot',is_write=true},finish,{'slot'},{})
assert(result=='UNAVAILABLE' and completed==4)
assert(not client.add_redis_script('return 1',{}),'unverified Redis settings must be rejected')
print('outbox script loading and bounded NOSCRIPT recovery retain TLS authority: PASS')
