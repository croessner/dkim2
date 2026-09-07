-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

package.path = assert(arg[1]) .. '/?.lua;' .. package.path
local queue_options, crypto_options, transport_options, redis_options
local loaded, timers = nil, {}
local queue = {ready=false, initialize=function(self,_,callback) self.ready=true;callback('READY') end,
  work=function() end,sweep=function() end,enqueue=function() return true end}
package.preload['dkim2.observation_outbox'] = function()
  return {new=function(options) queue_options=options;return queue end}
end
package.preload['dkim2.observation_outbox_crypto'] = function()
  return {new=function(options) crypto_options=options;return {} end}
end
package.preload['dkim2.policy_transport'] = function()
  return {new=function(options) transport_options=options;return {send=function() end} end}
end
package.preload.rspamd_cryptobox_secretbox = function() return {} end
package.preload['dkim2.protected_file'] = function()
  return {read=function() return 'synthetic-password' end}
end
local module = require 'dkim2.observation_runtime'
local runtime = {
  observation_counter=function() end,
  config={add_on_load=function(_,callback) loaded=callback end,
    add_periodic=function(_,_,_,callback) timers[#timers+1]=callback end},
  redis={redis_make_request=function() end,redis_make_request_taskless=function() end,parse_redis_server=function(name,options)
    assert(name=='dkim2_observation')
    redis_options=options.redis
    return options.redis
  end},
  util={get_time=function() return 1800000000 end,random_hex=function(length) return string.rep('a',length) end},
  ucl={to_format=function() return '{}' end,parser=function() end},http={},hash={},json_validator=function() return true end,
  decision_password_file='/protected/decision',retry_key_file='/protected/retry',capability_file='/protected/verifier',
}
local settings = {mode='asynchronous',source='scan',instance='fixture',failure_action='tempfail',
  endpoint='https://policy.example.test:9443/api/v1/policy/decisions',server_name='policy.example.test',
  username='ScanWriter',password_file='/protected/observation',timeout=1,
  outbox={allocation_key={file='/protected/allocation'},active_key={file='/protected/encryption'},
    shard_count=4,max_records=100,max_encrypted_bytes=100000,max_age_ms=60000,lease_ms=10000,
    max_attempts=3,backoff_min_ms=100,backoff_max_ms=1000,jitter_ms=20,tombstone_limit=100,
    tombstone_ttl_ms=60000,drain_generation=0,poll_interval=0.25,sweep_interval=1,
    redis={servers='redis.example.test:6379',username='outbox',password_file='/protected/redis',
      ssl=true,sni='redis.example.test',timeout=1}},
}
assert(module.new(settings,runtime))
assert(queue_options.redis ~= runtime.redis and type(queue_options.redis.exec_redis_script)=='function')
assert(queue_options.allocation.max_bytes==100000 and #crypto_options.authority_files==5)
assert(transport_options.background_config==runtime.config and transport_options.password_file=='/protected/observation')
assert(redis_options.password=='synthetic-password' and redis_options.password_file==nil and redis_options.ssl==true)
loaded(runtime.config,'event-loop',{is_scanner=function() return true end})
assert(#timers==3)
assert(timers[1]()==60)
timers[2]()
assert(queue.ready)
assert(timers[3]()==1)
settings.outbox.redis.no_ssl_verify=true
assert(module.new(settings,runtime)==nil)
settings.outbox.redis.no_ssl_verify=nil
settings.outbox.lease_ms=500
assert(module.new(settings,runtime)==nil,'lease must cover the HTTP and Redis completion budget')
settings.outbox.lease_ms=10000
settings.outbox.extra=true
assert(module.new(settings,runtime)==nil)
settings.outbox.extra=nil
settings.failure_action='continue'
assert(module.new(settings,runtime)==nil)
settings.failure_action='tempfail'
package.loaded.rspamd_cryptobox_secretbox=nil
package.preload.rspamd_cryptobox_secretbox=function() error('unsupported fixture primitive') end
local available, rejected=pcall(module.new,settings,runtime)
assert(available and rejected==nil,'unsupported authenticated encryption must reject asynchronous configuration cleanly')
settings.mode='synchronous'
assert(module.new(settings,runtime)==nil,'unused outbox configuration is not silently ignored')
settings.outbox=nil
assert(module.new(settings,runtime))
print('observation runtime closed config, TLS, secret ownership and worker startup: PASS')
