-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local events = require 'dkim2.observation_event'
local observation = require 'dkim2.nauthilus_observation'
local transport_module = require 'dkim2.policy_transport'
local protected_file = require 'dkim2.protected_file'
local state = require 'dkim2.observation_outbox_state'
local allocation = require 'dkim2.observation_allocation'
local M = {}

local TOP_KEYS = {mode=true,source=true,instance=true,failure_action=true,endpoint=true,server_name=true,
  username=true,password_file=true,timeout=true,max_response_bytes=true,outbox=true}
local OUTBOX_KEYS = {allocation_key=true,active_key=true,previous_key=true,shard_count=true,max_records=true,
  max_encrypted_bytes=true,max_age_ms=true,lease_ms=true,max_attempts=true,backoff_min_ms=true,
  backoff_max_ms=true,jitter_ms=true,tombstone_limit=true,tombstone_ttl_ms=true,drain_generation=true,
  poll_interval=true,sweep_interval=true,redis=true}
local REDIS_KEYS = {servers=true,username=true,password_file=true,timeout=true,ssl=true,no_ssl_verify=true,
  ssl_ca=true,ssl_ca_dir=true,sni=true}

-- closed rejects misspelled configuration instead of silently applying incomplete protection.
local function closed(value, allowed)
  if type(value) ~= 'table' then
    return false
  end
  for key in pairs(value) do
    if not allowed[key] then
      return false
    end
  end
  return true
end

-- interval validates a finite explicit runtime duration without string coercion.
local function interval(value, minimum, maximum)
  return type(value) == 'number' and value >= minimum and value <= maximum
end

-- redis_settings loads only the outbox credential and requires a named TLS/ACL authority.
local function redis_settings(settings, runtime)
  if not closed(settings, REDIS_KEYS) or settings.ssl ~= true or
      (settings.no_ssl_verify ~= nil and settings.no_ssl_verify ~= false) or
      type(settings.servers) ~= 'string' or #settings.servers == 0 or #settings.servers > 512 or
      type(settings.username) ~= 'string' or not settings.username:match('^[A-Za-z0-9_.-]+$') or
      #settings.username > 64 or type(settings.sni) ~= 'string' or #settings.sni > 253 or
      not settings.sni:match('^[a-z0-9][a-z0-9.-]*$') or not interval(settings.timeout, 0.1, 5) then
    return nil
  end
  local password = protected_file.read(settings.password_file, 1, 1024)
  if not password or password:find('[\r\n%z]') then
    return nil
  end
  local options = {password=password, no_ssl_verify=false}
  for key, value in pairs(settings) do
    if key ~= 'password_file' then
      options[key] = value
    end
  end
  local parameters = runtime.redis.parse_redis_server('dkim2_observation', {redis=options})
  if not parameters or parameters.ssl ~= true or parameters.no_ssl_verify ~= false or
      parameters.username ~= options.username or parameters.password ~= password then
    return nil
  end
  return parameters
end

-- queue_settings separates the sole allocation limits from per-record timing bounds.
local function queue_settings(settings)
  local assigned = {shard_count=settings.shard_count,max_records=settings.max_records,
    max_bytes=settings.max_encrypted_bytes,tombstone_limit=settings.tombstone_limit,
    drain_generation=settings.drain_generation}
  local limits = {max_age_ms=settings.max_age_ms,lease_ms=settings.lease_ms,
    max_attempts=settings.max_attempts,backoff_min_ms=settings.backoff_min_ms,
    backoff_max_ms=settings.backoff_max_ms,jitter_ms=settings.jitter_ms,
    tombstone_ttl_ms=settings.tombstone_ttl_ms}
  if not allocation.new(assigned) or not state.valid_limits(limits) then
    return nil
  end
  return assigned, limits
end

-- decoder keeps native UCL coercion behind strict JSON validation at both decrypted and claimed boundaries.
local function decoder(runtime)
  return function(body)
    if type(body) ~= 'string' or #body > 100000 or not runtime.json_validator(body) then
      return nil
    end
    local parser = runtime.ucl.parser()
    if not parser:parse_string(body) then
      return nil
    end
    return parser:get_object()
  end
end

-- register_workers initializes each scanner independently and schedules cleanup separately from delivery.
local function register_workers(runtime, queue, settings, metrics)
  runtime.config:add_on_load(function(_, ev_base, worker)
    if not worker:is_scanner() then
      return
    end
    runtime.config:add_periodic(ev_base, 60.0, function()
      metrics:flush()
      return 60.0
    end, false)
    local initializing = false
    runtime.config:add_periodic(ev_base, 0.0, function()
      if not queue.ready then
        if not initializing then
          initializing = true
          queue:initialize(ev_base, function()
            initializing = false
          end)
        end
      else
        for shard = 0, settings.shard_count - 1 do
          queue:work(ev_base, shard)
        end
      end
      return settings.poll_interval
    end, false)
    runtime.config:add_periodic(ev_base, 0.0, function()
      for shard = 0, settings.shard_count - 1 do
        queue:sweep(ev_base, shard)
      end
      return settings.sweep_interval
    end, false)
  end)
end

-- create_queue composes separate Redis and secret authorities before registering background work.
local function create_queue(settings, options, runtime, transport)
  if not closed(settings, OUTBOX_KEYS) or not interval(settings.poll_interval, 0.1, 10) or
      not interval(settings.sweep_interval, 0.1, 60) then
    return nil
  end
  local assigned, limits = queue_settings(settings)
  if not assigned then
    return nil
  end
  local parameters = redis_settings(settings.redis, runtime)
  if not parameters or limits.lease_ms < ((options.timeout or 2) + settings.redis.timeout * 2 + 1) * 1000 then
    return nil
  end
  local available, secretbox = pcall(require, 'rspamd_cryptobox_secretbox')
  if not available or type(secretbox) ~= 'table' then
    return nil
  end
  local decode = decoder(runtime)
  local crypto = require('dkim2.observation_outbox_crypto').new({
    allocation_key=settings.allocation_key,active_key=settings.active_key,previous_key=settings.previous_key,
    source=options.source,shard_count=settings.shard_count,hash=runtime.hash,util=runtime.util,decode=decode,
    secretbox=secretbox,
    authority_files={{file=options.password_file},{file=settings.redis.password_file},
      {file=runtime.decision_password_file},{file=runtime.retry_key_file},{file=runtime.capability_file}},
  })
  if not crypto then
    return nil
  end
  local metrics = require('dkim2.observation_metrics').new(runtime.observation_counter, runtime.observation_snapshot, settings.shard_count)
  if not metrics then
    return nil
  end
  local redis = require('dkim2.observation_redis').new(runtime.redis, runtime.config)
  if not redis then
    return nil
  end
  local queue = require('dkim2.observation_outbox').new({
    allocation=assigned,limits=limits,redis=redis,redis_params=parameters,crypto=crypto,
    observer=function(operation, outcome, shard, snapshot) metrics:observe(operation, outcome, shard, snapshot) end,
    transport=transport,random_hex=runtime.util.random_hex,decode=decode,
    encode=function(value) return runtime.ucl.to_format(value, 'json-compact') end,
  })
  if queue then
    register_workers(runtime, queue, settings, metrics)
  end
  return queue
end

-- M.new validates the complete observation configuration before granting any delivery authority.
function M.new(options, runtime)
  if not closed(options, TOP_KEYS) or type(runtime) ~= 'table' or
      (options.failure_action ~= nil and options.failure_action ~= 'tempfail') or
      (options.mode ~= 'synchronous' and options.mode ~= 'asynchronous') or
      (options.mode == 'synchronous' and options.outbox ~= nil) then
    return nil
  end
  local producer = events.new({source=options.source,instance=options.instance,
    now=runtime.util.get_time,random_hex=runtime.util.random_hex})
  local transport = transport_module.new({endpoint=options.endpoint,server_name=options.server_name,
    username=options.username,password_file=options.password_file,timeout=options.timeout,
    max_response_bytes=options.max_response_bytes,max_request_bytes=32768,
    http=runtime.http,ucl=runtime.ucl,util=runtime.util,json_validator=runtime.json_validator,
    background_config=runtime.config})
  if not producer or not transport then
    return nil
  end
  if options.mode == 'synchronous' then
    local delivery = observation.new({mode=options.mode,producer=producer,transport=transport})
    delivery.completion_timeout = options.timeout or 2
    return delivery
  end
  local queue = create_queue(options.outbox, options, runtime, transport)
  if not queue then
    return nil
  end
  local delivery = observation.new({mode=options.mode,producer=producer,outbox=queue})
  -- Reserve a bounded Redis script load/reload and mutation budget before SMTP completion.
  delivery.completion_timeout = options.outbox.redis.timeout * 3
  return delivery
end

return M
