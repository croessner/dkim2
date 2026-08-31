-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local N = 'dkim2'
local verifier = require 'dkim2.verifier'
local retry_cache_module = require 'dkim2.retry_cache'
local policy_module = require 'dkim2.nauthilus_policy'
local strict_json = require 'dkim2.strict_json'
local lua_redis = require 'lua_redis'
local rspamd_cryptobox_hash = require 'rspamd_cryptobox_hash'
local rspamd_http = require 'rspamd_http'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local lua_util = require 'lua_util'
local ucl = require 'ucl'

local TASK_PREPARED = 'dkim2.prepared_request'
local TASK_RESPONSE = 'dkim2.verifier_response'
local TASK_RETRY = 'dkim2.retry_context'
local POLICY_SYMBOL = 'DKIM2_NAUTHILUS_POLICY'
local POLICY_PERMIT = 'DKIM2_NAUTHILUS_PERMIT'
local POLICY_DENY = 'DKIM2_NAUTHILUS_DENY'
local POLICY_INDETERMINATE = 'DKIM2_NAUTHILUS_INDETERMINATE'
local FINALIZER_SYMBOL = 'DKIM2_RETRY_FINALIZE'

local allowed_top = {
  enabled = true, endpoint = true, transport = true, server_name = true,
  capability_file = true, timeout = true, max_response_bytes = true,
  failure_mode = true, authserv_id = true, retry_cache = true, nauthilus = true,
}
local allowed_retry = {
  secret_file = true, authority_generation = true, ttl_ms = true, lease_ms = true, redis = true,
}
local allowed_policy = {
  endpoint = true, server_name = true, username = true, password_file = true,
  instance = true, timeout = true, max_response_bytes = true, client_class = true,
  mail_from_class = true, recipient_classes = true,
}

-- disable_module reports one bounded startup category without configuration values.
local function disable_module(reason)
  rspamd_logger.errx(rspamd_config, '%s module disabled: %s', N, reason)
  lua_util.disable_module(N, reason)
end

-- closed_keys verifies one nested configuration vocabulary.
local function closed_keys(value, allowed)
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

-- closed_top_settings rejects accidental or unsupported module configuration.
local function closed_top_settings(value)
  if type(value) ~= 'table' then
    return false
  end
  for key in pairs(value) do
    if not allowed_top[key] then
      return false
    end
  end
  return true
end

-- smtp_peer returns the exact canonical MTA-supplied SMTP peer address.
local function smtp_peer(task)
  local ip = task:get_from_ip()
  if not ip or type(ip.is_valid) ~= 'function' or not ip:is_valid() or
      type(ip.to_string) ~= 'function' then
    return nil
  end
  local value = ip:to_string()
  if type(value) ~= 'string' or #value == 0 or #value > 45 or value == '0.0.0.0' or value == '::' then
    return nil
  end
  return value
end

-- cache_eligible restricts reuse to replay-committed successful chain outcomes.
local function cache_eligible(response)
  return type(response) == 'table' and response.verification.state == 'PASS' and
    response.verification.scope == 'chain' and response.verifier_projection ~= nil and
    (response.replay.class == 'first_seen' or response.replay.class == 'exploded') and
    (response.disposition == 'accept' or response.disposition == 'continue')
end

-- apply_not_applicable publishes the existing normal-filter applicability result.
local function apply_not_applicable(task)
  task:insert_result(verifier.symbols.check, 1.0)
  task:insert_result(verifier.symbols.not_applicable, 1.0)
end

-- fail_closed preserves existing non-delivery actions and otherwise selects temporary failure.
local function fail_closed(task)
  local present, action = task:has_pre_result()
  if not present or not retry_cache_module.preserves_non_delivery(action) then
    task:set_pre_result('soft reject', 'Temporary DKIM2 policy failure', N)
  end
end

-- remember_response hands validated verifier facts to the postfilter in task-local memory.
local function remember_response(task, prepared, response, retry_context)
  task:cache_set(TASK_PREPARED, prepared)
  task:cache_set(TASK_RESPONSE, response)
  if retry_context then
    task:cache_set(TASK_RETRY, retry_context)
  end
  verifier.apply_response(task, response)
end

-- register_policy_symbols registers zero-score bounded decision observations.
local function register_policy_symbols(config, parent)
  for _, symbol in ipairs({ POLICY_PERMIT, POLICY_DENY, POLICY_INDETERMINATE }) do
    config:register_symbol({
      name = symbol, type = 'virtual', parent = parent,
      score = 0.0, group = N,
    })
  end
end

local options = rspamd_config:get_all_opt(N)
local verifier_options = options and {
  enabled = options.enabled, endpoint = options.endpoint, transport = options.transport,
  server_name = options.server_name, capability_file = options.capability_file,
  timeout = options.timeout, max_response_bytes = options.max_response_bytes,
  failure_mode = options.failure_mode, authserv_id = options.authserv_id,
} or nil
if not closed_top_settings(options) or type(options.retry_cache) ~= 'table' or
    type(options.nauthilus) ~= 'table' or not closed_keys(options.retry_cache, allowed_retry) or
    not closed_keys(options.nauthilus, allowed_policy) or
    type(options.retry_cache.authority_generation) ~= 'string' or
    #options.retry_cache.authority_generation == 0 or
    #options.retry_cache.authority_generation > 128 or
    not verifier.configure(verifier_options) then
  disable_module('config')
  return
end

local redis_params = lua_redis.parse_redis_server(N, options.retry_cache)
if not redis_params then
  disable_module('redis')
  return
end

local retry_cache = retry_cache_module.new({
  redis = lua_redis, redis_params = redis_params, hash = rspamd_cryptobox_hash,
  secret_file = options.retry_cache.secret_file,
  authority_generation = options.retry_cache.authority_generation,
  ttl_ms = options.retry_cache.ttl_ms,
  lease_ms = options.retry_cache.lease_ms,
})
if not retry_cache then
  disable_module('retry_cache')
  return
end

local policy = policy_module.new({
  endpoint = options.nauthilus.endpoint,
  server_name = options.nauthilus.server_name,
  username = options.nauthilus.username,
  password_file = options.nauthilus.password_file,
  instance = options.nauthilus.instance,
  timeout = options.nauthilus.timeout,
  max_response_bytes = options.nauthilus.max_response_bytes,
  client_class = options.nauthilus.client_class,
  mail_from_class = options.nauthilus.mail_from_class,
  recipient_classes = options.nauthilus.recipient_classes,
  http = rspamd_http, ucl = ucl, util = rspamd_util,
  json_validator = strict_json.valid,
  projection_mapper = verifier.policy_attributes,
  envelope = {
    rcpt_count = function(task)
      local prepared = task:cache_get(TASK_PREPARED)
      return prepared and #prepared.envelope.rcpt_to or 0
    end,
    mail_from_class = function(task)
      local prepared = task:cache_get(TASK_PREPARED)
      return prepared and prepared.envelope.mail_from == '<>' and 'null' or
        options.nauthilus.mail_from_class
    end,
    recipient_classes = function()
      return options.nauthilus.recipient_classes
    end,
  },
})
if not policy then
  disable_module('nauthilus')
  return
end

-- verifier_callback resolves cache state before invoking the replay-mutating daemon route.
local function verifier_callback(task)
  local prepared = verifier.prepare_request(task)
  local peer = smtp_peer(task)
  if not prepared or prepared.applicable and not peer then
    verifier.apply_failure(task)
    return
  end
  if not prepared.applicable then
    apply_not_applicable(task)
    return
  end
  local key = retry_cache:identity({
    peer_ip = peer, content = prepared.content,
    mail_from = prepared.envelope.mail_from, rcpt_to = prepared.envelope.rcpt_to,
    draft = verifier.draft, projection_schema = verifier.projection_schema,
  })
  local owner = rspamd_util.random_hex(16)
  if not key or type(owner) ~= 'string' then
    verifier.apply_failure(task)
    return
  end
  local started = retry_cache:claim(task, key, owner, function(status, payload)
    if status == 'HIT' then
      local response = verifier.parse_response(payload)
      if not response or not cache_eligible(response) then
        verifier.apply_failure(task)
        return
      end
      remember_response(task, prepared, response, { key = key, owner = owner, peer_ip = peer })
      return
    end
    if status ~= 'MISS' then
      verifier.apply_failure(task)
      return
    end
    local submitted = verifier.submit_request(task, prepared, function(response, response_body)
      if response == false then
        apply_not_applicable(task)
      elseif response == nil then
        verifier.apply_failure(task)
      elseif not cache_eligible(response) then
        remember_response(task, prepared, response, nil)
      else
        local stored = retry_cache:store(task, key, owner, response_body, function(store_status)
          if store_status ~= 'STORED' then
            verifier.apply_failure(task)
            return
          end
          remember_response(task, prepared, response, { key = key, owner = owner, peer_ip = peer })
        end)
        if not stored then
          verifier.apply_failure(task)
        end
      end
    end)
    if not submitted then
      verifier.apply_failure(task)
    end
  end)
  if not started then
    verifier.apply_failure(task)
  end
end

local verifier_parent = verifier.register(rspamd_config, verifier_callback)

-- policy_callback sends only generic Policy request facts after the normal scan.
local function policy_callback(task)
  local response = task:cache_get(TASK_RESPONSE)
  local context = task:cache_get(TASK_RETRY)
  if not cache_eligible(response) then
    return
  end
  if not context or type(context.peer_ip) ~= 'string' then
    fail_closed(task)
    return
  end
  local started = policy:request(task, response, context.peer_ip, function(decision)
    local action = policy_module.decision_action(decision)
    if action == 'soft reject' then
      task:insert_result(POLICY_INDETERMINATE, 1.0)
      fail_closed(task)
    elseif action == 'continue' then
      task:insert_result(POLICY_PERMIT, 1.0)
    elseif action == 'reject' then
      task:insert_result(POLICY_DENY, 1.0)
      task:set_pre_result('reject', 'Message rejected by Nauthilus policy', N)
    end
  end)
  if not started then
    task:insert_result(POLICY_INDETERMINATE, 1.0)
    fail_closed(task)
  end
end

local policy_parent = rspamd_config:register_symbol({
  name = POLICY_SYMBOL, type = 'postfilter', callback = policy_callback,
  priority = lua_util.symbols_priorities.medium, score = 0.0, group = N,
  flags = 'nostat,ignore_passthrough',
  augmentations = { string.format('timeout=%f', options.nauthilus.timeout or 2.0) },
})
register_policy_symbols(rspamd_config, policy_parent)
rspamd_config:register_dependency(POLICY_SYMBOL, verifier.symbols.check, true)

-- finalizer_callback atomically arms retryable results or consumes terminal ones.
local function finalizer_callback(task)
  local context = task:cache_get(TASK_RETRY)
  if not context then
    return
  end
  local present, action = task:has_pre_result()
  action = present and action or task:get_metric_action()
  local retryable = retry_cache_module.is_retryable_action(action)
  local started = retry_cache:finalize(task, context.key, context.owner, retryable, function(status)
    if retryable and status ~= 'ARMED' or not retryable and status ~= 'CONSUMED' then
      rspamd_logger.errx(task, '%s retry finalization failed', N)
    end
  end)
  if not started then
    rspamd_logger.errx(task, '%s retry finalization could not be scheduled', N)
  end
end

rspamd_config:register_symbol({
  name = FINALIZER_SYMBOL, type = 'idempotent', callback = finalizer_callback,
  score = 0.0, group = N,
  flags = 'nostat,ignore_passthrough',
  augmentations = { string.format('timeout=%f', redis_params.timeout or 1.0) },
})
rspamd_logger.infox(rspamd_config,
  '%s verifier, retry cache, and generic Nauthilus Policy postfilter enabled', N)
