-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local plugin_path = assert(arg[1], 'plugin path is required')
local definitions = {}
local dependencies = {}
local verifier_callback
local policy_requests = 0
local finalizations = {}
local log_errors = 0
local eligible_body = '{"validated":"eligible"}'
local policy_options
local received_dsn_opt_in

local control = {}

-- reset_control restores one deterministic injected dependency scenario.
local function reset_control()
  control.prepared = {
    applicable = true, content = 'message',
    envelope = { mail_from = '<sender@example.test>', rcpt_to = { '<rcpt@example.test>' } },
  }
  control.peer = '203.0.113.25'
  control.claim_status = 'MISS'
  control.claim_payload = nil
  control.claim_started = true
  control.submit_response = nil
  control.submit_body = eligible_body
  control.submit_started = true
  control.store_status = 'STORED'
  control.store_started = true
  control.stored_payload = nil
  control.policy_decision = { action = 'continue' }
  control.policy_started = true
  control.finalize_status = nil
  control.finalize_started = true
  control.failures = 0
  control.applied = 0
end

local eligible_response = {
  verification = { state = 'PASS', scope = 'chain' },
  verifier_projection = {}, replay = { class = 'first_seen' }, disposition = 'continue',
}
local ineligible_response = {
  verification = { state = 'FAIL', scope = 'current' },
  replay = { class = 'not_checked' }, disposition = 'reject',
}

package.preload['dkim2.verifier'] = function()
  return {
    draft = 'draft-ietf-dkim-dkim2-spec-06',
    projection_schema = 'dkim2.verifier-projection.v1',
    symbols = { check = 'DKIM2_CHECK', not_applicable = 'DKIM2_NOT_APPLICABLE' },
    configure = function() return true end,
    register = function(config, callback)
      verifier_callback = callback
      return config:register_symbol({ name = 'DKIM2_CHECK', type = 'filter', callback = callback })
    end,
    prepare_request = function() return control.prepared end,
    parse_response = function(body)
      return body == eligible_body and eligible_response or nil
    end,
    submit_request = function(_, _, callback)
      if control.submit_started then
        callback(control.submit_response, control.submit_body)
      end
      return control.submit_started
    end,
    apply_failure = function() control.failures = control.failures + 1 end,
    apply_response = function() control.applied = control.applied + 1 end,
    policy_attributes = function(_, include_received_dsn)
      received_dsn_opt_in = include_received_dsn
      return {}
    end,
  }
end

local retry_cache_instance = {
  identity = function() return 'dkim2:retry:v1:key' end,
  claim = function(_, _, _, _, callback)
    if control.claim_started then
      callback(control.claim_status, control.claim_payload)
    end
    return control.claim_started
  end,
  store = function(_, _, _, _, payload, callback)
    control.stored_payload = payload
    if control.store_started then
      callback(control.store_status)
    end
    return control.store_started
  end,
  finalize = function(_, _, key, owner, retryable, callback)
    finalizations[#finalizations + 1] = { key = key, owner = owner, retryable = retryable }
    if control.finalize_started then
      callback(control.finalize_status or (retryable and 'ARMED' or 'CONSUMED'))
    end
    return control.finalize_started
  end,
}

package.preload['dkim2.retry_cache'] = function()
  return {
    new = function() return retry_cache_instance end,
    preserves_non_delivery = function(action)
      return ({ reject = true, discard = true, quarantine = true, greylist = true,
        ['soft reject'] = true })[action] == true
    end,
    is_retryable_action = function(action)
      return action == 'soft reject' or action == 'greylist'
    end,
  }
end

local policy_instance = {
  request = function(_, _, _, _, callback)
    policy_requests = policy_requests + 1
    if control.policy_started then
      callback(control.policy_decision)
    end
    return control.policy_started
  end,
}

package.preload['dkim2.nauthilus_policy'] = function()
  return {
    new = function(options)
      policy_options = options
      return policy_instance
    end,
    decision_action = function(decision)
      return decision and decision.action or 'soft reject'
    end,
  }
end

package.preload['dkim2.strict_json'] = function()
  return { valid = function() return true end }
end
package.preload.lua_redis = function()
  return {
    parse_redis_server = function() return { timeout = 1.0 } end,
    add_redis_script = function() return 1 end,
    exec_redis_script = function() return true end,
  }
end
package.preload.rspamd_cryptobox_hash = function()
  return { create_specific_keyed = function() end }
end
package.preload.rspamd_http = function() return { request = function() end } end
package.preload.rspamd_logger = function()
  return {
    infox = function() end,
    errx = function() log_errors = log_errors + 1 end,
  }
end
package.preload.rspamd_util = function()
  return { random_hex = function() return '0123456789abcdef0123456789abcdef' end }
end
package.preload.lua_util = function()
  return { symbols_priorities = { medium = 5 }, disable_module = function() error('disabled') end }
end
package.preload.ucl = function() return {} end

local plugin_options = {
  enabled = true, endpoint = 'http://127.0.0.1:8080/v1/process', transport = 'loopback',
  capability_file = '/protected/capability', failure_mode = 'tempfail',
  retry_cache = {
    secret_file = '/protected/retry', authority_generation = 'generation-1',
    ttl_ms = 60000, lease_ms = 1000, redis = { servers = 'redis:6379' },
  },
  nauthilus = {
    endpoint = 'https://nauthilus-policy:9443/api/v1/policy/decisions',
    server_name = 'nauthilus-policy', username = 'rspamd-verifier',
    password_file = '/protected/password', instance = 'mx.example.test',
    client_class = 'untrusted', mail_from_class = 'external',
    recipient_classes = { 'local' },
  },
}

rspamd_config = {
  get_all_opt = function()
    return plugin_options
  end,
  register_symbol = function(_, definition)
    definitions[definition.name] = definition
    return definition.name
  end,
  register_dependency = function(_, source, destination, hard)
    dependencies[#dependencies + 1] = { source = source, destination = destination, hard = hard }
  end,
}

reset_control()
assert(loadfile(plugin_path))()
assert(type(verifier_callback) == 'function')
assert(definitions.DKIM2_CHECK.type == 'filter')
assert(definitions.DKIM2_NAUTHILUS_POLICY.type == 'postfilter')
assert(definitions.DKIM2_RETRY_FINALIZE.type == 'idempotent')
assert(definitions.DKIM2_NAUTHILUS_POLICY.flags:find('ignore_passthrough', 1, true))
assert(definitions.DKIM2_RETRY_FINALIZE.flags:find('ignore_passthrough', 1, true))
assert(#dependencies == 1 and dependencies[1].source == 'DKIM2_NAUTHILUS_POLICY' and
  dependencies[1].destination == 'DKIM2_CHECK' and dependencies[1].hard == true)

-- new_task creates the bounded task surface consumed by orchestration callbacks.
local function new_task()
  local task = { cache = {}, symbols = {}, pre_action = nil, metric_action = 'no action' }
  function task:get_from_ip()
    if not control.peer then
      return nil
    end
    return {
      is_valid = function() return true end,
      to_string = function() return control.peer end,
    }
  end
  function task:cache_set(key, value) self.cache[key] = value end
  function task:cache_get(key) return self.cache[key] end
  function task:insert_result(symbol) self.symbols[symbol] = true end
  function task:has_pre_result()
    return self.pre_action ~= nil, self.pre_action
  end
  function task:set_pre_result(action) self.pre_action = action end
  function task:get_metric_action() return self.metric_action end
  return task
end

local policy_callback = definitions.DKIM2_NAUTHILUS_POLICY.callback
local finalizer_callback = definitions.DKIM2_RETRY_FINALIZE.callback

-- Normal-filter cache and daemon fault matrix.
reset_control()
control.prepared = { applicable = false }
local task = new_task()
verifier_callback(task)
assert(task.symbols.DKIM2_NOT_APPLICABLE and control.failures == 0)

reset_control()
control.peer = nil
task = new_task()
verifier_callback(task)
assert(control.failures == 1)

reset_control()
control.claim_status = 'BUSY'
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.claim_status = nil
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.claim_started = false
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.claim_status = 'HIT'
control.claim_payload = eligible_body
task = new_task()
verifier_callback(task)
assert(control.failures == 0 and control.applied == 1 and task.cache['dkim2.retry_context'])

reset_control()
control.claim_status = 'HIT'
control.claim_payload = '{}'
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.submit_response = eligible_response
task = new_task()
verifier_callback(task)
assert(control.applied == 1 and task.cache['dkim2.retry_context'] and
  control.stored_payload == eligible_body)

reset_control()
control.submit_response = false
task = new_task()
verifier_callback(task)
assert(task.symbols.DKIM2_NOT_APPLICABLE and control.failures == 0 and control.applied == 0)

reset_control()
control.submit_response = nil
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.submit_started = false
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.submit_response = eligible_response
control.store_status = 'EXISTS'
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.submit_response = eligible_response
control.store_status = nil
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.submit_response = eligible_response
control.store_started = false
task = new_task()
verifier_callback(task)
assert(control.failures == 1 and control.applied == 0)

reset_control()
control.submit_response = ineligible_response
task = new_task()
verifier_callback(task)
assert(control.failures == 0 and control.applied == 1 and not task.cache['dkim2.retry_context'])

-- Policy action and technical-failure matrix.
local function policy_task(pre_action)
  local value = new_task()
  value.cache['dkim2.verifier_response'] = eligible_response
  value.cache['dkim2.retry_context'] = {
    key = 'dkim2:retry:v1:key', owner = '0123456789abcdef', peer_ip = '203.0.113.25',
  }
  value.pre_action = pre_action
  return value
end

reset_control()
task = policy_task()
policy_callback(task)
assert(task.symbols.DKIM2_NAUTHILUS_PERMIT and task.pre_action == nil)

reset_control()
control.policy_decision = { action = 'reject' }
task = policy_task()
policy_callback(task)
assert(task.symbols.DKIM2_NAUTHILUS_DENY and task.pre_action == 'reject')

for _, preserved in ipairs({ 'reject', 'discard', 'quarantine', 'greylist', 'soft reject' }) do
  reset_control()
  control.policy_decision = { action = 'soft reject' }
  task = policy_task(preserved)
  policy_callback(task)
  assert(task.pre_action == preserved, preserved .. ' must survive technical Policy failure')
end

reset_control()
control.policy_started = false
task = policy_task('accept')
policy_callback(task)
assert(task.symbols.DKIM2_NAUTHILUS_INDETERMINATE and task.pre_action == 'soft reject')

reset_control()
task = new_task()
task.cache['dkim2.verifier_response'] = ineligible_response
local requests_before = policy_requests
policy_callback(task)
assert(policy_requests == requests_before and task.pre_action == nil)

reset_control()
task = new_task()
task.cache['dkim2.verifier_response'] = eligible_response
requests_before = policy_requests
policy_callback(task)
assert(policy_requests == requests_before and task.pre_action == 'soft reject')

-- Idempotent finalizer observes the already settled action and never mutates it.
for action, retryable in pairs({
  ['soft reject'] = true, greylist = true, reject = false, discard = false,
  quarantine = false, accept = false, ['no action'] = false,
}) do
  reset_control()
  task = policy_task(action)
  local before = #finalizations
  finalizer_callback(task)
  assert(#finalizations == before + 1 and finalizations[#finalizations].retryable == retryable)
  assert(task.pre_action == action)
end

reset_control()
task = policy_task()
task.metric_action = 'greylist'
local before = #finalizations
finalizer_callback(task)
assert(#finalizations == before + 1 and finalizations[#finalizations].retryable == true)

reset_control()
task = new_task()
before = #finalizations
finalizer_callback(task)
assert(#finalizations == before)

reset_control()
control.finalize_started = false
task = policy_task('soft reject')
local errors_before = log_errors
finalizer_callback(task)
assert(log_errors == errors_before + 1 and task.pre_action == 'soft reject')

reset_control()
control.finalize_status = 'STALE'
task = policy_task('soft reject')
errors_before = log_errors
finalizer_callback(task)
assert(log_errors == errors_before + 1 and task.pre_action == 'soft reject')

-- Received delivery-status Policy attribute opt-in matrix: absent and false
-- never send the attribute, exactly true sends it, and any other value is a
-- configuration error that disables the module.
for _, scenario in ipairs({
  { present = false, want = false },
  { present = true, value = false, want = false },
  { present = true, value = true, want = true },
}) do
  plugin_options.nauthilus.received_dsn_attribute = scenario.present and scenario.value or nil
  policy_options = nil
  received_dsn_opt_in = 'unset'
  assert(loadfile(plugin_path))()
  assert(type(policy_options) == 'table' and type(policy_options.projection_mapper) == 'function')
  assert(type(policy_options.projection_mapper(eligible_response)) == 'table')
  assert(received_dsn_opt_in == scenario.want,
    'received_dsn_attribute must reach the projection mapper as exactly ' .. tostring(scenario.want))
end
for _, hostile in ipairs({ 'true', 1, {} }) do
  plugin_options.nauthilus.received_dsn_attribute = hostile
  local errors_before = log_errors
  assert(not pcall(assert(loadfile(plugin_path))),
    'a non-boolean received_dsn_attribute must disable the module')
  assert(log_errors == errors_before + 1)
end
plugin_options.nauthilus.received_dsn_attribute = nil

print('dkim2 Rspamd plugin orchestration tests: PASS')
