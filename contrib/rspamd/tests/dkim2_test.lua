-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local plugin_path = assert(arg[1], 'plugin path is required')
local expected_endpoint = arg[2] or 'http://127.0.0.1:8080/v1/process'
local expected_transport = arg[3] or 'loopback'
local expected_server_name = arg[4]
local pending_response
local last_request
local last_encoded_message
local callback

local function contains(values, expected)
  for _, value in ipairs(values) do
    if value == expected then
      return true
    end
  end
  return false
end

local function response(state, verdict, replay, actions)
  local policy_reason = ({
    accept = 'protocol_pass', continue = 'protocol_pass', reject = 'protocol_fail',
    tempfail = 'protocol_temperror',
  })[verdict]
  return {
    api_version = 'v1',
    draft = 'draft-ietf-dkim-dkim2-spec-06',
    verification = {
      state = state, primary_reason = 'none', scope = 'current',
      historical_content = 'not_evaluated', historical_signatures = 'not_evaluated',
      custody_structure = 'not_evaluated',
      checks = { { class = 'protocol', reason = 'none' } }, signature_sets = {},
    },
    authentication = { state = state, primary_reason = 'none' },
    policy = {
      mode = 'strict', verdict = verdict, primary_reason = policy_reason,
      do_not_modify = 'not_requested',
      do_not_explode = 'not_requested',
      dns_testing_effective = false,
      feedback = { requested = false, relay_required = false, history_coverage = 'not_evaluated' },
      findings = { { reason = policy_reason, severity = 'info' } },
    },
    replay = { class = replay },
    disposition = verdict,
    actions = actions or {},
  }
end

local function new_task(headers, full_headers, bare_envelope, content)
  local task = {
    headers = headers or {},
    full_headers = full_headers or {},
    symbols = {},
    alterations = nil,
    pre_result = nil,
  }

  function task:has_header(name)
    return self.headers[name] == true
  end

  function task:get_content()
    return content or 'From: sender@example.test\r\n\r\nbody\r\n'
  end

  function task:get_header_full(name)
    return self.full_headers[name]
  end

  function task:get_from()
    return { { raw = bare_envelope and 'sender@example.test' or '<sender@example.test>' } }
  end

  function task:get_recipients()
    if bare_envelope then
      return { { raw = 'first@example.test' }, { raw = 'second@example.test' } }
    end
    return { { raw = '<first@example.test>' }, { raw = '<second@example.test>' } }
  end

  function task:insert_result(symbol)
    self.symbols[#self.symbols + 1] = symbol
  end

  function task:set_pre_result(action, message, module)
    self.pre_result = { action = action, message = message, module = module }
  end

  return task
end

package.preload.rspamd_logger = function()
  return { errx = function() end, infox = function() end }
end

package.preload.lua_util = function()
  return { disable_module = function(_, reason) error('module disabled: ' .. reason) end }
end

package.preload.rspamd_util = function()
  return {
    encode_base64 = function(value)
      if #value == 32 then
        return 'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg='
      end
      last_encoded_message = value
      return 'ZW5jb2RlZC1tZXNzYWdl'
    end,
    is_valid_utf8 = function() return true end,
  }
end

package.preload.lua_mime = function()
  return {
    modify_headers = function(task, alterations)
      task.alterations = alterations
    end,
  }
end

package.preload.lua_auth_results = function()
  return {
    get_ar_hostname = function(value)
      return value and value:match('^([a-z0-9.-]+)%s*;') or nil
    end,
  }
end

package.preload.ucl = function()
  return {
    parser = function()
      return {
        parse_string = function() return true end,
        get_object = function() return pending_response end,
      }
    end,
    to_format = function(value)
      last_request = value
      return '{}'
    end,
  }
end

package.preload.rspamd_http = function()
  return {
    request = function(request)
      assert(request.url == expected_endpoint)
      assert(request.no_ssl_verify == false)
      assert(request.headers['X-DKIM2-Capability'] ==
        'eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg')
      request.callback(nil, 200, '{}')
      return true
    end,
  }
end

local original_open = io.open
io.open = function(path, mode)
  assert(path == '/protected/process-capability')
  assert(mode == 'rb')
  local reads = 0
  return {
    read = function()
      reads = reads + 1
      if reads == 1 then
        return string.rep('x', 32)
      end
      return nil
    end,
    close = function() end,
  }
end

rspamd_config = {
  get_all_opt = function()
    return {
      enabled = true,
      endpoint = expected_endpoint,
      transport = expected_transport,
      server_name = expected_server_name,
      capability_file = '/protected/process-capability',
      timeout = 2,
      max_response_bytes = 262144,
      failure_mode = 'tempfail',
      authserv_id = 'mx.example.test',
      tenant = 'tenant-a',
    }
  end,
  register_symbol = function(_, definition)
    if definition.name == 'DKIM2_CHECK' then
      callback = definition.callback
      return 1
    end
    return 2
  end,
}

local verifier = assert(loadfile(plugin_path))()
assert(verifier.configure(rspamd_config:get_all_opt('dkim2')))
io.open = original_open
verifier.register(rspamd_config)
assert(type(callback) == 'function')

local unsigned = new_task()
callback(unsigned)
assert(contains(unsigned.symbols, 'DKIM2_NOT_APPLICABLE'))
assert(last_request == nil)

pending_response = response('PASS', 'accept', 'first_seen', {
  {
    type = 'add_header',
    name = 'Authentication-Results',
    value = 'mx.example.test; dkim2=pass',
  },
})
local accepted = new_task({ ['Message-Instance'] = true }, {
  ['Authentication-Results'] = {
    { decoded = 'mx.example.test; dkim2=fail' },
    { decoded = 'foreign.example; dkim=pass' },
  },
})
callback(accepted)
assert(last_request.message.fidelity == 'raw_rfc5322')
assert(last_encoded_message == 'From: sender@example.test\r\n\r\nbody\r\n')
assert(last_request.smtp.mail_from == '<sender@example.test>')
assert(last_request.smtp.rcpt_to[1] == '<first@example.test>')
assert(last_request.smtp.rcpt_to[2] == '<second@example.test>')

local lf_only = new_task(
  { ['Message-Instance'] = true }, nil, false,
  'From: sender@example.test\nSubject: restored\n\nbody\n')
callback(lf_only)
assert(lf_only.pre_result == nil)
assert(last_encoded_message ==
  'From: sender@example.test\r\nSubject: restored\r\n\r\nbody\r\n')

local mixed_endings = new_task(
  { ['Message-Instance'] = true }, nil, false,
  'From: sender@example.test\r\nSubject: normalized\n\r\nbody\r\n')
callback(mixed_endings)
assert(mixed_endings.pre_result == nil)
assert(last_encoded_message ==
  'From: sender@example.test\r\nSubject: normalized\r\n\r\nbody\r\n')

local bare_cr = new_task(
  { ['Message-Instance'] = true }, nil, false,
  'From: sender@example.test\rSubject: ambiguous\r\rbody')
callback(bare_cr)
assert(bare_cr.pre_result.action == 'soft reject')
assert(contains(bare_cr.symbols, 'DKIM2_SERVICE_ERROR'))
assert(last_request.reporting.authserv_id == 'mx.example.test')
assert(last_request.context.tenant == 'tenant-a')
assert(accepted.pre_result == nil)
assert(contains(accepted.symbols, 'DKIM2_PASS'))
assert(contains(accepted.symbols, 'DKIM2_REPLAY_FIRST_SEEN'))
assert(contains(accepted.symbols, 'DKIM2_DONOTMODIFY_NOT_REQUESTED'))
assert(contains(accepted.symbols, 'DKIM2_DONOTEXPLODE_NOT_REQUESTED'))
assert(#accepted.alterations.remove['Authentication-Results'] == 1)
assert(accepted.alterations.remove['Authentication-Results'][1] == 1)
assert(accepted.alterations.add['Authentication-Results'].value ==
  'mx.example.test; dkim2=pass')

local bare_envelope = new_task({ ['Message-Instance'] = true }, nil, true)
callback(bare_envelope)
assert(bare_envelope.pre_result == nil)
assert(last_request.smtp.mail_from == '<sender@example.test>')
assert(last_request.smtp.rcpt_to[1] == '<first@example.test>')
assert(last_request.smtp.rcpt_to[2] == '<second@example.test>')

pending_response = response('FAIL', 'reject', 'replayed')
pending_response.verification.state = 'PASS'
pending_response.authentication.primary_reason = 'duplicate_message_without_exploded'
local rejected = new_task({ ['DKIM2-Signature'] = true })
callback(rejected)
assert(rejected.pre_result.action == 'reject')
assert(contains(rejected.symbols, 'DKIM2_REPLAYED'))

pending_response = response('PASS', 'reject', 'first_seen')
pending_response.policy.do_not_modify = 'indeterminate'
pending_response.policy.do_not_explode = 'violated'
local policy_rejected = new_task({ ['DKIM2-Signature'] = true })
callback(policy_rejected)
assert(policy_rejected.pre_result.action == 'reject')
assert(contains(policy_rejected.symbols, 'DKIM2_PASS'))
assert(contains(policy_rejected.symbols, 'DKIM2_POLICY_REJECT'))
assert(contains(policy_rejected.symbols, 'DKIM2_DONOTMODIFY_INDETERMINATE'))
assert(contains(policy_rejected.symbols, 'DKIM2_DONOTEXPLODE_VIOLATED'))

pending_response = response('PASS', 'accept', 'first_seen')
pending_response.policy.do_not_modify = 'honored'
local unknown_policy_state = new_task({ ['DKIM2-Signature'] = true })
callback(unknown_policy_state)
assert(unknown_policy_state.pre_result.action == 'soft reject')
assert(contains(unknown_policy_state.symbols, 'DKIM2_SERVICE_ERROR'))

local projected = response('PASS', 'continue', 'first_seen', {
  { type = 'add_header', name = 'Authentication-Results', value = 'mx.example.test; dkim2=pass' },
})
projected.verification.primary_reason = 'none'
projected.verification.scope = 'chain'
projected.verification.historical_content = 'complete'
projected.verification.historical_signatures = 'complete'
projected.verification.custody_structure = 'nd_links_evaluated'
projected.policy.mode = 'strict'
projected.policy.primary_reason = 'protocol_pass'
projected.policy.dns_testing_effective = false
projected.verifier_projection = {
  schema = 'dkim2.verifier-projection.v1',
  draft = 'draft-ietf-dkim-dkim2-spec-06',
  binding_algorithm = 'sha-256',
  binding = string.rep('A', 43) .. '=',
  hops = {
    {
      sequence = '1', message_instance = '1', hop_binding = string.rep('B', 43) .. '=',
      signer_domain = 'origin.example', signature_algorithms = { 'ed25519-sha256' },
      signature_state = 'pass', custody_transition = 'origin', do_not_modify = false,
      do_not_explode = false, feedback = false, feed_here = false, exploded = false,
      recipe_mode = 'unchanged', recipe_has_header_changes = false,
      recipe_body_mode = 'absent', recipe_digest = string.rep('C', 43) .. '=',
      change_classes = {}, affected_headers = {}, history_header_state = 'matched',
      history_body_state = 'matched', body_availability = 'known', change_count = 0,
      affected_header_count = 0,
    },
  },
}
local attributes = assert(verifier.policy_attributes(projected))
assert(attributes['dkim2.projection_schema'].string == 'dkim2.verifier-projection.v1')
assert(attributes['dkim2.target_sequence'].integer == '1')
assert(attributes['dkim2.target_message_instance'].integer == '1')
assert(attributes['dkim2.claimed_hop_count'].integer == '1')
assert(attributes['dkim2.chain'].records[1].fields[1].value.integer == '1')
assert(attributes['dkim2.chain'].records[1].fields[2].value.integer == '1')
for _, field in ipairs(attributes['dkim2.chain'].records[1].fields) do
  if field.value.integer ~= nil then
    assert(type(field.value.integer) == 'string', field.name .. ' integer must be a decimal string')
  end
end
assert(attributes['dkim2.chain'].records[1].fields[4].value.string == 'origin.example')

local valid_projection = projected.verifier_projection
projected.verifier_projection = nil
assert(verifier.policy_attributes(projected) == nil,
  'PASS chain without verifier projection must fail closed')
projected.verifier_projection = valid_projection

projected.verifier_projection.hops[1].affected_headers = { 'z-trace', 'subject' }
assert(verifier.policy_attributes(projected) == nil,
  'unsorted affected headers must fail projection validation')

local incomplete_pass = response('PASS', 'accept', 'first_seen')
incomplete_pass.verification.scope = nil
assert(verifier.policy_attributes(incomplete_pass) == nil,
  'PASS without complete verification scope must fail closed')

pending_response = response('PASS', 'accept', 'first_seen', {
  {
    type = 'add_header',
    name = 'Authentication-Results',
    value = 'attacker.example; dkim2=pass',
  },
})
local malformed = new_task({ ['Message-Instance'] = true })
callback(malformed)
assert(malformed.pre_result.action == 'soft reject')
assert(contains(malformed.symbols, 'DKIM2_SERVICE_ERROR'))


local function delivery_status(overrides)
  local projection = {
    structure = 'valid', embedded = 'verified', outer_alignment = 'aligned',
    recipient_linkage = 'linked', local_hop = 'local', propagation = 'eligible',
  }
  for key, value in pairs(overrides or {}) do
    projection[key] = value
  end
  return projection
end

pending_response = response('PASS', 'accept', 'first_seen', {
  {
    type = 'add_header',
    name = 'Authentication-Results',
    value = 'mx.example.test; dkim2=pass',
  },
})
pending_response.delivery_status = delivery_status()
local received_dsn = new_task({ ['DKIM2-Signature'] = true })
callback(received_dsn)
assert(received_dsn.pre_result == nil, 'the projection must not change the gate result')
assert(contains(received_dsn.symbols, 'DKIM2_PASS'))
assert(contains(received_dsn.symbols, 'DKIM2_DSN_STRUCTURE_VALID'))
assert(contains(received_dsn.symbols, 'DKIM2_DSN_EMBEDDED_VERIFIED'))
assert(contains(received_dsn.symbols, 'DKIM2_DSN_OUTER_ALIGNMENT_ALIGNED'))
assert(contains(received_dsn.symbols, 'DKIM2_DSN_RECIPIENT_LINKAGE_LINKED'))
assert(contains(received_dsn.symbols, 'DKIM2_DSN_LOCAL_HOP_LOCAL'))
assert(contains(received_dsn.symbols, 'DKIM2_DSN_PROPAGATION_ELIGIBLE'))

pending_response = response('PASS', 'accept', 'first_seen', {
  {
    type = 'add_header',
    name = 'Authentication-Results',
    value = 'mx.example.test; dkim2=pass',
  },
})
pending_response.delivery_status = delivery_status({
  local_hop = 'not_evaluated', propagation = 'not_evaluated',
})
local untenanted_dsn = new_task({ ['DKIM2-Signature'] = true })
callback(untenanted_dsn)
assert(untenanted_dsn.pre_result == nil)
assert(contains(untenanted_dsn.symbols, 'DKIM2_DSN_LOCAL_HOP_NOT_EVALUATED'))
assert(contains(untenanted_dsn.symbols, 'DKIM2_DSN_PROPAGATION_NOT_EVALUATED'))

pending_response = response('PASS', 'accept', 'first_seen', {
  {
    type = 'add_header',
    name = 'Authentication-Results',
    value = 'mx.example.test; dkim2=pass',
  },
})
pending_response.delivery_status = delivery_status({ propagation = 'invented' })
local unknown_projection = new_task({ ['DKIM2-Signature'] = true })
callback(unknown_projection)
assert(unknown_projection.pre_result.action == 'soft reject',
  'an unknown projection value must fail closed')
assert(contains(unknown_projection.symbols, 'DKIM2_SERVICE_ERROR'))

pending_response = response('PASS', 'accept', 'first_seen', {
  {
    type = 'add_header',
    name = 'Authentication-Results',
    value = 'mx.example.test; dkim2=pass',
  },
})
pending_response.delivery_status = delivery_status()
pending_response.delivery_status.local_hop = nil
local partial_projection = new_task({ ['DKIM2-Signature'] = true })
callback(partial_projection)
assert(partial_projection.pre_result.action == 'soft reject',
  'a partial projection must fail closed')

for _, symbol in pairs(verifier.symbols) do
  assert(symbol:match('^DKIM2_[A-Z0-9_]+$'), 'every symbol stays a closed identifier')
end

projected.verifier_projection.hops[1].affected_headers = {}
projected.delivery_status = delivery_status({ propagation = 'not_failure' })
local projected_attributes = assert(verifier.policy_attributes(projected, true))
assert(projected_attributes['dkim2.received_dsn_propagation'].string == 'not_failure')
local default_attributes = assert(verifier.policy_attributes(projected))
assert(default_attributes['dkim2.received_dsn_propagation'] == nil,
  'the propagation class is opt-in and absent by default')
local disabled_attributes = assert(verifier.policy_attributes(projected, false))
assert(disabled_attributes['dkim2.received_dsn_propagation'] == nil,
  'an explicitly disabled propagation class is never sent')
assert(verifier.policy_attributes(projected, 'true')['dkim2.received_dsn_propagation'] == nil,
  'only the exact boolean true enables the propagation class')
for key in pairs(default_attributes) do
  assert(projected_attributes[key] ~= nil, key .. ' must be carried in both settings')
end
projected.delivery_status = nil
local plain_attributes = assert(verifier.policy_attributes(projected, true))
assert(plain_attributes['dkim2.received_dsn_propagation'] == nil,
  'a message that is not a received notification carries no propagation class')

print('dkim2 Rspamd Lua contract tests: PASS')
