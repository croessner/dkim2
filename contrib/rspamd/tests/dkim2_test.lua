-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local plugin_path = assert(arg[1], 'plugin path is required')
local expected_endpoint = arg[2] or 'http://127.0.0.1:8080/v1/process'
local expected_transport = arg[3] or 'loopback'
local expected_server_name = arg[4]
local pending_response
local last_request
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
  return {
    api_version = 'v1',
    draft = 'draft-ietf-dkim-dkim2-spec-06',
    verification = { state = state },
    authentication = { state = state, primary_reason = 'none' },
    policy = {
      verdict = verdict,
      do_not_modify = 'not_requested',
      do_not_explode = 'not_requested',
    },
    replay = { class = replay },
    disposition = verdict,
    actions = actions or {},
  }
end

local function new_task(headers, full_headers, bare_envelope)
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
    return 'From: sender@example.test\r\n\r\nbody\r\n'
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

assert(loadfile(plugin_path))()
io.open = original_open
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
assert(last_request.smtp.mail_from == '<sender@example.test>')
assert(last_request.smtp.rcpt_to[1] == '<first@example.test>')
assert(last_request.smtp.rcpt_to[2] == '<second@example.test>')
assert(last_request.reporting.authserv_id == 'mx.example.test')
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

print('dkim2 Rspamd Lua contract tests: PASS')
