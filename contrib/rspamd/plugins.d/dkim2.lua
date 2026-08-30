-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local N = 'dkim2'
local rspamd_http = require 'rspamd_http'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local lua_mime = require 'lua_mime'
local lua_auth_results = require 'lua_auth_results'
local lua_util = require 'lua_util'
local ucl = require 'ucl'

local API_VERSION = 'v1'
local DRAFT = 'draft-ietf-dkim-dkim2-spec-06'
local PROCESS_PATH = '/v1/process'
local MAX_MESSAGE_BYTES = 33554432
local MAX_RECIPIENTS = 2000
local MAX_PATH_BYTES = 256
local DEFAULT_RESPONSE_BYTES = 262144
local MAX_RESPONSE_BYTES = 262144
local DEFAULT_TIMEOUT = 2.0

local symbols = {
  check = 'DKIM2_CHECK',
  not_applicable = 'DKIM2_NOT_APPLICABLE',
  pass = 'DKIM2_PASS',
  fail = 'DKIM2_FAIL',
  permerror = 'DKIM2_PERMERROR',
  temperror = 'DKIM2_TEMPERROR',
  replay_first_seen = 'DKIM2_REPLAY_FIRST_SEEN',
  replay_exploded = 'DKIM2_REPLAY_EXPLODED',
  replay_replayed = 'DKIM2_REPLAYED',
  replay_not_checked = 'DKIM2_REPLAY_NOT_CHECKED',
  replay_disabled = 'DKIM2_REPLAY_DISABLED',
  replay_indeterminate = 'DKIM2_REPLAY_INDETERMINATE',
  policy_accept = 'DKIM2_POLICY_ACCEPT',
  policy_continue = 'DKIM2_POLICY_CONTINUE',
  policy_reject = 'DKIM2_POLICY_REJECT',
  policy_tempfail = 'DKIM2_POLICY_TEMPFAIL',
  donotmodify_not_requested = 'DKIM2_DONOTMODIFY_NOT_REQUESTED',
  donotmodify_indeterminate = 'DKIM2_DONOTMODIFY_INDETERMINATE',
  donotmodify_not_evaluated = 'DKIM2_DONOTMODIFY_NOT_EVALUATED',
  donotexplode_not_requested = 'DKIM2_DONOTEXPLODE_NOT_REQUESTED',
  donotexplode_violated = 'DKIM2_DONOTEXPLODE_VIOLATED',
  donotexplode_indeterminate = 'DKIM2_DONOTEXPLODE_INDETERMINATE',
  donotexplode_not_evaluated = 'DKIM2_DONOTEXPLODE_NOT_EVALUATED',
  service_error = 'DKIM2_SERVICE_ERROR',
}

local allowed_settings = {
  enabled = true,
  endpoint = true,
  transport = true,
  server_name = true,
  capability_file = true,
  timeout = true,
  max_response_bytes = true,
  failure_mode = true,
  authserv_id = true,
}

local verification_states = {
  PASS = true,
  FAIL = true,
  PERMERROR = true,
  TEMPERROR = true,
}

local authentication_results = {
  PASS = 'pass',
  FAIL = 'fail',
  PERMERROR = 'permerror',
  TEMPERROR = 'temperror',
}

local policy_verdicts = {
  accept = true,
  continue = true,
  reject = true,
  tempfail = true,
}

local replay_classes = {
  not_checked = true,
  disabled = true,
  first_seen = true,
  exploded = true,
  replayed = true,
  indeterminate = true,
}

local donotmodify_states = {
  not_requested = true,
  indeterminate = true,
  not_evaluated = true,
}

local donotexplode_states = {
  not_requested = true,
  violated = true,
  indeterminate = true,
  not_evaluated = true,
}

local settings = {
  enabled = false,
  timeout = DEFAULT_TIMEOUT,
  max_response_bytes = DEFAULT_RESPONSE_BYTES,
  failure_mode = 'tempfail',
}

local capability

-- contains_forbidden_octet rejects field-breaking bytes without Lua pattern ambiguity.
local function contains_forbidden_octet(value)
  return value:find('\r', 1, true) ~= nil or value:find('\n', 1, true) ~= nil or
    value:find('\0', 1, true) ~= nil
end

-- valid_authserv_id admits the daemon's canonical ASCII reporting authority.
local function valid_authserv_id(value)
  if type(value) ~= 'string' or #value == 0 or #value > 253 or value ~= string.lower(value) then
    return false
  end
  if not value:match('^[a-z0-9][a-z0-9.-]*[a-z0-9]$') and not value:match('^[a-z0-9]$') then
    return false
  end
  for label in value:gmatch('[^.]+') do
    if #label == 0 or #label > 63 or label:sub(1, 1) == '-' or label:sub(-1) == '-' then
      return false
    end
  end
  return not value:find('..', 1, true)
end

-- valid_service_name accepts one canonical service DNS name without IP fallback.
local function valid_service_name(value)
  if type(value) ~= 'string' or #value == 0 or #value > 253 or value ~= string.lower(value) or
      value == 'localhost' or value:find('..', 1, true) then
    return false
  end
  for label in value:gmatch('[^.]+') do
    if #label == 0 or #label > 63 or not label:match('^[a-z0-9][a-z0-9-]*[a-z0-9]$') then
      if not label:match('^[a-z0-9]$') then
        return false
      end
    end
  end
  return true
end

-- valid_endpoint restricts daemon access to the selected explicit transport boundary.
local function valid_endpoint(value, transport, server_name)
  if type(value) ~= 'string' then
    return false
  end
  local port
  if transport == 'loopback' then
    port = value:match('^http://127%.0%.0%.1:(%d+)' .. PROCESS_PATH .. '$')
    if not port then
      port = value:match('^http://%[::1%]:(%d+)' .. PROCESS_PATH .. '$')
    end
  elseif transport == 'tls_private_network' then
    local host
    host, port = value:match('^https://([a-z0-9.-]+):(%d+)' .. PROCESS_PATH .. '$')
    if not valid_service_name(host) or host ~= server_name then
      return false
    end
  else
    return false
  end
  port = tonumber(port)
  return port ~= nil and port >= 1 and port <= 65535
end

-- read_capability loads one exact raw route capability without diagnostic exposure.
local function read_capability(path)
  if type(path) ~= 'string' or path:sub(1, 1) ~= '/' or path:find('\0', 1, true) then
    return nil
  end
  local handle = io.open(path, 'rb')
  if not handle then
    return nil
  end
  local raw = handle:read(33)
  local trailing = handle:read(1)
  handle:close()
  if type(raw) ~= 'string' or #raw ~= 32 or trailing ~= nil then
    return nil
  end
  local nonzero = false
  for index = 1, #raw do
    if raw:byte(index) ~= 0 then
      nonzero = true
      break
    end
  end
  if not nonzero then
    return nil
  end
  local encoded = tostring(rspamd_util.encode_base64(raw, 0))
  encoded = encoded:gsub('+', '-'):gsub('/', '_'):gsub('=+$', '')
  if #encoded ~= 43 or not encoded:match('^[A-Za-z0-9_-]+$') then
    return nil
  end
  return encoded
end

-- validate_settings copies only the closed supported configuration vocabulary.
local function validate_settings(input)
  if type(input) ~= 'table' then
    return nil
  end
  for key in pairs(input) do
    if not allowed_settings[key] then
      return nil
    end
  end
  local transport = input.transport or 'loopback'
  if input.enabled ~= true or not valid_endpoint(input.endpoint, transport, input.server_name) or
      type(input.capability_file) ~= 'string' then
    return nil
  end
  local timeout = tonumber(input.timeout or DEFAULT_TIMEOUT)
  local response_bytes = tonumber(input.max_response_bytes or DEFAULT_RESPONSE_BYTES)
  local failure_mode = input.failure_mode or 'tempfail'
  if not timeout or timeout <= 0 or timeout > 10 or timeout ~= timeout or
      not response_bytes or response_bytes < 1024 or response_bytes > MAX_RESPONSE_BYTES or
      response_bytes % 1 ~= 0 or
      (failure_mode ~= 'tempfail' and failure_mode ~= 'continue') or
      (transport == 'tls_private_network' and not valid_service_name(input.server_name)) or
      (transport == 'loopback' and input.server_name ~= nil) or
      (input.authserv_id ~= nil and not valid_authserv_id(input.authserv_id)) then
    return nil
  end
  return {
    enabled = true,
    endpoint = input.endpoint,
    transport = transport,
    server_name = input.server_name,
    capability_file = input.capability_file,
    timeout = timeout,
    max_response_bytes = response_bytes,
    failure_mode = failure_mode,
    authserv_id = input.authserv_id,
  }
end

-- exact_keys verifies required and optional members without accepting extensions.
local function exact_keys(value, required, optional)
  if type(value) ~= 'table' then
    return false
  end
  local allowed = {}
  for _, key in ipairs(required) do
    allowed[key] = true
    if value[key] == nil then
      return false
    end
  end
  for _, key in ipairs(optional) do
    allowed[key] = true
  end
  for key in pairs(value) do
    if not allowed[key] then
      return false
    end
  end
  return true
end

-- valid_outcome enforces daemon-owned authentication, replay, policy, and disposition coherence.
local function valid_outcome(value)
  local verification = value.verification.state
  local authentication = value.authentication.state
  local replay = value.replay.class
  if value.policy.verdict ~= value.disposition then
    return false
  end
  if replay == 'replayed' then
    return verification == 'PASS' and authentication == 'FAIL' and
      value.authentication.primary_reason == 'duplicate_message_without_exploded' and
      value.disposition == 'reject'
  end
  if replay == 'indeterminate' then
    return verification == 'PASS' and authentication == 'TEMPERROR' and
      (value.authentication.primary_reason == 'replay_indeterminate' or
        value.authentication.primary_reason == 'replay_evidence_unavailable') and
      value.disposition == 'tempfail'
  end
  if authentication ~= verification then
    return false
  end
  if replay == 'disabled' or replay == 'first_seen' or replay == 'exploded' then
    return verification == 'PASS'
  end
  return replay == 'not_checked' and
    (verification ~= 'PASS' or value.policy.verdict ~= 'accept')
end

-- dense_array_len returns an array length only for positive contiguous indexes.
local function dense_array_len(value, maximum)
  if type(value) ~= 'table' then
    return nil
  end
  local count = 0
  for key in pairs(value) do
    if type(key) ~= 'number' or key < 1 or key % 1 ~= 0 or key > maximum then
      return nil
    end
    count = count + 1
  end
  if count > maximum then
    return nil
  end
  for index = 1, count do
    if value[index] == nil then
      return nil
    end
  end
  return count
end

-- valid_response validates the response members that authorize Rspamd effects.
local function valid_response(value)
  local top_required = {
    'api_version', 'draft', 'verification', 'authentication', 'policy',
    'replay', 'disposition', 'actions',
  }
  if not exact_keys(value, top_required, {}) or value.api_version ~= API_VERSION or
      value.draft ~= DRAFT or not policy_verdicts[value.disposition] then
    return false
  end
  if type(value.verification) ~= 'table' or not verification_states[value.verification.state] or
      not exact_keys(value.authentication, { 'state', 'primary_reason' }, {}) or
      not verification_states[value.authentication.state] or
      type(value.authentication.primary_reason) ~= 'string' or
      not exact_keys(value.replay, { 'class' }, {}) or not replay_classes[value.replay.class] or
      type(value.policy) ~= 'table' or not policy_verdicts[value.policy.verdict] or
      not donotmodify_states[value.policy.do_not_modify] or
      not donotexplode_states[value.policy.do_not_explode] or
      not valid_outcome(value) then
    return false
  end
  local state = value.authentication.state
  local action_count = dense_array_len(value.actions, 1)
  if action_count == nil or
      action_count > 0 and value.disposition ~= 'accept' and value.disposition ~= 'continue' then
    return false
  end
  if action_count == 0 then
    return settings.authserv_id == nil or value.disposition == 'reject' or value.disposition == 'tempfail'
  end
  local action = value.actions[1]
  if not exact_keys(action, { 'type', 'name', 'value' }, {}) or
      action.type ~= 'add_header' or action.name ~= 'Authentication-Results' or
      settings.authserv_id == nil or
      action.value ~= settings.authserv_id .. '; dkim2=' .. authentication_results[state] or
      #action.value > 65535 or contains_forbidden_octet(action.value) then
    return false
  end
  return true
end

-- parse_response accepts one bounded JSON object and rejects ambiguous shapes.
local function parse_response(body)
  if type(body) == 'userdata' then
    body = tostring(body)
  end
  if type(body) ~= 'string' or #body == 0 or #body > settings.max_response_bytes or
      body:sub(1, 1) ~= '{' or body:sub(-1) ~= '}' then
    return nil
  end
  local parser = ucl.parser()
  local ok = parser:parse_string(body)
  if not ok then
    return nil
  end
  local value = parser:get_object()
  if not valid_response(value) then
    return nil
  end
  return value
end

-- valid_path preserves one original bracketed SMTP path without normalization.
local function valid_path(value, allow_null)
  return type(value) == 'string' and #value >= 2 and #value <= MAX_PATH_BYTES and
      rspamd_util.is_valid_utf8(value) and not contains_forbidden_octet(value) and
      value:sub(1, 1) == '<' and value:sub(-1) == '>' and
      (allow_null or value ~= '<>')
end

-- smtp_path accepts Rspamd's bare SMTP raw value or an already bracketed path.
-- It preserves address bytes and restores only delimiters omitted by Rspamd.
local function smtp_path(value, allow_null)
  if type(value) ~= 'string' or not rspamd_util.is_valid_utf8(value) or
      contains_forbidden_octet(value) then
    return nil
  end
  if valid_path(value, allow_null) then
    return value
  end
  if value == '' then
    return allow_null and '<>' or nil
  end
  if #value > MAX_PATH_BYTES - 2 or value:find('[<>]') then
    return nil
  end
  local bracketed = '<' .. value .. '>'
  return valid_path(bracketed, allow_null) and bracketed or nil
end

-- original_envelope extracts only the original Rspamd SMTP address views.
local function original_envelope(task)
  local senders = task:get_from({ 'smtp', 'orig' })
  local recipients = task:get_recipients({ 'smtp', 'orig' })
  local sender_path = type(senders) == 'table' and type(senders[1]) == 'table' and
      smtp_path(senders[1].raw, true) or nil
  if type(senders) ~= 'table' or #senders ~= 1 or type(senders[1]) ~= 'table' or
      not sender_path or type(recipients) ~= 'table' or
      #recipients < 1 or #recipients > MAX_RECIPIENTS then
    return nil
  end
  local result = { mail_from = sender_path, rcpt_to = {} }
  for index, recipient in ipairs(recipients) do
    local recipient_path = type(recipient) == 'table' and smtp_path(recipient.raw, false) or nil
    if not recipient_path then
      return nil
    end
    result.rcpt_to[index] = recipient_path
  end
  return result
end

-- smtp_message_bytes restores only Rspamd's uniform LF representation to SMTP CRLF.
local function smtp_message_bytes(value)
  if type(value) == 'userdata' then
    value = tostring(value)
  end
  if type(value) ~= 'string' or #value == 0 or #value > MAX_MESSAGE_BYTES then
    return nil
  end
  local outside_crlf = value:gsub('\r\n', '')
  if outside_crlf:find('\r', 1, true) then
    return nil
  end
  if value:find('\r\n', 1, true) then
    if outside_crlf:find('\n', 1, true) then
      return nil
    end
    return value
  end
  if value:find('\n', 1, true) then
    local restored = value:gsub('\n', '\r\n')
    if #restored > MAX_MESSAGE_BYTES then
      return nil
    end
    return restored
  end
  return value
end

-- insert_symbol publishes one zero-score, option-free bounded result.
local function insert_symbol(task, symbol)
  task:insert_result(symbol, 1.0)
end

-- apply_failure maps applicable adapter ambiguity to the explicit local mode.
local function apply_failure(task)
  insert_symbol(task, symbols.check)
  insert_symbol(task, symbols.service_error)
  if settings.failure_mode == 'tempfail' then
    task:set_pre_result('soft reject', 'Temporary DKIM2 verification failure', N)
  end
end

-- apply_authentication_results applies only the daemon-owned reporting action.
local function apply_authentication_results(task, actions)
  if settings.authserv_id == nil or #actions == 0 then
    return
  end
  local remove = {}
  local existing = task:get_header_full('Authentication-Results') or {}
  for index, header in ipairs(existing) do
    local authority = lua_auth_results.get_ar_hostname(header.decoded or header.value)
    if authority == settings.authserv_id then
      remove[#remove + 1] = index
    end
  end
  local changes = {
    add = {
      ['Authentication-Results'] = { value = actions[1].value, order = 0 },
    },
  }
  if #remove > 0 then
    changes.remove = { ['Authentication-Results'] = remove }
  end
  lua_mime.modify_headers(task, changes, 'compat')
end

-- apply_response publishes trusted facts and the final DKIM2 gate result.
local function apply_response(task, response)
  insert_symbol(task, symbols.check)
  insert_symbol(task, symbols[authentication_results[response.authentication.state]])
  local replay_symbol = symbols['replay_' .. response.replay.class]
  if replay_symbol then
    insert_symbol(task, replay_symbol)
  end
  insert_symbol(task, symbols['policy_' .. response.policy.verdict])
  insert_symbol(task, symbols['donotmodify_' .. response.policy.do_not_modify])
  insert_symbol(task, symbols['donotexplode_' .. response.policy.do_not_explode])
  apply_authentication_results(task, response.actions)
  if response.disposition == 'reject' then
    task:set_pre_result('reject', 'Message rejected by DKIM2 policy', N)
  elseif response.disposition == 'tempfail' then
    task:set_pre_result('soft reject', 'Temporary DKIM2 verification failure', N)
  end
end

-- process_message submits one applicable task to the authenticated daemon route.
local function process_message(task)
  if not task:has_header('Message-Instance') and not task:has_header('DKIM2-Signature') then
    insert_symbol(task, symbols.check)
    insert_symbol(task, symbols.not_applicable)
    return
  end
  local content = smtp_message_bytes(task:get_content())
  local envelope = original_envelope(task)
  if not content or not envelope then
    apply_failure(task)
    return
  end
  local message = {
    raw_rfc5322_base64 = tostring(rspamd_util.encode_base64(content, 0)),
    fidelity = 'raw_rfc5322',
  }
  local request = {
    api_version = API_VERSION,
    draft = DRAFT,
    message = message,
    smtp = envelope,
  }
  if settings.authserv_id ~= nil then
    request.reporting = { authserv_id = settings.authserv_id }
  end
  local body = ucl.to_format(request, 'json-compact')
  if type(body) == 'userdata' then
    body = tostring(body)
  end
  if type(body) ~= 'string' or #body == 0 then
    apply_failure(task)
    return
  end
  local started = rspamd_http.request({
    task = task,
    url = settings.endpoint,
    method = 'POST',
    body = body,
    headers = {
      ['Accept'] = 'application/json',
      ['Cache-Control'] = 'no-store',
      ['X-DKIM2-Capability'] = capability,
    },
    mime_type = 'application/json',
    timeout = settings.timeout,
    max_size = settings.max_response_bytes,
    keepalive = true,
    no_ssl_verify = false,
    callback = function(err, code, response_body)
      if err then
        apply_failure(task)
        return
      end
      if code == 204 and (response_body == nil or #tostring(response_body) == 0) then
        insert_symbol(task, symbols.check)
        insert_symbol(task, symbols.not_applicable)
        return
      end
      if code ~= 200 then
        apply_failure(task)
        return
      end
      local response = parse_response(response_body)
      if not response then
        apply_failure(task)
        return
      end
      apply_response(task, response)
    end,
  })
  if not started then
    apply_failure(task)
  end
end

local configured = validate_settings(rspamd_config:get_all_opt(N))
if not configured then
  lua_util.disable_module(N, 'config')
  return
end
settings = configured
capability = read_capability(settings.capability_file)
if not capability then
  rspamd_logger.errx(rspamd_config, '%s configuration cannot load its protected capability', N)
  lua_util.disable_module(N, 'config')
  return
end

local parent = rspamd_config:register_symbol({
  name = symbols.check,
  type = 'normal',
  callback = process_message,
  score = 0.0,
  group = N,
  flags = 'nostat',
  augmentations = { string.format('timeout=%f', settings.timeout) },
})

for key, symbol in pairs(symbols) do
  if key ~= 'check' then
    rspamd_config:register_symbol({
      name = symbol,
      type = 'virtual',
      parent = parent,
      score = 0.0,
      group = N,
    })
  end
end

rspamd_logger.infox(rspamd_config, '%s verifier module enabled with failure_mode=%s', N, settings.failure_mode)
