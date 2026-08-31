-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}

local POLICY_PATH = '/api/v1/policy/decisions'
local MAX_PASSWORD_BYTES = 1024
local SIGNAL_SYMBOLS = {
  ARC_ALLOW = 'arc.pass', ARC_INVALID = 'arc.invalid', ARC_REJECT = 'arc.fail',
  CLAM_VIRUS = 'malware.detected', DMARC_POLICY_ALLOW = 'dmarc.pass',
  DMARC_POLICY_QUARANTINE = 'dmarc.fail', DMARC_POLICY_REJECT = 'dmarc.fail',
  PHISHING = 'phishing.detected', R_DKIM_ALLOW = 'dkim.pass',
  R_DKIM_PERMFAIL = 'dkim.permerror', R_DKIM_REJECT = 'dkim.fail',
  R_DKIM_TEMPFAIL = 'dkim.temperror', R_SPF_ALLOW = 'spf.pass',
  R_SPF_DNSFAIL = 'spf.temperror', R_SPF_FAIL = 'spf.fail',
  R_SPF_NA = 'spf.neutral', R_SPF_NEUTRAL = 'spf.neutral',
  R_SPF_PERMFAIL = 'spf.permerror', R_SPF_SOFTFAIL = 'spf.softfail',
  VIRUS_FOUND = 'malware.detected',
}
local METRIC_ACTIONS = {
  accept = true, ['no action'] = true, ['add header'] = true,
  ['rewrite subject'] = true, greylist = true, ['soft reject'] = true,
  reject = true, discard = true, quarantine = true,
}
local STATUS_CODES = {
  permit = { effect = 'permit', retryable = false },
  policy_denied = { effect = 'deny', retryable = false },
  not_applicable = { effect = 'not_applicable', retryable = false },
  no_applicable_rule = { effect = 'not_applicable', retryable = false },
  no_match_deny = { effect = 'deny', retryable = false },
  evaluation_failed = { effect = 'indeterminate', retryable = true },
  provider_unavailable = { effect = 'indeterminate', retryable = true },
  effect_outcome_unknown = { effect = 'indeterminate', retryable = false },
  effect_acceptance_rejected = { effect = 'indeterminate', retryable = true },
}

-- valid_json_content_type accepts JSON with an optional media-type parameter list.
local function valid_json_content_type(value)
  if type(value) ~= 'string' then
    return false
  end
  value = value:lower()
  return value:match('^application/json%s*$') ~= nil or
    value:match('^application/json%s*;') ~= nil
end

-- contains_forbidden_octet rejects field-breaking bytes without pattern parsing.
local function contains_forbidden_octet(value)
  return value:find('\r', 1, true) ~= nil or value:find('\n', 1, true) ~= nil or
    value:find('\0', 1, true) ~= nil
end

-- exact_keys validates a closed object without accepting extension fields.
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

-- dense_array validates a bounded contiguous array.
local function dense_array(value, maximum)
  if type(value) ~= 'table' then
    return false
  end
  local count = 0
  for key in pairs(value) do
    if type(key) ~= 'number' or key < 1 or key % 1 ~= 0 or key > maximum then
      return false
    end
    count = count + 1
  end
  for index = 1, count do
    if value[index] == nil then
      return false
    end
  end
  return true
end

-- empty_array permits absent or explicitly empty unsupported response effects.
local function empty_array(value)
  return value == nil or dense_array(value, 0)
end

-- read_password loads one protected Policy-Basic password without diagnostics.
local function read_password(path)
  if type(path) ~= 'string' or path:sub(1, 1) ~= '/' or path:find('\0', 1, true) then
    return nil
  end
  local handle = io.open(path, 'rb')
  if not handle then
    return nil
  end
  local password = handle:read(MAX_PASSWORD_BYTES + 1)
  handle:close()
  if type(password) ~= 'string' or #password == 0 or #password > MAX_PASSWORD_BYTES or
      contains_forbidden_octet(password) then
    return nil
  end
  return password
end

-- valid_endpoint confines Policy traffic to one exact verified HTTPS authority.
local function valid_endpoint(endpoint, server_name)
  if type(endpoint) ~= 'string' or type(server_name) ~= 'string' or
      server_name ~= server_name:lower() or server_name == 'localhost' then
    return false
  end
  if #server_name == 0 or #server_name > 253 or server_name:find('..', 1, true) then
    return false
  end
  for label in server_name:gmatch('[^.]+') do
    if #label == 0 or #label > 63 or label:sub(1, 1) == '-' or label:sub(-1) == '-' or
        not label:match('^[a-z0-9-]+$') then
      return false
    end
  end
  local host, port = endpoint:match('^https://([a-z0-9.-]+):(%d+)' .. POLICY_PATH .. '$')
  if not host then
    host = endpoint:match('^https://([a-z0-9.-]+)' .. POLICY_PATH .. '$')
  end
  port = port and tonumber(port) or 443
  return host == server_name and port >= 1 and port <= 65535 and
    not host:find('..', 1, true)
end

-- valid_identity accepts a bounded configured service or Basic principal identity.
local function valid_identity(value)
  return type(value) == 'string' and #value > 0 and #value <= 128 and
    not contains_forbidden_octet(value)
end

-- valid_username accepts one unambiguous printable Policy-Basic user identity.
local function valid_username(value)
  return valid_identity(value) and not value:find(':', 1, true) and
    value:match('^[A-Za-z0-9._-]+$') ~= nil
end

-- validate_detail validates one bounded response detail without consuming its text.
local function validate_detail(value)
  return exact_keys(value, { 'field', 'reason' }, {}) and type(value.field) == 'string' and
    #value.field > 0 and #value.field <= 512 and type(value.reason) == 'string' and
    #value.reason > 0 and #value.reason <= 512
end

-- validate_response enforces and correlates the exact generic Policy response consumed by Rspamd.
local function validate_response(value, request_id)
  local status_contract = type(value) == 'table' and type(value.status) == 'table' and
    STATUS_CODES[value.status.code] or nil
  if not exact_keys(value, { 'request_id', 'decision_id', 'effect', 'status' },
      { 'obligations', 'advice', 'diagnostics' }) or
      type(value.request_id) ~= 'string' or value.request_id ~= request_id or
      #value.request_id == 0 or #value.request_id > 128 or
      type(value.decision_id) ~= 'string' or #value.decision_id == 0 or #value.decision_id > 128 or
      not ({ permit = true, deny = true, not_applicable = true, indeterminate = true })[value.effect] or
      not exact_keys(value.status, { 'code', 'message', 'retryable' }, { 'details' }) or
      not status_contract or status_contract.effect ~= value.effect or
      type(value.status.message) ~= 'string' or #value.status.message > 512 or
      value.status.retryable ~= status_contract.retryable or value.diagnostics ~= nil or
      not empty_array(value.obligations) or not empty_array(value.advice) then
    return false
  end
  if value.status.details ~= nil then
    if not dense_array(value.status.details, 32) then
      return false
    end
    for _, detail in ipairs(value.status.details) do
      if not validate_detail(detail) then
        return false
      end
    end
  end
  return true
end

-- parse_response decodes and correlates one bounded successful generic Policy response.
local function parse_response(ucl, json_validator, body, maximum, request_id)
  if type(body) == 'userdata' then
    body = tostring(body)
  end
  if type(body) ~= 'string' or #body == 0 or #body > maximum or
      body:sub(1, 1) ~= '{' or body:sub(-1) ~= '}' or not json_validator(body) then
    return nil
  end
  local parser = ucl.parser()
  if not parser:parse_string(body) then
    return nil
  end
  local value = parser:get_object()
  return validate_response(value, request_id) and value or nil
end

-- normalized_signals maps only explicitly owned Rspamd states into Policy facts.
local function normalized_signals(task, score, reject_threshold)
  local present = {}
  for symbol, signal in pairs(SIGNAL_SYMBOLS) do
    if task:has_symbol(symbol) then
      present[signal] = true
    end
  end
  if score >= reject_threshold then
    present['spam.high_confidence'] = true
  end
  local result = {}
  for signal in pairs(present) do
    result[#result + 1] = signal
  end
  table.sort(result)
  return result
end

-- build_environment projects bounded current-scan facts with local rspamd.* keys.
local function build_environment(task, settings, peer_ip)
  local metric = task:get_metric_result()
  local score = type(metric) == 'table' and metric.score or nil
  local reject_threshold = task:get_metric_threshold('reject')
  local greylist_threshold = task:get_metric_threshold('greylist')
  local action = type(metric) == 'table' and metric.action or nil
  if type(peer_ip) ~= 'string' or #peer_ip == 0 or #peer_ip > 45 or
      type(score) ~= 'number' or type(reject_threshold) ~= 'number' or
      type(greylist_threshold) ~= 'number' or not METRIC_ACTIONS[action] or
      score ~= score or reject_threshold ~= reject_threshold or greylist_threshold ~= greylist_threshold then
    return nil
  end
  local authenticated = task:get_user() ~= nil
  local client_class = authenticated and 'authenticated' or settings.client_class
  local mail_from_class = settings.envelope.mail_from_class(task)
  local recipient_classes = settings.envelope.recipient_classes(task)
  if type(mail_from_class) ~= 'string' or not dense_array(recipient_classes, 16) then
    return nil
  end
  return {
    service = 'rspamd', instance = settings.instance, protocol = 'milter',
    attributes = {
      ['rspamd.scan_action_before_policy'] = { string = action },
      ['rspamd.metric_score'] = { double = score },
      ['rspamd.reject_threshold'] = { double = reject_threshold },
      ['rspamd.greylist_threshold'] = { double = greylist_threshold },
      ['rspamd.normalized_signals'] = {
        strings = normalized_signals(task, score, reject_threshold),
      },
      ['rspamd.smtp_client_ip'] = { string = peer_ip },
      ['rspamd.client_class'] = { string = client_class },
      ['rspamd.mail_from_class'] = { string = mail_from_class },
      ['rspamd.recipient_classes'] = { strings = recipient_classes },
      ['rspamd.smtp_authenticated'] = { boolean = authenticated },
      ['rspamd.recipient_count'] = { integer = tostring(settings.envelope.rcpt_count(task)) },
      ['rspamd.message_size'] = { integer = tostring(task:get_size()) },
      ['rspamd.message_fidelity'] = { string = 'milter_reconstructed_crlf' },
    },
  }
end

-- M.new constructs one generic Policy API client for the DKIM2 target.
function M.new(options)
  if type(options) ~= 'table' or not valid_endpoint(options.endpoint, options.server_name) or
      not valid_username(options.username) or not valid_identity(options.instance) or
      type(options.http) ~= 'table' or type(options.http.request) ~= 'function' or
      type(options.ucl) ~= 'table' or type(options.ucl.to_format) ~= 'function' or
      type(options.json_validator) ~= 'function' or
      type(options.util) ~= 'table' or type(options.util.encode_base64) ~= 'function' or
      type(options.util.random_hex) ~= 'function' or type(options.projection_mapper) ~= 'function' or
      type(options.envelope) ~= 'table' or type(options.envelope.rcpt_count) ~= 'function' or
      type(options.envelope.mail_from_class) ~= 'function' or
      type(options.envelope.recipient_classes) ~= 'function' then
    return nil
  end
  local password = options.password or read_password(options.password_file)
  local timeout = tonumber(options.timeout or 2.0)
  local maximum = tonumber(options.max_response_bytes or 65536)
  local classes = { untrusted = true, trusted = true, ['local'] = true }
  local address_classes = { external = true, ['local'] = true, relay = true, null = true }
  if type(password) ~= 'string' or #password == 0 or not timeout or timeout <= 0 or timeout > 10 or
      not maximum or maximum < 1024 or maximum > 262144 or maximum % 1 ~= 0 or
      not classes[options.client_class] or not address_classes[options.mail_from_class] or
      not dense_array(options.recipient_classes, 16) then
    return nil
  end
  for _, class in ipairs(options.recipient_classes) do
    if not address_classes[class] or class == 'null' then
      return nil
    end
  end
  for index = 2, #options.recipient_classes do
    if options.recipient_classes[index] <= options.recipient_classes[index - 1] then
      return nil
    end
  end
  return setmetatable({
    endpoint = options.endpoint, username = options.username, instance = options.instance,
    password = password, timeout = timeout, max_response_bytes = maximum,
    client_class = options.client_class, mail_from_class = options.mail_from_class,
    recipient_classes = options.recipient_classes, http = options.http, ucl = options.ucl,
    util = options.util, projection_mapper = options.projection_mapper, envelope = options.envelope,
    json_validator = options.json_validator,
  }, { __index = M })
end

-- M.request evaluates one validated verifier projection through the generic Policy API.
function M:request(task, verifier_response, peer_ip, callback)
  local attributes = self.projection_mapper(verifier_response)
  local environment = build_environment(task, self, peer_ip)
  if type(attributes) ~= 'table' or not environment or type(callback) ~= 'function' then
    return false
  end
  local request_id = self.util.random_hex(16)
  if type(request_id) ~= 'string' or #request_id < 16 or #request_id > 128 then
    return false
  end
  local request = {
    version = '1', request_id = request_id,
    target = { namespace = 'dkim2', action = 'accept-message-instance' },
    resource = { type = 'dkim2-message-instance', attributes = attributes },
    environment = environment,
    options = { include_diagnostics = false },
  }
  local body = self.ucl.to_format(request, 'json-compact')
  if type(body) == 'userdata' then
    body = tostring(body)
  end
  if type(body) ~= 'string' or #body == 0 then
    return false
  end
  local authorization = 'Basic ' .. tostring(self.util.encode_base64(
    self.username .. ':' .. self.password, 0))
  return self.http.request({
    task = task, url = self.endpoint, method = 'POST', body = body,
    headers = { Accept = 'application/json', Authorization = authorization,
      ['Cache-Control'] = 'no-store' },
    mime_type = 'application/json', timeout = self.timeout,
    max_size = self.max_response_bytes, keepalive = true, no_ssl_verify = false,
    callback = function(err, code, response_body, headers)
      local content_type = headers and (headers['content-type'] or headers['Content-Type'])
      if type(content_type) == 'table' then
        content_type = content_type[1]
      end
      if err or code ~= 200 or not valid_json_content_type(content_type) then
        callback(nil)
        return
      end
      callback(parse_response(
        self.ucl, self.json_validator, response_body, self.max_response_bytes, request_id))
    end,
  })
end

-- M.decision_action maps one validated Policy outcome to a closed local action.
function M.decision_action(decision)
  if type(decision) ~= 'table' then
    return 'soft reject'
  end
  if decision.effect == 'permit' then
    return 'continue'
  end
  if decision.effect == 'deny' then
    return 'reject'
  end
  if decision.effect == 'indeterminate' and decision.status.retryable == false then
    return 'reject'
  end
  return 'soft reject'
end

return M
