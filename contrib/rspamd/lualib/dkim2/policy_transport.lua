-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local protected_file = require 'dkim2.protected_file'
local M = {}
local POLICY_PATH = '/api/v1/policy/decisions'
local MAX_PASSWORD_BYTES = 1024
local STATUS_CODES = {
  permit = { effect = 'permit', retryable = false },
  policy_denied = { effect = 'deny', retryable = false },
  not_applicable = { effect = 'not_applicable', retryable = false },
  no_applicable_rule = { effect = 'not_applicable', retryable = false },
  no_match_deny = { effect = 'deny', retryable = false },
  evaluation_failed = { effect = 'indeterminate', retryable = true },
  provider_unavailable = { effect = 'indeterminate', retryable = true },
  effect_outcome_unknown_replay_safe = { effect = 'indeterminate', retryable = true },
  effect_outcome_unknown = { effect = 'indeterminate', retryable = false },
  effect_acceptance_rejected = { effect = 'indeterminate', retryable = true },
}

-- M.proposal_summary excludes response text and preserves unavailable versus validated outcomes.
function M.proposal_summary(decision)
  local status = type(decision) == 'table' and type(decision.status) == 'table' and decision.status or nil
  local contract = status and STATUS_CODES[status.code] or nil
  if contract and contract.effect == decision.effect and contract.retryable == status.retryable then
    return contract.effect, status.code
  end
  return 'unavailable', 'unavailable'
end

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
  local password = protected_file.read(path, 1, MAX_PASSWORD_BYTES)
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

-- valid_request_id accepts the bounded lowercase hexadecimal correlation IDs generated locally.
local function valid_request_id(value)
  return type(value) == 'string' and #value >= 16 and #value <= 128 and
    value:match('^[0-9a-f]+$') ~= nil
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
      not valid_request_id(value.request_id) or value.request_id ~= request_id or
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

-- M.new constructs the common verified HTTPS boundary without owning either decision or observation mapping.
function M.new(options)
  if type(options) ~= 'table' or not valid_endpoint(options.endpoint, options.server_name) or
      not valid_username(options.username) or type(options.http) ~= 'table' or
      type(options.http.request) ~= 'function' or type(options.ucl) ~= 'table' or
      type(options.ucl.parser) ~= 'function' or type(options.json_validator) ~= 'function' or
      type(options.util) ~= 'table' or type(options.util.encode_base64) ~= 'function' then
    return nil
  end
  local password = options.password or read_password(options.password_file)
  local timeout = tonumber(options.timeout or 2.0)
  local maximum = tonumber(options.max_response_bytes or 65536)
  local request_maximum = tonumber(options.max_request_bytes or 1048576)
  if type(password) ~= 'string' or #password == 0 or #password > MAX_PASSWORD_BYTES or
      contains_forbidden_octet(password) or not timeout or timeout ~= timeout or timeout <= 0 or timeout > 10 or
      not maximum or maximum ~= maximum or maximum < 1024 or maximum > 262144 or maximum % 1 ~= 0 or
      not request_maximum or request_maximum ~= request_maximum or request_maximum < 1024 or
      request_maximum > 1048576 or request_maximum % 1 ~= 0 then
    return nil
  end
  return setmetatable({endpoint = options.endpoint, username = options.username, password = password,
    timeout = timeout, max_response_bytes = maximum, max_request_bytes = request_maximum,
    http = options.http, ucl = options.ucl, util = options.util, json_validator = options.json_validator,
    background_config = options.background_config}, {__index = M})
end

-- send transmits immutable bytes through one TLS and correlated-response authority.
local function send(self, task, ev_base, body, request_id, callback)
  if type(body) ~= 'string' or #body == 0 or #body > self.max_request_bytes or
      not valid_request_id(request_id) or type(callback) ~= 'function' then
    return false
  end
  local authorization = 'Basic ' .. tostring(self.util.encode_base64(
    self.username .. ':' .. self.password, 0))
  return self.http.request({
    task = task, ev_base = ev_base, config = ev_base and self.background_config or nil,
    url = self.endpoint, method = 'POST', body = body,
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
        local terminal = not err and type(code) == 'number' and code >= 400 and code < 500 and
          code ~= 408 and code ~= 425 and code ~= 429
        callback(nil, terminal and 'rejected' or 'unavailable')
        return
      end
      callback(parse_response(
        self.ucl, self.json_validator, response_body, self.max_response_bytes, request_id))
    end,
  })
end

-- M.send retains the task session until the current synchronous request completes.
function M:send(task, body, request_id, callback)
  if not task then
    return false
  end
  return send(self, task, nil, body, request_id, callback)
end

-- M.send_background binds durable claimed delivery to the worker event loop instead of an SMTP task.
function M:send_background(ev_base, body, request_id, callback)
  if not ev_base or not self.background_config then
    return false
  end
  return send(self, nil, ev_base, body, request_id, callback)
end

M.valid_identity = valid_identity
M.valid_request_id = valid_request_id
M.dense_array = dense_array
return M
