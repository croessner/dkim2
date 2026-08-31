-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local module_path = assert(arg[1], 'policy module path is required')
local json_module_path = assert(arg[2], 'strict JSON module path is required')
local strict_json = assert(loadfile(json_module_path))()
local sent
local response_value
local ucl = {
  to_format = function(value) sent = value return '{}' end,
  parser = function()
    return { parse_string = function() return true end, get_object = function() return response_value end }
  end,
}
local response_content_type = 'application/json'
local http = { request = function(options)
  options.callback(nil, 200, '{}', { ['content-type'] = response_content_type })
  return true
end }
local util = {
  encode_base64 = function(value) assert(value == 'rspamd-verifier:secret') return 'encoded' end,
  random_hex = function() return '0123456789abcdef0123456789abcdef' end,
}
local ip = { is_valid = function() return true end, to_string = function() return '2001:db8::25' end }
local metric_score_calls = 0
local task = {
  get_from_ip = function() return ip end,
  get_metric_score = function()
    metric_score_calls = metric_score_calls + 1
    return { 6.2, 15.0 }
  end,
  get_metric_result = function() return { score = 6.2, action = 'greylist' } end,
  get_metric_threshold = function(_, action) return action == 'reject' and 15.0 or 4.0 end,
  get_metric_action = function() return 'greylist' end,
  get_user = function() return nil end,
  get_size = function() return 48312 end,
  has_symbol = function(_, symbol) return symbol == 'DMARC_POLICY_REJECT' or symbol == 'R_SPF_SOFTFAIL' end,
}
local module = assert(loadfile(module_path))()
local client = assert(module.new({
  endpoint = 'https://nauthilus-policy:9443/api/v1/policy/decisions',
  server_name = 'nauthilus-policy', username = 'rspamd-verifier', password = 'secret',
  instance = 'mx01.example.test', timeout = 2, max_response_bytes = 65536,
  client_class = 'untrusted', mail_from_class = 'external', recipient_classes = { 'local' },
  http = http, ucl = ucl, util = util,
  json_validator = strict_json.valid,
  projection_mapper = function() return { ['dkim2.projection_schema'] = { string = 'dkim2.verifier-projection.v1' } } end,
  envelope = {
    rcpt_count = function() return 1 end,
    mail_from_class = function() return 'external' end,
    recipient_classes = function() return { 'local' } end,
  },
}))

response_value = {
  request_id = '0123456789abcdef0123456789abcdef',
  decision_id = 'decision-1', effect = 'permit',
  status = { code = 'permit', message = 'permitted', retryable = false },
}
local result
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result.effect == 'permit')
assert(result.request_id == sent.request_id,
  'Policy response request ID must correlate with the request')
assert(metric_score_calls == 0,
  'Policy postfilter must use get_metric_result instead of the 4.1.5 score table API')
assert(sent.target.namespace == 'dkim2' and sent.target.action == 'accept-message-instance')
assert(sent.resource.attributes['dkim2.projection_schema'].string == 'dkim2.verifier-projection.v1')
assert(sent.environment.attributes['rspamd.smtp_client_ip'].string == '2001:db8::25')
assert(sent.environment.attributes['rspamd.normalized_signals'].strings[1] == 'dmarc.fail')
assert(sent.environment.attributes['rspamd.normalized_signals'].strings[2] == 'spf.softfail')
assert(sent.options.include_diagnostics == false)
assert(module.decision_action(result) == 'continue')

response_value.request_id = 'fedcba9876543210fedcba9876543210'
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'mismatched Policy response request ID must fail closed')
response_value.request_id = '0123456789abcdef0123456789abcdef'

response_value.request_id = nil
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'missing Policy response request ID must fail closed')
response_value.request_id = '0123456789abcdef0123456789abcdef'

response_value.unknown = true
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'unknown Policy response fields must fail closed')
response_value.unknown = nil

response_value.obligations = {}
response_value.advice = {}
response_value.status.details = { { field = 'resource.attributes', reason = 'valid' } }
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result ~= nil, 'supported optional Policy response fields must remain accepted')
response_value.obligations = nil
response_value.advice = nil
response_value.status.details = nil

response_value.obligations = { { id = 'unsupported', parameters = {} } }
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'unsupported Policy obligations must fail closed')
response_value.obligations = nil

response_value.status.unknown = true
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'unknown Policy status fields must fail closed')
response_value.status.unknown = nil

response_value.status.code = 'provider_unavailable'
response_value.status.retryable = true
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'Policy permit with an indeterminate status must fail closed')
response_value.status.code = 'permit'
response_value.status.retryable = false

response_value.status.code = 'unknown'
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'unknown Policy status codes must fail closed')
response_value.status.code = 'permit'

response_value.status.retryable = true
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'Policy retryability must match the status taxonomy')
response_value.status.retryable = false

response_value.status.message = string.rep('x', 513)
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'oversized Policy status messages must fail closed')
response_value.status.message = 'permitted'

response_value.status.details = { { field = '', reason = 'invalid' } }
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'empty Policy validation-detail fields must fail closed')
response_value.status.details = nil

response_value.effect = 'indeterminate'
response_value.status.code = 'evaluation_failed'
response_value.status.retryable = true
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(module.decision_action(result) == 'soft reject')
response_value.status.code = 'effect_outcome_unknown'
response_value.status.retryable = false
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(module.decision_action(result) == 'reject')
response_value.effect = 'not_applicable'
response_value.status.code = 'no_applicable_rule'
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(module.decision_action(result) == 'soft reject')

response_value.diagnostics = { entries = {} }
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'unsolicited diagnostics must fail closed')

response_value.diagnostics = nil
response_content_type = 'text/plain'
assert(client:request(task, {}, '2001:db8::25', function(value) result = value end))
assert(result == nil, 'non-JSON response content type must fail closed')

response_content_type = 'application/json; charset=utf-8'
assert(not client:request(task, {}, '', function() end), 'missing captured SMTP peer must fail closed')
assert(sent.environment.attributes['rspamd.smtp_client_ip'].string == '2001:db8::25',
  'Policy must use the caller-captured peer instead of reading the task again')

local missing_action_task = setmetatable({
  get_metric_result = function() return { score = 6.2 } end,
}, { __index = task })
assert(not client:request(missing_action_task, {}, '2001:db8::25', function() end),
  'missing metric action must fail closed before Policy I/O')

local unknown_action_task = setmetatable({
  get_metric_result = function() return { score = 6.2, action = 'custom-action' } end,
}, { __index = task })
assert(not client:request(unknown_action_task, {}, '2001:db8::25', function() end),
  'unknown metric action must fail closed before Policy I/O')

assert(strict_json.valid('{"status":{"retryable":true},"items":[1,-2.5e3,null]}'))
for _, invalid in ipairs({
  '{effect = "permit"}', '{"effect":"permit",}', '{"effect":"permit" // comment\n}',
  '{"effect":"permit","effect":"deny"}', '{"\\u0065ffect":"permit"}',
}) do
  assert(not strict_json.valid(invalid), 'non-strict JSON must be rejected: ' .. invalid)
end
