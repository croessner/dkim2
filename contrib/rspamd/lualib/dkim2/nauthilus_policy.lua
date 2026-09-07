-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
local transport_module = require 'dkim2.policy_transport'
local valid_identity = transport_module.valid_identity
local valid_request_id = transport_module.valid_request_id
local dense_array = transport_module.dense_array
local SIGNAL_SYMBOLS = {
  ARC_ALLOW = 'arc.pass', ARC_INVALID = 'arc.invalid', ARC_REJECT = 'arc.fail',
  CLAM_VIRUS = 'malware.detected', DMARC_POLICY_ALLOW = 'dmarc.pass',
  DMARC_BAD_POLICY = 'dmarc.permerror', DMARC_DNSFAIL = 'dmarc.temperror',
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

-- M.new constructs the DKIM2 decision mapper over the shared authenticated transport.
function M.new(options)
  local transport = transport_module.new(options)
  if not transport or not valid_identity(options.instance) or
      type(options.ucl.to_format) ~= 'function' or type(options.util.random_hex) ~= 'function' or
      type(options.projection_mapper) ~= 'function' or type(options.envelope) ~= 'table' or
      type(options.envelope.rcpt_count) ~= 'function' or type(options.envelope.mail_from_class) ~= 'function' or
      type(options.envelope.recipient_classes) ~= 'function' then
    return nil
  end
  local classes = {untrusted = true, trusted = true, ['local'] = true}
  local address_classes = {external = true, ['local'] = true, relay = true, null = true}
  if not classes[options.client_class] or not address_classes[options.mail_from_class] or
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
  return setmetatable({transport = transport, instance = options.instance,
    client_class = options.client_class, mail_from_class = options.mail_from_class,
    recipient_classes = options.recipient_classes, ucl = options.ucl, util = options.util,
    projection_mapper = options.projection_mapper, envelope = options.envelope}, {__index = M})
end

-- M.request evaluates one validated verifier projection through the generic Policy API.
function M:request(task, verifier_response, peer_ip, callback)
  local attributes = self.projection_mapper(verifier_response)
  local environment = build_environment(task, self, peer_ip)
  if type(attributes) ~= 'table' or not environment or type(callback) ~= 'function' then
    return false
  end
  local request_id = self.util.random_hex(16)
  if not valid_request_id(request_id) then
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
  return self.transport:send(task, body, request_id, callback)
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
