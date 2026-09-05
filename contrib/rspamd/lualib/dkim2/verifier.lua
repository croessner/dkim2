-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local N = 'dkim2'
local M = {}
local rspamd_http = require 'rspamd_http'
local rspamd_logger = require 'rspamd_logger'
local rspamd_util = require 'rspamd_util'
local lua_mime = require 'lua_mime'
local lua_auth_results = require 'lua_auth_results'
local lua_util = require 'lua_util'
local ucl = require 'ucl'

local API_VERSION = 'v1'
local DRAFT = 'draft-ietf-dkim-dkim2-spec-06'
local PROJECTION_SCHEMA = 'dkim2.verifier-projection.v1'
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

-- delivery_status_members is the closed received delivery-status vocabulary.
-- Its member order is the daemon's evaluation order, and the symbol suffixes
-- are drawn from it so that no symbol can outlive its contract value.
local delivery_status_order = {
  'structure', 'embedded', 'outer_alignment', 'recipient_linkage',
  'local_hop', 'propagation',
}
local delivery_status_members = {
  structure = { 'limit_exceeded', 'malformed', 'valid' },
  embedded = {
    'absent', 'not_evaluated', 'temperror', 'unverified', 'verified',
    'verified_headers_only',
  },
  outer_alignment = { 'aligned', 'misaligned', 'not_evaluated' },
  recipient_linkage = { 'linked', 'not_evaluated', 'unlinked' },
  local_hop = { 'local', 'mismatch', 'not_evaluated', 'not_local', 'temperror' },
  propagation = {
    'eligible', 'forbidden_null_previous_sender', 'not_applicable',
    'not_evaluated', 'not_failure', 'not_reconstructable', 'terminal_origin',
    'unsupported_chain',
  },
}

-- delivery_status_values indexes each member vocabulary for strict validation.
local delivery_status_values = {}
for member, values in pairs(delivery_status_members) do
  local allowed = {}
  for _, value in ipairs(values) do
    allowed[value] = true
    symbols['dsn_' .. member .. '_' .. value] =
      'DKIM2_DSN_' .. string.upper(member) .. '_' .. string.upper(value)
  end
  delivery_status_values[member] = allowed
end

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
  tenant = true,
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

local verification_reasons = {
  none = true, limit_exceeded = true, malformed_message = true, malformed_protocol = true,
  duplicate_hash_algorithm = true, invalid_recipe_json = true, duplicate_selector = true,
  too_many_signatures = true, missing_protocol = true, sequence_invalid = true,
  unsupported_algorithm = true, hash_mismatch = true, signature_mismatch = true,
  missing_key = true, invalid_key = true, ambiguous_key = true, revoked_key = true,
  unsupported_key_type = true, key_algorithm_mismatch = true, provider_temporary = true,
  provider_permanent = true, provider_contract = true, timestamp_invalid = true,
  envelope_mismatch = true, domain_alignment_mismatch = true, next_domain_mismatch = true,
  out_of_band_required = true, internal_contract = true,
}

local authentication_reasons = {}
for reason in pairs(verification_reasons) do
  authentication_reasons[reason] = true
end
authentication_reasons.duplicate_message_without_exploded = true
authentication_reasons.replay_indeterminate = true
authentication_reasons.replay_evidence_unavailable = true

local policy_reasons = {
  protocol_pass = true, protocol_fail = true, protocol_permerror = true,
  protocol_temperror = true, permissive_override = true, testing_mode_observe = true,
  dns_testing_effective = true, dns_testing_mixed = true, dns_testing_ineligible = true,
  donotmodify_indeterminate = true, donotmodify_not_evaluated = true,
  donotexplode_violated = true, donotexplode_indeterminate = true,
  donotexplode_not_evaluated = true, feedback_requested = true,
  feedback_relay_selected = true, feedhere_inert = true, exploded_reported = true,
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

-- valid_tenant accepts one bounded canonical administrative tenant identifier.
-- The tenant is an authority key for received delivery-status locality only; it
-- is never an identity claim and never reaches a symbol or log value.
local function valid_tenant(value)
  if type(value) ~= 'string' or #value == 0 or #value > 128 then
    return false
  end
  if not value:match('^[a-z0-9][a-z0-9._-]*$') then
    return false
  end
  return true
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
      (input.authserv_id ~= nil and not valid_authserv_id(input.authserv_id)) or
      (input.tenant ~= nil and not valid_tenant(input.tenant)) then
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
    tenant = input.tenant,
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

-- sorted_unique_strings validates a bounded canonical string-set representation.
local function sorted_unique_strings(value, maximum, allowed, member_validator)
  local count = dense_array_len(value, maximum)
  if count == nil then
    return false
  end
  local previous
  for _, member in ipairs(value) do
    if type(member) ~= 'string' or previous and member <= previous or
        allowed and not allowed[member] or member_validator and not member_validator(member) then
      return false
    end
    previous = member
  end
  return true
end

-- valid_base64_digest accepts one canonical padded 32-byte base64 value.
local function valid_base64_digest(value)
  return type(value) == 'string' and #value == 44 and value:sub(-1) == '=' and
    value:sub(1, 43):match('^[A-Za-z0-9+/]+$') ~= nil
end

-- valid_canonical_uint accepts the OpenAPI canonical positive integer string.
local function valid_canonical_uint(value)
  return type(value) == 'string' and value:match('^[1-9][0-9]*$') ~= nil and #value <= 20
end

-- valid_domain accepts one canonical lowercase DNS signer identity.
local function valid_domain(value)
  return valid_service_name(value)
end

-- valid_header_name accepts one bounded canonical lower-case field name.
local function valid_header_name(value)
  if #value == 0 or #value > 64 then
    return false
  end
  local allowed = "abcdefghijklmnopqrstuvwxyz0123456789!#$%&'*+-.^_`|~"
  for index = 1, #value do
    if not allowed:find(value:sub(index, index), 1, true) then
      return false
    end
  end
  return true
end

local signature_algorithms = {
  ['rsa-sha256'] = true, ['rsa-sha512'] = true,
  ['ed25519-sha256'] = true, ['ed25519-sha512'] = true,
}
local custody_transitions = {
  origin = true, ordinary = true, next_domain = true, terminal_next_domain = true,
}
local recipe_modes = { unchanged = true, applied = true }
local recipe_body_modes = { absent = true, steps = true, unavailable = true }
local change_classes = { ['body.rewrite'] = true, ['header.rewrite'] = true }
local history_states = { matched = true, mismatch = true, unavailable = true, unsupported = true }
local body_availability = { known = true, unavailable = true }

-- valid_projection_hop validates one complete bounded verifier-owned hop projection.
local function valid_projection_hop(value, expected_sequence)
  local required = {
    'sequence', 'message_instance', 'hop_binding', 'signer_domain',
    'signature_algorithms', 'signature_state', 'custody_transition',
    'do_not_modify', 'do_not_explode', 'feedback', 'feed_here', 'exploded',
    'recipe_mode', 'recipe_has_header_changes', 'recipe_body_mode', 'recipe_digest',
    'change_classes', 'affected_headers', 'history_header_state', 'history_body_state',
    'body_availability', 'change_count', 'affected_header_count',
  }
  if not exact_keys(value, required, {}) or not valid_canonical_uint(value.sequence) or
      tonumber(value.sequence) ~= expected_sequence or not valid_canonical_uint(value.message_instance) or
      not valid_base64_digest(value.hop_binding) or not valid_domain(value.signer_domain) or
      not sorted_unique_strings(value.signature_algorithms, 4, signature_algorithms) or
      value.signature_state ~= 'pass' or not custody_transitions[value.custody_transition] or
      type(value.do_not_modify) ~= 'boolean' or type(value.do_not_explode) ~= 'boolean' or
      type(value.feedback) ~= 'boolean' or type(value.feed_here) ~= 'boolean' or
      type(value.exploded) ~= 'boolean' or not recipe_modes[value.recipe_mode] or
      type(value.recipe_has_header_changes) ~= 'boolean' or
      not recipe_body_modes[value.recipe_body_mode] or not valid_base64_digest(value.recipe_digest) or
      not sorted_unique_strings(value.change_classes, 2, change_classes) or
      not sorted_unique_strings(value.affected_headers, 128, nil, valid_header_name) or
      not history_states[value.history_header_state] or not history_states[value.history_body_state] or
      not body_availability[value.body_availability] or type(value.change_count) ~= 'number' or
      value.change_count < 0 or value.change_count > 2 or value.change_count % 1 ~= 0 or
      type(value.affected_header_count) ~= 'number' or value.affected_header_count < 0 or
      value.affected_header_count > 128 or value.affected_header_count % 1 ~= 0 or
      value.affected_header_count ~= #value.affected_headers then
    return false
  end
  return true
end

-- valid_verifier_projection validates the exact transport-neutral v1 projection.
local function valid_verifier_projection(value)
  if not exact_keys(value, { 'schema', 'draft', 'binding_algorithm', 'binding', 'hops' }, {}) or
      value.schema ~= PROJECTION_SCHEMA or value.draft ~= DRAFT or
      value.binding_algorithm ~= 'sha-256' or not valid_base64_digest(value.binding) then
    return false
  end
  local count = dense_array_len(value.hops, 128)
  if not count or count == 0 then
    return false
  end
  for index, hop in ipairs(value.hops) do
    if not valid_projection_hop(hop, index) then
      return false
    end
  end
  return true
end

local verification_scopes = { current = true, chain = true }
local historical_content_states = { not_evaluated = true, complete = true, partial = true }
local historical_signature_states = { not_evaluated = true, complete = true }
local custody_structures = {
  not_evaluated = true, not_present = true, nd_links_evaluated = true,
  terminal_nd_requires_oob = true,
}
local check_classes = {
  message = true, protocol = true, body_hash = true, header_hash = true,
  signature = true, key = true, timestamp = true, envelope = true,
  domain_alignment = true, next_domain = true, provider = true, internal_contract = true,
}
local signature_set_algorithms = {
  ['rsa-sha256'] = true, ['ed25519-sha256'] = true, unknown = true,
}
local signature_set_states = {
  pass = true, fail = true, permerror = true, temperror = true, ignored = true,
}
local policy_modes = { strict = true, permissive = true, testing = true }
local feedback_history_states = {
  complete = true, indeterminate = true, not_evaluated = true,
}
local finding_severities = {
  info = true, warning = true, permanent = true, temporary = true,
}

-- valid_verification_check validates one closed daemon check result.
local function valid_verification_check(value)
  return exact_keys(value, { 'class', 'reason' }, {}) and check_classes[value.class] and
    verification_reasons[value.reason]
end

-- valid_signature_set validates one closed signature-set result.
local function valid_signature_set(value)
  if not exact_keys(value, { 'algorithm', 'status', 'reason', 'key_policy' }, { 'selector' }) or
      not signature_set_algorithms[value.algorithm] or not signature_set_states[value.status] or
      not verification_reasons[value.reason] or
      not exact_keys(value.key_policy,
        { 'testing_declared', 'strict_identity_declared', 'strict_identity_applicable' }, {}) or
      type(value.key_policy.testing_declared) ~= 'boolean' or
      type(value.key_policy.strict_identity_declared) ~= 'boolean' or
      value.key_policy.strict_identity_applicable ~= false then
    return false
  end
  return value.selector == nil or type(value.selector) == 'string' and
    #value.selector > 0 and #value.selector <= 253 and not contains_forbidden_octet(value.selector)
end

-- valid_verification_result validates the complete closed verification evidence object.
local function valid_verification_result(value)
  if not exact_keys(value, {
      'state', 'primary_reason', 'scope', 'historical_content', 'historical_signatures',
      'custody_structure', 'checks', 'signature_sets',
    }, { 'target' }) or not verification_states[value.state] or
      not verification_reasons[value.primary_reason] or not verification_scopes[value.scope] or
      not historical_content_states[value.historical_content] or
      not historical_signature_states[value.historical_signatures] or
      not custody_structures[value.custody_structure] then
    return false
  end
  local check_count = dense_array_len(value.checks, 128)
  local signature_count = dense_array_len(value.signature_sets, 16)
  if not check_count or check_count == 0 or not signature_count then
    return false
  end
  for _, check in ipairs(value.checks) do
    if not valid_verification_check(check) then
      return false
    end
  end
  for _, signature_set in ipairs(value.signature_sets) do
    if not valid_signature_set(signature_set) then
      return false
    end
  end
  return value.target == nil or exact_keys(value.target, { 'sequence', 'instance' }, {}) and
    valid_canonical_uint(value.target.sequence) and valid_canonical_uint(value.target.instance)
end

-- valid_policy_result validates the complete closed local policy object.
local function valid_policy_result(value)
  if not exact_keys(value, {
      'mode', 'verdict', 'primary_reason', 'do_not_modify', 'do_not_explode',
      'dns_testing_effective', 'feedback', 'findings',
    }, {}) or not policy_modes[value.mode] or not policy_verdicts[value.verdict] or
      not policy_reasons[value.primary_reason] or not donotmodify_states[value.do_not_modify] or
      not donotexplode_states[value.do_not_explode] or
      type(value.dns_testing_effective) ~= 'boolean' or
      not exact_keys(value.feedback,
        { 'requested', 'relay_required', 'history_coverage' }, { 'relay_sequence' }) or
      type(value.feedback.requested) ~= 'boolean' or
      type(value.feedback.relay_required) ~= 'boolean' or
      not feedback_history_states[value.feedback.history_coverage] or
      value.feedback.relay_sequence ~= nil and
        not valid_canonical_uint(value.feedback.relay_sequence) then
    return false
  end
  local finding_count = dense_array_len(value.findings, 128)
  if not finding_count or finding_count == 0 then
    return false
  end
  for _, finding in ipairs(value.findings) do
    if not exact_keys(finding, { 'reason', 'severity' }, { 'sequence' }) or
        not policy_reasons[finding.reason] or not finding_severities[finding.severity] or
        finding.sequence ~= nil and not valid_canonical_uint(finding.sequence) then
      return false
    end
  end
  return true
end

-- valid_delivery_status validates the closed received delivery-status
-- projection. Every member is required and closed, so a partial or unknown
-- projection is contract drift and fails the whole response.
local function valid_delivery_status(value)
  if not exact_keys(value, delivery_status_order, {}) then
    return false
  end
  for _, member in ipairs(delivery_status_order) do
    if not delivery_status_values[member][value[member]] then
      return false
    end
  end
  return true
end

-- valid_response validates the response members that authorize Rspamd effects.
local function valid_response(value)
  local top_required = {
    'api_version', 'draft', 'verification', 'authentication', 'policy',
    'replay', 'disposition', 'actions',
  }
  if not exact_keys(value, top_required, { 'verifier_projection', 'delivery_status' }) or
      value.api_version ~= API_VERSION or
      value.draft ~= DRAFT or not policy_verdicts[value.disposition] then
    return false
  end
  if value.delivery_status ~= nil and not valid_delivery_status(value.delivery_status) then
    return false
  end
  if not valid_verification_result(value.verification) or
      not exact_keys(value.authentication, { 'state', 'primary_reason' }, {}) or
      not verification_states[value.authentication.state] or
      not authentication_reasons[value.authentication.primary_reason] or
      not exact_keys(value.replay, { 'class' }, {}) or not replay_classes[value.replay.class] or
      not valid_policy_result(value.policy) or
      not valid_outcome(value) then
    return false
  end
  local projection_required = value.verification.state == 'PASS' and
    value.verification.scope == 'chain'
  if projection_required ~= (value.verifier_projection ~= nil) or
      value.verifier_projection ~= nil and not valid_verifier_projection(value.verifier_projection) then
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

-- record_field constructs one generic Policy record field.
local function record_field(name, value)
  return { name = name, value = value }
end

-- projection_hop_record maps one already validated hop without deriving verifier facts.
local function projection_hop_record(hop)
  return { fields = {
    record_field('sequence', { integer = tostring(hop.sequence) }),
    record_field('message_instance', { integer = tostring(hop.message_instance) }),
    record_field('hop_binding', { bytes = hop.hop_binding }),
    record_field('signer_domain', { string = hop.signer_domain }),
    record_field('signature_algorithms', { strings = hop.signature_algorithms }),
    record_field('signature_state', { string = hop.signature_state }),
    record_field('custody_transition', { string = hop.custody_transition }),
    record_field('do_not_modify', { boolean = hop.do_not_modify }),
    record_field('do_not_explode', { boolean = hop.do_not_explode }),
    record_field('feedback', { boolean = hop.feedback }),
    record_field('feed_here', { boolean = hop.feed_here }),
    record_field('exploded', { boolean = hop.exploded }),
    record_field('recipe_mode', { string = hop.recipe_mode }),
    record_field('recipe_has_header_changes', { boolean = hop.recipe_has_header_changes }),
    record_field('recipe_body_mode', { string = hop.recipe_body_mode }),
    record_field('recipe_digest', { bytes = hop.recipe_digest }),
    record_field('change_classes', { strings = hop.change_classes }),
    record_field('affected_headers', { strings = hop.affected_headers }),
    record_field('history_header_state', { string = hop.history_header_state }),
    record_field('history_body_state', { string = hop.history_body_state }),
    record_field('body_availability', { string = hop.body_availability }),
    record_field('change_count', { integer = tostring(hop.change_count) }),
    record_field('affected_header_count', { integer = tostring(hop.affected_header_count) }),
  } }
end

-- policy_attributes maps validated daemon facts to local dkim2.* generic Policy values.
local function policy_attributes(response)
  if not valid_response(response) or response.verifier_projection == nil then
    return nil
  end
  local projection = response.verifier_projection
  local target = projection.hops[#projection.hops]
  local records = {}
  for index, hop in ipairs(projection.hops) do
    records[index] = projection_hop_record(hop)
  end
  local attributes = {
    ['dkim2.projection_schema'] = { string = projection.schema },
    ['dkim2.draft'] = { string = projection.draft },
    ['dkim2.projection_binding_algorithm'] = { string = projection.binding_algorithm },
    ['dkim2.projection_binding'] = { bytes = projection.binding },
    ['dkim2.verification_state'] = { string = response.verification.state },
    ['dkim2.verification_reason'] = { string = response.verification.primary_reason },
    ['dkim2.scope'] = { string = response.verification.scope },
    ['dkim2.historical_content'] = { string = response.verification.historical_content },
    ['dkim2.historical_signatures'] = { string = response.verification.historical_signatures },
    ['dkim2.custody_structure'] = { string = response.verification.custody_structure },
    ['dkim2.target_sequence'] = { integer = tostring(target.sequence) },
    ['dkim2.target_message_instance'] = { integer = tostring(target.message_instance) },
    ['dkim2.claimed_hop_count'] = { integer = tostring(#projection.hops) },
    ['dkim2.authentication_state'] = { string = response.authentication.state },
    ['dkim2.authentication_reason'] = { string = response.authentication.primary_reason },
    ['dkim2.replay_class'] = { string = response.replay.class },
    ['dkim2.local_policy_mode'] = { string = response.policy.mode },
    ['dkim2.local_policy_verdict'] = { string = response.policy.verdict },
    ['dkim2.local_policy_reason'] = { string = response.policy.primary_reason },
    ['dkim2.do_not_modify_state'] = { string = response.policy.do_not_modify },
    ['dkim2.do_not_explode_state'] = { string = response.policy.do_not_explode },
    ['dkim2.dns_testing_effective'] = { boolean = response.policy.dns_testing_effective },
    ['dkim2.disposition'] = { string = response.disposition },
    ['dkim2.chain'] = { records = records },
  }
  if response.delivery_status ~= nil then
    attributes['dkim2.received_dsn_propagation'] =
      { string = response.delivery_status.propagation }
  end
  return attributes
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

-- smtp_message_bytes canonicalizes Rspamd's filter buffer to SMTP CRLF.
local function smtp_message_bytes(value)
  if type(value) == 'userdata' then
    value = tostring(value)
  end
  if type(value) ~= 'string' or #value == 0 or #value > MAX_MESSAGE_BYTES then
    return nil
  end
  local without_crlf = value:gsub('\r\n', '')
  if without_crlf:find('\r', 1, true) then
    return nil
  end
  local normalized = value:gsub('\r\n', '\n'):gsub('\n', '\r\n')
  if #normalized > MAX_MESSAGE_BYTES then
    return nil
  end
  return normalized
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

-- apply_delivery_status publishes the already validated received
-- delivery-status projection as zero-score observations. It changes no
-- disposition, no Authentication-Results value, and no other DKIM2 fact.
local function apply_delivery_status(task, projection)
  if projection == nil then
    return
  end
  for _, member in ipairs(delivery_status_order) do
    insert_symbol(task, symbols['dsn_' .. member .. '_' .. projection[member]])
  end
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
  apply_delivery_status(task, response.delivery_status)
  apply_authentication_results(task, response.actions)
  if response.disposition == 'reject' then
    task:set_pre_result('reject', 'Message rejected by DKIM2 policy', N)
  elseif response.disposition == 'tempfail' then
    task:set_pre_result('soft reject', 'Temporary DKIM2 verification failure', N)
  end
end

-- prepare_request captures the exact bounded message and ordered SMTP envelope.
local function prepare_request(task)
  if not task:has_header('Message-Instance') and not task:has_header('DKIM2-Signature') then
    return { applicable = false }
  end
  local content = smtp_message_bytes(task:get_content())
  local envelope = original_envelope(task)
  if not content or not envelope then
    return nil
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
  if settings.tenant ~= nil then
    request.context = { tenant = settings.tenant }
  end
  local body = ucl.to_format(request, 'json-compact')
  if type(body) == 'userdata' then
    body = tostring(body)
  end
  if type(body) ~= 'string' or #body == 0 then
    return nil
  end
  return { applicable = true, content = content, envelope = envelope, body = body }
end

-- submit_request calls dkim2d and returns only a strictly validated applicable result.
local function submit_request(task, prepared, callback)
  if type(prepared) ~= 'table' or prepared.applicable ~= true or type(callback) ~= 'function' then
    return false
  end
  return rspamd_http.request({
    task = task,
    url = settings.endpoint,
    method = 'POST',
    body = prepared.body,
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
        callback(nil)
        return
      end
      if code == 204 and (response_body == nil or #tostring(response_body) == 0) then
        callback(false)
        return
      end
      if code ~= 200 then
        callback(nil)
        return
      end
      local response = parse_response(response_body)
      if not response then
        callback(nil)
        return
      end
      callback(response, tostring(response_body))
    end,
  })
end

-- process_message preserves the standalone normal-filter behavior without retry caching.
local function process_message(task)
  local prepared = prepare_request(task)
  if not prepared then
    apply_failure(task)
    return
  end
  if not prepared.applicable then
    insert_symbol(task, symbols.check)
    insert_symbol(task, symbols.not_applicable)
    return
  end
  local started = submit_request(task, prepared, function(response)
    if response == false then
      insert_symbol(task, symbols.check)
      insert_symbol(task, symbols.not_applicable)
    elseif response == nil then
      apply_failure(task)
    else
      apply_response(task, response)
    end
  end)
  if not started then
    apply_failure(task)
  end
end

-- M.configure validates verifier transport settings and loads its route capability.
function M.configure(input)
  local configured = validate_settings(input)
  if not configured then
    return false
  end
  local configured_capability = read_capability(configured.capability_file)
  if not configured_capability then
    return false
  end
  settings = configured
  capability = configured_capability
  return true
end

-- M.register installs the normal verifier symbol and its closed virtual results.
function M.register(config, callback)
  local parent = config:register_symbol({
    name = symbols.check,
    type = 'normal',
    callback = callback or process_message,
    score = 0.0,
    group = N,
    flags = 'nostat,ignore_passthrough',
    augmentations = { string.format('timeout=%f', settings.timeout) },
  })
  for key, symbol in pairs(symbols) do
    if key ~= 'check' then
      config:register_symbol({
        name = symbol, type = 'virtual', parent = parent,
        score = 0.0, group = N,
      })
    end
  end
  return parent
end

M.process_message = process_message
M.prepare_request = prepare_request
M.submit_request = submit_request
M.parse_response = parse_response
M.apply_response = apply_response
M.apply_failure = apply_failure
M.original_envelope = original_envelope
M.smtp_message_bytes = smtp_message_bytes
M.policy_attributes = policy_attributes
M.projection_schema = PROJECTION_SCHEMA
M.draft = DRAFT
M.symbols = symbols

return M
