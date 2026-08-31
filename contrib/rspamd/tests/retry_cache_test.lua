-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local module_path = assert(arg[1], 'retry cache module path is required')
local registered_script
local calls = {}

local redis = {
  add_redis_script = function(script)
    registered_script = script
    return 7
  end,
  exec_redis_script = function(id, params, callback, keys, args)
    calls[#calls + 1] = { id = id, params = params, keys = keys, args = args }
    callback(nil, { args[1] == 'claim' and 'MISS' or args[1] == 'store' and 'STORED' or 'ARMED' })
    return true
  end,
}

local hash_input
local hash = {
  create_specific_keyed = function(secret, algorithm, input)
    assert(secret == string.rep('s', 32))
    assert(algorithm == 'sha256')
    hash_input = input
    local checksum = 0
    for index = 1, #input do
      checksum = (checksum + input:byte(index) * index) % 4294967296
    end
    local encoded = string.format('%08x', checksum)
    return { hex = function() return encoded:rep(8) end }
  end,
}

local cache_module = assert(loadfile(module_path))()
for _, action in ipairs({ 'reject', 'discard', 'quarantine', 'greylist', 'soft reject' }) do
  assert(cache_module.preserves_non_delivery(action), action .. ' must survive technical failure')
end
for _, action in ipairs({ 'accept', 'no action', 'add header', 'rewrite subject' }) do
  assert(not cache_module.preserves_non_delivery(action), action .. ' must not widen technical failure')
end
assert(cache_module.is_retryable_action('soft reject'))
assert(cache_module.is_retryable_action('greylist'))
assert(not cache_module.is_retryable_action('reject'))
local cache = assert(cache_module.new({
  redis = redis, redis_params = {}, hash = hash, secret = string.rep('s', 32),
  authority_generation = 'verifier-policy-replay-2026-08-31',
  ttl_ms = 86400000, lease_ms = 30000,
}))
assert(type(registered_script) == 'string' and registered_script:find("state == 'provisional'", 1, true))

local input = {
  peer_ip = '2001:db8::25',
  content = 'From: sender@example.test\r\n\r\nbody\r\n',
  mail_from = '<sender@example.test>',
  rcpt_to = { '<z@example.test>', '<a@example.test>', '<z@example.test>' },
  draft = 'draft-ietf-dkim-dkim2-spec-06',
  projection_schema = 'dkim2.verifier-projection.v1',
}
local key = assert(cache:identity(input))
assert(key:match('^dkim2:retry:v1:[0-9a-f]+$') and #key == #('dkim2:retry:v1:') + 64)
local first_input = hash_input

input.rcpt_to = { '<a@example.test>', '<z@example.test>', '<z@example.test>' }
assert(cache:identity(input) ~= key)
assert(hash_input ~= first_input, 'recipient ordering must be identity-bearing')

input.rcpt_to = { '<z@example.test>', '<a@example.test>' }
assert(cache:identity(input) ~= key)
assert(hash_input ~= first_input, 'recipient multiplicity must be identity-bearing')

input.rcpt_to = { '<z@example.test>', '<a@example.test>', '<z@example.test>' }
local rotated = assert(cache_module.new({
  redis = redis, redis_params = {}, hash = hash, secret = string.rep('s', 32),
  authority_generation = 'verifier-policy-replay-2026-09-01',
  ttl_ms = 86400000, lease_ms = 30000,
}))
assert(rotated:identity(input) ~= key)
assert(hash_input ~= first_input, 'authority generation must force a cache miss identity')

local status
assert(cache:claim({}, key, '0123456789abcdef', function(value) status = value end))
assert(status == 'MISS')
assert(calls[1].args[1] == 'claim' and calls[1].args[3] == '30000')

assert(cache:store({}, key, '0123456789abcdef', '{"validated":true}', function(value) status = value end))
assert(status == 'STORED')
assert(calls[2].args[1] == 'store' and calls[2].args[5] == '{"validated":true}')

assert(cache:finalize({}, key, '0123456789abcdef', true, function(value) status = value end))
assert(status == 'ARMED' and calls[3].args[1] == 'arm')

assert(cache_module.new({ redis = redis, hash = hash, secret = 'short', ttl_ms = 86400000,
  authority_generation = 'generation-1', lease_ms = 30000 }) == nil)
assert(cache_module.new({ redis = redis, hash = hash, secret = string.rep('s', 32),
  authority_generation = 'invalid generation', ttl_ms = 86400000, lease_ms = 30000 }) == nil)
