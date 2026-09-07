-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local protected_file = require 'dkim2.protected_file'
local events = require 'dkim2.observation_event'
local M = {}
local owners = setmetatable({}, {__mode = 'k'})
local DOMAIN = 'dkim2.observation.outbox.v1/'

-- hexadecimal checks exact lowercase envelope identifiers before any cryptographic operation.
local function hexadecimal(value, length)
  return type(value) == 'string' and #value == length and not value:find('[^0-9a-f]')
end

-- hex_encode renders the fixed-size native nonce without locale or external codecs.
local function hex_encode(value)
  return (value:gsub('.', function(byte) return string.format('%02x', byte:byte()) end))
end

-- hex_decode decodes an already validated fixed-size nonce.
local function hex_decode(value)
  return (value:gsub('..', function(pair) return string.char(tonumber(pair, 16)) end))
end

-- digest separates every identity and subkey purpose using keyed SHA-256.
local function digest(hash, key, purpose, value, binary)
  local result = hash.create_specific_keyed(key, 'sha256', DOMAIN .. purpose .. '\0' .. (value or ''))
  return binary and result:bin() or result:hex()
end

-- encryption_key derives a secretbox subkey and material-bound public key identifier.
local function encryption_key(options, material)
  local id = digest(options.hash, material, 'encryption-key-id')
  local key = digest(options.hash, material, 'secretbox-key', '', true)
  return id, options.secretbox.create(key)
end

-- valid_options closes the configuration and enforces deterministic power-of-two allocation.
local function valid_options(options)
  if type(options) ~= 'table' or type(options.source) ~= 'string' or #options.source > 32 or
      not options.source:match('^[A-Za-z][A-Za-z0-9_.-]*$') or type(options.decode) ~= 'function' or
      type(options.hash) ~= 'table' or type(options.secretbox) ~= 'table' or type(options.util) ~= 'table' then
    return false
  end
  local shards = options.shard_count
  if type(shards) ~= 'number' or shards < 1 or shards > 64 or shards % 1 ~= 0 then
    return false
  end
  while shards > 1 do
    if shards % 2 ~= 0 then
      return false
    end
    shards = shards / 2
  end
  local allowed = {allocation_key=true, active_key=true, previous_key=true, source=true,
    shard_count=true, hash=true, secretbox=true, util=true, decode=true, authority_files=true}
  for name in pairs(options) do
    if not allowed[name] then
      return false
    end
  end
  return true
end

-- separate_authorities compares bounded material without exposing it or accepting sparse references.
local function separate_authorities(references, allocation, active, previous)
  if references == nil then
    return true
  end
  if type(references) ~= 'table' or #references > 8 then
    return false
  end
  local count = 0
  for index in pairs(references) do
    if type(index) ~= 'number' or index % 1 ~= 0 or index < 1 or index > #references then
      return false
    end
    count = count + 1
  end
  if count ~= #references then
    return false
  end
  for _, reference in ipairs(references) do
    local material = protected_file.reference(reference, 1, 1024)
    if not material or material == allocation or material == active or material == previous then
      return false
    end
  end
  return true
end

-- M.new retains independent allocation and encryption authorities in private owner state.
function M.new(options)
  if not valid_options(options) then
    return nil
  end
  local allocation, active = protected_file.reference(options.allocation_key, 32, 64), protected_file.reference(options.active_key, 32, 64)
  local previous = options.previous_key and protected_file.reference(options.previous_key, 32, 64)
  if not allocation or not active or (options.previous_key and not previous) or
      allocation == active or allocation == previous or (previous and active == previous) or
      not separate_authorities(options.authority_files, allocation, active, previous) then
    return nil
  end
  local id, box = encryption_key(options, active)
  local boxes = {[id] = box}
  if previous then
    local old_id, old_box = encryption_key(options, previous)
    boxes[old_id] = old_box
  end
  local owner = setmetatable({}, {__index = M, __metatable = false})
  owners[owner] = {allocation=allocation, id=digest(options.hash, allocation, 'allocation-key-id'),
    active=id, boxes=boxes, hash=options.hash, util=options.util, decode=options.decode,
    source=options.source, shards=options.shard_count}
  return owner
end

-- M.allocation_id exposes only a domain-separated material identity for startup drift fencing.
function M:allocation_id()
  return owners[self].id
end

-- identity binds a source event and its immutable complete request under the stable allocation key.
local function identity(state, event_id, body)
  return digest(state.hash, state.allocation, 'allocation-tag', event_id),
    digest(state.hash, state.allocation, 'payload-fingerprint', body)
end

-- frame authenticates envelope metadata inside secretbox because its API has no associated-data argument.
local function frame(record, body)
  return '1\n' .. record.key_id .. '\n' .. record.allocation_tag .. '\n' ..
    record.payload_fingerprint .. '\n' .. body
end

-- M.seal encrypts only an issued canonical event, preserving allocation across encryption-key rotation.
function M:seal(event)
  local state = owners[self]
  if not events.is_sealed(event) then
    return nil
  end
  local body = event:body()
  local event_id, _, source = events.inspect(body, state.decode)
  if not event_id or source ~= state.source then
    return nil
  end
  local tag, fingerprint = identity(state, event_id, body)
  local record = {allocation_tag=tag, payload_fingerprint=fingerprint, key_id=state.active}
  local ciphertext, nonce = state.boxes[state.active]:encrypt(frame(record, body))
  ciphertext, nonce = tostring(ciphertext), tostring(nonce)
  if #nonce ~= 24 then
    return nil
  end
  record.nonce = hex_encode(nonce)
  record.ciphertext = tostring(state.util.encode_base64(ciphertext, 0))
  if #record.ciphertext > 65536 then
    return nil
  end
  return record, tonumber(tag:sub(1, 8), 16) % state.shards
end

-- envelope rejects malformed encodings and unknown key versions before native decryption.
local function envelope(state, record)
  if type(record) ~= 'table' or not hexadecimal(record.key_id, 64) or not state.boxes[record.key_id] or
      not hexadecimal(record.allocation_tag, 64) or not hexadecimal(record.payload_fingerprint, 64) or
      not hexadecimal(record.nonce, 48) or type(record.ciphertext) ~= 'string' or
      #record.ciphertext < 24 or #record.ciphertext > 65536 or #record.ciphertext % 4 ~= 0 or
      record.ciphertext:find('[^A-Za-z0-9+/=]') then
    return nil
  end
  local binary = tostring(state.util.decode_base64(record.ciphertext))
  if tostring(state.util.encode_base64(binary, 0)) ~= record.ciphertext then
    return nil
  end
  return binary
end

-- M.open authenticates metadata and canonical source identity before releasing bytes to the HTTP owner.
function M:open(record)
  local state = owners[self]
  local binary = envelope(state, record)
  if not binary then
    return nil
  end
  local ok, plaintext = state.boxes[record.key_id]:decrypt(binary, hex_decode(record.nonce))
  if not ok then
    return nil
  end
  plaintext = tostring(plaintext)
  local prefix = frame(record, '')
  if plaintext:sub(1, #prefix) ~= prefix then
    return nil
  end
  local body = plaintext:sub(#prefix + 1)
  local event_id, request_id, source = events.inspect(body, state.decode)
  if not event_id or source ~= state.source then
    return nil
  end
  local tag, fingerprint = identity(state, event_id, body)
  if tag ~= record.allocation_tag or fingerprint ~= record.payload_fingerprint then
    return nil
  end
  return body, request_id
end

return M
