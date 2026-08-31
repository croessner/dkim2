-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
local MAX_DEPTH = 32

-- skip_space advances over RFC 8259 whitespace only.
local function skip_space(input, position)
  while true do
    local byte = input:byte(position)
    if byte ~= 0x20 and byte ~= 0x09 and byte ~= 0x0a and byte ~= 0x0d then
      return position
    end
    position = position + 1
  end
end

-- parse_string validates one JSON string and returns a duplicate-key token.
local function parse_string(input, position, object_key)
  if input:byte(position) ~= 0x22 then
    return nil
  end
  position = position + 1
  local token = {}
  while position <= #input do
    local byte = input:byte(position)
    if byte == 0x22 then
      return position + 1, table.concat(token)
    end
    if byte < 0x20 then
      return nil
    end
    if byte == 0x5c then
      local escaped = input:sub(position + 1, position + 1)
      if escaped == 'u' then
        if object_key or not input:sub(position + 2, position + 5):match('^[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]$') then
          return nil
        end
        position = position + 6
      elseif escaped:match('^["\\/bfnrt]$') then
        token[#token + 1] = '\\' .. escaped
        position = position + 2
      else
        return nil
      end
    else
      token[#token + 1] = string.char(byte)
      position = position + 1
    end
  end
  return nil
end

local parse_value

-- parse_array validates one bounded-depth JSON array.
local function parse_array(input, position, depth)
  position = skip_space(input, position + 1)
  if input:byte(position) == 0x5d then
    return position + 1
  end
  while true do
    position = parse_value(input, position, depth + 1)
    if not position then
      return nil
    end
    position = skip_space(input, position)
    local byte = input:byte(position)
    if byte == 0x5d then
      return position + 1
    end
    if byte ~= 0x2c then
      return nil
    end
    position = skip_space(input, position + 1)
  end
end

-- parse_object validates one JSON object and rejects duplicate literal keys.
local function parse_object(input, position, depth)
  local keys = {}
  position = skip_space(input, position + 1)
  if input:byte(position) == 0x7d then
    return position + 1
  end
  while true do
    local next_position, key = parse_string(input, position, true)
    if not next_position or keys[key] then
      return nil
    end
    keys[key] = true
    position = skip_space(input, next_position)
    if input:byte(position) ~= 0x3a then
      return nil
    end
    position = parse_value(input, skip_space(input, position + 1), depth + 1)
    if not position then
      return nil
    end
    position = skip_space(input, position)
    local byte = input:byte(position)
    if byte == 0x7d then
      return position + 1
    end
    if byte ~= 0x2c then
      return nil
    end
    position = skip_space(input, position + 1)
  end
end

-- parse_number validates the RFC 8259 number grammar.
local function parse_number(input, position)
  if input:byte(position) == 0x2d then
    position = position + 1
  end
  local first = input:byte(position)
  if first == 0x30 then
    position = position + 1
    if (input:byte(position) or 0) >= 0x30 and (input:byte(position) or 0) <= 0x39 then
      return nil
    end
  elseif first and first >= 0x31 and first <= 0x39 then
    repeat
      position = position + 1
      first = input:byte(position)
    until not first or first < 0x30 or first > 0x39
  else
    return nil
  end
  if input:byte(position) == 0x2e then
    position = position + 1
    first = input:byte(position)
    if not first or first < 0x30 or first > 0x39 then
      return nil
    end
    repeat
      position = position + 1
      first = input:byte(position)
    until not first or first < 0x30 or first > 0x39
  end
  first = input:byte(position)
  if first == 0x65 or first == 0x45 then
    position = position + 1
    first = input:byte(position)
    if first == 0x2b or first == 0x2d then
      position = position + 1
      first = input:byte(position)
    end
    if not first or first < 0x30 or first > 0x39 then
      return nil
    end
    repeat
      position = position + 1
      first = input:byte(position)
    until not first or first < 0x30 or first > 0x39
  end
  return position
end

-- parse_value dispatches one bounded JSON value.
parse_value = function(input, position, depth)
  if depth > MAX_DEPTH then
    return nil
  end
  local byte = input:byte(position)
  if byte == 0x7b then
    return parse_object(input, position, depth)
  end
  if byte == 0x5b then
    return parse_array(input, position, depth)
  end
  if byte == 0x22 then
    return parse_string(input, position, false)
  end
  for _, literal in ipairs({ 'true', 'false', 'null' }) do
    if input:sub(position, position + #literal - 1) == literal then
      return position + #literal
    end
  end
  return parse_number(input, position)
end

-- M.valid accepts exactly one complete RFC 8259 JSON value.
function M.valid(input)
  if type(input) ~= 'string' or #input == 0 then
    return false
  end
  local position = parse_value(input, skip_space(input, 1), 0)
  return position ~= nil and skip_space(input, position) == #input + 1
end

return M
