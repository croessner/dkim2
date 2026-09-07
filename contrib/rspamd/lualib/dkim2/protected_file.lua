-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}

-- M.read bounds binary reads from explicit absolute paths without rendering secret bytes or I/O errors.
function M.read(path, minimum, maximum)
  if type(path) ~= 'string' or #path > 4096 or path:sub(1, 1) ~= '/' or path:find('\0', 1, true) or
      type(minimum) ~= 'number' or type(maximum) ~= 'number' or minimum < 1 or maximum < minimum or
      maximum > 4096 or minimum % 1 ~= 0 or maximum % 1 ~= 0 then
    return nil
  end
  local handle = io.open(path, 'rb')
  if not handle then
    return nil
  end
  local value = handle:read(maximum + 1)
  handle:close()
  if type(value) ~= 'string' or #value < minimum or #value > maximum then
    return nil
  end
  return value
end

-- M.reference admits only the typed protected-file form instead of inline key material.
function M.reference(reference, minimum, maximum)
  if type(reference) ~= 'table' then
    return nil
  end
  for name in pairs(reference) do
    if name ~= 'file' then
      return nil
    end
  end
  return M.read(reference.file, minimum, maximum)
end

return M
