-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}
local OPERATIONS = {'ack','claim','dead','enqueue','initialize','retry','sweep'}
local OUTCOMES = {'ACKED','ALLOCATION_MISMATCH','CONFLICT','CORRUPT','DEAD','DUPLICATE','EMPTY',
  'ENQUEUED','EXPIRED','FULL','INVALID','LEASED','MISSING','READY','RETRY','STALE','SWEPT','UNAVAILABLE'}
local MAXIMUM_COUNT = 1000000000

-- M.new allocates only the fixed operation/outcome vocabulary, never event-derived labels.
function M.new(sink)
  if type(sink) ~= 'function' then
    return nil
  end
  local counts = {}
  for _, operation in ipairs(OPERATIONS) do
    counts[operation] = {}
    for _, outcome in ipairs(OUTCOMES) do
      counts[operation][outcome] = 0
    end
  end
  return setmetatable({counts=counts,sink=sink},{__index=M})
end

-- M.observe counts one completed operation without retaining any request or Redis material.
function M:observe(operation, outcome)
  local counters = self.counts[operation]
  if counters and counters[outcome] then
    counters[outcome] = math.min(MAXIMUM_COUNT, counters[outcome] + 1)
  end
end

-- M.flush emits bounded process-local counter deltas; sink failure never changes delivery authority.
function M:flush()
  for _, operation in ipairs(OPERATIONS) do
    for _, outcome in ipairs(OUTCOMES) do
      local count = self.counts[operation][outcome]
      if count > 0 then
        self.counts[operation][outcome] = 0
        pcall(self.sink, operation, outcome, count)
      end
    end
  end
end

return M
