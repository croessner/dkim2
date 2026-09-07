-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local events = require 'dkim2.observation_event'
local M = {}

-- M.new requires either a task-bound acknowledged transport or the dedicated durable outbox.
function M.new(options)
  if type(options) ~= 'table' or type(options.producer) ~= 'table' or
      type(options.producer.capture) ~= 'function' then
    return nil
  end
  if options.mode == 'synchronous' then
    if type(options.transport) ~= 'table' or type(options.transport.send) ~= 'function' or options.outbox then
      return nil
    end
  elseif options.mode == 'asynchronous' then
    if type(options.outbox) ~= 'table' or type(options.outbox.enqueue) ~= 'function' or options.transport then
      return nil
    end
  else
    return nil
  end
  for key in pairs(options) do
    if not ({mode=true,producer=true,transport=true,outbox=true})[key] then
      return nil
    end
  end
  return setmetatable({mode=options.mode, producer=options.producer,
    transport=options.transport, outbox=options.outbox}, {__index=M})
end

-- M.capture freezes the independent scan while the current Policy call has not started.
function M:capture(task)
  return self.producer:capture(task)
end

-- M.deliver completes only on acknowledged learning or durable persistence of the original sealed event.
function M:deliver(task, event, callback)
  if type(callback) ~= 'function' then
    return false
  end
  if not events.is_sealed(event) then
    callback('UNAVAILABLE')
    return false
  end
  local completed = false
  -- finish prevents a scheduling failure from reporting a second completion after an inline callback.
  local function finish(status)
    if not completed then
      completed = true
      callback(status)
    end
  end
  local started
  if self.mode == 'asynchronous' then
    started = self.outbox:enqueue(task, event, function(status)
      finish((status == 'ENQUEUED' or status == 'DUPLICATE') and 'PERSISTED' or 'UNAVAILABLE')
    end)
  else
    started = self.transport:send(task, event:body(), event:request_id(), function(result)
      finish(result and result.effect == 'permit' and result.status.code == 'permit' and
        'ACKNOWLEDGED' or 'UNAVAILABLE')
    end)
  end
  if not started then
    finish('UNAVAILABLE')
  end
  return started
end

return M
