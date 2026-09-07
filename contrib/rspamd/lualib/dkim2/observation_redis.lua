-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

local M = {}

-- request retains the verified Redis authority for ordinary commands, including script loading.
local function request(raw, config, parameters, context, command, args, callback)
  local completed = false
  -- finish contains duplicate callbacks and scheduling failures within one command.
  local function finish(err, value)
    if completed then
      return
    end
    completed = true
    callback(err, value)
  end
  local ok, started
  if context.task then
    ok, started = pcall(raw.redis_make_request, context.task, parameters, context.key,
      context.is_write, finish, command, args)
  else
    ok, started = pcall(raw.redis_make_request_taskless, context.ev_base, config, parameters,
      context.key, context.is_write, finish, command, args)
  end
  if not ok or not started then
    finish('unavailable')
  end
  return ok and started == true
end

-- execute bounds script recovery to three requests and completes the logical operation once.
local function execute(raw, config, script, context, callback, keys, args)
  local completed, requests, reloaded = false, 0, false
  -- finish exposes only a closed transport failure instead of Redis error details.
  local function finish(err, value)
    if not completed then
      completed = true
      callback(err and 'unavailable' or nil, value)
    end
  end
  -- send shares the request budget across initial loading and cache recovery.
  local function send(command, values, respond)
    if requests >= 3 then
      finish('unavailable')
      return false
    end
    requests = requests + 1
    return request(raw, config, script.parameters, context, command, values, respond)
  end
  local evaluate
  -- load obtains the server digest through the same TLS-aware authenticated request path.
  local function load()
    return send('SCRIPT', {'LOAD', script.body}, function(err, digest)
      if err or type(digest) ~= 'string' or #digest ~= 40 or digest:find('[^0-9a-f]') then
        finish('unavailable')
        return
      end
      script.digest = digest
      evaluate()
    end)
  end
  -- evaluate retries only an explicit missing-script response and never replays arbitrary errors.
  evaluate = function()
    local values = {script.digest, tostring(#keys)}
    for _, key in ipairs(keys) do
      values[#values + 1] = key
    end
    for _, value in ipairs(args) do
      values[#values + 1] = value
    end
    return send('EVALSHA', values, function(err, value)
      if type(err) == 'string' and err:match('^NOSCRIPT%s') and not reloaded then
        reloaded = true
        script.digest = nil
        load()
        return
      end
      finish(err, value)
    end)
  end
  if script.digest then
    return evaluate()
  end
  return load()
end

-- M.new isolates outbox scripts from the upstream loader that omits Redis TLS parameters.
function M.new(raw, config)
  if type(raw) ~= 'table' or type(raw.redis_make_request) ~= 'function' or
      type(raw.redis_make_request_taskless) ~= 'function' or not config then
    return nil
  end
  local scripts, client = {}, {}
  -- add_redis_script registers only the two bounded outbox scripts without network activity.
  function client.add_redis_script(body, parameters)
    if #scripts >= 2 or type(body) ~= 'string' or #body == 0 or #body > 65536 or
        type(parameters) ~= 'table' or parameters.ssl ~= true or parameters.no_ssl_verify ~= false then
      return nil
    end
    scripts[#scripts + 1] = {body=body, parameters=parameters}
    return #scripts
  end
  -- exec_redis_script preserves task or background lifetime and the caller's same-slot routing key.
  function client.exec_redis_script(id, context, callback, keys, args)
    local script = scripts[id]
    if not script or type(context) ~= 'table' or not (context.task or context.ev_base) or
        type(context.key) ~= 'string' or context.is_write ~= true or
        type(keys) ~= 'table' or type(args) ~= 'table' then
      callback('unavailable')
      return false
    end
    return execute(raw, config, script, context, callback, keys, args)
  end
  return client
end

return M
