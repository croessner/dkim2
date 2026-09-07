-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

package.path = assert(arg[1]) .. '/?.lua;' .. package.path
local transport = require 'dkim2.policy_transport'
local code, failure, classification = 400, nil, nil
local client = assert(transport.new({
  endpoint='https://policy.test/api/v1/policy/decisions', server_name='policy.test',
  username='fixture', password='synthetic', background_config={},
  util={encode_base64=function() return 'synthetic' end},
  ucl={parser=function() error('non-success HTTP bodies must never be interpreted') end},
  json_validator=function() return true end,
  http={request=function(options)
    assert(options.no_ssl_verify == false)
    options.callback(failure, code, 'untrusted error body', {})
    return true
  end},
}))
for _, candidate in ipairs({400,401,403,404,405,409,413,415,422,408,425,429,500,503}) do
  code=candidate
  classification=nil
  assert(client:send_background({}, '{}', string.rep('a',32), function(result, reason)
    assert(result==nil)
    classification=reason
  end))
  local terminal=candidate<500 and candidate~=408 and candidate~=425 and candidate~=429
  assert(classification==(terminal and 'rejected' or 'unavailable'), 'wrong closed HTTP classification: '..candidate)
end
failure='TLS failure'
code=403
client:send_background({}, '{}', string.rep('a',32), function(result, reason)
  assert(result==nil and reason=='unavailable', 'transport errors cannot prove terminal server rejection')
end)
print('verified HTTP terminal rejection and transient retry classification: PASS')
