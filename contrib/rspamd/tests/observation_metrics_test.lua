-- Copyright 2026 Christian Roessner
-- SPDX-License-Identifier: Apache-2.0

package.path = assert(arg[1]) .. '/?.lua;' .. package.path
local module = require 'dkim2.observation_metrics'
local emitted = {}
local metrics = assert(module.new(function(operation, outcome, count)
  emitted[#emitted+1]={operation,outcome,count}
end))
metrics:observe('enqueue','FULL')
metrics:observe('enqueue','FULL')
metrics:observe('claim','UNAVAILABLE')
metrics:observe('smtp-peer-192.0.2.8','FULL')
metrics:observe('enqueue','arbitrary-secret')
metrics:flush()
assert(#emitted==2)
assert(emitted[1][1]=='claim' and emitted[1][2]=='UNAVAILABLE' and emitted[1][3]==1)
assert(emitted[2][1]=='enqueue' and emitted[2][2]=='FULL' and emitted[2][3]==2)
metrics:flush()
assert(#emitted==2,'idle metrics must not emit duplicate increments')
local unavailable=assert(module.new(function() error('synthetic sink failure') end))
unavailable:observe('retry','UNAVAILABLE')
assert(pcall(unavailable.flush,unavailable),'observability failure must not abort delivery')
assert(module.new('invalid')==nil)
print('bounded closed outbox counter deltas and observer isolation: PASS')
