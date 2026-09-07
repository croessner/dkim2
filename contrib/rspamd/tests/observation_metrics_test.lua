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
local snapshots = {}
local detailed = assert(module.new(function() end, function(shard, snapshot)
  snapshots[#snapshots+1]={shard,snapshot}
end, 2))
local snapshot = {observed_at=1000,live_records=1,live_bytes=128,due_records=1,tombstones=0,
  expired=0,missing=0,reclaimed=0,tombstone_expired=0,tombstone_evicted=0}
detailed:observe('enqueue','ENQUEUED',0,snapshot)
snapshot.live_records=999
-- Only the immutable bounded snapshot may survive the callback.
detailed:flush()
assert(#snapshots==1 and snapshots[1][1]==0 and snapshots[1][2].live_records==1)
snapshot.secret='raw-subject'
detailed:observe('sweep','SWEPT',0,snapshot)
detailed:observe('sweep','SWEPT','allocation-tag',snapshot)
detailed:flush()
assert(#snapshots==1,'unknown fields and invalid shards must not enter telemetry')
print('bounded closed outbox counter deltas and observer isolation: PASS')
