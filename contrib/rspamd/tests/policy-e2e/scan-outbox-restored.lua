dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "outbox-outage", applicable = false})
-- Independent greylisting remains authoritative after durable observation recovers.
assert_replycode(actions, "451 4.7.1")
quit()
