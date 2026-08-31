dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "two-hop-historical-deny"})
assert_replycode(actions, "554 5.7.1")
quit()
