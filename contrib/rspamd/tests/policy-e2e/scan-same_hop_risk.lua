dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "same_hop_risk"})
assert_replycode(actions, "554 5.7.1")
quit()
