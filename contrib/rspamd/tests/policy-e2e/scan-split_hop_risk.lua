dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "split_hop_risk"})
assert_replycode(actions, "451 4.7.1")
quit()
