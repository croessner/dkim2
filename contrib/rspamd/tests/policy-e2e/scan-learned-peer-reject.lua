dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "learned-peer-risk"})
assert_replycode(actions, "554 5.7.1")
quit()
