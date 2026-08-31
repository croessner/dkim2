dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "unrelated-reject", action = "reject"})
assert_replycode(actions, "554 5.7.1")
quit()
