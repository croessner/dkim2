dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "policy-retry-proof"})
assert_replycode(actions, "554 5.7.1")
quit()
