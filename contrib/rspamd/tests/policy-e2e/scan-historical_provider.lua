dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "historical_provider"})
assert_replycode(actions, "554 5.7.1")
quit()
