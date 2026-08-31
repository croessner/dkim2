dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "corrupt-cache"})
assert_replycode(actions, "451 4.7.1")
quit()
