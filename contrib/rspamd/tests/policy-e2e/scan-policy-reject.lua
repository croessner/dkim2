dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "policy-reject", peer_ip = "198.51.100.25"})
assert_replycode(actions, "554 5.7.1")
quit()
