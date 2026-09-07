dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "geoip-outage", applicable = true})
assert_replycode(actions, "451 4.7.1")
quit()
