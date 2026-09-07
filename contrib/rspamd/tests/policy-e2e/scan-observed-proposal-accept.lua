dofile("/fixture/message.lua")
local actions = policy_e2e_message({identity = "observed-proposal"})
assert_final(actions, "accept")
quit()
