dofile("/fixture/message.lua")
local actions = policy_e2e_message({
  identity = "cache-identity",
  recipient = "alternate-recipient@example.test",
  header_recipient = "recipient@example.test",
})
assert_replycode(actions, "554 5.7.1")
quit()
