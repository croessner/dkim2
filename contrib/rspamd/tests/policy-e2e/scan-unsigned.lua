dofile("/fixture/message.lua")
local actions = policy_e2e_message({
  identity = "unsigned",
  applicable = false,
  sender = "unsigned@source.example.test",
  recipient = "unsigned@sink.example.test",
})
assert_replycode(actions, "451 4.7.1")
quit()
