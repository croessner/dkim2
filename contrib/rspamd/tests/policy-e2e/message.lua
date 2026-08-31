-- Build one deterministic Milter message while keeping scenario scripts small.
function policy_e2e_message(options)
  options = options or {}
  local peer_ip = options.peer_ip or "203.0.113.25"
  local identity = options.identity or "policy-retry-proof"
  local sender = options.sender or "sender@example.test"
  local recipient = options.recipient or "recipient@example.test"
  local header_recipient = options.header_recipient or recipient

  negotiate(6, 0xffffffff, 0xffffffff)
  connect("client.example.test", peer_ip)
  helo("client.example.test")
  mailfrom("<" .. sender .. ">")
  rcptto("<" .. recipient .. ">")
  data()
  header("From", sender)
  header("To", header_recipient)
  header("Subject", identity)
  header("Message-ID", "<" .. identity .. "@example.test>")
  if options.applicable ~= false then
    header("Message-Instance", "1")
  end
  if options.action then
    header("X-Policy-E2E-Action", options.action)
  end
  eoh()
  body("deterministic body for " .. identity .. "\r\n")
  return eom()
end
