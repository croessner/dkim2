# dkim2-milter

`dkim2-milter` is planned as the first SMTP integration adapter.

The Milter should collect SMTP envelope metadata and message content, call the
HTTP/JSON service at EOM time, and apply the returned action plan. It must not
contain protocol logic that belongs in the DKIM2 core.

This command has its own Go module so future Milter-specific dependencies do not
become dependencies of library consumers.

The first implementation should treat Milter fidelity as an explicit runtime
property. It must report whether the message given to the daemon is raw RFC
5322 input or a reconstructed representation from Milter callbacks.
