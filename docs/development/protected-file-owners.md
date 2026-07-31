# Protected File Owner Isolation

The Exim and Milter commands are intentionally standalone Go modules. Neither
command may import the other command's `internal` packages, and moving the
owner into `lib/` would put OS ACL and command-runtime policy into the
standalone DKIM2 protocol library. The protected-file implementations therefore
remain adapter-local isolation copies.

`scripts/check-securefile-parity.sh` is the required drift gate. It verifies
the shared no-follow traversal, exact-parent, link-count, root-owner, race-event
and platform-access policies remain present in both owners, while requiring
adapter-specific fingerprint domains. Both packages retain the same security
vector families and platform compilation checks. A policy change must update
both owners or document why one adapter cannot support it.

Trusted ancestry accepts exact-UID or root-owned non-writable directories. A
root-owned sticky directory such as `/tmp` is accepted only as an intermediate
ancestor; the retained final protected directory still requires the exact
service UID, exact configured mode, local-filesystem allowlist, and stable
ACL/xattr fingerprint.
