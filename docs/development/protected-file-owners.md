# Protected File Owner Isolation

The Exim and Milter commands are intentionally standalone Go modules. Neither
command may import the other command's `internal` packages. The protected-file
implementations therefore remain adapter-local isolation copies rather than
moving command-runtime policy into the standalone DKIM2 protocol library.

`scripts/check-securefile-parity.sh` is the required drift gate. It verifies
the shared no-follow traversal, exact-parent, link-count, owner/mode/size, and
race-event policies remain present in both owners. Both packages retain the
same portable security vector families and platform compilation checks. A
policy change must update both owners or document why one adapter cannot
support it.

Directory traversal is descriptor-relative and rejects symlink components. It
does not classify mounts, filesystem types, ACLs, xattrs, or every ancestor's
permissions. Where a direct protected parent is part of the application
contract, that parent still requires the exact service UID and configured mode.
Protected files retain their exact owner, mode, link, regular-file, size, and
same-descriptor read checks. Deployment and container policy own the surrounding
filesystem.
