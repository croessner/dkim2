# DKIM2 Exim Adapter Operations

The Exim adapter has three separately configured operations: the Linux-only
inbound `local_scan` service, one-shot originator signing, and one-shot
ordinary-transit revision. Use the examples under
`cmd/dkim2-exim/examples/` as reviewed starting points, not as credentials.

## Installation and ownership

Build the Go executable for Linux amd64 or arm64. Inbound support additionally
requires rebuilding the exact authenticated Exim source-package revision with
the source-matched C module and generated build ID. A C object from another
Exim revision is unsupported.

Run the service and both one-shot filters as the exact Exim/MTA UID. Debian and
Ubuntu packages use the `Debian-exim` unit drop-in; a source installation uses
the `exim` drop-in. Set `DKIM2_EXIM_UID` in `/etc/default/dkim2-exim` to that
account's numeric UID. Startup rejects any `peer_uid` different from the
service effective UID because a mode-0600 socket could never admit it.
The transport `user` and `group` must name that same MTA identity. Verify that
the account can read every Exim lookup or database used during transport
expansion; release qualification records that proof in the live
distro/source-package matrix.

Use the existing MTA service user and group; do not create a second adapter
identity. The socket directory,
evidence root, and readiness directory must be distinct, owned by the service
UID, and mode `0700`. Protected configuration and capability/key parents are
mode `0500`; files are regular, single-link, service-owned, and mode `0400` or
`0600`. Never place two protected authorities in the same final directory.

The service unit creates `/run/dkim2-exim`; the administrator creates the
distinct persistent evidence and protected-secret directories. The inbound
socket is always mode `0600` and admits only the configured Exim UID.

## Activation

1. Verify the signed Exim source metadata and recorded SHA-256 values.
2. Build the source-matched Exim package and the Go executable.
3. Install operation-specific capabilities and the evidence key without
   displaying their contents.
4. Install strict YAML snapshots for inbound, sign, and revise.
5. Set `spool_wireformat=false` and `dkim2_spool_format=unix_lf`.
6. Configure `max_rcpt=1`, negative `size_addition`, no transport
   `return_path` assignment, separately quoted
   `$dkim2_transport_filter_return_path` and `$pipe_addresses`, an
   absolute filter command, and no post-filter header or byte mutation.
7. Start the service, then run `make test-exim-packaging` and
   `cmd/dkim2-exim/packaging/validate-deployment.sh`.
8. Confirm readiness is `1` only after the socket, telemetry, and accept loop
   are live.

Filter commands are silent: failure returns exit status 75 with no diagnostic
on stdout or stderr. A fail-open inbound policy additionally requires
Authentication-Results ownership and a durable mandatory warning; warning
failure keeps the message closed.

## Envelope representation and revision continuity

Exim exposes `sender_address` and each `recipients_list[index].address` to the
C `local_scan` hook as bare addresses. Its `transport_filter` arguments may be
bare or already RFC 5321 bracketed paths. The adapter converts both hook inputs
through one shared boundary: a bare address becomes `<address>`, an existing
unambiguous path is preserved, and an empty reverse path becomes `<>`. Empty
forward paths, partial or nested angle-bracket framing, NUL, CR, and LF fail
closed. The conversion preserves permitted SMTPUTF8/EAI bytes; it does not
silently downgrade them.

The durable incoming evidence and every daemon SMTP DTO therefore contain the
same RFC 5321 path spelling. This is required for revision custody: an inbound
message signed at a later transport boundary must compare the stored
receive-time envelope to the current message without a representation-only
mismatch. Do not add receive-time headers, including local
`Authentication-Results`, to a message selected for a hash-unchanged revision
proof. The qualification path uses an explicitly authentication-results-disabled
inbound configuration for that case; normal receive-time reporting and forged
header rejection remain independently tested.

Exim generates the leading `Received` field before `local_scan()` and updates
its timestamp after the hook returns. The adapter sends the exact
pre-acceptance Exim observation to the daemon. Qualification requires a
leading `Received` field at both phases and compares all subsequent header and
body bytes exactly; it does not hide later trace fields or other mutations.

## Upgrade and rollback

Stop Exim before changing the C module, source-matched package, build-ID
allowlist, socket ownership, or representation settings. Back up configuration
and immutable evidence without copying capability/key contents into reports.
Apply the checked transport-filter return-path patch to the authenticated Exim
source tree before rebuilding it. The patch enables only the exact
`$dkim2_transport_filter_return_path` direct argument for SMTP
`transport_filter`; it is not a general taint exception. Upgrade the rebuilt
Exim package and Go executable together, validate, then
restart the DKIM2 service before Exim.

Rollback stops Exim and the DKIM2 service, restores the prior signed Exim
package, executable, configuration, and matching build-ID allowlist, validates
the prior transport representation, and restarts in dependency order. Do not
delete evidence during rollback. A stale socket is removed only after verifying
that no prior service process owns it.

The current capability is `unqualified_draft05`. The pinned upstream, Debian,
and Ubuntu source-package matrix qualifies a release only when all five rows
are freshly executed and imported against the exact unchanged Draft-05
candidate snapshot. The historical Draft-04 matrix must not be relabeled or
reused. The repository does not claim a published image, package, tag, or
stable release until the separate release workflow creates it.
