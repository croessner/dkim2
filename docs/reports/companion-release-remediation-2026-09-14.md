# Companion release remediation, 2026-09-14

This follow-up addresses the inherited release-check failures and the Rspamd
compatibility gap found during the mailstack review. Sender Policy remains out
of scope. The message protocol stays at Draft-06; DNS identifiers move to the
normatively equivalent WG DNS-00 document.

## Corrections

- The API reference now binds one reviewed revision and its exact exported
  root surface, with the historical discrepancies and migrations documented
  in the API/mail-flow review.
- Release validation reads the actual YAML tag-push workflow. It requires the
  stable-version gate, annotated tag, exact commit match, quality dependency
  and version-bound image tag. GitHub's `--latest` release marker is distinct
  from a forbidden Docker `:latest` tag. Mutation tests reject removal of these
  controls; the old check incorrectly expected a release-event workflow.
- Checked-in candidate archive checksums now match the current library bytes.
  The three new adapter dependencies carry that exact checksum. Go's isolated
  workspace synchronization also removes two unused DSN-propagator x/net sums;
  no required dependency or authentication check is removed.
- Standalone module proof derives the synthetic local library's go.mod h1
  from snapshot-bound source, as Go tidy requires. That single metadata sum
  is explicitly admitted; changed metadata, archive substitutions and other
  module paths are rejected by regression tests. Third-party sums retain their
  committed authentication. The proof inventory now includes the DSN propagator
  and reads sums from every workspace module.
- The canonical Rspamd adapter accepts legacy bare reporting or the exact
  negative diagnostic bound to validated authentication facts. Forged
  authorities, states, reasons, CRLF and appended methods remain rejected.
  The mailstack owner must deploy the corresponding adapter update together
  with the daemon; updating only the daemon is incompatible.
- The new report fuzz target is registered in the closed security inventory.
  Its existing drift test correctly caught the missing registration during
  the full tools run; the inventory now contains all 98 discovered targets.

The old failure descriptions in earlier dated reports are historical evidence,
not the final remediation status. Validation for release comprises
`make guardrails`, `make check-workspace`, `make reference-module-proof`,
`make govulncheck`, the complete reference-package tests and
`contrib/rspamd/tests/run.sh`. Release publication and production acceptance
must additionally be verified against the exact commit, image digests and
mailstack-owned rollout report.

## Mailstack boundary

The initial active post-signing MIME-rewrite claim was incorrect. Live MIME
checks are empty, with no service override, and the real Postfix 3.11.6 control
test shows the old outbound rule was inert. The mailstack owner removes only
three inert rules from MX, egress and relay. Existing pre-signing egress cleanup
and all other content handling remain unchanged; no new normalization is added.
Twelve real SMTP/Milter cases cover ordinary, fallback, prepared and local
injection paths, plus an explicitly enabled mutation as a negative control.
The owner also prepares the Rspamd copy update and coordinated rollback.

Missing automatic feedback sending, private alias provisioning and general
DLP/AV classification are documented capabilities outside this release, not
features silently added as part of a patch update.
