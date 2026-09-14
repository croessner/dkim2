# Public API and deployed mail-flow review, 2026-09-14

The [release remediation](companion-release-remediation-2026-09-14.md) records
the subsequent fixes to release checks and Rspamd compatibility. Findings and
test failures below describe the initial audit, before those fixes.

## Result and scope

The public API reference is reconciled with current committed library source.
The production mail host was inspected read-only through the documented
management hop. No mail was sent, queued content read, service restarted,
configuration deployed, or release published.

## Public API reference

The old metadata mixed three different snapshots:

- Documented revision `f30fecbd35ae3afd1b590ddfe55ee45f0cf6555a`:
  645 declarations, hash
  `2d755de5b0941bc8a1b12270fd43e86a4ace9a8b432d94a77b260d9f5901988f`.
- Recorded revision `74b18fd2a685a9e0a7e53bd015dd2a8fdadec393`:
  679 declarations, hash
  `fc7d28bcc073d310815df57b7b2bc4eac2d1ff4fad8701f6ffc496f2bbfad96a`.
- Stored 691-declaration hash
  `ddf0ef36cdc47bac57495a5d14fd5c56243d1bc9b82f68c80e14a48c95c45748`:
  reproduced exactly at Draft-05 commit
  `f21d279b6d2b078dd5434269c7f4a0f11292ff7b`. That commit updated the hash
  without updating the recorded revision.

Each historical manifest was reconstructed from Git using the current
deterministic generator. Against the actual 691-declaration Draft-05 manifest,
existing function signatures and type declarations remain after removing
comments; existing grouped constant entries remain unchanged. Additions include
chain projections, authentication/replay coordination and received-DSN
evaluation/propagation. The draft identifier changes from Draft-05 to Draft-06,
and the Go language requirement changes from 1.26 to 1.27. Unchanged function
signatures do not promise unchanged protocol behavior; Draft-06 migration
documentation remains authoritative.

For users updating from the older 679-declaration snapshot, commit
`245ba7cfdb9dda22bb054916e31404b5897779b0` already changed
`NewDSNSigningEvidenceRequest`: callers must remove `originalReversePath` and
`originalForwardPaths`, retaining the outer message, outer SMTP envelope and
`DSNIdentity`. Original-message evidence is verified from the DSN through the
documented trusted Postfix-origin path; callers must not fabricate it.
This constructor change predates the actual stored Draft-05 hash.

The new reference pins `f7099dbd47ff3bd79e30f7801814c87eb0914b4c`,
883 declarations, hash
`5958926bb0b972d164d6d6dee00c372cc8966b30f1b0906c2c494262577fd2b2`.
HEAD and working-tree manifests are identical. No function implementation or
compatibility check was relaxed. The root-only scanner does not qualify public
subpackages or the effective methods of internally aliased types.

## Production observations

Live `postconf`, `postconf -P`, the SMTP header map and `timedatectl` establish:

| Check | Observation | Meaning |
| --- | --- | --- |
| Normal originated mail | Egress chain: OpenDKIM RSA, OpenDKIM Ed25519, Doppelgaenger, DKIM2 | Both generations configured; per-domain keys and recipient-side verification not tested |
| Clock | `NTPSynchronized=yes` | Host reports synchronized time |
| Prepared forwarding | `srsmail-prepared` uses `cleanup-prepared` and `forwarding-smtp`; header/body checks, generic maps and MIME conversion disabled | Route explicitly preserves prepared signed content |
| Normal SMTP egress | SMTP transports run `smtp_header_checks.pcre` after signing | Last-Milter placement alone does not prove final-byte signing |
| Locally generated DSNs | `dsn_smtpd_milters` contains only DKIM2 | Not every outgoing message is configured for dual signing |

Most outbound removals affect DKIM2-excluded fields (`X-*`,
`Authentication-Results`, `Received`). These do not themselves prove DKIM2
breakage. The initial audit incorrectly inferred that a MIME-Version rule in
`smtp_header_checks` was active for MIME fields. Its local canonicalizer probe
only established that changing `1.0 (client)` to `1.0` would change signed bytes;
it did not establish that Postfix applied the rule.

The subsequent mailstack-owner review disproved the active-failure claim:
live MX, egress and relay have empty `smtp_mime_header_checks` and
`smtp_nested_header_checks`, including service overrides. A real Postfix 3.11.6
test preserves the original MIME value with the old rule. An explicitly enabled
SMTP MIME mutation serves only as a negative control. The owner removes the
three inert outbound rules, preserves existing pre-signing egress cleanup and
introduces no new normalization. See the mailstack report
`docs/migration-reports/20260914-postfix-mime-preservation.md` for all twelve
SMTP/Milter cases and live observations. No production signature-corruption
incident was demonstrated by this audit.

## Removed-content handling

The current batch revision service calls `SignExisting` with `RecipeCopyOnly`
and `RejectUnavailableBody`. It cannot silently embed removed content as
recipe literals; an unrepresentable change is rejected. The native SRS client
admits only a complete successful batch and checks binding and output set.
These are source findings, not a production DLP/AV deletion test or proof of
deployed-image/source equivalence. No general automatic sanitizer policy has
been demonstrated here.

## Validation and remaining limits

All Go checks use exact Go 1.27.0 and `GOEXPERIMENT=runtimesecret`.

- Toolchain contract and operator-document checks passed.
- Root API check passed after reconciliation.
- Focused deterministic API-manifest tests passed; `git diff --check` passed.
- Local canonicalization probe passed: the deployed MIME replacement changes
  signed bytes for the example above. The probe uses a temporary Go overlay;
  it does not modify production code or existing tests.
- The complete reference-package suite failed at
  `TestCheckReleasePlanAcceptsRepositoryPlan` with `release_stable_workflow`.
  This is a separate release-plan check, not an API comparison failure.
- The earlier full implementation guardrails remain recorded in the companion
  report; this follow-up changes only reference metadata and documentation.

The private-workspace archive/checksum issue also remains open. An API-reference
refresh does not qualify either release check. DNSSEC, actual dual-signature
verification at a destination, all forwarding producers and sanitizer
integration remain outside the completed evidence.
