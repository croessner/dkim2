# Draft-08 Migration For Operators

This guide covers the move of every DKIM2 component from
`draft-ietf-dkim-dkim2-spec-07` plus `draft-ietf-dkim-dkim2-dns-01` to
`draft-ietf-dkim-dkim2-spec-08` plus `draft-ietf-dkim-dkim2-dns-02`. The
change-by-change record is
[`docs/specs/draft-08-migration-disposition.md`](../specs/draft-08-migration-disposition.md);
library API changes are listed in
[`docs/reference/compatibility.md`](../reference/compatibility.md).

Draft-08 renames the "Validly Signed DKIM2 Message" of earlier drafts to
"Fully Verified DKIM2 Message". The verification state PASS means Fully
Verified; FAIL means verification completed and concluded that the message is
not Fully Verified.

## Ship Everything Together

The REST draft enum (`DraftVersion`) accepts exactly
`draft-ietf-dkim-dkim2-spec-08`. A client that still sends the Draft-07
identifier receives HTTP 400 `unsupported_draft` before any processing. The
API version (`v1`) and every path stay unchanged.

Upgrade these components in one maintenance window, with inbound mail paused
(MX deferred or Milter tempfail) while the daemons and adapters switch:

- `dkim2d` first, then the adapters that call it
- `dkim2-milter`
- the Exim Go adapter and the Exim `local_scan` module, rebuilt from this
  tree: its build ID changed, and a mismatched pair fails closed as a
  contract failure (`451 4.7.1`)
- `dkim2ctl` and `dkim2-dsn-propagator`
- the Rspamd adapter (`contrib/rspamd`): its `DRAFT` constant, the closed
  reason and state vocabularies, and the verifier projection algorithm list
  move with the daemon; a mismatched pair is contract drift and fails closed

External consumers of the daemon's REST contract move in the same step:

- `dkim2pub` (vendored OpenAPI contract and generated client, draft
  constants, the algorithm list with `mldsa44`, reason and state texts)
- `dkim2-intelligence` (the verifier projection draft identifier, its
  `*.draft08` fixtures, the projection binding golden, and the state and
  reason vocabularies). The verifier projection binding covers the draft
  identifier, so every Draft-07 binding changes value.

A mixed-draft deployment is unsupported and fails closed.

## Configuration Changes

No configuration path is renamed or removed. These paths keep their syntax
and validation but change meaning or acceptance:

- `signing.policy.delivery_status.reporting_domain` is no longer the signing
  identity of every Postfix bounce. Draft-08 Section 16.2 requires the
  notification `d=` to relaxed-match an `rt=` recipient address of the
  reported message's highest DKIM2-Signature. The daemon chooses among the
  local `delivery_status` profile domains that match (RFC 3464-linked
  recipients first, then `reporting_domain` when it is itself a candidate,
  then the most specific domain). A configured domain that does not match is
  never used. Keep the setting only if it is the recipient domain, or a
  parent, of the bounced mail you want signed under it.
- The notification's own From must be Authentic for the chosen `d=`
  (Sections 11 and 12.4). Under Postfix, `MAILER-DAEMON@$myorigin` must lie
  at or below the delivery-status profile domain. Multi-domain hosts get
  signed notifications only for recipient domains under a matching profile.
- RSA signing floor: every RSA signing key must have at least 2048 bits
  (`dkim2.MinSigningRSABits`). A generation, flat-file custody key, or legacy
  import that holds a smaller RSA signing key fails the complete load. Before
  upgrading, list the modulus sizes of every RSA credential in the current
  generation and rotate smaller keys. Verification still accepts RSA keys
  from 1024 to 8192 bits.
- A signing profile holds up to three credentials, one per algorithm, in the
  order `rsa-sha256`, `ed25519-sha256`, `mldsa44`. Every credential owns its
  own key handle, so the datasource handle ceilings are 3072 (default) and
  98304 (production), and the record ceilings 11264 and 294912. The hard
  maxima are 393216 handles and 1179648 records.
- ML-DSA-44 (`mldsa44`) keys: custody keys are the seed-only PKCS#8 form;
  `dkim2d datasource key generate --algorithm mldsa44` creates one together
  with its `v=DKIM1; k=mldsa44; p=<raw 1312-octet key>` DNS record. The
  signer emits classical signatures as one group and ML-DSA-44 as an
  alternative group (`rsa,ed25519 | mldsa44`), so verifiers without ML-DSA
  still pass through the classical group; until the classical group is
  removed, ML-DSA adds no forgery resistance. Selectors must be distinct
  across all credentials of a profile.
- PostgreSQL and MySQL/MariaDB: apply the forward-only migration
  `contrib/schema/{postgresql,mysql}/010_mldsa44_algorithm.sql` with all
  DKIM2 writers stopped, after upgrading `dkim2d` and before any writer
  stores an `mldsa44` row. It only widens the algorithm constraints. LDAP
  needs no schema change. See
  [`datasource-backends.md`](datasource-backends.md).
- FIPS 140-3 Go Cryptographic Module v1.0.0: that module has no ML-DSA.
  A binary built against it (`GOFIPS140=v1.0.0`) refuses to start
  (`dkim2d serve`, `dkim2d validate`) with a fixed diagnostic, rejects
  `mldsa44` in verifier policy, and rejects `mldsa44` credentials.

## REST And Signal Changes

- Verification reasons: `too_many_signatures` is removed (Draft-08 allows
  several signatures per algorithm with distinct selectors; the local bounds
  of 16 signature sets and 16 hash sets stay as `limit_exceeded`). New
  reasons are `custody_mismatch` (Chain of Custody `mf=`/`d=` versus the
  previous `rt=`), `body_history_unavailable` (a null body Recipe in the
  history), and `invalid_recipe` (Recipe schema, step, or application error;
  `invalid_recipe_json` stays for JSON syntax only).
- State remap (Section 14.1): `timestamp_invalid`, `envelope_mismatch`,
  `domain_alignment_mismatch`, `next_domain_mismatch`, `out_of_band_required`,
  and `from_not_authentic` move from PERMERROR to FAIL; the strict policy
  primary reason moves from `protocol_permerror` to `protocol_fail`. Verdicts
  and actions are unchanged for every existing reason. Rspamd reports these
  reasons with `DKIM2_FAIL` instead of `DKIM2_PERMERROR`. Chain of Custody
  adjacency failures move from PERMERROR `malformed_protocol` to FAIL
  `custody_mismatch`.
- Per-set status: `SignatureSetResult.status` no longer has the value
  `ignored`. A set with an unknown algorithm is the Section 14.6 step 4
  PERMERROR intermediate and reports `permerror` with reason
  `unsupported_algorithm` and its selector, like a locally disabled
  algorithm. The combined state and primary reason are unchanged; update
  dashboards or scripts that matched `ignored`.
- Per-set selectors: every non-passing `SignatureSetResult` carries its
  `selector`. The Authentication-Results comment keeps its closed
  `(reason=<code>)` vocabulary and never carries a selector.
- `VerifierHop.signature_algorithms` lists only `rsa-sha256`,
  `ed25519-sha256`, and `mldsa44` (at most three); `SignatureSetResult.algorithm`
  admits `mldsa44`.
- `POST /v1/dsn/sign`: when no local profile matches Section 16.2, or none
  makes the report From Authentic, the daemon answers HTTP 204 with
  `X-DKIM2-Unsigned-Reason: delivery_status_identity_unavailable` or
  `delivery_status_from_not_authentic` (next to the existing
  `unsigned_original`). The Postfix DSN Milter accepts the bounce without
  mutation; Postfix delivers it unsigned. Neither outcome tempfails or
  rejects mail. A sender-side bounce (the highest embedded signature is ours
  and its `rt=` is remote) can never satisfy Section 16.2 and always leaves
  unsigned (`DKIM2-ISSUE-0023`).
- New metric `dkim2d_dsn_unsigned_total{unsigned_reason}` with the three
  closed reasons above, and the log event `dsn.unsigned.completed`. Expect a
  nonzero `delivery_status_identity_unavailable` share on hosts that bounce
  mail for domains without a local delivery-status profile and for every
  sender-side bounce.
- Received notifications: the propagation member gains
  `forbidden_identity_misaligned` (Rspamd symbol
  `DKIM2_DSN_PROPAGATION_FORBIDDEN_IDENTITY_MISALIGNED`); the propagator
  reports `discarded_identity_misaligned`. A notification whose completion
  `d=` does not relaxed-match the previous hop's `rt=` is not propagated.
- Header placement: Message-Instance and DKIM2-Signature are trace fields.
  The Milter inserts this hop's block at the top (`SMFIR_INSHEADER` index 0),
  Exim prepends it, and library complete-message outputs start with it. The
  closed Milter action label for signing mutations changes from `add_header`
  to `insert_header`; update dashboards that select on it. Consumers that
  read these fields by physical position must select by `i=` or `m=`.
- `/v1/revise/batch`: `insertion_offset` is always 0 and
  `header_fields_base64` is in top-down order.

## Mail-Flow Consequences

- Null body Recipe: a history containing `"b":null` is now FAIL
  `body_history_unavailable` instead of PASS with `partial` historical
  content. Strict policy rejects such mail, permissive policy accepts it only
  through its override, testing mode continues. Transit and revision signing
  (`/v1/revise`, `/v1/revise/batch`) refuse such messages because only a
  Fully Verified message may be signed again. There is no acceptance knob.
  Before the upgrade, search the last 14 days of logs for partial content
  history to estimate the affected share.
- Unimplemented algorithms are a PERMERROR intermediate, never a pass; an
  OR group (`|`) still passes when another alternative passes.
- `Auto-Submitted` and `VBR-Info` are now signed header fields.

## Replay Store Transition

The draft identifier is bound into the replay HMAC frame, so Draft-08 keys
never equal Draft-07 keys. Upgrade in place: keep the replay epoch, HMAC
secret, and `replay.valkey.attestation.rotation_state: unchanged`, and restart
every daemon that shares the store on the new release. The replay identity
space restarts: a message first seen under Draft-07 and replayed afterwards
counts as `first_seen` once more, for up to the 14-day retention, and only if
it verifies under Draft-08. A notification propagated before the upgrade may
be propagated once more within the at-least-once contract. The Valkey key
grammar, namespace, ACL, and commands do not change.

## Rollback

- Roll back with the previous image digests of every component and the
  previous Rspamd configuration set, in the same maintenance step; a
  Draft-07 adapter against a Draft-08 daemon fails closed.
- Replay state is not backward compatible: records written under Draft-08 are
  not found by a Draft-07 daemon and expire by their own TTL; the restart
  exposure above repeats in the other direction.
- Datasource: a Draft-07 `dkim2d` rejects `mldsa44` credentials and profiles
  with three credentials. Before rolling back, activate a generation without
  `mldsa44` credentials. Migration 010 only widens constraints and can stay
  applied.
- Remove `k=mldsa44` DNS records only after the overlap that covers mail
  already signed with them.
