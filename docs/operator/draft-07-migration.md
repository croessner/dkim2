# Draft-07 Migration For Operators

This guide covers the move of every DKIM2 component from
`draft-ietf-dkim-dkim2-spec-06` plus `draft-ietf-dkim-dkim2-dns-00` to
`draft-ietf-dkim-dkim2-spec-07` plus `draft-ietf-dkim-dkim2-dns-01`. The
change-by-change record is `docs/specs/draft-07-migration-disposition.md`.

## Ship Everything Together

The REST draft enum accepts exactly `draft-ietf-dkim-dkim2-spec-07`. A client
that still sends the Draft-06 identifier receives HTTP 400 `unsupported_draft`
before any processing. The API version (`v1`) and every path stay unchanged.

Upgrade these components in one maintenance window:

- `dkim2d`
- `dkim2-milter`
- the Exim Go adapter and the Exim `local_scan` module. Rebuild the module
  from this tree: its build ID changed. A mismatched pair fails closed as a
  contract failure, answering `451 4.7.1 DKIM2 service temporarily
  unavailable` and logging a `contract` failure class.
- `dkim2ctl` and `dkim2-dsn-propagator`
- the rspamd plugin

A mixed-draft deployment is unsupported and fails closed.

## Replay Store Transition

The replay identity changed in two ways:

- The draft identifier is bound into the identity, which rotates the replay
  HMAC epoch.
- The identity is now derived from the authenticated `m=1` hash declarations,
  framed as `dkim2-replay-origin-declaration-v1`.

Records written by Draft-06 instances are therefore unreachable. Follow the
existing drain-only procedure in `docs/replay-store-valkey.md`:

1. Stop replay traffic.
2. Keep the drained Draft-06 deployment quiescent for the complete retention
   window.
3. Restart every instance with the new epoch and secret set.
4. Resume traffic.

Starting Draft-07 earlier leaves a bounded replay-detection gap for old
records. It is not a supported rolling upgrade.

The Valkey key grammar, namespace, ACL, and commands do not change.

Replay counting is now local delivery policy (Draft-07 Section 15.1):

- Only messages carrying more than one DKIM2-Signature are counted.
- A direct delivery that carries only the originator's `i=1` signature reports
  the new replay class `not_eligible` and touches no store. This also applies
  to every DSN.
- Dashboards, log filters, and rspamd rules should expect `not_eligible` and
  the rspamd symbol `DKIM2_REPLAY_NOT_ELIGIBLE`.
- `not_checked` keeps its old meaning: verification or policy did not reach
  PASS/accept.

## Removed Configuration And Signals

- The `donotmodify` and `donotexplode` signing-policy keys are removed. Draft-07
  retired both flags. Configuration that still sets them fails at startup
  with a removed-field error naming the path. Delete these keys:
  - `signing.policy.originator.donotmodify`
  - `signing.policy.originator.donotexplode`
  - `signing.policy.ordinary_transit.donotmodify`
  - `signing.policy.ordinary_transit.donotexplode`
  - `signing.policy.delivery_status.donotmodify`
  - `signing.policy.delivery_status.donotexplode`
  - the matching `DKIM2D_SIGNING_POLICY_*` environment variables
- The DNS key-record `t=` tag is retired (DNS-01 Section 3.4.1) and ignored:
  - `t=y` no longer produces testing-only results.
  - `t=s` no longer restricts identities.
  - The REST members `key_policy` and `dns_testing` are gone.
  - The configured local testing policy mode is unchanged.
- The timestamp windows are now fixed protocol constants:
  - 14 days maximum age and one day of future tolerance.
  - They are checked on every DKIM2-Signature, not only the newest one.
  - The revision skew stays five minutes.

## Behavior Changes Visible In Mail Flow

- **Tag names:** Uppercase tag names in `DKIM2-Signature` or
  `Message-Instance` are PERMERROR. Hash, algorithm, and flag values are
  case-sensitive.
- **From authentication:** A message whose From is not authentic for the
  responsible signer (Draft-07 Section 11) is PERMERROR `from_not_authentic`.
  This includes a legacy unencoded 8-bit `From`, which earlier failed as
  `malformed_message`.
- **8-bit header bytes:** Header values that are not valid UTF-8 (for example
  an unencoded Latin-1 `Subject`) are accepted and hashed as bytes instead of
  failing as `malformed_message`.
- **Exploded flag:** An `exploded` flag on the `i=1` signature is PERMERROR
  `malformed_protocol`.
- **Composite algorithm:** `mldsa44-ed25519-sha512` signatures and keys
  (`k=mldsa44-ed25519-sha512`) are verified. They are never produced; see
  "Known Limitations".
- **SMTP replies (Draft-07 Section 13):**
  - A tempfail caused by a temporary public-key (DNS) lookup failure answers
    `451 4.7.5`. The matching daemon reason is `provider_temporary`.
  - Other tempfails answer `451 4.7.1`.
  - DKIM2 rejections answer `550 5.7.1`.
  - The Exim `local_scan` texts now start with these enhanced status codes.
- **Inbound DSN authority:** It comes from the DSN's `i=1` signer, so a
  forwarded DSN keeps its originator's authority.
- **DSN From:** An MTA-generated DSN is a new `i=1` message, and its From must
  be authentic for the DSN signing domain. With Postfix, the bounce sender is
  `MAILER-DAEMON@$myhostname`, so `$myhostname` must equal the DSN signing
  domain or be a subdomain of it.

## Known Limitations

- **Composite signing:** It stays disabled. DNS-01 cites the LAMPS
  composite-signature construction, which differs from Draft-07 Section 3.4.
  The verifier implements Section 3.4. No interoperability claim is made
  until the working group resolves the conflict.
- **IDNA:** Domains use a strict IDNA2008 profile from `golang.org/x/net/idna`.
  That package merges some IDNA2008 code-point categories, so it is not a
  complete strict validator (`DKIM2-ISSUE-0003`).
- **Replay equality:** Replay equality uses the `m=1` header and body hash
  pair. This is deliberately finer than the body-only prose of Section 15.1,
  which would merge distinct originals that share a body.
  - SHA-256 is preferred.
  - A SHA-512-only origin never matches a mixed-algorithm origin.
- **Delivery instant:** `/v1/verify` carries no delivery instant. A stored
  message is checked against the daemon clock, so an old message fails closed
  with `timestamp_invalid`. Only library callers can pass a reference time.
- **Mailbox parser:** The From mailbox parser does not accept obsolete RFC
  5322 route syntax (`obs-route`). Such a From is not authentic.
- **EAI envelopes:** Adapter signing stays ASCII-path only.
  - The Milter continues unsigned for a non-ASCII originator path and
    tempfails non-ASCII transit paths.
  - Exim rejects non-ASCII outbound scalars.
  - Inbound SMTPUTF8 messages are preserved and verified.
- **Algorithm allow-list:** Draft-07 Section 3 requires verifiers to
  implement all five algorithms (SHA-256, SHA-512, `rsa-sha256`,
  `ed25519-sha256`, `mldsa44-ed25519-sha512`). DNS-01 makes the last two
  signing algorithms only SHOULD; the default verifier follows the stricter
  Draft-07 rule. Removing an algorithm from the verifier's allowed set is a
  documented non-conformant local mode.
- **Exim qualification:** The real Exim matrix for Draft-07 still needs to be
  run against an external patched Exim source tree. That run must prove:
  - revise output verifies after transmission;
  - each reply line carries exactly one enhanced status code.
- **External interoperability:** Peers observed under Draft-06 (for example
  the `signature-mixed-case` parser agreement) are recorded as
  `draft07-requalification-required` until they are observed again against
  Draft-07.

## Library Consumers

The Go library removed these public APIs without replacement:

- `donotmodify` and `donotexplode` flags, compliance states, and reasons
- DNS-testing reasons and the `KeyPolicyMetadata` accessors
- the missing-tag-terminator error code

Rebuild against the new API.

The migration also adds members to closed vocabularies. Extend every
exhaustive `switch` over them:

- `AuthenticationReplayNotEligible` (`not_eligible`), also as the REST
  `ReplayResult.class` value `not_eligible`
- `AlgorithmMLDSA44Ed25519SHA512` and `FoundCompositePublicKey`
- the result reason `from_not_authentic`

The exported API baseline (`testdata/reference/go-api-base.json`) is bound to
a reviewed commit. Regenerate it, then update the bound revision, when the
Draft-07 migration is committed.
