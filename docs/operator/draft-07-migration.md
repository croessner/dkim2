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

- The draft identifier is bound into the replay HMAC frame, so Draft-07 keys
  never equal Draft-06 keys, even under the same epoch and secret.
- The identity is now derived from the authenticated `m=1` hash declarations,
  framed as `dkim2-replay-origin-declaration-v1`.

Upgrade in place. Keep the existing replay epoch, HMAC secret, and
`replay.valkey.attestation.rotation_state: unchanged`, and restart every daemon
instance that shares the store on the Draft-07 release. No drain or retention
wait is needed, and Draft-06 records expire by their own TTL.

What is lost is replay continuity with Draft-06 records. A message first seen
before the upgrade and replayed afterwards can be accepted as `first_seen` once
more, and only if it still verifies under Draft-07; its next copy is detected
again. A delivery-status notification propagated before the upgrade may be
propagated once more, within the at-least-once propagation contract. The exposure
ends when the Draft-06 records would have expired. See
[`../replay-store-redis.md`](../replay-store-redis.md#replay-identity-contract) for the key
derivation evidence and for the drain-only procedure that still applies to
secret or epoch rotation.

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
- A receiver that relied on single-shot replay of direct mail, such as a
  reflector, sets `replay.count_direct_deliveries: true` to keep counting
  `i=1`-only messages as local delivery policy. A retransmitted direct
  message is then rejected as a replay, and of recipients split into
  separate transactions only the first is delivered, so ordinary mailbox
  receivers keep the default.

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
- **Composite algorithm:** `mldsa44-ed25519-sha512` (Draft-07 Section 3.4)
  is deliberately not implemented; see "Known Limitations".
  - A composite signature set is ignored with `unsupported_algorithm`, like
    any unknown algorithm; other sets of the same signature still verify. A
    `k=mldsa44-ed25519-sha512` DNS record is an unsupported key type.
  - A signing profile holds at most one `rsa-sha256` and one
    `ed25519-sha256` credential, emitted in that order.
  - `dkim2d` custody, the private-key manifest, datasource credentials,
    `dkim2d datasource key generate`, onboarding, and rotation accept only
    `rsa-sha256` and `ed25519-sha256`; anything that declares the composite
    fails closed.
  - Installations that applied `contrib/schema/*/007_composite_algorithm.sql`
    remove composite rows and then apply
    `contrib/schema/*/009_remove_composite_algorithm.sql`; see
    [Removed Composite Algorithm](datasource-backends.md#removed-composite-algorithm).
- **SMTP replies (Draft-07 Section 13):**
  - A tempfail caused by a temporary public-key (DNS) lookup failure answers
    `451 4.7.5`. The matching daemon reason is `provider_temporary`.
  - Other tempfails answer `451 4.7.1`.
  - DKIM2 rejections answer `550 5.7.1`.
  - The Exim `local_scan` texts now start with these enhanced status codes.
- **SMTPUTF8 signing:** Envelopes with UTF-8 local parts or U-label domains
  are now signed in originator and transit mode by both the Milter and Exim.
  `mf=` and `rt=` record local parts unchanged and domains as A-labels
  (Draft-07 Section 18). The Milter's `envelope_sender` domain source maps a
  U-label sender domain to its A-label before the signing-domain lookup, so
  the datasource must hold the A-label form. A non-ASCII path without the
  SMTP `SMTPUTF8` parameter still fails closed. Previously the Milter left
  such originator mail unsigned and deferred it in transit mode, and Exim
  deferred it.
- **Inbound DSN authority:** It comes from the DSN's `i=1` signer, so a
  forwarded DSN keeps its originator's authority.
- **DSN From:** An MTA-generated DSN is a new `i=1` message, and its From must
  be authentic for the DSN signing domain. With Postfix, the bounce sender is
  `MAILER-DAEMON@$myhostname`, so `$myhostname` must equal the DSN signing
  domain or be a subdomain of it.

## Known Limitations

- **Composite algorithm:** The DKIM working group has not settled the DKIM2
  post-quantum construction (October 2026 list discussion: separate multiple
  signatures, the LAMPS composite, or plain ML-DSA-44; to be revisited at
  IETF 127). The implementation therefore does not ship
  `mldsa44-ed25519-sha512` at all. This deliberately deviates from the
  Draft-07 Section 3 verifier requirement and the DNS-01 Section 3.3 SHOULD
  for the key type (`DKIM2-ISSUE-0019`).
- **IDNA:** Domains use a strict IDNA2008 profile from `golang.org/x/net/idna`.
  That package merges some IDNA2008 code-point categories, so it is not a
  complete strict validator (`DKIM2-ISSUE-0003`).
- **Replay equality:** Replay equality uses the `m=1` header and body hash
  pair. This is deliberately finer than the body-only prose of Section 15.1,
  which would merge distinct originals that share a body.
  - SHA-256 is preferred.
  - A SHA-512-only origin never matches a mixed-algorithm origin.
- **Delivery instant:** The daemon verifies only live mail through
  `/v1/process`; there is no stored-message verification route. Section 14.3
  windows are evaluated against the daemon clock, which is the delivery
  instant for live mail. `/v1/dsn/sign` judges the reported original at the
  RFC 3464 `Arrival-Date` of the local MTA's report, so a bounce generated
  after a long queue lifetime still gets signed. An absent, future, or more
  than 14 days old `Arrival-Date` falls back to the daemon clock. Library callers that re-verify stored messages must
  construct the verifier with `WithVerificationClock` set to the original
  delivery instant; otherwise an old message fails closed with
  `timestamp_invalid`.
- **Mailbox parser:** The From mailbox parser does not accept obsolete RFC
  5322 route syntax (`obs-route`). Such a From is not authentic.
- **Algorithm allow-list:** Draft-07 Section 3 requires verifiers to
  implement SHA-256, SHA-512, `rsa-sha256`, `ed25519-sha256`, and
  `mldsa44-ed25519-sha512`. The default verifier implements all of them
  except the composite (see above). Removing a further algorithm from the
  verifier's allowed set is a documented non-conformant local mode.
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
- the result reason `from_not_authentic`

The private-key callback changed shape:

- `PrivateKeySignRequest.Digest` returns a `[]byte` (32 bytes of SHA-256 for
  `rsa-sha256` and `ed25519-sha256`) instead of the former fixed-size 32-byte
  array.

Composite support that existed briefly during the Draft-07 migration was
removed again. Library consumers that used it must drop
`AlgorithmMLDSA44Ed25519SHA512`, `ObservationAlgorithmMLDSA44Ed25519`,
`FoundCompositePublicKey`, `PublicKeyResult.CompositePublicKey`,
`CompositeSigningCredential`, `NewCompositeSigningCredential`,
`NewCompositeSigningProfile`, `NewMultiSigningProfile`, the
`SigningCredential` interface, `CompositeSigningKey`,
`GenerateCompositeSigningKey`, `GenerateCompositeSigningKeyFrom`,
`ParseCompositeSigningKeyPKCS8`, `ParseCompositePublicKeySPKI`,
`MarshalCompositePublicKeySPKI`, and `provider.AlgorithmMLDSA44Ed25519SHA512`.

The exported API baseline (`testdata/reference/go-api-base.json`) is bound to
a reviewed commit. Regenerate it, then update the bound revision, when the
Draft-07 migration is committed.
