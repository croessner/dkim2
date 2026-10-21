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
  (`k=mldsa44-ed25519-sha512`) are verified and signed under the LAMPS
  composite construction; see "Known Limitations".
  - A signing profile may hold one credential per algorithm, up to all three.
    The signature sets are emitted in the order `rsa-sha256`,
    `ed25519-sha256`, `mldsa44-ed25519-sha512`.
  - `dkim2d` custody accepts composite PKCS#8 keys under OID
    1.3.6.1.5.5.7.6.39 with the manifest and datasource algorithm
    `mldsa44-ed25519-sha512`.
  - Domain onboarding and rotation generate composite keys with `d2m-`
    selectors and export `k=mldsa44-ed25519-sha512` records with the raw
    1344-byte key.
  - Domain reports add `mldsa44_ed25519_credential_count` only when a
    composite credential exists.
  - SQL datasources apply `contrib/schema/*/007_composite_algorithm.sql`
    before storing composite credentials.
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

- **Composite construction:** `mldsa44-ed25519-sha512` follows the LAMPS
  composite construction (`draft-ietf-lamps-pq-composite-sigs`) that DNS-01
  cites and the DKIM2 interoperability round uses, not a literal reading of
  Draft-07 Section 3.4, which does not spell out the message representative.
  Signatures from Stalwart mail-auth verify. If the working group settles on
  a different representative, signatures of the two constructions do not
  interoperate (`DKIM2-ISSUE-0019`).
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

Composite signing changes the private-key callback:

- `PrivateKeySignRequest.Digest` returns a `[]byte` whose length depends on
  the algorithm: 32 bytes of SHA-256 for `rsa-sha256` and `ed25519-sha256`,
  64 bytes of SHA-512 for `mldsa44-ed25519-sha512`. It replaces the former
  fixed-size 32-byte array.
- A `PrivateKeySigner` that holds composite keys signs through
  `CompositeSigningKey.SignDigest`; it must not rebuild the construction.
- New constructors: `NewCompositeSigningCredential`,
  `NewCompositeSigningProfile`, and `NewMultiSigningProfile` for up to one
  credential per algorithm. Key handling uses `GenerateCompositeSigningKey`,
  `ParseCompositeSigningKeyPKCS8`, and `ParseCompositePublicKeySPKI`.

The exported API baseline (`testdata/reference/go-api-base.json`) is bound to
a reviewed commit. Regenerate it, then update the bound revision, when the
Draft-07 migration is committed.
