# Compatibility Statement

The preview baseline implements `draft-ietf-dkim-dkim2-spec-08` with the
`draft-ietf-dkim-dkim2-dns-02` DNS behavior identifier. A later draft
is a reviewed behavior migration, not an automatic compatibility update.

## Public surfaces

- The exported root library API is reviewed against the exact base
  `38edd52d9d1f2a09319ddc24d8a846249732bf4a`. The deterministic API manifest
  has 899 declarations and SHA-256
  `134e557a4ad24a4145a670a51d9c6fcd7dcaf207f65158d51a12f3e4253f756b`.
  The [root library API delta](#root-library-api-delta) lists every
  declaration removed, added, or changed since the previous reviewed base
  `f7099dbd47ff3bd79e30f7801814c87eb0914b4c` (883 declarations); the
  [dated review](../reports/api-and-mailflow-review-2026-09-14.md) records
  the reviews before that base. This is a reviewed current reference, not a
  claim of Draft-04 to Draft-07 behavioral compatibility. The checker covers
  the root package only; `authresults` is a separately tested subpackage.
- Daemon HTTP shapes and bounds are authoritative only in
  `docs/specs/openapi/dkim2d.yaml`. The wire `api_version` remains `v1`;
  product prerelease versioning does not alter that field.
- Complete-fanout revision is an additive daemon capability at
  `/v1/revise/batch`, with separately authenticated discovery at
  `/v1/revise/batch/capabilities` and the stable configuration path
  `server.batch_revise_capability_file`. Existing single-message revise and
  public library contracts retain their semantics. See the
  [batch revision contract](../specs/implementation/batch-revision.md).
- Generated server, client, Milter client, Milter test-server, Exim client,
  and delivery-status propagator client and test-server artifacts must remain
  byte-equal to output from the pinned generator.
- CLI JSON and JSON Lines remain bounded machine surfaces. Human help text is
  not a parallel wire model.
- Declared daemon, Milter, and delivery-status propagator configuration paths
  remain in their existing stability window. Environment expansion occurs
  before typed validation and never expands map keys. The daemon adds the
  stable paths `server.dsn_propagate_capability_file`,
  `process.default_tenant`, and `dsn_propagation.pending_lease`; the
  propagator module introduces the frozen configuration root
  `dkim2-dsn-propagator-config-v1` documented in
  [`cmd/dkim2-dsn-propagator/README.md`](../../cmd/dkim2-dsn-propagator/README.md).
- Exim compatibility is `unqualified_draft08`. The exact five source-linked
  rows in the dated compatibility report are historical Draft-04 evidence and
  do not qualify Draft-08. There is no portable Exim report, universal
  local-scan ABI binary, binary package, or container image.

## Root library API delta

`make check-reference` compares the deterministic manifest of the exported
root package (`go -C tools run ./cmd/reference -root .. api`) with
`testdata/reference/go-api-base.json`. The reviewed base moved from
`f7099dbd47ff3bd79e30f7801814c87eb0914b4c` to the Draft-08 surface of the
`v0.1.48` release. A changed declaration keeps its name but changes its
signature, type, or value. Doc-comment-only changes are not listed.

Draft-07 migration, trusted null-sender signing, replay counting, and the
earlier DSN reporting identity (released up to `v0.1.47`; the module also
gained the direct dependency `golang.org/x/net` and moved
`golang.org/x/sys`):

- Removed: `KeyPolicyMetadata`, `KeyPolicyMetadata.StrictIdentityApplicable`,
  `KeyPolicyMetadata.StrictIdentityDeclared`,
  `KeyPolicyMetadata.TestingDeclared`, `LocalOnlySignedMessage`,
  `LocalOnlySignedMessage.Facts`, `LocalOnlySignedMessage.Format`,
  `LocalOnlySignedMessage.GoString`,
  `LocalOnlySignedMessage.ReleaseToInControl`,
  `LocalOnlySignedMessage.String`, `LocalOnlySignedMessage.Valid`,
  `PolicyCompliance`, `PolicyCompliance.Known`, `PolicyComplianceHonored`,
  `PolicyComplianceIndeterminate`, `PolicyComplianceNotEvaluated`,
  `PolicyComplianceNotRequested`, `PolicyComplianceViolated`,
  `PolicyDecision.DNSTestingEffective`,
  `PolicyDecision.DoNotExplodeCompliance`,
  `PolicyDecision.DoNotModifyCompliance`, `PolicyReasonDNSTestingEffective`,
  `PolicyReasonDNSTestingIneligible`, `PolicyReasonDNSTestingMixed`,
  `PolicyReasonDoNotExplodeIndeterminate`,
  `PolicyReasonDoNotExplodeNotEvaluated`, `PolicyReasonDoNotExplodeViolated`,
  `PolicyReasonDoNotModifyHonored`, `PolicyReasonDoNotModifyIndeterminate`,
  `PolicyReasonDoNotModifyNotEvaluated`, `PolicyReasonDoNotModifyViolated`,
  `PublicKeyResult.KeyPolicyMetadata`, `SignatureSetFact.KeyPolicyMetadata`,
  `SignedMessageFlagDoNotExplode`, `SignedMessageFlagDoNotModify`,
  `SigningFlagDoNotExplode`, `SigningFlagDoNotModify`,
  `SigningRestrictionLocalOnly`, `SigningResult.LocalOnly`,
  `VerifierHop.DoNotExplode`, `VerifierHop.DoNotModify`.
- Added: `AuthenticationReplayNotEligible`, `AuthenticatorOption`,
  `ClassifyHeaderFromNullSender`, `DSNEvidenceStageEmbeddedUnsigned`,
  `DirectDeliveryReplayCountingPolicy`, `EnvelopePathDomain`,
  `HeaderFromDomain`, `HeaderFromNullSenderAuthorUnusable`,
  `HeaderFromNullSenderClass`, `HeaderFromNullSenderContentTypeAmbiguous`,
  `HeaderFromNullSenderDeliveryStatus`, `HeaderFromNullSenderEligible`,
  `HeaderFromNullSenderProtocolFields`,
  `NewHeaderFromNullSenderSigningRequest`,
  `NewPostfixReportingDSNSigningEvidenceRequest`,
  `PublicKeyResult.PublicKeySPKI`, `ReasonFromNotAuthentic`,
  `ReplayCountingPolicy`, `ReplayCountingPolicy.Counts`,
  `ReplayCountingPolicy.CountsDirectDeliveries`,
  `UnrestrictedSignedMessage.SigningIdentity`, `ValidEnvelopePath`,
  `WithDirectDeliveryReplayCounting`.
- Changed: `DraftIdentifier`, `HardMaxRawMessageBytes`, `NewAuthenticator`,
  `NewDisabledAuthenticator`, `PrivateKeySignRequest.Digest`.

Draft-08 migration (`v0.1.48`):

- Removed: `NewDerivedDSNSigningEvidenceRequest`,
  `NewPostfixDerivedDSNSigningEvidenceRequest`,
  `NewPostfixReportingDSNSigningEvidenceRequest`, `ReasonTooManySignatures`,
  `SignatureStatusIgnored`.
- Added: `AlgorithmMLDSA44`, `DSNEvidenceStageFromNotAuthentic`,
  `DSNEvidenceStageIdentityUnavailable`, `DSNIdentity.Domain`,
  `DSNProfileSource`, `DSNSigningEvidence.Resolved`,
  `DSNSigningEvidenceRequest.WithPreferredIdentity`, `FoundMLDSA44PublicKey`,
  `MLDSA44Available`, `MLDSA44SignerOptions`, `MLDSA44SigningCredential`,
  `MLDSA44SigningCredential.Format`, `MLDSA44SigningCredential.GoString`,
  `MLDSA44SigningCredential.String`, `MLDSA44SigningCredential.Valid`,
  `MinSigningRSABits`, `NewMLDSA44NextDomainPublicationRequest`,
  `NewMLDSA44SigningCredential`, `NewMLDSA44SigningProfile`,
  `NewPostfixDSNSigningEvidenceRequest`, `NewSigningProfile`,
  `ObservationAlgorithmMLDSA44`,
  `PrivateKeySignRequest.MessageRepresentative`,
  `PublicKeyResult.MLDSA44PublicKey`, `ReasonBodyHistoryUnavailable`,
  `ReasonCustodyMismatch`, `ReasonInvalidRecipe`,
  `ReceivedDSNPropagationForbiddenIdentityMisaligned`,
  `SignatureSetFact.Format`, `SignatureSetFact.GoString`,
  `SignatureSetFact.String`, `Signer.ResolveDSNSigningIdentity`,
  `SigningCredential`.
- Changed: `DraftIdentifier`, `NewDSNSigningEvidenceRequest`.

`SignatureStatusIgnored` leaves the `SignatureStatus` constant block: an
unknown algorithm is reported as `SignatureStatusPERMERROR` with
`ReasonUnsupportedAlgorithm` (Draft-08 Section 14.6 step 4); the declaration
count is unchanged because the manifest counts the constant block as one
declaration.

`DraftIdentifier` is `draft-ietf-dkim-dkim2-spec-08`.
`NewDSNSigningEvidenceRequest` no longer takes a `DSNIdentity`; the Section
16.2 resolver chooses it (see
[Delivery-status signing identity](#delivery-status-signing-identity)).
`PrivateKeySignRequest.Digest` returned `[sha256.Size]byte` before
`v0.1.47`, returns `[]byte` since, and is deprecated in favor of
`MessageRepresentative`, which covers `mldsa44`. `NewAuthenticator` and
`NewDisabledAuthenticator` gained variadic `AuthenticatorOption` arguments,
which keeps existing calls source compatible. `HardMaxRawMessageBytes` is
now defined through the raw-message owner and rose from 32 MiB to 128 MiB
(`128 << 20`) before `v0.1.47`.

## Qualified storage services

The table distinguishes executable qualification from a broader product-family
assumption. The digest-pinned subjects in
[`scripts/test-datasource-services.sh`](../../scripts/test-datasource-services.sh)
and the exact `valkey-server` binary check of the Redis replay harness are authoritative for the current candidate.
A nearby patch, later minor, vendor rebuild, proxy, managed service, fork, or
wire-compatible product is unqualified until the same security and parity
evidence passes.

| Facility | Exact qualified line | Evidence boundary | Broader claim |
| --- | --- | --- | --- |
| LDAP signing datasource | OpenLDAP `2.6.13-r4` image at the pinned digest | schema install, verified TLS, paging, native v2/v3 load, v3 onboarding stage/readback/activation, runtime signing, parity, and denials | no generic LDAP server claim |
| PostgreSQL signing datasource | PostgreSQL `18.3-alpine` image at the pinned digest | DDL/upgrades, roles, verified TLS, v2/v3 loading, v3 onboarding and observed lock contention, runtime signing, parity, and denials | no automatic older/newer PostgreSQL claim |
| MySQL signing datasource | MySQL `8.4` image at the pinned digest | DDL/upgrades, exact grants/definers, verified TLS, v2/v3 loading, v3 onboarding and observed lock contention, runtime signing, parity, and denials | no generic MySQL 8 claim |
| MariaDB signing datasource | MariaDB `10.11` image at the pinned digest | common MySQL contract, exact grants/definers, verified TLS, v2/v3 loading, v3 onboarding and observed lock contention, runtime signing, parity, and denials | no other MariaDB line or MySQL-compatible fork claim |
| Redis replay | Valkey `9.1.2` exact binary as the harness server | standalone with TLS and an ACL user, Sentinel with forced failover, three-primary cluster, nonce-bearing commands, retry idempotency, startup checks, health probe, parity, and propagation | Redis 7.0+ and Valkey 7.2+ are supported by contract only; no managed-service, proxy, or other-version evidence claim |
| Flat-file signing datasource | current supported Linux and macOS filesystem implementations | descriptor confinement, ownership/mode/link checks, atomic reload, race and abuse evidence | unsupported platforms return `unsupported_platform` |

MySQL and MariaDB deliberately share `signing.backend: mysql`; qualification is
still recorded separately because their server implementations and privilege
semantics are independently exercised. Signing SQL backends do not imply an
SQL replay backend.

Native domain onboarding is an offline `dkim2d datasource domain` CLI and is
not a public Go or HTTP compatibility surface. Its protected admin/intent
schemas and bounded machine report are versioned contracts. The current
worktree implementation remains an unpublished closeout candidate; exact
operation guidance and limitations are in the
[native-domain runbook](../operator/native-domain-onboarding.md).

Draft-06 delivery-status propagation adds two operations to the same
contract, `POST /v1/dsn/propagate` and `POST /v1/dsn/propagate/commit`, behind
one distinct security scheme carried in `X-DKIM2-DSN-Propagate-Capability`.
They are additive: the shared `Disposition` enum is unchanged and
`PropagationDisposition` is a distinct schema, because propagation adds
`discard` and never uses `continue`. `ProcessRequest` gains the optional
`context.tenant`, `ProcessResponse` gains the optional closed
`delivery_status` projection, `MessageInput.fidelity` gains
`lmtp_delivered_crlf`, and `PolicyReason` gains the ten closed
`received_dsn_*` values. The generated Milter and Exim clients keep their
existing operation sets, because both exclude the propagation operations;
their shared `ErrorResponseCode` enum gains `propagation_commit_unresolved`,
so their artifacts are regenerated and deployed with the rest of the
digest-pinned set. The commit route answers
`409` with the error code `propagation_commit_unresolved` for a token it
cannot resolve, which is the caller's instruction to defer rather than to
retry immediately.

The `POST /v1/process` schema is the one canonical Draft-08 contract for both
current-only and authenticated multi-instance results. Its closed policy enums
contain only states produced by the current verifier and policy projection;
there are no deprecated aliases, version fallbacks, or alternate legacy
values. Draft-06 intentionally replaces the `DraftVersion` enum and adds the
closed verification reasons `duplicate_hash_algorithm`,
`invalid_recipe_json`, and `duplicate_selector`; Draft-08 removed the
Draft-06/07 `too_many_signatures` reason together with the per-algorithm cap,
and adds `custody_mismatch`, `body_history_unavailable`, and `invalid_recipe`.
Draft-08 Section 14.1 also moves `timestamp_invalid`, `envelope_mismatch`,
`domain_alignment_mismatch`, `next_domain_mismatch`, `out_of_band_required`,
and `from_not_authentic` from PERMERROR to FAIL; Chain of Custody adjacency
failures formerly reported as PERMERROR `malformed_protocol` are FAIL
`custody_mismatch` for the selected target, and Recipe schema and application
errors formerly reported as `invalid_recipe_json` or `malformed_protocol` are
PERMERROR `invalid_recipe`. Policy verdicts and SMTP outcomes are unchanged
for all of these. A history with a null body Recipe is FAIL
`body_history_unavailable` instead of a PASS with partial history, so strict
policy now rejects it and transit or revision signing refuses it; the
`partial` historical content and `indeterminate` feedback coverage values stay
in the closed vocabulary but are no longer produced. Consumers that switch on
the state or reason (Rspamd symbols `DKIM2_FAIL` versus `DKIM2_PERMERROR`,
dashboards, the Nauthilus projection) must expect the new values.
Signature-set result rows are positional and are not keyed or merged by
algorithm. The per-set status `ignored` is removed from
`SignatureSetResult.status` and from the root library
(`SignatureStatusIgnored`): Draft-08 Section 14.6 step 4 makes an unknown
algorithm a PERMERROR intermediate, so its set now reports `permerror` with
reason `unsupported_algorithm` and its selector, exactly like a locally
disabled algorithm. The combined state and primary reason do not change.
Consumers that matched `ignored` (Rspamd `verifier.lua`, dashboards, parsers
of the daemon response) must match `permerror` with `unsupported_algorithm`
instead. A daemon response carrying `ignored` is rejected by the
hand-written response validation of the Milter handler, the Exim adapter,
and the `dkim2ctl` runtime (each checks `SignatureSetResult.status` against
the regenerated closed enum) and by the Rspamd verifier; the generated
clients themselves only decode the value. The daemon, Milter, Exim adapter, delivery-status propagator, and every
generated client are regenerated from the same OpenAPI source and must be
deployed and rolled back as one digest-pinned set. The exact multi-instance response states are
documented in the
[Milter adapter contract](../specs/implementation/milter-adapter.md#canonical-multi-instance-policy-response).

### ML-DSA-44 (`mldsa44`)

Draft-08 Section 3.4 makes pure ML-DSA-44 a verifier MUST. The library,
`dkim2d`, the generated clients, and the Rspamd contrib add it together.

Breaking changes to the exported root Go API (`github.com/croessner/dkim2`):

- `PrivateKeySigner` implementations: `PrivateKeySignRequest.Valid` now also
  accepts `mldsa44`, and the bytes to sign are
  `PrivateKeySignRequest.MessageRepresentative()`. For `rsa-sha256` and
  `ed25519-sha256` this is the unchanged 32-byte SHA-256 digest; for
  `mldsa44` it is the complete Section 12.8 input (bounded by
  `SigningLimits.MaxSignatureInputBytes`, 2 MiB by default), which the signer
  passes to the hedged `crypto/mldsa` `PrivateKey.Sign` with
  `MLDSA44SignerOptions()` (context string `DKIM2`). `Digest()` is
  deprecated and returns nil for `mldsa44`; a callback that assumed a 32-byte
  digest for every valid request must switch to `MessageRepresentative()`.
  The interface method keeps its name `SignDigest`.
- `Algorithm.Known` accepts `AlgorithmMLDSA44`; exhaustive switches over
  `Algorithm` (and over `ObservationAlgorithm`, which appends
  `ObservationAlgorithmMLDSA44` after the existing values without
  renumbering them) need a new case.
- A `SigningProfile` may hold three credentials, `SignedMessageFacts.Algorithms()`
  may contain `mldsa44`, and the emitted `s=` value then contains a `|`
  separator (`rsa,ed25519 | mldsa44`).
- `SigningLimits.MaxPrivateSignatureBytes` defaults to 2420 (was 1024) and
  must be at least 2420; `MaxGeneratedSignatureSets` and
  `MaxPrivateSigningCalls` default to 3 (were 2). A caller that pinned the old
  values gets `invalid_options`.
- `NewVerifier` and `NewMLDSA44SigningCredential` fail when the binary is
  built against the FIPS 140-3 Go Cryptographic Module v1.0.0, which has no
  ML-DSA; `MLDSA44Available` reports the condition.

RSA signing floor (Draft-08 Section 3.2 SHOULD made a local MUST):
`NewRSASigningCredential`, every internal signing credential, the
datasource-to-signing projection, and `dkim2d` custody keys reject RSA
moduli below 2048 bits (`MinSigningRSABits`) with `key_mismatch` and the
secret-free detail `limit_name=min_rsa_bits limit=2048 actual=<bits>`; a
signing profile that holds such a key fails at load. Verification keeps the
1024 to 8192 bit bounds.

Additive declarations: `AlgorithmMLDSA44`, `FoundMLDSA44PublicKey`,
`PublicKeyResult.MLDSA44PublicKey`, `MLDSA44SigningCredential`,
`NewMLDSA44SigningCredential`, `NewMLDSA44SigningProfile`, the sealed
`SigningCredential` interface with `NewSigningProfile`,
`NewMLDSA44NextDomainPublicationRequest`, `MLDSA44SignerOptions`,
`MLDSA44Available`, `MinSigningRSABits`, `ObservationAlgorithmMLDSA44`, and
`PrivateKeySignRequest.MessageRepresentative`.

Repository-internal packages (not a public surface, listed for sibling
modules): `signing.PrivateKeySignRequest.Digest` is replaced by
`MessageRepresentative`, and `cryptodkim2.VerifyDigest`, `SelfVerifyDigest`,
`DigestBytes`, and `SignatureInputDigest` are replaced by
`VerifyRepresentative`, `SelfVerifyRepresentative`,
`ValidRepresentativeLength`, and `MessageRepresentative`.

HTTP wire `v1`: `SignatureSetResult.algorithm` and
`VerifierHop.signature_algorithms` gain `mldsa44`.
`VerifierHop.signature_algorithms` drops `rsa-sha512` and `ed25519-sha512`
and its `maxItems` becomes 3: only verified Draft-08 Section 3 algorithms are
listed, so the daemon never produced those values. Generated clients reject
values outside their enum, so every generated artifact and the Rspamd
vocabulary are deployed with the daemon as one digest-pinned set. `dkim2d
serve` and `dkim2d validate` refuse to start without ML-DSA support.

### Delivery-status signing identity

Draft-08 Section 16.2 binds the DSN signing domain to an `rt=` address of the
reported message's highest DKIM2-Signature. Breaking changes to the exported
root Go API:

- `NewDerivedDSNSigningEvidenceRequest`,
  `NewPostfixDerivedDSNSigningEvidenceRequest`, and
  `NewPostfixReportingDSNSigningEvidenceRequest` are removed.
  `NewDSNSigningEvidenceRequest` no longer takes a `DSNIdentity`; the new
  `NewPostfixDSNSigningEvidenceRequest` replaces the Postfix constructors, and
  `DSNSigningEvidenceRequest.WithPreferredIdentity` carries an optional
  preferred domain that is used only when it matches.
- `EvaluateDSNForSigning` binds no identity: `DSNSigningEvidence.SigningDomain`
  is empty until `Signer.ResolveDSNSigningIdentity` (new) binds one through a
  caller-supplied `DSNProfileSource` (new); `SignDSN` accepts only resolved
  evidence (`DSNSigningEvidence.Resolved`, new).
- `DSNEvidenceStage` adds `identity_unavailable` and `from_not_authentic`;
  `signing_domain` now reports a failed identity resolution. `DSNIdentity`
  adds `Domain`.
- `ReceivedDSNPropagation` adds `forbidden_identity_misaligned`.

HTTP wire `v1`: the `/v1/dsn/sign` 204 response gains the required header
`X-DKIM2-Unsigned-Reason` (`unsigned_original`,
`delivery_status_identity_unavailable`, `delivery_status_from_not_authentic`)
and is also produced when Section 16.2 or Sections 11 and 12.4 leave no
signing identity. `DeliveryStatusProjection.propagation` gains
`forbidden_identity_misaligned`. The stable configuration path
`signing.policy.delivery_status.reporting_domain` keeps its syntax; its meaning
changed from "signing identity" to "preferred candidate when matching" (see
`cmd/dkim2d/README.md`).

### Header field placement

Draft-08 Sections 9 and 10 make Message-Instance and DKIM2-Signature trace
header fields. RFC 5322 Section 3.6 says trace fields SHOULD be kept in
blocks prepended to the message. This is a visible behavior change of the
adapters:

- `dkim2-milter` inserts this hop's fields with `SMFIR_INSHEADER` index 0
  instead of appending them with `SMFIR_ADDHEADER`. The queued header now
  starts with `Message-Instance`, `DKIM2-Signature` (and an optional
  `X-DKIM2-Info`), then the previous top field. Under Postfix that is
  Postfix's own `Received` field. The negotiated actions are unchanged. The
  closed Milter action label for these mutations changes from `add_header` to
  `insert_header`.
- `dkim2-exim` prepends the same block above Exim's own `Received` field
  instead of inserting it before the header/body separator.
- The daemon action plan, its `add_header` type, and the field order are
  unchanged; the OpenAPI `ActionPlan` description now documents the top-down
  block order.
- Library completed-message outputs place the block at the top too:
  signing results' `Bytes()`, daemon results carrying library bytes, and
  DSNs relayed by `dkim2-dsn-propagator` now start with `Message-Instance`
  (when added) and `DKIM2-Signature` instead of ending the header block with
  them.
- REST: `/v1/revise/batch` `insertion_offset` is always 0 (OpenAPI
  `maximum: 0`); it previously pointed after the final header field CRLF.
  `header_fields_base64` is in top-down order: with a controlled intermediate
  hop the final hop's `DKIM2-Signature` comes first, and a
  `Message-Instance` may appear only directly before the final
  `DKIM2-Signature`. Clients that insert the decoded fields at the returned
  offset and compare `result_sha256` need no other change.

Verification, revision, and the Section 16.3 DSN rebuild do not depend on
placement and accept top-placed, bottom-placed, and mixed chains. A Section
16.3 rebuild keeps a previous hop's own `Received` fields only when that hop
was top-placed. Consumers that read these fields by physical position (for
example "the last DKIM2-Signature") must select by `i=` or `m=` instead.

The compatibility window begins only if all seven `v0.1.0-rc.1` module tags
are later created under separately authorized release work. From then through
`v0.1.0`, breaking exported Go API, HTTP wire `v1`, configuration, CLI machine
output, or report-schema changes require a documented Draft/RFC/security
correctness exception, migration notes, and a new candidate.
