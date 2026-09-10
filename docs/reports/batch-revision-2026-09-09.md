# Complete fanout revision qualification — 2026-09-09

The daemon now exposes a separately authorized complete-fanout revision operation
over the unchanged public reference library. Original SMTP bytes and envelope,
every actual current local/external copy, prepared outgoing envelopes and exact
signing contexts remain distinct inputs. Only external completed header deltas
are returned. Existing local delivery may stand when external authorization
fails; the operation does not introduce a global local-delivery veto.

The authority is [the daemon OpenAPI](../specs/openapi/dkim2d.yaml), with the exact
client and received-DSN workflow in [the implementation contract](../specs/implementation/batch-revision.md).
The baseline remains `draft-ietf-dkim-dkim2-spec-06`; no later BCP or RFC
conformance is claimed by this service extension.

## Implemented boundary

- `POST /v1/revise/batch` verifies the exact original through
  `Signer.VerifyForRevision`, seals all actual copies through `PlanRouteFanout`
  and signs each external private recipient with its own library-issued ticket.
- One SigningAuthority lease resolves the operation's exact profiles and
  controlled intermediate domains. Optional `via` performs a real intermediate
  revision and reverification; it does not relax custody or sender alignment.
- The MTA prepares outgoing SRS reverse paths. This daemon neither implements
  SRS nor trusts caller-provided DKIM2 verdicts or inherited request flags.
- Authenticated `donotmodify`, `donotexplode` and actual modification/fanout
  facts remain enforced by the library. Failed batches return no partial
  external fields. Cryptographic/policy rejection is permanent; temporary
  provider failures defer.
- Response binding, original/current/result SHA-256, external IDs and exact
  insertion offsets let the caller bind the returned private header deltas to
  its immutable delivery plan. The caller still owns delivery idempotency.
- `GET /v1/revise/batch/capabilities` requires the same dedicated credential
  and actual readiness and advertises the implementation's exact capabilities
  and bounds without a signing or DNS probe.
- The stable opt-in setting is `server.batch_revise_capability_file`, whose
  protected 32-byte capability is independent of existing operation roles.
  Native transport security, protected generation handling and existing
  SigningAuthority/provider policies are retained.
- OpenAPI generated server/client artifacts and independent schema/config
  inventories cover the new route and capability. Domain services do not
  import generated REST DTOs or another component's models.

## Received DSN result

The real-cryptography fixture spans originating, hosted, forwarding and remote
custody domains. An original accepted message produces one local and two private
external copies. Each real outgoing copy passes independent verification. The
remote test authority records its own custody, creates a validated signed DSN
and propagates its own hop to the actual prepared SRS reverse path.

The receiving daemon's existing authenticated propagation operation evaluates
the adjacent hosted and forwarding domains as one locally controlled hop run.
The reference library checks each step and removes the complete local run,
reconstructing the preceding message state. Its output recipient is the prior
authenticated sender rather than the imaginary intermediate router. The
resulting message passes independent verification and contains the newly signed
outer DSN plus the original embedded signature. Commit succeeds and replay is
discarded for each external copy.

Negative cases cover modified report bytes, a prematurely decoded recipient,
another copy's issued reverse path, another tenant, unavailable outer DNS keys,
and an unchanged golden vector whose outer null-sender signature is valid but
whose DSN structure is malformed. A valid outer signature alone does not
authorize a DSN return. SRS cryptography and issuance-ledger checks belong to the
calling return adapter and remain additional requirements.

## Qualification evidence

All logs are local ignored artifacts under `temp/`. They contain no production
messages or keys. Real fixture input/output files and generated private keys are
separate mode-restricted files and are never logged.

| Check | Result / evidence |
| --- | --- |
| Focused application, real HTTP sockets and config matrix | PASS; `temp/batch-revision-focused.log` |
| Independent generated OpenAPI/config inventories | PASS; `temp/batch-revision-contracts.log` |
| Exported protected config and actual flat-file transit/DSN profiles, independent final-byte verification | PASS; `temp/batch-revision-fixture.log` |
| Existing real Milter executable driven by unchanged miltertest-go | PASS, RSA and RSA+Ed25519; `temp/batch-revision-miltertest.log` |
| Full repository guardrails | PASS, exit 0, including race, generation, vendor, platform builds, boundaries and operator documentation; `temp/batch-revision-guardrails.log` |
| All-module vulnerability check | PASS, no reported vulnerabilities; `temp/batch-revision-govulncheck.log` |
| Public reference library preservation | 527 tracked `lib/` files compared by SHA-256 with the initial candidate baseline; no changes |
| Working-tree whitespace | `git diff --check` PASS |

The Milter oracle's verified SHA-256 is
`b9caf2d3b6c2fe1d76026e554e2c7b6796e651233b162fdfd0605b9d85198c99`.
Its existing opt-in test is additional process evidence, not a new production
dependency. Normal guardrails skip that external binary unless configured; the
separate run above supplied it explicitly.

The static Linux/amd64 test daemon was built with exact Go 1.27.0,
`GOEXPERIMENT=runtimesecret`, `CGO_ENABLED=0` and `-trimpath`. Its ignored path is
`temp/dkim2d-batch-linux-amd64-final`, SHA-256
`276510953ddbfe566459115abb1b9bd3d6016b344caf5f643d2e0c7852d709bd`.
The authoritative OpenAPI SHA-256 is
`08ce479da812682535d961691dbf1b6dfeb44be68ac1ed1a78bbc816db328cfc`.
This is a local integration artifact, not a published release.

The separate native-MTA integration owner also completed a 14-group run with
unmodified Postfix 3.11.6 and the real daemon. Its native capture and queue reader
provided the original/current and actual local/archive/external plan; earlier
isolated Milter cases in that same report explicitly retain their synthetic-plan
qualification boundary. Actual output bytes from both external copies and the
received propagated DSN passed this repository's independent fixture verifier.
The observed return used the real SRS socket-map/issuance path, native delivery
adapter, authenticated propagation endpoint, null-sender SMTP reinjection and
propagation commit. This is separate integration evidence, not a new native-MTA
implementation inside this repository.

The integration owner's local report is
`/Users/croessner/src/mailstack/temp/postfix-native-dkim2-r4/proof.json`, SHA-256
`ff7ade034a6496e6d029e45de85d04b151e48fe8c6fae91877a8d37220664f9f`.
Its original signable test source now includes Date and Message-ID before
signing; no signature-validation rule was relaxed to accommodate MTA-added
headers.

## Remaining owner responsibilities and bounds

The authenticated MTA supplies complete native delivery facts. The daemon does
not independently inspect queues, infer LDAP/Sieve routing, commit local copies,
prove downstream TLS or establish archiving. The separate MTA integration must
verify its actual output and ingress/return behavior with this API.

The contract admits at most 32 actual copies and 32 MiB of aggregate decoded
original/current data. Repeated snapshots count repeatedly. The 47,878,316-byte
request, 262,144-byte response and three-generated-field bounds remain enforced;
larger production messages are not qualified by this profile. Ordinary external
revision with `MAIL FROM:<>` is explicitly unavailable in the unchanged library.
Valid received DSNs use propagation. A classic path for fully absent DKIM2 is
an explicit caller policy and never receives a fabricated DKIM2 PASS here.

Propagation reservation, SMTP acceptance and commit are not one atomic
transaction. The caller must persist its own retry state and commit only after
durable acceptance. A crash in that gap must not be represented as an atomic
exactly-once guarantee.

No public library files, dependencies, native MTAs, production services or other
owner repositories were changed by this package. Commit, publication and
deployment are coordinated separately by the integration owner.
