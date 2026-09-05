# Compatibility Statement

The preview baseline implements `draft-ietf-dkim-dkim2-spec-06` with the
historical `draft-chuang-dkim2-dns-04` DNS behavior identifier. A later draft
is a reviewed behavior migration, not an automatic compatibility update.

## Public surfaces

- The exported root library API is reviewed against the exact base
  `f30fecbd35ae3afd1b590ddfe55ee45f0cf6555a`. The candidate retains the public
  datasource-provider bridge and adds closed, nonbreaking verification and
  signing applicability assessments so protocol absence is not represented as
  a four-state result. The
  deterministic API manifest has 691 declarations and SHA-256
  `ddf0ef36cdc47bac57495a5d14fd5c56243d1bc9b82f68c80e14a48c95c45748`.
- Daemon HTTP shapes and bounds are authoritative only in
  `docs/specs/openapi/dkim2d.yaml`. The wire `api_version` remains `v1`;
  product prerelease versioning does not alter that field.
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
- Exim compatibility is `unqualified_draft06`. The exact five source-linked
  rows in the dated compatibility report are historical Draft-04 evidence and
  do not qualify Draft-06. There is no portable Exim report, universal
  local-scan ABI binary, binary package, or container image.

## Qualified storage services

The table distinguishes executable qualification from a broader product-family
assumption. The digest-pinned subjects in
[`scripts/test-datasource-services.sh`](../../scripts/test-datasource-services.sh)
and the exact Valkey binary check are authoritative for the current candidate.
A nearby patch, later minor, vendor rebuild, proxy, managed service, fork, or
wire-compatible product is unqualified until the same security and parity
evidence passes.

| Facility | Exact qualified line | Evidence boundary | Broader claim |
| --- | --- | --- | --- |
| LDAP signing datasource | OpenLDAP `2.6.13-r4` image at the pinned digest | schema install, verified TLS, paging, native v2/v3 load, v3 onboarding stage/readback/activation, runtime signing, parity, and denials | no generic LDAP server claim |
| PostgreSQL signing datasource | PostgreSQL `18.3-alpine` image at the pinned digest | DDL/upgrades, roles, verified TLS, v2/v3 loading, v3 onboarding and observed lock contention, runtime signing, parity, and denials | no automatic older/newer PostgreSQL claim |
| MySQL signing datasource | MySQL `8.4` image at the pinned digest | DDL/upgrades, exact grants/definers, verified TLS, v2/v3 loading, v3 onboarding and observed lock contention, runtime signing, parity, and denials | no generic MySQL 8 claim |
| MariaDB signing datasource | MariaDB `10.11` image at the pinned digest | common MySQL contract, exact grants/definers, verified TLS, v2/v3 loading, v3 onboarding and observed lock contention, runtime signing, parity, and denials | no other MariaDB line or MySQL-compatible fork claim |
| Valkey replay | Valkey `9.1.0` exact binary | TLS/authority policy, ACL audit, persistence and topology attestation, atomic command, parity, and recovery | no cluster, Sentinel, managed, or alternate-version claim |
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

The `POST /v1/process` schema is the one canonical Draft-06 contract for both
current-only and authenticated multi-instance results. Its closed policy enums
contain only states produced by the current verifier and policy projection;
there are no deprecated aliases, version fallbacks, or alternate legacy
values. Draft-06 intentionally replaces the `DraftVersion` enum and adds the
four closed verification reasons `duplicate_hash_algorithm`,
`invalid_recipe_json`, `duplicate_selector`, and `too_many_signatures`.
Signature-set result rows are positional and are not keyed or merged by
algorithm. The daemon, Milter, Exim adapter, delivery-status propagator, and every
generated client are regenerated from the same OpenAPI source and must be
deployed and rolled back as one digest-pinned set. The exact multi-instance response states are
documented in the
[Milter adapter contract](../specs/implementation/milter-adapter.md#canonical-multi-instance-policy-response).

The compatibility window begins only if all seven `v0.1.0-rc.1` module tags
are later created under separately authorized release work. From then through
`v0.1.0`, breaking exported Go API, HTTP wire `v1`, configuration, CLI machine
output, or report-schema changes require a documented Draft/RFC/security
correctness exception, migration notes, and a new candidate.
