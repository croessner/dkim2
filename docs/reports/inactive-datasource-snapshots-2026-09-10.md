# Inactive datasource snapshot recovery

The patch fixes daemon startup and reload for complete native datasource
generations containing inactive signing policies or profiles. A normal
administrative onboarding generation can contain active profiles alongside new
`disabled`/`off` profiles awaiting their separate DNS-verified activation.
Previously the shared signing-registry constructor tried to authorize every
profile during loading. The legitimate `inactive` result then rejected the
entire generation, including otherwise usable active profiles.

The registry now inspects exact immutable policy and profile facts through an
internal `InspectionProvider` contract. It validates every binding, including
inactive keys, before accepting the snapshot. Tenant, domain, use, generation,
handle, algorithm, public-key digest, and complete credential-group membership
remain mandatory. Native private-key parsing, key uniqueness, full candidate
commitments, and current/root publication fences are unchanged.

Inspection returns inert datasource records and never a signing profile.
Message-time `ResolvePolicy` and the existing signing projection still enforce
active policy/profile status, `enforce` rollout, and the current validity window.
An all-inactive complete generation is loadable but grants no signing authority;
a future-valid profile can become eligible at message time without rebuilding
the same immutable registry.

The common fix covers the public dataset bridge, flat-file signing provider,
network runtime, and the `NewSnapshot` validation used by LDAP/SQL v3 commitment
checks, administrative snapshots, onboarding, migration, and rotation. It does
not change HTTP/OpenAPI, LDAP/SQL schema, public library signatures, configuration,
DNS publication, activation, or DKIM2 protocol rules.

The regression first failed on the unchanged implementation for both v2 and v3.
Qualification includes mixed active/inactive profiles, all-inactive snapshots,
disabled status, off/observe rollout, future/expired validity, complete and
partial dual-algorithm groups, hostile inspection outcomes, malformed inactive
private keys, foreign scope, changed commitments, and the complete v3 LDAP
loader-to-runtime path. The existing active-signing and fail-closed regression
suites remain part of the release gates.

Release note: **Fix datasource loading when a complete immutable generation
contains inactive profiles, without permitting those profiles to sign.** The
fix is intended for the next coordinated patch release; no release or live
datasource mutation is performed by this implementation task.
