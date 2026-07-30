# Compatibility Statement

The preview baseline implements `draft-ietf-dkim-dkim2-spec-04` with the
historical `draft-chuang-dkim2-dns-04` DNS behavior identifier. A later draft
is a reviewed behavior migration, not an automatic compatibility update.

## Public surfaces

- The exported root library API is unchanged from the exact reviewed base
  `25a9944329d0067db4c7c30b0ba69c1028a44b30` except for the reviewed public
  datasource-provider bridge required by the LDAP/PostgreSQL adapters. The
  deterministic API manifest has 645 declarations and SHA-256
  `2d755de5b0941bc8a1b12270fd43e86a4ace9a8b432d94a77b260d9f5901988f`.
- Daemon HTTP shapes and bounds are authoritative only in
  `docs/specs/openapi/dkim2d.yaml`. The wire `api_version` remains `v1`;
  product prerelease versioning does not alter that field.
- Generated server, client, Milter client, and Milter test-server artifacts
  must remain byte-equal to output from the pinned generator.
- CLI JSON and JSON Lines remain bounded machine surfaces. Human help text is
  not a parallel wire model.
- Declared daemon and Milter configuration paths remain in their existing
  stability window. Environment expansion occurs before typed validation and
  never expands map keys.

No public Go or HTTP breaking migration is introduced by this candidate. If the final
candidate cleanup exposes one, its source change, call-site migration, and
operator note must land together before the candidate is approved.

The compatibility window begins only if all five `v0.1.0-rc.1` module tags
are later created under separately authorized release work. From then through
`v0.1.0`, breaking exported Go API, HTTP wire `v1`, configuration, CLI machine
output, or report-schema changes require a documented Draft/RFC/security
correctness exception, migration notes, and a new candidate.
