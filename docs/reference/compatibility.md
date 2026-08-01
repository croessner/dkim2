# Compatibility Statement

The preview baseline implements `draft-ietf-dkim-dkim2-spec-04` with the
historical `draft-chuang-dkim2-dns-04` DNS behavior identifier. A later draft
is a reviewed behavior migration, not an automatic compatibility update.

## Public surfaces

- The exported root library API is reviewed against the exact base
  `f30fecbd35ae3afd1b590ddfe55ee45f0cf6555a`. The candidate retains the public
  datasource-provider bridge and adds closed, nonbreaking verification and
  signing applicability assessments so protocol absence is not represented as
  a four-state result. The
  deterministic API manifest has 655 declarations and SHA-256
  `6f75cb7845f19721de7f6ca60b003c31f620217f186255b18224318523678607`.
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
- Exim compatibility is `qualified_linux` only for the exact five source-linked
  rows in the dated compatibility report. It does not imply a portable Exim
  report, universal local-scan ABI binary, binary package, or container image.

No public Go or HTTP breaking migration is introduced by this candidate. If the final
candidate cleanup exposes one, its source change, call-site migration, and
operator note must land together before the candidate is approved.

The compatibility window begins only if all six `v0.1.0-rc.1` module tags
are later created under separately authorized release work. From then through
`v0.1.0`, breaking exported Go API, HTTP wire `v1`, configuration, CLI machine
output, or report-schema changes require a documented Draft/RFC/security
correctness exception, migration notes, and a new candidate.
