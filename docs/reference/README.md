# DKIM2 Reference Index

This directory is the public-preview reference entry point. Protocol truth
remains the pinned drafts and repository architecture; OpenAPI truth remains
the generated source contract. Reference prose summarizes tested behavior and
limitations without creating a second protocol model.

- [Draft issue log](draft-issues.md) separates upstream text, local behavior,
  executable tests, external observations, and release effects.
- [Compatibility](compatibility.md) records the public Go, HTTP, CLI,
  configuration, and module compatibility window.
- [Known limitations](known-limitations.md) states incomplete or unavailable
  capabilities without converting them into passing evidence.
- [Preview release candidate](release-candidate.md) freezes the intended
  version, six-tag plan, non-publication boundary, and capability status.
- [Conformance](../conformance.md) defines claim classes and exact report
  profiles.
- [Security testing](../security-testing.md) defines resource, privacy, fuzz,
  race, and vulnerability evidence.
- [Draft-05 semantics audit](../reports/draft-05-semantics-audit-2026-08-26.md)
  records the historical Draft-05 compatibility, diagnostics, replay,
  security, and evidence boundaries.
- [Postfix deployment](../operator/postfix-compose.md) is the implemented
  adapter qualification and operator path.
- [Exim operations](../operations/exim-adapter.md) and the historical
  [Draft-04 compatibility matrix](../reports/exim-compatibility-2026-07-27.md)
  describe the source-rebuild deployment and the separately invalidated
  five-row qualification boundary.
- [Signing datasource backends](../operator/datasource-backends.md), the
  [LDAP schema reference](../operator/ldap-schema-reference.md), the
  [key-rotation runbook](../operator/datasource-key-rotation.md), and
  [OpenDKIM migration](../operator/opendkim-migration.md) define the
  implemented storage and offline administration boundaries.
- [Native domain onboarding](../operator/native-domain-onboarding.md) defines
  the protected offline plan, DNS export/proof, activation, recovery, and
  external runtime-verification workflow.
- [Container supply chain](../operator/container-supply-chain.md) defines
  image, SBOM, provenance, and publication boundaries.
- [OpenAPI source](../specs/openapi/dkim2d.yaml) is authoritative for daemon
  HTTP request and response shapes.

The first intended product preview is `v0.1.0-rc.1`. Preparing the candidate
does not create a Git tag, module release, container publication, stable alias,
or claim that the drafts are final.
