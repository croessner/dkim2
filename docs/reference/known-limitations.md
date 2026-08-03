# Known Limitations

The first preview is a tested reference candidate, not a final DKIM2 standard,
certification, or universal interoperability claim.

- Draft-04 architecture references, full-chain policy guidance, EAI, IANA,
  and Security Considerations still contain `TBA` text. The implementation
  does not invent normative behavior for those sections.
- External discovery found runnable parser overlap with MailAuthLens and
  Turscar. It found a tag-case interpretation difference with MailAuthLens.
  Stalwart's observed source revision has no `Cargo.lock`, so no immutable
  transitive build closure can be reproduced. The aggregate evidence is
  `eligible_not_runnable`, not interoperability PASS.
- Runtime comparison covers only explicitly equivalent parser operations and
  reserved synthetic inputs. It does not cover another implementation's full
  signing, verification, recipe, custody, SMTP, replay, daemon, OpenAPI,
  telemetry, or deployment behavior.
- Postfix/Milter qualification is implemented. Exim is Linux-qualified only for
  the five source-linked upstream, Debian, and Ubuntu rows recorded in the
  compatibility report. There is no portable Exim execution claim, universal
  local-scan binary, or Exim container image.
- Null-reverse-path DSN signing is deferred. The originator Milter tempfails
  every null sender before daemon I/O because its callbacks and current request
  contract cannot authenticate the RFC 3462 three-part structure, Draft-04
  Section 12.1 embedded verification, and Section 12.1.2 alignment evidence.
  The reserved configured DSN domain does not authorize signing by itself.
- Flat-file, LDAP, PostgreSQL, MySQL, MariaDB, and Valkey datasource paths are implemented.
  The offline OpenDKIM migration requires separately managed verified-TLS
  services, explicit mapping, and distinct least-authority principals.
- The online daemon has no key-generation, DNS-mutation, or datasource-write
  surface. Native key generation and onboarding exist only in the protected
  offline `dkim2d datasource domain` workflow. It exports DNS records but does
  not publish them, proves only a fresh configured recursive resolver path,
  makes no authoritative-query or cache-bypass claim, persists no
  runtime-verified state, and performs no automatic candidate deletion. At
  most eight outstanding candidates are permitted; retained or ambiguous
  candidates require separately authorized cleanup. Rollback republishes
  known-good content under a higher generation, and activation still requires
  external runtime/mailflow smoke evidence. Manual LDAP/SQL key mutation
  remains unsupported. This implementation candidate is pending final review
  and is not a release claim. See the
  [native-domain runbook](../operator/native-domain-onboarding.md).
- Product images are Linux `amd64` and `arm64`; release preparation does not
  publish them or create `latest`, stable, minor, or major aliases.

Stable IDs and resolution criteria for draft and interpretation limits are in
[the issue log](draft-issues.md).
