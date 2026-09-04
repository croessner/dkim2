# Known Limitations

The first preview is a tested reference candidate, not a final DKIM2 standard,
certification, or universal interoperability claim.

- Draft-06 architecture references, full-chain policy guidance, EAI, IANA,
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
- Postfix/Milter qualification is implemented. Exim is
  `unqualified_draft06`; the five source-linked upstream, Debian, and Ubuntu
  rows in the compatibility report are historical Draft-04 evidence. There is
  no current Draft-06 Exim execution claim, universal local-scan binary, or
  Exim container image.
- The daemon supports outgoing null-reverse-path DSN signing only through the
  Postfix-exclusive route, `delivery_status` profile, route ticket, and
  protected DSN capability. The library retains a strict generic evidence
  constructor for trusted integrations. The originator Milter deliberately tempfails every null
  sender. The dedicated `postfix_dsn` adapter requires the bounce-only Postfix
  `{postfix_dsn_origin}` enum patch and accepts only exact `internal`.
  Received-DSN evaluation and Draft-06 Section 12.1.1 DSN propagation are
  not implemented yet. Their implementation-ready contract is
  [delivery-status-propagation.md](../specs/implementation/delivery-status-propagation.md);
  until it is closed out, an inbound DSN is verified only as an ordinary
  message and no DSN is propagated backwards. That contract also excludes
  propagation when the previous hop is itself an `nd=` signature, and it
  cannot propagate when the previous hop's public key was rotated away or
  revoked between forwarding and the arrival of the DSN.
- Flat-file, LDAP, PostgreSQL, MySQL, MariaDB, and Valkey datasource paths are implemented.
  The offline OpenDKIM migration requires separately managed verified-TLS
  services, explicit mapping, and distinct least-authority principals.
- The online daemon has no key-generation, DNS-mutation, or datasource-write
  surface. Native key generation and onboarding exist only in the protected
  offline `dkim2d datasource domain` workflow. It exports DNS records but does
  not publish them, proves only a fresh configured recursive resolver path,
  makes no authoritative-query or cache-bypass claim, persists no
  runtime-verified state, and performs no automatic candidate deletion. Normal
  scheduled rotation is an offline one-candidate global campaign; retention
  plans and explicit purge applies remain separately authorized, provider-role
  fenced operations. Retained or ambiguous candidates require reconciliation
  rather than implicit cleanup. Rollback republishes
  known-good content under a higher generation, and activation still requires
  external runtime/mailflow smoke evidence. Manual LDAP/SQL key mutation
  remains unsupported. This implementation candidate is pending final review
  and is not a release claim. See the
  [native-domain runbook](../operator/native-domain-onboarding.md).
- Product images are Linux `amd64` and `arm64`; release preparation does not
  publish them or create `latest`, stable, minor, or major aliases.
- The Draft-06 replay identifier is a drain-only epoch rotation. Draft-04 and
  Draft-06 replay traffic cannot overlap; old records become unreachable and
  the resulting detection gap is bounded by the configured retention period.

Stable IDs and resolution criteria for draft and interpretation limits are in
[the issue log](draft-issues.md).
