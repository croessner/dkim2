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
  implemented against
  [delivery-status-propagation.md](../specs/implementation/delivery-status-propagation.md)
  through the read-only `delivery_status` projection of `POST /v1/process`,
  the replay-gated `POST /v1/dsn/propagate` and
  `POST /v1/dsn/propagate/commit` routes, and the `dkim2-dsn-propagator`
  adapter. The following limits remain.
- Propagation is refused as `unsupported_chain` when the previous hop is
  itself an `nd=` signature without `mf=`, or when a member of the local hop
  run does not verify. Reconstructing an earlier system's custody scheme is
  out of scope, and the refusal is deliberate rather than an approximation.
- Propagation cannot complete when the previous hop's public key was rotated
  away or revoked between forwarding and the arrival of the notification. The
  previous hop's signature is verified over the reconstructed state, with the
  Draft-06 Section 8.4 window evaluated at the completion signature's `t=`,
  before its `mf=` may become a recipient; without a resolvable key the
  outcome is a permanent refusal, not a best-effort delivery.
- An EAI previous hop cannot be propagated to. The signed-envelope grammar of
  this implementation is ASCII-only, so a previous-hop `mf=` carrying a
  non-ASCII address does not parse, the embedded signature therefore does not
  verify, and the outcome is `embedded = unverified` with a propagation state
  that is never `eligible`. The refusal happens at signature parsing, before
  any rebuild. The `smtputf8_required` fact still exists for notifications
  whose rebuilt header fields carry non-ASCII bytes for other reasons; it is
  computed over every rendered byte outside the embedded original's body, and
  the adapter fails closed when the re-injection listener does not advertise a
  required `SMTPUTF8` or `8BITMIME` extension.
- Propagation is at-least-once, bounded by the two-phase replay gate. A
  duplicate notification can reach the previous hop in three windows: the
  crash window between the re-injection listener's `250` and the commit; a
  lease that expired while an attempt was still running; and a commit token
  the daemon can no longer resolve, because tokens live in a bounded
  process-local ledger that a daemon restart empties and that evicts entries
  once its capacity is reached. An unresolvable token is answered `409`, is
  deferred by the adapter as `451`, is retried by the MTA, and is re-served
  with a fresh rebuild once the lease expires. Set the MTA's minimum retry
  interval for the LMTP transport above `dsn_propagation.pending_lease` so a
  retry cannot land
  inside a live lease.
- The Valkey replay parity gate accepts only the exact `valkey-server` 9.1.0
  binary. The propagation store's conditional `SET` forms need Valkey 8.1 for
  `IFEQ` and `NX GET` and stay inside that 9.1 floor, but the pinned parity
  test does not run against a nearby patch release and offers no container
  path; a host carrying a different 9.1 patch level cannot produce this
  evidence.
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
