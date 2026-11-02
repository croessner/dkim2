# Draft-09 Migration For Operators

This guide covers the move of every DKIM2 component from
`draft-ietf-dkim-dkim2-spec-08` to `draft-ietf-dkim-dkim2-spec-09`. The DNS
baseline stays `draft-ietf-dkim-dkim2-dns-02`. The change-by-change record is
[`docs/specs/draft-09-migration-disposition.md`](../specs/draft-09-migration-disposition.md);
library API changes are listed in
[`docs/reference/compatibility.md`](../reference/compatibility.md). The
previous step is described in [`draft-08-migration.md`](draft-08-migration.md).

Draft-09 adds a fifth verification state, NONE (neither a Message-Instance nor a
DKIM2-Signature header field present),
lets a subdomain `d=` make a parent From domain Authentic unless that domain
publishes a Domain Policy Record with `f=strict`, and turns a null body Recipe
into PERMERROR.

## Ship Everything Together

The REST draft enum (`DraftVersion`) accepts exactly
`draft-ietf-dkim-dkim2-spec-09`. A client that still sends the Draft-08
identifier receives HTTP 400 `unsupported_draft` before any processing. The
API version (`v1`) and every path stay unchanged.

Upgrade these components in one maintenance window, with inbound mail paused
(MX deferred or Milter tempfail) while the daemons and adapters switch:

- `dkim2d` first, then the adapters that call it
- `dkim2-milter`
- the Exim Go adapter and the Exim `local_scan` module, rebuilt from this
  tree: its build ID changed, and a mismatched pair fails closed as a
  contract failure (`451 4.7.1`)
- `dkim2ctl` and `dkim2-dsn-propagator`
- the Rspamd adapter (`contrib/rspamd`): its `DRAFT` constant, the NONE
  state, and the new reasons move with the daemon; a mismatched pair is
  contract drift and fails closed

External consumers of the daemon's REST contract move in the same step:

- `dkim2pub` (vendored OpenAPI contract and generated client, draft
  constants, the NONE state, and the new reason texts)
- `dkim2-intelligence` (the verifier projection draft identifier, its
  fixtures, the projection binding golden, and the state and reason
  vocabularies). The verifier projection binding covers the draft identifier,
  so every Draft-08 binding changes value. Upgrade it directly after the
  daemon, in the same window.

A mixed-draft deployment is unsupported and fails closed.

## Configuration Changes

No configuration path is renamed or removed. One path is new:

- `verification.domain_policy.allow_subdomain_from` (default `true`,
  environment `DKIM2D_VERIFICATION_DOMAIN_POLICY_ALLOW_SUBDOMAIN_FROM`). With
  `true` the verifier follows Draft-09 Section 11.1: when `d=` is a subdomain
  of the From domain, it queries the From domain's Domain Policy Record at
  `_domainkey.<from-domain>` and accepts the From as Authentic unless the
  record carries `f=strict`. With `false` the verifier keeps the Draft-08
  downward-only rule: such a From is `from_not_authentic` and no policy
  record is ever queried. Signers always stay downward only; they never sign
  a parent From with a subdomain key.

Library consumers must make this choice explicitly: `dkim2.NewVerifier` and
`dkim2.NewSigner` fail with `invalid_option` unless the key provider also
resolves Domain Policy Records (`DNSPublicKeyProvider` does) or the caller
passes a policy provider option or the downward-only option.

## Publishing f=strict

A domain that never wants a subdomain signature to speak for its own From
publishes:

```text
_domainkey.example.test. 3600 IN TXT "v=DKIM1; f=strict"
```

`dkim2d datasource domain dns export --domain-policy-strict` appends this
record after the key records, once per exported domain, and proves it
through the same resolver the verifier uses. Before publishing, list every
sender that signs mail with a From in the domain using a `d=` in a subdomain
(ESPs, newsletter tools, ticket systems). Under `f=strict` their mail becomes
FAIL `from_subdomain_forbidden` at Draft-09 verifiers. Draft-08 verifiers
already treated such mail as `from_not_authentic`, so `f=strict` keeps the
earlier behavior for these senders. The record has no effect on signatures
whose `d=` equals or is a parent of the From domain.

## REST And Signal Changes

- NONE: `POST /v1/process` answers HTTP 200 with `verification.state: NONE`
  for a message with neither a Message-Instance nor a DKIM2-Signature field,
  instead of HTTP 204. The policy
  object is `{verdict: continue, reason: none}`, replay is `not_checked`,
  and with an authserv-id configured the plan carries
  `Authentication-Results: <authserv-id>; dkim2=none`. Milter, Exim,
  `dkim2ctl`, and Rspamd treat a 204 from `/v1/process` as a contract failure.
  Dashboards on the state label gain the value `none`.
- Null body Recipe: `body_history_unavailable` moves from FAIL to PERMERROR
  (Section 14.2). Verdicts and actions are unchanged; Rspamd reports it with
  `DKIM2_PERMERROR` instead of `DKIM2_FAIL`.
- New reasons:
  - `from_subdomain_forbidden` (FAIL): the From domain publishes `f=strict`
    and only a subdomain `d=` signed for it.
  - `domain_policy_temporary` (TEMPERROR): the Domain Policy Record lookup
    failed temporarily. The adapters tempfail like any other temporary DNS
    failure.
  - `domain_policy_ambiguous` (PERMERROR): more than one record beginning
    with `v=DKIM1` at `_domainkey.<from-domain>`.
  - `domain_policy_invalid` (PERMERROR): the record is malformed or the
    lookup failed permanently.
- Key records (Section 3.7): TXT records at a selector owner whose `v=` is not
  `DKIM1` are ignored before the uniqueness check. Resolvers now carry up to
  eight records (`dkim2.MaxCarriedTXTRecords`); more are ambiguous.
- `rt=` rendering (Section 2.14): a base64 string has no leading or trailing
  FWS, so the signer folds inside the next recipient instead of after the
  comma. The parser still accepts FWS after the `rt=` comma for compatibility
  with Draft-08 signers; FWS before a comma is rejected.
- DNS lookups: a message whose `d=` is a subdomain of its From domain costs
  one more TXT query per distinct From domain, counted in the verification
  usage. `dkim2d_dns_lookups_total` still counts key lookups only.
- `X-DKIM2-Info`: `draft=` names Draft-09, and `date=` is now the date the
  emitted behavior last changed (draft-gondwana-dkim2-debug-header-02), not
  the signing date. The hop block order is unchanged.

## Replay Store Transition

The draft identifier is bound into the replay HMAC frame, so Draft-09 keys
never equal Draft-08 keys. Upgrade in place: keep the replay epoch and HMAC
secret and restart every daemon that shares the store on the new release. The
replay identity space restarts: a message first seen under Draft-08 and
replayed afterwards counts as `first_seen` once more, for up to the 14-day
retention. The Redis key grammar, namespace, ACL, and commands do not change.

## Rollback

- Roll back with the previous image digests of every component and the
  previous Rspamd configuration set, in the same maintenance step; a
  Draft-08 adapter against a Draft-09 daemon fails closed.
- Roll back `dkim2pub` and `dkim2-intelligence` together with the daemon.
- Replay state is not backward compatible: records written under Draft-09 are
  not found by a Draft-08 daemon and expire by their own TTL; the restart
  exposure above repeats in the other direction.
- A Draft-08 daemon rejects `verification.domain_policy.allow_subdomain_from`
  as an unknown key; remove it before rolling back.
- A published `f=strict` record can stay: Draft-08 verifiers ignore it.
