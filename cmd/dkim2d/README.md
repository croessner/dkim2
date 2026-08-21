# dkim2d

`dkim2d` is the local HTTP/JSON daemon around the standalone DKIM2 library.
The current API performs inbound verification, local policy evaluation, replay
coordination, and disposition projection, and also performs datasource-backed
originator signing and ordinary-transit revision.

The daemon is a thin adapter. Raw RFC 5322/RFC 6532 message bytes, SMTP
envelope evidence, DKIM2 verification, policy, and replay semantics remain
owned by `github.com/croessner/dkim2`. The authoritative REST contract is
[`docs/specs/openapi/dkim2d.yaml`](../../docs/specs/openapi/dkim2d.yaml).
The production navigation and container trust topology start in
[`docs/operator/postfix-compose.md`](../../docs/operator/postfix-compose.md).
LDAP/PostgreSQL/MySQL/MariaDB installation and migration are documented in
[`docs/operator/datasource-backends.md`](../../docs/operator/datasource-backends.md)
and
[`docs/operator/opendkim-migration.md`](../../docs/operator/opendkim-migration.md).

## Local Security Boundary

Run one daemon instance under a dedicated, unprivileged service UID. The
effective UID, local root, and the kernel are trusted. Other local UIDs and
processes that can merely reach localhost are not trusted.

The listener accepts exactly one canonical loopback IP literal and nonzero
port. The default is `127.0.0.1:8080`. Hostnames, wildcard or unspecified
addresses, non-loopback addresses, IPv4-mapped IPv6, zone identifiers, Unix
sockets, port zero, and multiple listeners are rejected. There is no remote
plaintext compatibility mode.

`/v1/process`, `/v1/sign`, and `/v1/revise` each require
`X-DKIM2-Capability`. The value is the canonical unpadded Base64url encoding
of the exact 32 raw bytes in that route's current-generation capability file.
Process, sign, and revise capabilities must be distinct. Missing, duplicate,
malformed, noncanonical, or mismatching values all receive the same closed
`403` response before readiness, body, DNS, policy, replay, or signing work.
`/healthz`, `/readyz`, and `/metrics` do not use this header.

Grant capability-file access only to the daemon UID and approved local
adapters. Do not place capability bytes or their encoded form in arguments,
environment variables, logs, traces, metrics, diagnostics, or ordinary
configuration. `dkim2-milter` and `dkim2ctl` provide protected-file loaders for
the capabilities they use; they never receive private keys or datasource
records.

Loopback HTTP is deliberately plaintext and HTTP/1-only. Do not put a reverse
proxy, TCP forwarder, TLS terminator, container port publication, or other
reachability expansion in front of it.

## Command And Exit Status

Run:

```text
dkim2d serve --config /absolute/path/to/dkim2d.yaml
```

Before activation, validate the same configuration and complete protected
generation without opening a listener:

```text
dkim2d validate --config /absolute/path/to/dkim2d.yaml
```

Validation performs the production descriptor-confined load, including the
selected replay, tracing, datasource, signing-manifest, and PKCS#8 children,
then releases all protected values. It is silent on success and never creates,
repairs, changes ownership of, or rewrites protected state.

The container readiness probe is:

```text
dkim2d probe
```

It performs one non-proxied, non-retrying, two-second `GET` of the fixed
`http://127.0.0.1:8080/readyz` endpoint, discards bounded response bytes, and
succeeds only on `200`. Deployments using the product image health check
therefore keep the daemon on its default container-local authority.

The command accepts no positional arguments. The only configuration flags are:

```text
--listen
--policy-mode
--replay-backend
```

Exit status is `0` for help or a clean shutdown, `2` for command-shape and flag
errors, and `1` for configuration, startup, dependency, serve, or shutdown
failure. Runtime diagnostics are stable and content-free; the daemon does not
print an effective configuration or raw dependency errors.

Offline datasource administration uses separate commands and authorities:

```text
dkim2d datasource bootstrap-opendkim --config /absolute/migration.yaml
dkim2d datasource bootstrap-opendkim --config /absolute/migration.yaml --apply
dkim2d datasource rollback --config /absolute/migration.yaml --generation 43
```

These commands never start the ordinary daemon graph. Dry-run is the default;
mutation requires `--apply` or the explicit rollback command.

### Native domain onboarding

Native domain onboarding is a separate one-shot offline workflow. Its complete
stable command tree is:

```text
dkim2d datasource domain plan --config /abs/admin.yaml --intent /abs/domain.yaml --operation /abs/op.json
dkim2d datasource domain prepare --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain dns export --config /abs/admin.yaml --operation /abs/op.json --output /abs/records.txt
dkim2d datasource domain prove --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain activate --config /abs/admin.yaml --operation /abs/op.json --apply
dkim2d datasource domain status --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain reconcile --config /abs/admin.yaml --operation /abs/op.json
dkim2d datasource domain abort --config /abs/admin.yaml --operation /abs/op.json
```

The complete operator sequence, recovery matrix, backup requirements,
higher-generation rollback, and parser-checked configuration and intent
examples are in
[`docs/operator/native-domain-onboarding.md`](../../docs/operator/native-domain-onboarding.md).

Only the single bare token `--apply` authorizes activation. Missing `--apply`,
`--apply=false`, `--apply=true`, aliases, short forms, repeated forms, and
tokens after `--` fail as command-shape errors. `status` does not update the
journal or backend and opens only an already-existing operation lock. A status
request for a missing operation therefore creates neither a journal nor a lock
artifact. `reconcile` is the sole command that may update journal knowledge
from an exact backend inspection. There is no `verify` command and no persisted
verified state.

All paths must be clean absolute paths beneath trusted owner-only directories.
The administration document, intent, operation journal, DNS export, CA bundle,
and three credential files must not overlap. Protected documents and secrets
are regular owner-only `0600` files with no links. DNS material is written only
to the explicitly requested protected export artifact and never to stdout,
logs, traces, or metrics. Export is create-only: an exact existing artifact is
an idempotent success, while any different existing content is a conflict and
is never replaced. A create whose final outcome cannot be proved exactly fails
as ambiguous and must be retried against the same path.

The administration schema is `dkim2-domain-admin-v1`. It requires a random,
deployment-unique, nonzero 128-bit `authority_id` in canonical lower-case
unpadded Base32, one direct verified-TLS endpoint, one protected CA bundle,
and distinct snapshot, staging, and activation identities and credential
files. LDAP uses `ldap` plus a canonical base DN and three canonical service
DNs. PostgreSQL uses `postgresql`, database plus the fixed
`dkim2_datasource` schema, and three roles. MySQL and MariaDB use their exact
backend class, and `schema` must equal `database`. The legacy
`dkim2_publisher` role is never a v3 administration authority. Generic DSNs,
shared roles, shared credential contents, insecure transport, and provider
fallbacks are rejected.

Scalar values support one nonrecursive `${NAME}` environment expansion pass
before typed validation. Plain whole placeholders are resolved through native
YAML scalar typing; quoted placeholders remain strings. Missing or malformed
variables fail closed, map keys are never expanded, and secret bytes remain in
their protected files.

`dns export` produces DNS-04 records for operator publication. `prove` and
`activate` use a fresh configured recursive resolver path and compare exact
SPKI material. This is not a direct authoritative-server observation and does
not claim recursive-cache bypass. After activation, whether completed directly
by `activate` or recovered authoritatively by `reconcile`, the successful
report says `runtime_smoke_required=true`: operators must perform the existing
external runtime signing and mailflow smoke. The flag is mandatory for exactly
those two successful activated results and forbidden everywhere else. The
offline command never claims that runtime behavior is verified.

Complete human and `--machine` operation reports contain only bounded state,
backend, phase, result, failure, boolean classes, expected/candidate generation
numbers, total/RSA/Ed25519 credential counts, and a current generation only
when it is authoritatively known. Expected, candidate, and credential-count
facts remain present for every complete-plan result. A known zero current for
first publication remains explicit, while a failure without authoritative
current evidence omits the entire current field rather than printing zero. A
successful terminal-conflict `reconcile` is the sole nonactivated success that
reports a current different from the expected generation: it preserves the
authoritatively observed third-party value, distinct from both expected and
candidate. All other successful nonactivated workflows report the exact
expected current. A bounded workflow failure report is written before the fixed
content-free runtime diagnostic, while the process still exits `1`.
Receipt reports are a distinct projection and expose no state, generation,
credential count, revision, operation identity, authority, paths, selectors,
DNS content, or digests. `release_required` and `unresolved` direct the operator
to `status` and explicit `reconcile`; repeated abort of a `closed` receipt is an
idempotent success.

Every offline domain command constructs one command-local, exporter-free
observer. Exactly one bounded event must match the command result or status;
missing, duplicate, invalid, or contradictory evidence fails the command. This
path does not construct the daemon Fx graph, listeners, OpenTelemetry exporters,
or Prometheus endpoints and emits no observation payload to stdout or stderr.

The first publication into a proven-empty backend uses the exact
`expected_current: "0"` administrative fence and a nonzero candidate. LDAP
proves the subtree empty and publishes current only at Activate through one
atomic LDAP Add with no placeholder current. PostgreSQL proves all datasource
tables empty in the serializable activation transaction and uniquely inserts
the singleton current row. Zero is never runtime-loadable, a nonempty
pointerless backend fails closed, and later publication requires the exact
nonzero current generation.

The internal receipt-before-Claim boundary is recovery evidence, not another
public state. `release_required` is write-ahead authorization for explicit
reconcile only: ownerless unchanged revision does not close it. An unresolved
receipt may close directly only from authoritative ownerless exact-revision
evidence and performs no Release. Receipt or journal ambiguity never
authorizes another backend mutation from an in-memory result.

## Configuration Sources

The required YAML version is:

```yaml
config:
  version: dkim2d-config-v1
```

Configuration precedence is typed defaults, YAML, explicitly bound
environment variables, then the three flags above.
`config.version` and `protected.generation` are YAML-only. Every other stable
path has one explicit `DKIM2D_...` environment name, for example
`DKIM2D_SERVER_LISTEN` and `DKIM2D_REPLAY_HMAC_KEY_FILE`. Arbitrary
environment names are ignored.

Scalar string values may contain one nonrecursive `${NAME}` expansion pass.
Map keys are never expanded. Missing variables fail closed. Secret bytes are
never configuration or environment values; only protected absolute paths may
be supplied.

### DNS key cache

The daemon retains DNS TTLs and caches public-key lookup outcomes in process.
Cache lifetimes are the shorter of authoritative DNS TTL evidence and the
configured cap; the daemon does not invent a fallback TTL. CNAME chains use
their shortest TTL, while NXDOMAIN and NODATA use the RFC 2308 SOA rule.

```yaml
dns:
  lookup_timeout: 5s
  max_concurrent_lookups: 64
  cache:
    max_entries: 4096
    positive_ttl_cap: 1h
    negative_ttl_cap: 5m
    stable_error_ttl_cap: 1m
```

`max_entries` accepts 0 through 65,536. The TTL caps accept zero to disable
their respective cache class and are bounded at 24 hours, 1 hour, and 5
minutes. The corresponding environment variables are
`DKIM2D_DNS_CACHE_MAX_ENTRIES`, `DKIM2D_DNS_CACHE_POSITIVE_TTL_CAP`,
`DKIM2D_DNS_CACHE_NEGATIVE_TTL_CAP`, and
`DKIM2D_DNS_CACHE_STABLE_ERROR_TTL_CAP`.

### Inbound policy mode

`policy.mode` defaults to `strict`; omitting it enables enforcement. Operators
must select a compatibility policy explicitly when the Draft-04 verifier is
introduced beside an existing inbound path:

- `strict` accepts `PASS`, rejects `FAIL` and `PERMERROR`, and temporarily
  defers `TEMPERROR`;
- `permissive` accepts `FAIL` and `PERMERROR` for rollout compatibility while
  preserving temporary deferral for `TEMPERROR`; and
- `testing` returns non-terminal `continue` for every coherent verification
  state so the daemon can report results without controlling delivery; when
  reporting is enabled, the response still carries the exact daemon-owned
  `Authentication-Results` action.

These modes apply only when at least one DKIM2 protocol field family is
present. A syntactically valid message with neither `Message-Instance` nor
`DKIM2-Signature` is not a failed verification: `/v1/process` returns HTTP 204
with no body, performs no DNS lookup, policy evaluation, replay check, or
daemon-requested mutation, and the Milter continues delivery without a DKIM2
result action. Independently, an enabled Milter trust boundary still removes
forged local `Authentication-Results` fields as required by RFC 8601. A message
containing only one field family, malformed fields, missing referenced fields, or
inconsistent sequences remains an applicable `PERMERROR`; `strict` may reject
it. There is no domain-wide DNS participation probe because the selector and
signing domain needed for key lookup come from a present DKIM2 signature.

The verification state remains unchanged in every mode. `testing` is the
delivery-neutral pilot choice and reports applicable results on its accepting
non-terminal `continue` disposition. `permissive` is useful when failed or
permanently erroneous verification should receive an accepting terminal
disposition. Neither mode converts local daemon ambiguity, invalid responses,
unavailable dependencies, or Milter fidelity failures into success.

Originator signing has a separate authorization boundary and does not inherit
the inbound policy mode. A healthy authoritative absent or inactive exact
signing policy returns bodyless HTTP 204: signing is not applicable and the
caller continues without mutation. An unavailable, degraded, ambiguous, or
inconsistent datasource remains temporary; malformed active configuration
remains permanent. HTTP 204 is never an availability fallback.

Null senders are classified by the originator Milter before daemon I/O and
continue to tempfail there. The separate `postfix_dsn` adapter may call the DSN
route only after exact Postfix-only `internal` origin validation. The body has
no caller-selected fidelity; the dedicated DSN capability is the server-side
provenance attestation and must not be shared. The adapter requires the corresponding Postfix
patch before deployment. Address literals and otherwise unsupported valid
SMTPUTF8 envelopes remain not applicable and continue unchanged. Malformed
Milter callback syntax remains fail-closed. The implementation does not infer
DSN signing authority from message headers, HELO, recipients, suffixes,
wildcards, tenant defaults, or caller-selected domains. It verifies the
embedded DKIM2 object first and resolves `delivery_status` policy by the exact
canonical authenticated highest `d=` value.

### Explicitly disabled replay

This is the smallest valid document:

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  backend: disabled
```

Disabled replay is explicit local policy. It loads no replay HMAC, constructs
no replay deriver, and does not silently fall back to another backend.

### Flat-file signing, revision, and delivery status

Signing is disabled by default. Enabling the flat-file backend requires one or
more distinct signing-route capabilities and a datasource, private-key
manifest, and referenced PKCS#8 children from the same protected generation:

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
  sign_capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/sign-capability
  revise_capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/revise-capability
  dsn_sign_capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/dsn-sign-capability
replay:
  backend: disabled
signing:
  backend: flat_file
  datasource_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/datasource
  private_manifest_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/private-manifest
```

Omit every unused route capability. `dsn_sign_capability_file` authorizes only
the Postfix-exclusive `/v1/dsn/sign`; possession attests that its sole adapter
established trusted `internal` origin. It is distinct from process, sign,
revise, replay, and all other protected material and must not be shared with a
diagnostic client or another adapter. The datasource is the closed
`dkim2-datasource-v1` format documented in
[`docs/specs/implementation/datasource-providers.md`](../../docs/specs/implementation/datasource-providers.md).
The private manifest is `dkim2-private-keys-v1`; every entry binds one exact
tenant, domain, `originator`, `ordinary_transit`, or `delivery_status` use, opaque datasource
handle, `rsa-sha256` or
`ed25519-sha256` algorithm, canonical Base64 SHA-256 digest of the public SPKI,
and direct-child private-key filename. A private-key child is one unencrypted
PKCS#8 `PRIVATE KEY` PEM whose derived public key matches that digest,
algorithm, datasource credential, and handle. Unknown fields, duplicate
bindings, aliasing children, mixed identities, encrypted or legacy PEM, and
partial generations fail the complete load. Documentation and test fixtures
use reserved `.test` identities; operators supply only their own authorized
production policy.

The reload interval revalidates the same descriptor-confined snapshot; it does
not authorize editing an active protected generation or switching generation
selectors. A complete valid candidate is published atomically. An invalid
candidate is never published: the prior snapshot remains retained only for
owned in-flight work while the runtime becomes degraded and readiness
withdraws.

### LDAP, PostgreSQL, MySQL, and MariaDB signing

The `ldap`, `postgresql`, and `mysql` signing backends replace the flat-file
datasource with one verified-TLS immutable committed generation containing the
canonical PKCS#8 DER keys for its opaque handles. LDAP, PostgreSQL, MySQL, and
MariaDB accept an exact complete `dkim2-datasource-v2` or
`dkim2-datasource-v3` generation. These backends reject
`private_manifest_file`; no local private-key tree is mounted. The public
dataset and native keys must validate as one exact generation. Initial-load failure
prevents readiness; a linearized refresh failure makes new leases unavailable
until a complete higher generation loads. Exact configuration examples,
schema/DDL installation, role separation, backup, and recovery are in the
datasource operator guide linked above. MariaDB uses the `mysql` selector and
the same typed, verified-TLS provider contract.

The LDAP tree and attributes are documented in the
[`LDAP schema reference`](../../docs/operator/ldap-schema-reference.md); normal
generation replacement and retirement are documented in the
[`key-rotation runbook`](../../docs/operator/datasource-key-rotation.md).

### Offline global rotation campaigns

`dkim2d datasource rotation` is a closed offline command surface. A scheduled
normal run always means the complete frozen active-binding inventory: it creates
one immutable candidate and moves `current` once only after every bounded DNS
batch has fresh proof. It never creates one generation per domain.

```text
dkim2d datasource rotation run --config /path/to/rotation.yaml --journal /path/to/campaign.json --automatic
dkim2d datasource rotation run --config /path/to/rotation.yaml --journal /path/to/campaign.json --automatic --apply
dkim2d datasource rotation emergency --config /path/to/rotation.yaml --journal /path/to/campaign.json --tenant <exact> --domain <exact> --use <exact> --profile <exact> --reason <bounded-class> --apply
dkim2d datasource rotation abort --config /path/to/rotation.yaml --journal /path/to/campaign.json --apply
dkim2d datasource rotation purge plan --config /path/to/rotation.yaml --journal /path/to/campaign.json --output /path/to/purge.json
dkim2d datasource rotation purge apply --config /path/to/rotation.yaml --journal /path/to/campaign.json --plan /path/to/purge.json --apply
```

`--automatic` is mandatory for a normal campaign. Emergency selection, pointer
mutation, and purge destruction are never defaults: they require their explicit
subcommand and one exact bare `--apply`. The normal command defaults to
read-only `--dry-run`; `--dry-run` and `--apply` are mutually exclusive.
Human and machine reports contain only counts, backend class, command, state,
and closed result classes; they never contain domains, DNs, selectors, plan
digests, DNS content, provider errors, or key material.

The protected campaign configuration uses five distinct role credentials:
snapshot, staging, activation, purge, and the terminal-only closer. All configured limits are finite and
below compiled maxima. The selected public compatibility contract is
[`admincontract`](../../lib/admincontract), whose strict synthetic fixture is
checked by `make check-admin-contract` before a consumer binds the owner API.

### Process-local memory replay

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  backend: memory
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
```

Memory replay is bounded but process-local. Restart, multiple daemon instances,
and failover do not share its state.

### Production Valkey replay

Valkey is the default backend, but missing authority or attestation fields
fail configuration; there is no fallback. A complete shape is:

```yaml
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/capability
replay:
  hmac_key_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/hmac
  epoch: 1
  valkey:
    address: 127.0.0.1:6379
    server_name: replay.example
    ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/ca
    application_username: application
    application_password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/application-password
    auditor_username: auditor
    auditor_password_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/auditor-password
    attestation:
      persistence_mode: rdb
      append_fsync_policy: inactive
      save_schedule: "60 1"
      min_replicas_to_write: 0
      min_replicas_max_lag_seconds: 30
      loss_window_acceptance: asynchronous_acknowledged
      rotation_state: unchanged
      no_global_exactly_once_claim: true
      dedicated_deployment: true
      dedicated_database_zero: true
      direct_ip_authority: true
      no_endpoint_substitution: true
      standalone_authority: true
      shared_draft: true
      shared_algorithm: true
      shared_namespace: true
      shared_epoch: true
      shared_secret_set: true
      shared_retention: true
```

The supported authority is one directly addressed standalone Valkey primary,
database zero, with TLS 1.3, exact peer identity, private roots, separate
application and auditor principals, no retries, and no endpoint substitution.
Cluster, Sentinel, redirects, DNS authority selection, replicas, load
balancers, Unix sockets, active-active products, and automatic failover are
unsupported. See
[`docs/replay-store-valkey.md`](../../docs/replay-store-valkey.md) for the ACL,
persistence, replication, loss-window, and rotation contract.

## Protected Generation

The YAML file and every protected object are owned by the daemon's effective
UID. The YAML file is mode `0400` or `0600`, is outside the generation
directory, has one link, and is inode-distinct from every protected child.

The generation directory:

- is absolute and ends with the exact 32-character lowercase hexadecimal
  `protected.generation` value;
- is mode `0500` and owned by the daemon UID;
- contains every selected protected path as a direct child; and
- is immutable after publication and never reused.

The capability and HMAC files contain exactly 32 raw nonzero bytes, with no
hex, Base64, delimiter, or stripped newline. Password files contain 1 through
1,024 opaque bytes with no NUL, CR, or LF. Secret files are mode `0400` or
`0600`. The CA file contains only the bounded accepted PEM CA set and may use
the documented read-only modes.

Protected loading uses portable descriptor-native ownership, mode, link, size,
regular-file, no-follow, and stable-read checks on Linux and Darwin. The
application does not classify filesystems, mounts, ACLs, or xattrs; deployment
and container policy own that surrounding boundary.

Create a complete new read-only generation directory, then atomically replace
only the YAML file that selects it. There is no hot reload. Activation requires
a process restart.

## HTTP API

Exactly these paths are routable:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/metrics` | Bounded process-local Prometheus exposition |
| `GET`, `HEAD` | `/healthz` | In-process liveness; no dependency I/O |
| `GET`, `HEAD` | `/readyz` | No-I/O readiness snapshot |
| `POST` | `/v1/process` | Verification, policy, replay, disposition |
| `POST` | `/v1/sign` | Originator signing and ordered append-only actions |
| `POST` | `/v1/revise` | Ordinary-transit verification, revision, and ordered actions |
| `POST` | `/v1/dsn/sign` | Postfix-exclusive authenticated delivery-status signing |

Health and readiness support their declared strong-ETag conditional behavior.
Readiness is `200` only after immutable configuration and protected loading,
dependency construction, listener and serve ownership, open process
admission, and replay authority are ready. Valkey readiness uses the
provider-owned unexpired audit evidence and performs no Valkey call.

The process request carries bounded Base64 message bytes and separate SMTP
reverse/forward path spellings. After JSON and Base64 validation, the adapter
passes the exact decoded message and UTF-8 envelope spellings to the library;
it does not normalize headers, MIME, EAI, SMTPUTF8, or envelope values.
Malformed mail-domain evidence is represented by the library's bounded domain
result rather than repaired by the HTTP layer.

Sign requests carry the exact outgoing message and SMTP envelope plus a
server-owned tenant/domain selector. Revise requests additionally carry exact
incoming SMTP envelope evidence. The daemon resolves policy and private-key
handles from its current signing snapshot and returns only a closed ordered
append-only header action plan; it never exposes a private key, capability,
datasource record, or handle. Generated OpenAPI DTOs remain at this HTTP
boundary and are not a second protocol model.

Every application response has `Connection: close`. Connection reuse,
pipelining, HTTP/2, h2c, generic path cleaning, and redirects are not supported.
All request, connection, body, JSON, envelope, DNS, replay, admission, and
shutdown work is bounded. Error output uses closed status/code mappings and
does not include request bytes, protected values, endpoints, or raw errors.

## Observability

Every daemon instance owns one central JSON `slog` provider, one fresh
Prometheus registry, and one OpenTelemetry provider. None of these use global
registration. Telemetry is nonnormative and cannot change protocol, policy,
replay, HTTP, health, or readiness results.

The secure default uses `info` logging, all debug modules disabled, and no
trace exporter:

```yaml
observability:
  logging:
    level: info
  debug:
    message_shape: false
    dns: false
    replay: false
  tracing:
    exporter: none
```

OTLP/HTTP tracing is explicit and may use a direct local or remote HTTPS
collector:

```yaml
observability:
  tracing:
    exporter: otlp_http
    endpoint: https://collector.example:4318/v1/traces
    ca_file: /var/lib/dkim2d/protected/0123456789abcdef0123456789abcdef/otlp-ca
    sample_per_million: 10000
    export_timeout: 5s
```

The endpoint must use a canonical lowercase ASCII DNS name or canonical IP
literal, an explicit nonzero decimal port, HTTPS, and exactly `/v1/traces`.
The CA is a protected generation child. The URL hostname is the sole TLS peer
identity; normal certificate and hostname/IP verification applies, so there is
no separate `server_name` override. Exactly TLS 1.3 is permitted. Proxies,
redirects, arbitrary headers, environment-driven exporter configuration,
compression overrides, userinfo, queries, and fragments remain rejected.
Loopback HTTPS endpoints remain supported. Remote export does not relax the
daemon HTTP listener's separate loopback-only contract.

`GET /metrics` is public on the same loopback listener and does not require
readiness or the process capability. It accepts no body, query, conditional,
trace, or capability input. Scrapes are untraced and nonrecursive, use the
Prometheus 0.0.4 text format, and are capped at 256 KiB. `HEAD /metrics`
returns `405` with `Allow: GET`.

Logs, trace attributes, and metric labels use closed allowlists. They never
contain message bytes, headers, identities, domains, selectors, recipients,
client addresses, request/session/trace IDs, endpoints, DNS payloads, replay
keys, protected paths or values, certificates, credentials, hashes, or raw
errors. Debug modules add only documented bucket or result classes; they do
not enable payload logging. Prometheus labels are fixed low-cardinality enums,
and the registry deliberately omits standard process/runtime collectors.

## Lifecycle And Recovery

Startup publishes readiness only after all selected owners and loops are live.
The outer startup bound is 115 seconds, including a 100-second acquisition
budget, ten-second reverse rollback budget, and five-second orchestration
margin. Any ambiguous or incomplete startup fails without readiness.

Shutdown first withdraws readiness and closes admission, then joins the
listener and serve loop, performs the configured graceful drain, and uses a
bounded forced close when graceful drain or handler quiescence is not proven.
Only after handlers join does it stop revalidation, cancel DNS, close replay,
flush the instance telemetry provider within five seconds, and release
protected material. If an accept or handler owner cannot be joined, the daemon
reports failure and deliberately retains dependencies rather than tearing
them down underneath live work.

Valkey is audited before readiness and revalidated at the configured interval,
which must be 10 through 60 seconds. Calls do not overlap. Evidence is valid
for strictly less than five minutes. Authority loss, stale evidence, or
revalidation-clearable degradation withdraws readiness; restart-only
credential and contract failures require provider reconstruction or process
restart.

## Deliberately Unsupported

The current daemon does not provide:

- Milter or Exim action application;
- remote HTTP exposure, TLS serving, proxy trust, Unix sockets, or multiple
  listeners;
- OAuth, bearer tokens, request-selected policy, or remote authentication;
- HTTP/2, h2c, persistent connections, or effective-config output;
- hot configuration, secret, certificate, capability, or replay-key reload;
- Valkey cluster, Sentinel, redirects, endpoint discovery, automatic failover,
  or global exactly-once replay claims.

## Verification

From the repository root:

```text
make test
make vet
make lint
make race
make check-openapi
make check-vendor
make test-valkey
make guardrails
```
