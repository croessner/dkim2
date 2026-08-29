# Postfix Compose Operator Guide

This guide deploys the implemented daemon and Milter with Postfix while
preserving the existing trust boundaries. Protocol behavior remains pinned to
`draft-ietf-dkim-dkim2-spec-06` and the tested
`draft-chuang-dkim2-dns-04` behavior. The authoritative HTTP contract remains
[`docs/specs/openapi/dkim2d.yaml`](../specs/openapi/dkim2d.yaml).

## Reference map

This guide is the durable deployment entry point. Use
[`cmd/dkim2d/README.md`](../../cmd/dkim2d/README.md) for typed configuration,
protected generations, process/sign/revise capabilities, flat-file signing,
disabled/memory/Valkey replay, readiness, HTTP limits, and observability;
[`cmd/dkim2-milter/README.md`](../../cmd/dkim2-milter/README.md) for Milter
modes, message fidelity, ordered actions, Authentication-Results, failure
policy, probes, and socket ownership; and
[`cmd/dkim2ctl/README.md`](../../cmd/dkim2ctl/README.md) for generated-client
smoke and fixture workflows. Image and evidence procedures live in
[`docs/operator/container-supply-chain.md`](container-supply-chain.md).
Normative implementation details remain in the linked implementation specs
and are not redefined here.

## Trust topology

Each route has a distinct daemon/Milter pair:

```text
daemon-inbound     loopback HTTP <- milter-inbound     -> inbound/milter.sock
daemon-originator  loopback HTTP <- milter-originator  -> originator/milter.sock
daemon-transit     loopback HTTP <- milter-transit     -> transit/milter.sock
                                                        |
                                                   Postfix queue
```

The Milter shares only its daemon container's network namespace. The daemon
continues to listen on canonical `127.0.0.1`; no bridge listener is introduced.
Postfix can access only the three read-only Unix-socket mounts, its durable
queue, and its own writable runtime configuration volume. It cannot access
daemon configuration, capabilities, datasource generations, signing manifests,
private keys, replay material, or traces.

The default Compose rendering publishes zero host ports. The optional demo
override publishes only Postfix SMTP as `127.0.0.1:2525`. Daemon HTTP,
metrics, and Milter endpoints are never published.

## Host and protected-state prerequisites

Production protected state may use the storage selected by the deployment.
DKIM2 validates direct-child placement, owner, mode, link count, regular-file
shape, size, no-follow traversal, and stable descriptor reads. It does not
classify filesystem type, mount identity, ACLs, or xattrs. A generic Docker
secret is suitable only when it preserves the remaining file contract.

The daemon images use numeric UID/GID `2000:2000`; the Milter images use
`2000:103`. Before start, create:

```text
deployments/postfix-compose/state/daemon/inbound/<32-lowercase-hex-generation>/
deployments/postfix-compose/state/daemon/originator/<32-lowercase-hex-generation>/
deployments/postfix-compose/state/daemon/transit/<32-lowercase-hex-generation>/
deployments/postfix-compose/state/milter/inbound/
deployments/postfix-compose/state/milter/originator/
deployments/postfix-compose/state/milter/transit/
deployments/postfix-compose/state/sockets/inbound/
deployments/postfix-compose/state/sockets/originator/
deployments/postfix-compose/state/sockets/transit/
deployments/postfix-compose/config/
```

Each daemon route root and generation is owner `2000:2000`, mode `0500`, and
immutable after validation. The generation name is the exact
`protected.generation` selector: 32 lowercase hexadecimal characters. Every
selected protected path is a direct child of that generation and an
owner-`2000` regular file with one link and mode `0400` or
`0600`. No selected children may alias one inode. Capability and replay HMAC
files contain exactly 32 raw nonzero random bytes. Valkey password children
contain 1 through 1,024 opaque bytes without NUL, CR, or LF; the private CA
bundle and optional OTLP CA must satisfy their bounded PEM loaders. The
signing manifest and PKCS#8 children follow the signing-store contract in
[`cmd/dkim2d/README.md`](../../cmd/dkim2d/README.md). The flat-file datasource
is one complete validated `dkim2-datasource-v1` generation.

The three Milter capability files are separate 32-byte values below their
route-local roots:

```text
state/milter/inbound/capability
state/milter/originator/capability
state/milter/transit/capability
```

Never reuse a route capability. Milter YAML files are owner `2000`, mode
`0400` or `0600`; their capability files are owner `2000`, one-link regular
files with mode `0400` or `0600`, below the same owner-`2000`, mode-`0500`
route root. Use group `103` consistently for these route-local Milter files;
the loaders authorize by effective UID and mode, not by a broader group grant.
Each route socket directory is owner `2000:103`, mode `0750`, and not writable
by other users. A Milter receives only its route directory read-write. Postfix
receives the three directories read-only at distinct subpaths and traverses
them through supplementary GID `103`; no Milter can inspect, delete, or replace
another route's socket. Steady-state containers never generate, repair, chmod,
or chown protected material.

Preparation is an operator-owned offline step. Use a restrictive umask, create
files without following links, set the numeric owner and final mode, and
publish only a complete generation. The product has no
production key, capability, password, or HMAC generator. Never copy the
test-only deployment bootstrap or its reserved-domain material into production.
Never repair an active generation in place.

The checked Compose YAML files are templates. Copy the exact daemon and Milter
configuration shapes from the component READMEs, use only absolute in-container
paths, validate them before activation, and store the resulting YAML as:

```text
config/dkim2d-inbound.yaml
config/dkim2d-originator.yaml
config/dkim2d-transit.yaml
state/milter/inbound/inbound.yaml
state/milter/originator/originator.yaml
state/milter/transit/transit.yaml
```

Optional OTLP/HTTP export may use a canonical remote HTTPS collector as
documented in the daemon README. Provide the selected generation's protected
CA child and only the required outbound DNS/HTTPS reachability. This does not
authorize publishing or proxying the daemon's loopback-only HTTP listener.

Inbound uses the process capability and may use disabled, memory, or a
separately operated directly addressed Valkey replay backend. Originator uses
the sign capability. Ordinary transit uses the revise capability. Only the
daemon loads the flat-file datasource, private manifest, and PKCS#8 children.

The originator Milter continues to tempfail every `MAIL FROM <>` message before
daemon I/O. Locally generated Postfix bounces use a separate `postfix_dsn`
Milter route whose signing block contains only the administrative tenant and
`domain_source: verified_embedded`; it must not contain `signing.domain` or
`signing.dsn_domain`. The adapter admits that route only for the exact
EOH-confirmed `{postfix_dsn_origin}=internal` value. The daemon then verifies
the complete embedded Draft-06 evidence before datasource access, derives the
canonical highest authenticated `d=`, and resolves the exact
`delivery_status` policy for that tenant/domain pair. This permits one route to
serve multiple domains without trusting the outer envelope or caller-selected
domain. Missing, ambiguous, unavailable, or mismatched policy/profile data
fails closed.

For a rejected DSN before policy resolution, inspect the single
`dsn.evidence.completed` log event or the matching
`dkim2d_dsn_evidence_total{evidence_stage=...,result=...}` counter. The closed
stage distinguishes outer MIME parsing, embedded-message parsing or
verification, RFC 3464 linkage, outer-recipient linkage, and signing-domain
derivation without logging the domain, selector, address, queue ID, signature,
or message bytes. `authorized` proves evidence completed before datasource
acquisition; it does not by itself prove policy resolution or signing.

### Postfix DSN wire-profile upgrade

This is a closed contract change, not a rolling-compatible configuration
addition. Replace either legacy Postfix DSN signing shape:

```yaml
mode: postfix_dsn
signing:
  tenant: tenant-a
  domain: example.test
  domain_source: static
```

or the legacy `domain_source: envelope_sender` variant with:

```yaml
mode: postfix_dsn
signing:
  tenant: tenant-a
  domain_source: verified_embedded
```

The corresponding `/v1/dsn/sign` v1 request first changed from:

```json
{"context":{"tenant":"tenant-a","domain":"example.test"}}
```

to the tenant-only context:

```json
{"context":{"tenant":"tenant-a"}}
```

The Postfix bounce wire-profile correction makes the same route Postfix-exclusive
and removes the caller-selected message fidelity. The previous message object:

```json
{"message":{"raw_rfc5322_base64":"...","fidelity":"postfix_dsn_milter_reconstructed_crlf"}}
```

becomes:

```json
{"message":{"raw_rfc5322_base64":"..."}}
```

The distinct DSN route capability is now the explicit server-side attestation
that its sole adapter established exact Postfix `internal` origin. Never mount
or copy this capability into another Milter mode, Exim, or a diagnostic client.
There is no generic HTTP DSN signing route; trusted library integrations retain
the strict generic evidence constructor.

Old DSN clients/configurations are rejected by the new closed schema and
configuration loader; new DSN clients are likewise incompatible with an old
daemon that requires `context.domain` or the former fidelity member. Do not run
a mixed pair. Pull and verify
the exact daemon and Milter image digests first, validate the new configuration
offline, drain or stop the dedicated DSN route, and activate the new daemon,
new Milter/configuration, and `{postfix_dsn_origin}`-capable patched Postfix as
one pinned change. The daemon and Milter update for the fidelity removal must
be atomic; either mixed direction fails the closed request contract. Reopen the route only after capability, readiness, and
positive/negative DSN smoke checks pass. Roll back the daemon, Milter, patched
Postfix, and configuration together to their previous digest-pinned set; never
roll back only one side of the DSN API.

Validate every route through the final read-only mounts. The daemon validation
performs the complete protected generation, replay/Valkey, OTLP CA, datasource,
signing manifest, PKCS#8, selector, ownership, mode, link-count, and stable-read
checks. Both commands are silent on success and content-free on failure:

```text
docker compose -f deployments/postfix-compose/compose.yaml run --rm --no-deps \
  daemon-inbound validate --config /etc/dkim2d/config.yaml
docker compose -f deployments/postfix-compose/compose.yaml run --rm --no-deps \
  daemon-originator validate --config /etc/dkim2d/config.yaml
docker compose -f deployments/postfix-compose/compose.yaml run --rm --no-deps \
  daemon-transit validate --config /etc/dkim2d/config.yaml
```

Start and wait for the daemon containers before validating Milter containers,
because each Milter intentionally joins its route daemon's network namespace:

```text
docker compose -f deployments/postfix-compose/compose.yaml up -d --wait \
  daemon-inbound daemon-originator daemon-transit
docker compose -f deployments/postfix-compose/compose.yaml run --rm --no-deps \
  milter-inbound validate --config /etc/dkim2-milter/inbound.yaml
docker compose -f deployments/postfix-compose/compose.yaml run --rm --no-deps \
  milter-originator validate --config /etc/dkim2-milter/originator.yaml
docker compose -f deployments/postfix-compose/compose.yaml run --rm --no-deps \
  milter-transit validate --config /etc/dkim2-milter/transit.yaml
```

## Image selection and validation

For a clean local build, export trusted metadata:

```text
export DKIM2_REVISION=<exact-40-character-source-revision>
export SOURCE_DATE_EPOCH=<trusted-decimal-release-time>
export DKIM2_VERSION=0.0.0-dev
export DKIM2_DIRTY=clean
make check-images
docker compose -f deployments/postfix-compose/compose.yaml build --pull=false
```

For production, set `DKIM2D_IMAGE` and `DKIM2_MILTER_IMAGE` to immutable
registry digest references. Never deploy a mutable alias as authority.

Validate the effective default:

```text
docker compose -f deployments/postfix-compose/compose.yaml config
make check-deployment
make deployment-postfix
make deployment-security
```

`check-deployment` is the static topology and policy gate.
`deployment-postfix` executes the isolated two-run lifecycle and mail-flow
proof. `deployment-security` additionally rebuilds candidate-bound image
evidence and proves the seeded privacy boundary. These test targets use
reserved `.test` fixtures and do not operate a production queue or protected
generation.

The product services are non-root, read-only, capability-free, use
`no-new-privileges`, bounded PID/memory/CPU settings, and only the declared
tmpfs or bind mounts. Postfix needs a writable root filesystem because the
pinned upstream entrypoint runs `postfix set-permissions`; it is the only
read-only-root exception. Postfix remains digest-pinned, drops all capabilities
before restoring only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `NET_BIND_SERVICE`,
`SETGID`, `SETUID`, and `SYS_CHROOT`, and uses `no-new-privileges`. Its only
declared state mounts are the writable queue and Postfix configuration volumes,
the three read-only route sockets, and read-only files under the upstream
`/etc/postfix/custom-config/` interface. It has no host network, devices,
engine socket, or protected daemon mounts.

## Start and verify

Start the daemons and Milter instances first, verify readiness through their
internal namespace and owned sockets, then admit Postfix:

```text
docker compose -f deployments/postfix-compose/compose.yaml up -d \
  daemon-inbound daemon-originator daemon-transit
docker compose -f deployments/postfix-compose/compose.yaml up -d \
  milter-inbound milter-originator milter-transit
docker compose -f deployments/postfix-compose/compose.yaml up -d postfix
```

The checked Postfix configuration deliberately contains:

```text
milter_protocol = 6
milter_default_action = tempfail
smtpd_milters = unix:/run/dkim2/inbound/milter.sock
non_smtpd_milters = unix:/run/dkim2/originator/milter.sock
```

The checked `master.cf` exposes a Postfix-container-loopback-only `transit`
SMTP service on `127.0.0.1:2526` with an exact per-service `smtpd_milters`
override for `transit/milter.sock`. It is neither host-published nor reachable
from another container on the mail network. Route traffic to it from an
explicitly classified internal Postfix transport only after classifying the
message as unchanged-envelope ordinary transit. Do not attach two route modes
to one message path.

An unchanged-envelope ordinary-transit route must preserve Draft-06 custody
continuity: the successor `mf=` domain must relaxed-match a predecessor `rt=`
domain, and each non-null signature `d=` must align with its own `mf=` domain.
The isolated deployment test therefore uses one reserved mail domain across
that synthetic envelope and both profiles while retaining distinct selectors,
keys, policies, capabilities, and route-local services. Production routing
must establish the same protocol relationship from real policy; unrelated
domains are a permanent policy rejection, not a configuration to bypass.

For the explicit synthetic demo only:

```text
docker compose \
  -f deployments/postfix-compose/compose.yaml \
  -f deployments/postfix-compose/compose.demo.yaml \
  up -d
```

Submit only reserved `.test` identities to `127.0.0.1:2525`. Validate public
cryptography and the exact ordered action plan with `dkim2ctl` or the
conformance fixtures; a grep-only header assertion is not cryptographic proof.
Postfix simulated non-SMTP callbacks omit path brackets, and the adapter adds
only the missing outer brackets as documented.

## Shutdown, upgrade, and rollback

### Draft-06 protocol and replay upgrade

Draft-06 is a closed protocol-baseline change. Upgrade the daemon, Milter,
generated clients, fixtures, and configuration references as one digest-pinned
set; do not run a Draft-04 adapter or client against a Draft-06 daemon. The
wire enum changes to `draft-ietf-dkim-dkim2-spec-06`, and verification may now
return `duplicate_hash_algorithm`, `invalid_recipe_json`,
`duplicate_selector`, or `too_many_signatures` as permanent non-4xx results.

Replay migration is drain-only. Stop SMTP admission, drain every Draft-04
instance and its in-flight replay work, retain the old deployment offline for
the complete configured retention period, and only then admit traffic to the
Draft-06 deployment. Never operate mixed Draft-04/Draft-06 instances, a
rolling upgrade, fallback, or dual replay epochs. Old replay records are
intentionally unreachable after the Draft-06 epoch activates, so the possible
detection gap is bounded by that retention period. Follow the exact procedure
in [`../replay-store-valkey.md`](../replay-store-valkey.md); the Valkey
namespace, key width, ACL, and topology do not otherwise change.

The message baseline change does not migrate the DNS identifier. Keep
`draft-chuang-dkim2-dns-04` and its versioned vectors until the deferred
working-group DNS rename receives a separate reviewed update.
Rollback must restore the complete prior Draft-04 application set only after
the Draft-06 replay epoch has likewise drained; an online cross-version
rollback is unsupported.

Stop SMTP admission first. Let Postfix finish active sessions, retain its named
queue volume, and stop Postfix before replacing socket owners. For an upgrade
that must retain queued mail without delivery, record the exact queue IDs and
place only those IDs on hold before stopping; do not use a later blanket
release that could alter unrelated operator holds. Then stop Milter instances
and daemons within their configured grace periods:

```text
docker compose -f deployments/postfix-compose/compose.yaml stop postfix
docker compose -f deployments/postfix-compose/compose.yaml stop \
  milter-inbound milter-originator milter-transit
docker compose -f deployments/postfix-compose/compose.yaml stop \
  daemon-inbound daemon-originator daemon-transit
```

Compose sends the normal stop signal and applies the declared 30-second
Postfix and 15-second product bounds before forcing termination. A forced stop
is a failed clean-shutdown result: keep the queue held, inspect only bounded
status/log classes, prove the old processes no longer own sockets, and remove
only stale socket inodes owned by this deployment before retrying.

An image upgrade changes `DKIM2D_IMAGE` and `DKIM2_MILTER_IMAGE` only to
reviewed immutable `name@sha256:<64-lowercase-hex>` subjects. Record the
currently running image IDs and subjects first. Recreate daemons, wait for all
three readiness checks, recreate Milter instances, wait for their owned socket
checks, and only then recreate/start Postfix. Prove the recorded held queue IDs
and message records are unchanged before releasing only those IDs.

A protected-generation rotation is a restart, never a reload:

1. Create a new unused 32-lowercase-hex generation beside the retained old
   generation. Populate every selected direct child, set final ownership,
   modes, and make no further changes to that directory.
2. Create a complete replacement daemon YAML file outside the generation. It
   selects only the new generation and direct children and has the required
   owner, mode, link count, and inode separation.
3. Atomically replace the host YAML selector while the old daemon remains
   running. Its already-owned snapshot does not hot reload.
4. Run `dkim2d validate` through the final read-only Compose mounts. On any
   failure, atomically restore the retained old selector; do not repair the new
   generation.
5. Stop Postfix, then the route Milter and daemon. Recreate the daemon, wait
   for readiness, recreate the Milter, verify its socket, then start Postfix.
   Validate public DNS/key readiness separately before releasing held mail.

For rollback, stop Postfix, remove only owned stale socket inodes after proving
no old process owns them, atomically select the retained prior YAML and prior
immutable image subjects, recreate in dependency order, and compare the held
queue records before release. Never run old and new Milter instances against
one socket path. A partial generation, missing route capability, wrong
owner/mode/link count, invalid selector, or socket
collision is a closed validation/startup failure and must not trigger an
in-place repair or automatic fallback.

## Backup and restore

Back up separately, under access control suitable for private keys and
credentials:

- every retained immutable protected generation and active YAML selector;
- flat-file datasource and signing registry/PKCS#8 material;
- Valkey according to its persistence and replay-loss policy;
- the Postfix queue volume while Postfix is consistently stopped or through a
  Postfix-supported snapshot procedure; and
- immutable image digests plus SBOM, provenance, and vulnerability evidence.

These backups are not a globally atomic snapshot. Postfix, Valkey, datasource,
and signer state each require their own component-consistent capture point and
documented replay-loss window; completing them at nearby times does not create
one transaction.

Restore into new empty offline destinations with numeric ownership, modes,
link counts and immutable generation names preserved. Never extract
over an active generation. Validate generation cross-references,
private/public key bindings, Valkey TLS/credential configuration, and every
daemon/Milter configuration through the final mounts before startup. Restore
Postfix queue ownership using Postfix-supported procedures and without passing
queue contents through DKIM2 tooling. A filesystem-copy restore can change
queue-file inode numbers, and Postfix can consequently rename queue IDs during
startup. Reconcile restored queue entries against bounded message/control
evidence, record the post-restore IDs, and keep those IDs held until the exact
restored image/config/generation set is ready. Release only the reconciled
post-restore IDs.

## Troubleshooting and current limits

Invalid config, missing capability, partial/mixed generation, weak mode,
unsupported filesystem, daemon loss, Milter loss, overload, and ambiguous
state fail closed or tempfail. Inspect bounded result classes, readiness,
low-cardinality metrics, and secret-safe logs. Do not print raw config,
capabilities, key files, messages, envelope values, selectors, DNS TXT,
datasource records, replay keys, or raw errors.

The daemon OpenAPI, `dkim2ctl`, typed configuration, flat-file provider,
disabled/memory/Valkey replay, observability, Milter modes, fidelity,
Authentication-Results, and failure policy are documented in the component
READMEs and linked durable specs.

The source-linked Exim adapter, `local_scan()`, transport filter, packaging
validation, and five-row qualification matrix runner are implemented separately from
this Postfix deployment. Exim is `unqualified_draft06`: its exact five-row
compatibility report is historical Draft-04 evidence and does not extend this
Postfix deployment or qualify current Draft-06 bytes. No universal binary
package or Exim image is claimed.

LDAP, PostgreSQL, MySQL, and MariaDB providers, drivers, pools, schema/DDL delivery, immutable
generation loading, and the offline legacy OpenDKIM migration are documented
in
[`datasource-backends.md`](datasource-backends.md) and
[`opendkim-migration.md`](opendkim-migration.md). They require separately
managed verified-TLS services and least-authority credentials; the demo stack
does not create those external authorities.
