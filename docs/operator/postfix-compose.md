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

A verification daemon may resolve locality without signing capabilities. The
inbound route may configure `signing.backend` together with
`process.default_tenant` and no route capability at all: the datasource is
loaded read-only so that received delivery-status notifications can be
classified as local or foreign, no signing route is registered, and
`/v1/sign`, `/v1/revise`, `/v1/dsn/sign`, and `/v1/dsn/propagate` answer `403`
for every credential. Do not add an unused sign or delivery-status capability
to the inbound route to satisfy the datasource.

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

The transit Milter serves unchanged-envelope transit only. It sees one SMTP
transaction and therefore sends the outgoing envelope as both the inherited
and the outgoing envelope of `POST /v1/revise`. Mail whose return path this
system rewrites on forwarding, which is exactly the mail that delivery-status
propagation is for, is rejected by that route as a custody discontinuity, and
no `main.cf` or `master.cf` setting changes that. Revise such mail through a
client that presents both envelopes explicitly, as the qualification lane
does through the daemon route; the Milter chain must not be attached to it.

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

## Delivery-status propagation

Forwarded mail that fails at a later hop produces a delivery-status
notification addressed to the return path this system signed. Draft-06
Section 12.1.1 requires that notification to be rebuilt for, and delivered to,
the previous hop of the forwarded message. The transport component is
`dkim2-dsn-propagator`, an MTA-neutral adapter that is not a Milter: it
receives one notification over LMTP, calls the daemon's
`POST /v1/dsn/propagate` and `POST /v1/dsn/propagate/commit` operations,
re-injects the rebuilt notification through a trusted internal listener, and
only then acknowledges the LMTP transaction. No Postfix patch is involved. The
runtime and configuration reference is
[`cmd/dkim2-dsn-propagator/README.md`](../../cmd/dkim2-dsn-propagator/README.md);
the request and response shapes remain authoritative only in
[`docs/specs/openapi/dkim2d.yaml`](../specs/openapi/dkim2d.yaml).

### The three deployment requirements

These three properties are what the adapter assumes of any MTA. The Postfix
parameters that satisfy them follow in the next subsection.

1. Mail addressed to the local return-path addresses of forwarded messages,
   and only that mail, reaches the adapter's LMTP socket with one recipient
   per transaction, and the recipient address is handed to LMTP unrewritten.
   The daemon compares that address byte-wise against the signed `mf=` apart
   from domain case, so any address rewriting on that path is a permanent
   refusal rather than a tolerated difference.
2. A trusted internal null-sender submission listener exists for re-injection
   with no DKIM2 signing route and no content filter attached. It must support
   `SMTPUTF8` when a previous hop address is non-ASCII and `8BITMIME` when the
   signed notification carries eight-bit content; the adapter fails closed and
   defers rather than downgrading.
3. The minimum retry interval for the LMTP transport exceeds the daemon's
   `dsn_propagation.pending_lease`. A retry that lands inside a live lease is
   deferred once more before it can be served, which wastes a delivery attempt
   without changing the outcome.

Forwarded mail must also already leave this system with a local `mf=` whose
domain is a local authority domain. Automatic sender rewriting is out of
scope: without a local return path no notification reaches this system and
there is nothing to propagate. The rewritten return path also decides which
signing path may add the forwarding signature: the `ordinary_transit` Milter
cannot, because it presents the outgoing envelope as the inherited one and
the daemon rejects the changed return path; the forwarding signature must
come from a `POST /v1/revise` client that supplies the inherited envelope as
`incoming_smtp` and the forwarding envelope as `smtp`.

### Concrete Postfix configuration

Route the reserved return-path address class to the adapter's LMTP socket and
force one recipient per transaction:

```text
smtpd_relay_restrictions = permit_mynetworks,
    check_recipient_access inline:{ {bounces@operator.test = OK} },
    reject_unauth_destination
transport_maps = inline:{ {bounces@operator.test = dsn_propagator:unix:/run/dkim2/propagation/lmtp.sock} }
dsn_propagator_destination_recipient_limit = 1
dsn_propagator_destination_concurrency_limit = 10
```

`transport_maps` selects a route; it does not authorize a destination. The
reserved return-path address is neither in `mydestination` nor in
`relay_domains`, so without the `check_recipient_access` entry every incoming
notification is refused by `reject_unauth_destination` before the transport is
ever consulted. Permit exactly the reserved address and nothing else: the
`transport_maps` entry then pins that address to the adapter, so the permit
cannot be used to relay anywhere.

Write both inline tables in the brace-delimited form
`inline:{ {key = value} }`. Postfix rejects the flat form
`inline:{ key = value }` at table-open time with `missing '=' after attribute
name`, and that failure surfaces only when the table is first queried, not
when `postfix check` parses `main.cf`.

The transport name in `transport_maps` is the `master.cf` service name, and
`dsn_propagator_destination_recipient_limit` is that service's per-transport
recipient limit. Declare the transport and the dedicated re-injection listener
in `master.cf`:

```text
dsn_propagator unix  -       -       n       -       -       lmtp
  -o syslog_name=postfix/dsn-propagator
  -o lmtp_lhlo_name=$myhostname
127.0.0.1:10025 inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/dkim2-reinjection
  -o smtpd_milters=
  -o non_smtpd_milters=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject_unauth_destination
  -o content_filter=
  -o receive_override_options=no_address_mappings
```

The four empty overrides are the point of the listener: the rebuilt
notification is already signed by the propagation route, so no Milter, no
`non_smtpd_milters` callback, and no content filter may see or alter it, and
no client outside `mynetworks` may reach it. `no_address_mappings` keeps the
previous hop's address unrewritten on the way out. The listener is
container-loopback only; it is neither host-published nor reachable from
another container on the mail network.

`minimal_backoff_time` and `maximal_backoff_time` are queue-manager parameters
with no per-transport override, so the minimum retry interval is global:

```text
minimal_backoff_time = 600s
maximal_backoff_time = 4000s
```

The daemon's default `dsn_propagation.pending_lease` and the adapter's default
`daemon.pending_lease` are both 120 seconds. Postfix's own default
`minimal_backoff_time` of 300 seconds already exceeds that; the rendering sets
600 seconds so that a lease raised to any value below 600 seconds stays covered
without a second change. `maximal_backoff_time` is set to its default
only to keep the retry envelope explicit next to the minimum. Keep the three
values ordered as `dsn_propagation.pending_lease` equals
`daemon.pending_lease` and both stay strictly below `minimal_backoff_time`. If
you raise the lease, raise `minimal_backoff_time` above the new value in the
same change; if you lower `minimal_backoff_time`, lower both lease values
first.

Finally, provision the daemon route. Add the distinct propagation capability
and, if the default does not fit, the lease:

```text
server:
  dsn_propagate_capability_file: /var/lib/dkim2d/<generation>/dsn-propagate-capability
process:
  default_tenant: tenant-a
dsn_propagation:
  pending_lease: 120s
```

The propagation capability is a fifth distinct 32-byte protected value. It
must differ from the process, sign, revise, and delivery-status signing
capabilities, is accepted on no other route, and no other capability is
accepted on the two propagation routes. It does not require the
delivery-status signing capability to be configured. `process.default_tenant`
is what `POST /v1/process` uses when a request carries no `context.tenant`;
the inbound Milter sends none and relies on this value. Without a tenant the
projection reports `local_hop: not_evaluated` and `propagation:
not_evaluated`, and policy accepts.

### Routing options for the return-path address class

The routing rule must select exactly the return paths of forwarded mail. Three
shapes are workable; the second and third scale, the first is easiest to
audit.

- One reserved local part on a local authority domain, as in the example
  above. The `transport_maps` key is the full address, so ordinary mail to the
  same domain is unaffected, and the matching `check_recipient_access` entry
  authorizes that one address without making the domain relayable. Use this
  when forwarding uses a single fixed return path.
- One reserved subdomain of a local authority domain, for example
  `returns.operator.test`, keyed by domain in `transport_maps` and listed in
  `relay_domains`. The signing `d=` must still relaxed-match the `mf=` domain
  under Draft-06 Section 9.4, which a subdomain of the signing domain
  satisfies. Use this when the return path carries a variable local part.
- A regular-expression table over a variable-envelope return path prefix. This
  is the only shape that can accidentally capture ordinary mail, so anchor the
  pattern to both the exact prefix and the exact domain and prove the negative
  cases before activation.

Whichever shape you choose, do not attach an address-rewriting map, an alias,
a virtual mapping, or a canonical mapping to that class. The daemon refuses a
recipient that does not match the signed `mf=` byte-wise apart from domain
case, and a rewritten address is indistinguishable from a misrouted one.

### Provisioning `delivery_status` for forwarding domains

The propagation signing domain is the canonical `d=` of the removed, verified
completion signature. The outgoing delivery-status authority, which derives
the domain from the embedded highest `d=`, does not apply and is not reachable
through the propagation capability. Every domain this deployment forwards mail
under therefore needs an active `delivery_status` signing profile for the
tenant, in addition to whatever `originator`, `ordinary_transit`, or
`next_domain_transit` profiles it already holds.

A local domain without that profile is a permanent refusal: the route answers
`permerror` with `propagation_failure: unprovisioned_domain`, the disposition
is `discard`, and no notification reaches the previous hop. It is not a
tempfail and it does not fall back to another profile use. Provision the
profiles for the flat-file, LDAP, PostgreSQL, MySQL, and MariaDB backends as
described in [`datasource-backends.md`](datasource-backends.md),
[`ldap-schema-reference.md`](ldap-schema-reference.md), and
[`datasource-key-rotation.md`](datasource-key-rotation.md), and publish the
selector's DNS record before routing return paths to the adapter.

### Rendering the propagation overlay

The propagation topology is an overlay on the base rendering, not a separate
project. Four checked-in files carry it:

```text
deployments/postfix-compose/compose.propagation.yaml
deployments/postfix-compose/postfix/propagation-main.cf
deployments/postfix-compose/postfix/propagation-master.cf
deployments/postfix-compose/examples/dsn-propagator.yaml
```

`compose.propagation.yaml` adds the `daemon-propagation` and `dsn-propagator`
services and re-points Postfix at the two `propagation-*.cf` renderings. The
two `.cf` files are the base `main.cf` and `master.cf` plus exactly the
propagation additions documented above, so a deployment that already diverged
from the base rendering must merge rather than substitute.
`examples/dsn-propagator.yaml` is a complete adapter document to copy, not a
file the overlay mounts.

Render and inspect the overlay before starting it:

```text
docker compose \
  --project-name dkim2-postfix \
  --project-directory deployments/postfix-compose \
  --file deployments/postfix-compose/compose.yaml \
  --file deployments/postfix-compose/compose.propagation.yaml \
  config
```

The overlay is a deliberate topology change. In the base rendering Postfix
reaches the Milter routes only through read-only socket mounts and joins the
`mail` network. Here Postfix, the adapter, and the adapter's daemon share one
network namespace, because the adapter confines both of its endpoints to
canonical literal loopback: it calls its daemon on `127.0.0.1` and re-injects
into the `127.0.0.1:10025` listener. Nothing new is published to the host.

Create the additional state before the first start, using the same ownership
and mode rules as the other routes:

```text
deployments/postfix-compose/state/daemon/propagation/<32-lowercase-hex-generation>/
deployments/postfix-compose/state/propagator/
deployments/postfix-compose/state/sockets/propagation/
deployments/postfix-compose/config/dkim2d-propagation.yaml
```

`state/daemon/propagation` follows the daemon rules exactly: owner
`2000:2000`, mode `0500`, and one protected child per selected value,
including the distinct propagation capability. `state/propagator` is mounted
read-only at `/etc/dkim2-dsn-propagator` and holds the adapter's own
configuration document as `config.yaml` and its propagation capability as
`protected/capability`, matching the `command` and `healthcheck` entries and
the `daemon.capability_file` value in `examples/dsn-propagator.yaml`. Its
identity is `2000:103`, the same as the Milter images.
`state/sockets/propagation` is the
writable socket directory the adapter creates its LMTP socket in and Postfix
mounts read-only.

Both the adapter configuration document and the capability are loaded through
the protected-file contract, so each must be a regular file with one link,
owned by the effective identity, and mode `0400` or `0600`. A configuration
document left at the usual `0644` is refused, and every command exits with the
same content-free `dkim2-dsn-propagator: runtime failure` diagnostic, so check
the mode first when `validate` fails on a document you believe is correct. The
capability additionally requires its parent directory to be exactly `0500`.

### Adapter configuration and health probe

The adapter's complete strict configuration reference, including every stable
path, default, and the frozen `dkim2-dsn-propagator-config-v1` root, is in
[`cmd/dkim2-dsn-propagator/README.md`](../../cmd/dkim2-dsn-propagator/README.md).
Four deployment facts matter here.

- `daemon.endpoint` and `reinjection.endpoint` must be canonical
  literal-loopback origins. The adapter shares its daemon container's network
  namespace exactly as a Milter does, and it reaches the re-injection listener
  over the mail network; hostnames, remote addresses, redirects, proxies, and
  ambient credentials are rejected on both endpoints.
- `daemon.pending_lease` is the operator's declaration of the daemon's
  `dsn_propagation.pending_lease`. The sum of `daemon.request_timeout`, the
  three `reinjection.*` timeouts, and `daemon.commit_timeout` must stay below
  it, so one complete attempt finishes inside the reservation. Configuration
  loading refuses a document that violates this bound.
- `propagation.permanent_failure_reply` is the adapter's only policy knob. It
  governs every daemon `reject`, that is a verification failure and the
  misrouting case where the notification is not ours, and never affects
  `discard`, `tempfail`, or `accept`. The default `reject` answers `550 5.7.1`;
  a `550` to a null-sender notification cannot be bounced, so an MTA discards
  it, notifies postmaster, or freezes it. An operator who prefers silence sets
  `discard`, which answers `250` and drops the notification.
- Validate before activation with
  `dkim2-dsn-propagator validate --config <absolute-path>`, which is silent on
  success and contacts neither the socket nor the daemon.

The propagator image deliberately carries no `HEALTHCHECK`. Only the daemon
image declares one; the container release policy rejects a healthcheck on any
other product, exactly as for the Milter. The deployment therefore supplies
the probe:

```text
healthcheck:
  test: ["CMD", "/usr/local/bin/dkim2-dsn-propagator", "probe", "--config", "/etc/dkim2-dsn-propagator/config.yaml"]
```

Outside a container, the same check is
`dkim2-dsn-propagator probe --config <absolute-path>`.

`probe` reloads the strict configuration and checks that the configured socket
is a single-link Unix socket owned by the effective UID with no permissions
for other users. It opens no LMTP session and contacts no daemon. `--config`
must be an absolute path, so a bare `dkim2-dsn-propagator probe` cannot
succeed.

### Duplicate windows and operational expectations

Propagation is at-least-once, bounded by the two-phase replay gate. The
adapter acknowledges only after the re-injection listener's own `250` and the
commit's `200`, so a failed re-injection is retried by Postfix and never
silently discarded. Three windows can deliver a duplicate to the previous hop:
a crash between the re-injection `250` and the commit; a lease that expired
while an attempt was still running; and a daemon restart, because commit
tokens live in a bounded process-local ledger, so a token issued before the
restart is unresolvable, is answered `409`, is deferred by the adapter as
`451`, and is re-served with a fresh rebuild once the lease expires. Keeping
the minimum retry interval above the lease is what keeps that last window from
producing repeated wasted attempts.

For a refused or deferred notification, inspect the single
`dsn.propagation.completed` log event or the matching
`dkim2d_dsn_propagation_total{stage=...,result=...}` counter on the daemon,
and the adapter's `dsn_propagator_transactions_total{outcome=...}`,
`dsn_propagator_reinjection_total{outcome=...}`, and
`dsn_propagator_commit_total{outcome=...}` counters. The closed stage
distinguishes evaluation, replay, rebuild, previous-hop verification, signing
domain, policy, and signing without logging the domain, selector, address,
queue ID, capability, commit token, signature, or message bytes. For a
received notification that is only evaluated and not propagated, the
equivalent daemon evidence is `dsn.received.completed` and
`dkim2d_dsn_received_total{stage=...,result=...}`.

### The same requirements without Postfix parameter names

An MTA other than Postfix satisfies the same contract when it can do four
things. This project makes no qualification claim for any of them; the
executed evidence is Postfix only.

1. Select, by envelope recipient, exactly the return-path addresses of
   forwarded mail and deliver them to a local LMTP endpoint on a Unix socket,
   without applying any address rewriting, alias expansion, or canonical
   mapping to that class, and without batching a second recipient into the
   same transaction.
2. Offer a local submission endpoint that accepts a null reverse path from a
   trusted internal client, applies no signing, filtering, or rewriting to the
   submitted message, and advertises `SMTPUTF8` and `8BITMIME`.
3. Treat a `4xx` LMTP reply as a retryable deferral that keeps the
   notification queued, and schedule the next attempt no sooner than the
   daemon's configured propagation lease.
4. Leave the notification's bytes unchanged between acceptance and the LMTP
   transfer, because the daemon verifies the outer signature over exactly
   those bytes.

An MTA that cannot express a per-transport single-recipient limit can instead
use a transport whose delivery agent is inherently single-recipient, or an
intermediate that splits transactions before the LMTP socket. An MTA whose
retry schedule cannot be raised above the lease can instead lower the daemon's
lease below the shortest retry interval, provided the sum of the adapter's
timeouts still fits inside the new lease.

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
