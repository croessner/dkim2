# Packaging, Container Delivery, And Operator Guide

Status: implementation-ready planning baseline.

Implementation base: `62a3d8282f65001e24f669be3962cd13474442f1`.
Protocol behavior remains pinned to `draft-ietf-dkim-dkim2-spec-04` and the
historical `draft-chuang-dkim2-dns-04` behavior baseline. Packaging, deployment,
health probes, supply-chain evidence, and operator procedures are local product
policy. They must not be described as new DKIM2 protocol requirements.

## Later M17 Qualification Addendum (2026-07-31)

This document's later Exim deferral rows remain historical M20 acceptance
records. M17 subsequently qualified the source-linked Exim adapter on Linux
across five authenticated upstream, Debian, and Ubuntu rows, with all 43 cases
passing per row and the fail-closed privacy verifier passing. The
candidate-bound run ID remains in generated full-profile evidence.
That `qualified_linux` result is source-row qualification, not a claim that a
portable universal Exim object or container image exists. Current packaging
and operator boundaries are documented in `docs/operations/exim.md`,
`docs/reports/exim-compatibility-2026-07-27.md`, and
`docs/reference/known-limitations.md`.

## Source Documents And Precedence

This specification is governed, in order, by:

1. `draft-ietf-dkim-dkim2-spec-04` for DKIM2 protocol meaning;
2. `draft-chuang-dkim2-dns-04` for the repository's tested DNS behavior;
3. RFC 5321, RFC 5322, RFC 6376, RFC 6531, RFC 6532, and RFC 8601 for the
   SMTP, message, DKIM heritage, internationalized-message, and
   Authentication-Results behavior used by the deployed product;
4. `docs/specs/openapi/dkim2d.yaml` for the daemon HTTP contract;
5. `AGENTS.md`, `POLICY.md`, and `docs/ARCHITECTURE.md` for product boundaries,
   restrictive defaults, stable configuration, and release policy;
6. the completed daemon, generated-client, observability, Milter, conformance,
   and security-hardening specifications for implemented runtime behavior;
7. the official Postfix Milter documentation for Postfix-specific behavior;
8. OCI Image Specification and OCI Distribution Specification for image
   artifacts and descriptors;
9. SLSA provenance, SPDX, and CycloneDX only for the artifact/evidence formats
   selected by the implementation; and
10. this document for production packaging, Compose topology, operator
    delivery, release evidence, and documentation acceptance.

Current images, Dockerfiles, Compose files, generated reports, scanners, and
deployment examples are evidence, not authority over the pinned drafts,
OpenAPI, or completed runtime contracts. A conflict stops implementation until
the durable source set and tests agree.

The existing `contrib/qualification/postfix-milter/` stack is a conformance
fixture. It can supply proven test ideas, but its process layout, synthetic
material, entrypoints, and qualification defaults are not production guidance
and must not be copied into an operator deployment without a separate
security and lifecycle review.

## Original Gap

The repository contains production binaries and strong hermetic, Valkey,
portable-Milter, and real-Postfix qualification evidence, but it does not yet
ship the production delivery around them.

In particular:

- there are no product Dockerfiles or Containerfiles for `dkim2d`,
  `dkim2-milter`, or `dkim2ctl`;
- no checked build contract freezes Go 1.26, vendored module use, target
  platforms, build flags, binary ownership, OCI metadata, or reproducibility;
- no minimal runtime image contract proves non-root execution, lack of a
  shell/package manager, read-only-root operation, dropped capabilities,
  bounded writable state, and correct signal behavior;
- image inputs, builder/runtime bases, CI actions, scanners, and release tools
  are not yet managed as immutable reviewed identities;
- there is no repository-owned multi-architecture OCI layout, SBOM,
  provenance, signature/attestation, or image vulnerability gate;
- the real Postfix fixture proves adapter behavior but is intentionally not an
  installable production or pilot deployment;
- no operator-ready topology preserves the daemon's canonical-loopback-only
  HTTP boundary while allowing separate Milter containers to call it;
- no default deployment keeps SMTP, daemon HTTP, metrics, Milter, and control
  interfaces off the host while still offering an explicit loopback-only demo
  override;
- protected daemon configuration, capabilities, datasource generations,
  private-key manifests, PKCS#8 children, tracing roots, replay secrets, and
  Milter socket ownership are documented in separate component notes rather
  than one deployable ownership model;
- startup, readiness, shutdown, upgrade, rollback, backup, restore, queue
  handling, key/generation rotation, and incident troubleshooting are not
  presented as one tested operator workflow;
- daemon, Milter, and client READMEs contain historical scope statements and
  examples that are not sufficient as current container/operator guidance; and
- deployment notes must remain truthful that Exim is incomplete under M17 and
  LDAP/SQL execution and legacy migration remain M22 work.

## Goal

Deliver a production-capable, reproducible package that lets an operator build,
inspect, and run the implemented daemon and Milter with Postfix without
weakening any runtime trust boundary.

The increment produces:

- one reviewed multi-stage production build definition with named targets, or
  separate equivalent definitions, for `dkim2d`, `dkim2-milter`, and
  `dkim2ctl`;
- Linux `amd64` and `arm64` OCI images built from the exact Go 1.26 workspace
  and vendored dependencies;
- minimal non-root runtime images with deterministic users, ownership,
  entrypoints, metadata, and read-only-root compatibility;
- closed local image build/check targets and least-privilege CI/release
  workflows;
- deterministic SBOM and provenance generation plus vulnerability and
  dependency gates;
- a hardened Compose/Postfix deployment that an operator can actually run,
  with no host publication by default and an explicit loopback-only demo
  override;
- clear ownership for protected generations, capabilities, signing keys,
  datasource files, replay material, configuration, Milter sockets, and
  writable runtime state;
- current API, configuration, datasource, replay, observability, Milter,
  container, Postfix, upgrade, rollback, backup, restore, and troubleshooting
  documentation; and
- deterministic container, topology, health/readiness, shutdown, upgrade,
  rollback, privacy, multi-architecture, SBOM, provenance, vulnerability, and
  full existing guardrail evidence.

Successful completion means an operator can follow one documented path from a
clean checkout and prepared protected generation to a healthy internal
daemon/Milter/Postfix stack, opt in to a loopback SMTP test port, submit a
synthetic message, verify the resulting permitted DKIM2 fields and disposition,
stop cleanly, upgrade by immutable image digest, and roll back without
discarding the Postfix queue or corrupting protected state.

## Delivery Shape

One implementation agent executes these slices sequentially:

1. Freeze the image/build contract, immutable inputs, target-platform matrix,
   reproducible binary and OCI metadata, and deterministic local check tools.
2. Build and harden the three production image targets, including non-root
   runtime identities, read-only-root behavior, probes, signals, and static
   policy tests.
3. Add multi-architecture OCI build/release automation, SBOM, provenance,
   vulnerability, digest, and publication evidence with least privileges.
4. Build the hardened Postfix Compose topology and explicit loopback-only demo
   override while preserving daemon-loopback and Unix-Milter boundaries.
5. Add protected-generation preparation/validation guidance and tested
   startup, shutdown, rotation, upgrade, rollback, backup, restore, and queue
   procedures.
6. Complete API/config/datasource/replay/observability/Milter/container/Postfix
   reference documentation and truthful Exim/M22 deferrals.
7. Add hostile deployment, privacy, topology, lifecycle, reproducibility, and
   cross-architecture integration tests.
8. Run release-quality image, supply-chain, conformance, security, and
   repository gates and freeze one unchanged candidate for review.

One fresh independent reviewer then audits and fixes the cumulative candidate.
There are no slice commits. The orchestrator creates exactly one
project-formatted commit only after all findings are fixed, every required gate
passes, and two approvals bind one unchanged snapshot.

## Implementation Effort

| Field | Value |
| --- | --- |
| Estimated size | large |
| Estimated wall-clock effort | 1 to 3 agent-days, excluding an unavailable container runtime or external registry outage |
| Highest-risk areas | protected-generation ownership in containers, daemon/Milter loopback topology, reproducible multi-arch artifacts, supply-chain evidence, safe Postfix upgrade/rollback |
| Expected prompt count | eight implementation prompts plus one independent review/fix prompt |
| Required final gate | product image/release/operator gates plus the complete M19 security and M18 conformance profiles |

Measured wall-clock timing, blocked time, findings, fixes, candidate digests,
image/config/SBOM/provenance/report digests, and approvals remain in the ignored
prompt-pack ledger until closeout.

## Scope

### In Scope

- Production container build definitions for `dkim2d`, `dkim2-milter`, and
  `dkim2ctl`.
- A central immutable build-input policy, a minimal fail-fast metadata
  validator, a pinned Go 1.26 builder, and `scratch` runtime images.
- Reproducible `CGO_ENABLED=0` Linux builds for `amd64` and `arm64`.
- OCI image labels, annotations, digests, manifests, platforms, SBOMs,
  provenance, and vulnerability evidence.
- Local Makefile targets and immutable least-privilege CI/release workflows.
- A production-oriented Postfix/Compose example using the released product
  images or exact locally built equivalents.
- A no-host-exposure default and explicit loopback-only SMTP demonstration
  override.
- Daemon, originator, ordinary-transit, and inbound Milter topology where the
  documented trust boundary requires separate instances/capabilities.
- Protected configuration, datasource, signing-store, replay, tracing,
  capability, and socket ownership/mount contracts.
- Operator-visible liveness/readiness without expanding the daemon API or
  exposing protected data.
- Startup, shutdown, restart, queue drain, upgrade, rollback, backup, restore,
  protected-generation rotation, and troubleshooting procedures.
- Current component and root READMEs, API navigation, and operator/reference
  documents.
- Deterministic static and real-container tests on a supported Linux container
  engine.

### Out Of Scope

- A new DKIM2 or DNS behavior baseline.
- New protocol semantics, algorithms, normalization, or DNSSEC policy.
- Remote daemon HTTP, daemon TLS serving, proxy trust, public metrics, or a TCP
  Milter listener.
- Kubernetes, Helm, systemd packages, distribution packages, or orchestration
  platforms other than the reviewed Compose delivery.
- Automatic production DNS publication or general-purpose private-key
  generation.
- A hosted registry namespace, public release push, release tag, or production
  deployment performed by an implementation/review prompt.
- Exim implementation, packaging, compatibility claims, or live evidence.
  Exim remains incomplete and deferred to M17.
- Executable LDAP/SQL providers, drivers, schemas, database migrations,
  OpenDKIM import, or migration tooling. Those remain M22.
- Valkey cluster, Sentinel, load-balancer, endpoint discovery, or global
  exactly-once claims.
- A privileged Docker socket inside a product container.
- A shell, package manager, compiler, source tree, test key, or build cache in
  a final runtime image.
- A second OpenAPI model or hand-written REST client.
- Staging, committing, pushing, publishing, signing external artifacts, or
  changing the deferred Exim stash from implementation/review prompts.

## Artifact And Build Contract

### Source And Dependency Closure

The build context is allowlisted. It contains only exact files needed for the
Go workspace build, product metadata, licenses, and container definitions. It
must exclude `.git`, `temp/`, `.artifacts/`, local environment/config files,
credentials, protected generations, caches, reports, editor files, unrelated
contrib assets, and developer home material.

Product builds:

- use exact Go `1.26.0` or a reviewed later `1.26.x` patch consistently across
  repository metadata, builder identity, docs, and CI;
- use the checked-in vendor tree with `-mod=vendor` and no network access after
  immutable builder/runtime image acquisition;
- build the command modules from the workspace without inserting command-local
  `replace` directives;
- set `CGO_ENABLED=0`, `GOOS=linux`, and a closed `TARGETARCH` of `amd64` or
  `arm64`;
- use `-trimpath`, deterministic build IDs, and reviewed linker metadata;
- embed only trusted release version, exact source revision, dirty state,
  pinned draft identifiers, and a reproducible creation time derived from a
  trusted release input;
- reject unset, malformed, moving, or caller-controlled metadata that could
  create ambiguous images; and
- produce binaries whose version output is bounded and secret-safe.

Builder and runtime `FROM` values use immutable digest references. Human-readable
tags may be documented beside the digest for review, but a tag alone is never
executed. Digest updates are explicit dependency changes and must refresh
multi-architecture, license, vulnerability, and reproducibility evidence.

Build arguments cannot select arbitrary Dockerfiles, commands, package
repositories, download URLs, scripts, mounts, registries, or shell fragments.
Closed platform and image-target selections are mapped by repository-owned
code or Make targets.

### Reproducibility

For the same source snapshot, target, platform, toolchain/base digests, and
trusted metadata:

- two clean builds produce byte-identical product binaries;
- two OCI-layout builds produce a deterministic equivalent inventory of
  config, layers, paths, modes, ownership, entrypoint, user, labels,
  annotations, and subject digests;
- normalized evidence is byte-identical; and
- timestamps, BuildKit provenance metadata, compression metadata, and manifest
  ordering are either fixed or intentionally excluded from byte-identity
  claims and compared through a documented semantic digest model.

The implementation must state exactly which artifact is byte-reproducible and
which is semantically reproducible. It must not claim bit-for-bit OCI archive
identity when the selected builder cannot provide it.

### Runtime Images

Each final image:

- contains only the intended product binary, required public license notices,
  and the minimal CA/timezone data the runtime actually needs;
- has no shell, package manager, compiler, VCS metadata, source tree, test
  binary, qualification helper, or writable application directory;
- runs as one deterministic numeric non-root UID/GID;
- has one exec-form entrypoint and no shell-form command;
- handles SIGTERM/SIGINT through the binary's existing bounded lifecycle;
- defaults to a read-only root filesystem and uses only declared tmpfs or
  volumes for required writable paths;
- sets no ambient capability and requires Compose to drop all capabilities;
- does not request privileged mode, host PID/IPC/network, device access, or the
  container-engine socket;
- defines OCI source, revision, version, created, title, description, licenses,
  documentation, and vendor metadata from trusted inputs;
- has a deterministic health/readiness policy appropriate to its role; and
- is scanned and inspected by exact manifest digest, not by a mutable tag.

`dkim2d` and `dkim2-milter` may gain narrowly scoped local `healthcheck` or
`probe` command behavior only if existing endpoints/state cannot support a
correct container probe. Such a command must use existing readiness owners,
perform no protocol, DNS, datasource, replay mutation, key, or signing work,
accept no secret, and have focused unit/integration tests. `dkim2ctl` is a
one-shot client and declares no long-running container health claim.

Images must run with `--read-only`, `--cap-drop=ALL`, `no-new-privileges`,
bounded process/file limits, and declared tmpfs/volume mounts in integration
tests. Rootless-compatible operation is required where the container engine and
host bind-mount ownership permit the same numeric service identity. Any
necessary rootful setup is confined to an explicit one-shot host/operator
preparation step, never the steady-state product containers.

## Image And Release Evidence

The repository provides closed local targets for at least:

```text
make check-images
make images
make images-multiarch
make image-sbom
make image-vulnerability
make image-provenance
make check-release
```

Names may be refined if one authoritative target set is clearer, but help,
docs, CI, and prompt evidence must agree. Targets must not evaluate
caller-supplied commands.

The release-quality matrix covers:

- `dkim2d` on Linux amd64 and arm64;
- `dkim2-milter` on Linux amd64 and arm64;
- `dkim2ctl` on Linux amd64 and arm64.

For each image/platform, evidence records the exact source snapshot, builder
digest, build-only metadata-validator digest, runtime digest, Go version,
binary digest, image config digest, layer digest, manifest digest, target
platform, OCI metadata, effective user, entrypoint, filesystem inventory,
capability expectation, and normalized probe result. It records no hostname,
username, local absolute path, container ID, registry credential, protected
mount, secret, message, envelope, key, raw scanner output, or
attacker-controlled string.

SBOM output:

- is generated from the final image by an immutable pinned tool;
- uses one explicitly versioned SPDX or CycloneDX JSON format;
- includes OS and Go dependencies without embedding local paths;
- is bound to the exact image subject digest;
- is validated against a strict schema and deterministic policy; and
- is retained as release evidence, not copied into the runtime filesystem.

Publication-authoritative provenance:

- names the exact source revision, trusted workflow, build definition,
  platform, immutable inputs, output subjects, and builder identity;
- is generated only by the trusted release workflow;
- cannot be accepted from an untrusted pull-request artifact as publication
  authority;
- uses an explicit SLSA/in-toto predicate version; and
- is verified against the exact image subject before release.

Local and pull-request builds may generate an explicitly non-authoritative
`local-test` statement to verify this data model. Such a statement is not
trusted release provenance, cannot set publication authority, and cannot be
promoted by caller-controlled environment variables.

Image vulnerability scanning is release-blocking for every reported finding,
irrespective of its severity label. Each offline scan consumes an exclusive
copy-on-write scanner, OCI-layout, metadata, and database view created from
descriptor-confined source bytes. The database owner uses constant-memory
hashing under a separate 2 GiB limit and checks metadata, database descriptor
identity, source candidate, input inventory, and tool identity around every
scan. The scanner has a fixed timeout, minimal credential-free environment,
and bounded output. Portable ignored evidence records only candidate/tool
identity, shared scan time, database schema/update identity, fixed limits, and
exact file size/hash values. The database must be unexpired at scan and
verification time, no more than 48 hours behind its update time, and no more
than five minutes future-dated. Host device, inode, UID, mode, and filesystem
timestamps remain private guard state. Exceptions require the same durable, time-bounded
maintainer policy as M19; agents cannot invent one. Scanner output never
substitutes for `govulncheck`, dependency review, minimal-filesystem
inspection, or behavior tests.

Publication, when separately authorized, occurs only from a protected release
ref and trusted workflow. It publishes immutable digests plus conventional
version aliases, verifies the registry digest after push, attaches SBOM and
provenance to the exact digest, and never uses `latest` as deployment
authority. Pull requests and ordinary branch pushes build and verify without
registry write, OIDC token, package write, or signing authority.

## Compose And Postfix Topology

The durable example belongs under a production-oriented path such as:

```text
deployments/postfix-compose/
```

The default Compose file contains no `ports` entry. It creates no public
daemon, metrics, Milter, SMTP, control, or management listener. An explicit
demo override may publish Postfix SMTP only to canonical host loopback, for
example `127.0.0.1:2525:25`. It must not publish daemon HTTP, metrics, or a
Milter TCP endpoint.

The daemon retains its canonical loopback-literal HTTP listener. Milter
instances that call it share only the daemon's container network namespace or
an equivalent reviewed loopback namespace. The design must not widen the
daemon listener to a Compose bridge address. Postfix reaches Milter instances
only through owned Unix sockets on an explicitly shared runtime volume. It
does not receive daemon capabilities, signing keys, datasource records, replay
secrets, or daemon configuration.

The initial example supports distinct service instances for:

- inbound processing with the process capability;
- originator signing with the sign capability; and
- ordinary-transit revision with the revise capability.

The synthetic unchanged-envelope transit proof uses one reserved shared mail
domain for the originator and transit profiles, the reverse path, and the
forward-path domain. It retains distinct selectors, keys, policies, daemon
capabilities, and service instances. This is a protocol invariant rather than
a topology shortcut: draft-04 ordinary custody requires the successor `mf=`
domain to relaxed-match a predecessor `rt=` domain, while each non-null
signature `d=` must align with its own `mf=` domain. A test fixture with three
unrelated domains cannot be made valid by weakening revision verification.

The default demonstration may enable only the path needed for its documented
mail flow, but it must not reuse one Milter mode/capability at multiple trust
boundaries. Postfix `smtpd_milters` and `non_smtpd_milters` are assigned
deliberately. The example explicitly sets Milter protocol 6 and tempfail
behavior and accounts for Postfix's simulated non-SMTP callbacks and
Received-header visibility.

Compose hardening includes:

- exact image digests or locally built immutable image IDs;
- `read_only: true` for every DKIM2 product service;
- `cap_drop: [ALL]`;
- `security_opt: [no-new-privileges:true]`;
- deterministic numeric user/group;
- bounded pids, file descriptors, memory, and CPU suitable for the documented
  defaults;
- explicit `stop_grace_period` matching application shutdown bounds;
- only named volumes/tmpfs required for Postfix queue/config runtime state and
  Milter sockets;
- no privileged mode, host network, Docker socket, device, or broad bind
  mount;
- health dependencies that do not confuse liveness with readiness; and
- restart behavior that cannot silently loop on invalid protected state.

The pinned Postfix image is the deliberate exception to read-only-root
operation. Its upstream entrypoint runs `postfix set-permissions` and therefore
requires a writable Postfix root filesystem during startup. Postfix remains
root in that container with all capabilities dropped and only the exact
`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `NET_BIND_SERVICE`, `SETGID`, `SETUID`, and
`SYS_CHROOT` capabilities restored. Its image digest, writable config and queue
volumes, read-only route sockets and custom configuration mounts, private
network, zero default publications, pids, file descriptors, memory, CPU, and
shutdown bound are all checked exactly. The DKIM2 daemon and Milter services
remain non-root and read-only-root.

Postfix queue state is durable and separate from replaceable images. A daemon
or Milter failure retains the explicit tempfail behavior. Upgrade and rollback
procedures preserve queue files, avoid simultaneous old/new socket ownership,
wait for readiness before admitting mail, and prove that the prior immutable
image digest and protected generation can be selected again.

The demo uses only reserved `.test` names, synthetic test identities, and
clearly marked non-production key material generated or installed by an
explicit demo bootstrap. Production documentation must not tell operators to
reuse synthetic keys, capabilities, HMAC material, or datasource records.

## Protected Configuration And State Ownership

The deployment defines one numeric service UID/GID contract shared only where
the existing file-owner rules require the daemon and its approved local
adapter to load the same route capability. Capabilities remain distinct by
route. Sharing an OS identity in separate containers does not authorize
sharing process/sign/revise capability bytes.

Protected daemon material remains outside the image. It is mounted read-only
from an operator-created local filesystem that the existing protected loader
accepts. The guide must explicitly discuss the host filesystem, owner, ACL,
mode, direct-child, link-count, immutable-generation, and path rules. Docker
secret mounts, ConfigMaps, generic OverlayFS paths, or root-owned injected
files must not be advertised as compatible when they fail those rules.

The deployment separates:

- the strict daemon YAML selector outside the protected generation;
- route capabilities;
- replay HMAC and Valkey credentials/CA;
- optional OTLP CA;
- flat-file datasource generation;
- private signing manifest;
- PKCS#8 private-key children;
- Milter configuration;
- Postfix configuration;
- Milter socket runtime volume; and
- Postfix queue/data state.

The steady-state daemon and Milter containers never chown, chmod, generate,
rewrite, or repair protected input. Preparation validates a complete new
generation before activation. Activation replaces only the selector/config
that names it, then restarts under the documented dependency order. Partial,
mutable, symlinked, weakly owned, unsupported-filesystem, or mixed-generation
input fails closed.

A demo bootstrap may generate ephemeral capabilities and synthetic signing
material, but it must:

- run only on explicit operator request;
- use a restrictive umask and cryptographic randomness;
- never print secret bytes or place them in arguments/environment;
- refuse existing/nonempty destinations unless a documented explicit replace
  flow is selected;
- create exact owners/modes and validate the final tree;
- label all key/domain material as reserved test-only;
- emit only bounded completion classes; and
- be excluded from production key-generation guidance.

Backups cover protected generations, the active selector/config, datasource
generation, signing registry/material, and any required replay/queue state
according to their separate consistency models. Documentation must not claim
that backing up a Valkey replica, Postfix queue, datasource generation, and
private-key registry independently creates one globally atomic snapshot.

## Operator Documentation Contract

Durable documentation has one navigation path from the root README. It should
include, either as separate cohesive documents or a smaller well-indexed set:

- container image build, verification, and supported platforms;
- architecture and trust-boundary diagram;
- Postfix Compose quick start and hardened deployment;
- configuration reference with stable paths, defaults, conditional fields,
  environment placeholder behavior, and redaction;
- protected-generation and signing-key ownership;
- generated OpenAPI/API navigation and `dkim2ctl` usage;
- flat-file datasource and explicit M22 LDAP/SQL deferral;
- memory/disabled/Valkey replay topology and limitations;
- logs, metrics, traces, readiness, alerting, and secret-safe diagnostics;
- Milter modes, fidelity, Postfix callbacks, sockets, actions, failure policy,
  and Authentication-Results;
- startup, shutdown, reload/restart, image upgrade, rollback, backup, restore,
  queue handling, protected-generation rotation, and incident response;
- supported Linux platforms and rootless/bind-mount caveats;
- security hardening, SBOM, provenance, vulnerability, and report verification;
- known draft `TBA` areas and no overclaim of certification; and
- Exim notes that state exactly what is incomplete and deferred to M17.

API documentation is generated from or links directly to the authoritative
OpenAPI source. It must not create a hand-maintained parallel REST schema.
Configuration tables should be extracted from or drift-checked against typed
configuration owners where practical. Numeric limits and telemetry labels
must not be duplicated without an automated drift check.

Documentation examples contain no live domain, mailbox, key, credential,
token, capability, protected path from a real host, or non-reserved endpoint.
Commands avoid printing secret environment or file contents.

The Exim note may describe the planned separate adapter boundary and current
absence. It must not claim a working `local_scan()`, transport filter,
compatible package/version, image, or live conformance result. M17 owns fixes,
implementation, packaging, compatibility evidence, and completion.

LDAP/SQL documentation may link to the design and M22 plan. It must state that
the executable providers, drivers, pool configuration, schema/DDL delivery,
immutable-generation loading, and OpenDKIM migration are not available until
M22.

## Security, Privacy, And Observability

All image, build, deployment, bootstrap, release, and documentation tooling is
hostile-input aware and bounded. Repository scripts:

- use fixed command selection and safe argument arrays;
- reject path escape, symlink traversal, special files, hard-link ambiguity,
  weak ownership, and unsafe output parents;
- use project-scoped container cleanup;
- never delete unrelated images, volumes, networks, or files;
- bound build, pull, probe, startup, shutdown, report, and scanner work; and
- fail closed on missing tools, digests, reports, required platforms, or
  evidence.

Images, manifests, Compose labels, probes, logs, metrics, traces, SBOMs,
provenance, scanner reports, CI artifacts, shell output, errors, and docs must
not reveal:

- private keys or public-key-derived protected identities;
- capabilities, HMAC secrets, credentials, tokens, or protected config;
- raw messages, bodies, header values, signatures, Message-Instance values,
  senders, recipients, local parts, message IDs, selectors, domains, or nonces;
- raw datasource records, paths, handles, DNS TXT, replay/Valkey keys, LDAP
  DNs, SQL text, endpoints, client/container addresses, or raw errors;
- local absolute repository paths, hostnames, usernames, container IDs, or
  registry credentials; or
- unbounded attacker-selected image labels, annotations, filenames, event
  names, label names/values, or diagnostic text.

Product telemetry remains owned by the existing daemon and Milter
observability packages. Packaging does not invent a second metric or health
model. Container and Compose labels are a small static vocabulary and never
carry message, tenant, deployment-secret, or raw runtime identity.

Health probes are non-authoritative observations. They do not perform signing,
replay mutation, DNS, datasource mutation, or message processing. Liveness
does not imply dependency readiness. Compose startup ordering is not a
substitute for runtime failure handling.

## Required Tests And Evidence

### Static Build And Policy Tests

- every `FROM` and external tool/action is immutable and allowlisted;
- hostile target architecture and build metadata are rejected in a minimal
  stage before source copying or compilation, and every product target depends
  on its validation result;
- Go builder version matches repository Go 1.26 policy;
- build context closure and `.dockerignore` exclude secret/local paths;
- final images contain only expected paths, modes, owners, and file types;
- build-only validator and builder bytes are absent from both final platforms;
- final user is non-root, entrypoint is exec-form, and no shell/package manager
  or setuid/setgid file exists;
- OCI labels/annotations are complete, bounded, trusted, and deterministic;
- Dockerfile/Containerfile targets and platform mapping are closed;
- Compose has no host port by default and no daemon/Milter publication in any
  supported override;
- Compose hardening, volume, capability, network-namespace, user, and
  stop-policy invariants are drift-checked;
- protected paths and example permissions match the actual loaders; and
- docs, examples, generated API navigation, config tables, Make help, and CI
  target names remain synchronized.

### Build And Supply-Chain Tests

- clean vendored, network-disabled product builds for all six
  image/platform pairs;
- two independent same-input binary builds and semantic OCI reproducibility;
- multi-architecture manifest/platform inspection;
- SBOM generation, schema validation, subject binding, license inventory, and
  privacy scanning;
- provenance generation/verification against exact subjects;
- vulnerability scans with exact tool/database identities and closed severity
  policy;
- scanner/SBOM/provenance tamper, stale-subject, wrong-platform,
  wrong-builder/runtime-digest, and missing-evidence negatives;
- standalone image version/help/probe commands; and
- no reachable `govulncheck` finding.

### Runtime And Postfix Tests

- each DKIM2 product service runs non-root with a read-only root, all
  capabilities dropped, no-new-privileges, and only declared writable mounts;
- Postfix runs with the exact documented writable-root exception, narrow
  capability allowlist, no-new-privileges, immutable image identity, and exact
  queue/config/socket/custom-config mount inventory;
- daemon HTTP remains canonical loopback inside the shared namespace;
- Milter endpoints remain owned Unix sockets and no Milter TCP listener exists;
- default Compose publishes zero host ports;
- explicit demo override publishes only Postfix SMTP on host loopback;
- Postfix uses protocol 6 and tempfail for both SMTP and non-SMTP Milter paths;
- originator signing, inbound processing, and configured ordinary-transit
  revision use distinct instances and route capabilities, while the synthetic
  unchanged-envelope route proves the required predecessor-`rt=` to
  successor-`mf=` domain continuity with distinct selectors and keys;
- synthetic SMTP and local submission produce the exact permitted action
  ordering and public cryptographic verification;
- readiness/liveness, dependency startup, stopped daemon, stopped Milter,
  overload, invalid generation, and malformed configuration produce documented
  closed outcomes;
- clean SIGTERM, forced-timeout, restart, socket cleanup, queue persistence,
  upgrade, rollback, and protected-generation switch behavior;
- project-scoped cleanup on success and injected failure;
- repeated normalized runtime reports are identical; and
- seeded privacy markers are absent from images, metadata, logs, metrics,
  reports, SBOM, provenance, scanner evidence, errors, and final messages
  except the isolated synthetic message fixture where expected.

The existing M18 Postfix qualification remains a separate required regression.
Passing the new deployment test does not replace it, and passing the
qualification fixture does not prove the operator deployment.

### Final Gates

The implementation defines one authoritative release/packaging target, for
example:

```text
make check-images
make images-multiarch
make image-sbom
make image-provenance
make image-vulnerability
make check-deployment
make deployment-postfix
make check-operator-docs
make check-release
```

The exact final names are frozen in Make help and durable docs. On one
unchanged candidate, completion also requires:

```text
make fmt
make test
make vet
make lint
make race
make check-openapi
make check-workspace
make check-vendor
make check-protected-platforms
make test-valkey
make check-conformance
make conformance
make conformance-postfix
make conformance-all
make check-security
make fuzz-security
make security
make govulncheck
make guardrails
git diff --check
```

A skipped, stale, failed, unavailable, mismatched, unpublished-required, or
wrong-platform release/deployment gate is not approval. If registry publication
is not authorized for the milestone, the workflow must still build and verify
the exact multi-architecture OCI layouts, manifests, SBOMs, and provenance
locally or in trusted CI; it must not pretend that a registry push occurred.

## Acceptance Criteria

- All three product images build from immutable Go 1.26 and runtime inputs for
  Linux amd64 and arm64.
- Product binaries and normalized OCI inventories satisfy the documented
  reproducibility contract.
- Final images are minimal, non-root, read-only-root compatible, capability
  free, signal-correct, metadata-complete, and free of build/test material.
- SBOM, provenance, manifest, vulnerability, and release evidence bind the
  exact image subjects and pass privacy/tamper checks.
- The default Compose deployment exposes no host port and preserves daemon
  loopback plus Unix-Milter boundaries.
- The explicit demo path publishes only Postfix SMTP on host loopback and
  completes a synthetic end-to-end flow.
- Daemon, Milter modes, Postfix paths, route capabilities, protected files,
  replay, datasource, signing keys, sockets, queue state, and writable state
  have one clear owner.
- Startup, health/readiness, shutdown, restart, upgrade, rollback, backup,
  restore, generation rotation, and failure behavior are tested and documented.
- Operator docs accurately describe current API, config, datasource, replay,
  observability, Milter, Postfix, security, and supply-chain behavior.
- Exim remains explicitly incomplete/deferred to M17 with no fabricated image
  or evidence.
- Executable LDAP/SQL providers and migration remain explicitly M22, and no
  driver or runtime configuration is added early.
- Existing OpenAPI, conformance, security, Valkey, Postfix, fuzz, race,
  vulnerability, workspace, vendor, platform, and guardrail profiles remain
  green.
- All findings are fixed at their root, two approvals bind one unchanged
  snapshot, `temp/` and generated reports remain ignored/unstaged, and exactly
  one project-formatted M20 commit is ready for the orchestrator.

## Review Requirements

The independent reviewer:

- reads the actual diff and every produced image, manifest, SBOM, provenance,
  Compose rendering, deployment report, and operator document;
- independently verifies every external digest and tool/action identity;
- rebuilds representative binaries and OCI layouts from clean state;
- inspects both architectures and proves no host-architecture artifact was
  mislabeled;
- verifies final filesystem, user, capabilities, entrypoint, signals,
  writable mounts, and probe behavior;
- traces daemon/Milter/Postfix network and socket topology from effective
  runtime state, not YAML intent alone;
- reproduces default no-host-exposure and explicit loopback-only SMTP;
- verifies protected-generation ownership and route-capability separation;
- exercises startup, shutdown, failure, queue persistence, upgrade, rollback,
  cleanup, and privacy paths;
- validates documentation against typed config, OpenAPI, completed specs, and
  actual commands;
- rejects any Exim or LDAP/SQL completion overclaim;
- runs every required release, deployment, conformance, security, and
  guardrail gate; and
- fixes every finding at the root with a stable reproducer first where
  practical.

The orchestrator performs a separate second review of the unchanged snapshot,
image/report identities, diff, index, ignored paths, Exim deferment, M22
boundary, and complete gate evidence before exact staging.

## Completion Evidence

Fill after implementation and independent review:

- implementation prompt timings and measured effort;
- fixed base and candidate-snapshot digest;
- exact builder/runtime/tool/action digests;
- per-platform binary/config/layer/manifest image digests;
- reproducibility report digest;
- SBOM and provenance subject/report digests;
- vulnerability tool/database identity and report digest;
- Compose render/topology and Postfix deployment report digests;
- upgrade/rollback/cleanup evidence digests;
- focused container/deployment test results;
- M18 conformance and M19 security report digests;
- full guardrail result;
- reviewer findings and root-cause fixes;
- independent reviewer approval;
- orchestrator approval;
- exact staged durable path inventory; and
- final commit identity.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Authority | Draft/RFC/OpenAPI/product/deployment/supply-chain claims remain separate | pending | pending | |
| Build | Go 1.26, vendor, immutable inputs, deterministic metadata, closed platforms | pending | pending | |
| Images | Minimal non-root hardened runtime for all three products and two architectures | pending | pending | |
| Supply chain | Digests, SBOM, provenance, vulnerability, release policy and tamper proof | pending | pending | |
| Topology | Daemon loopback, Unix Milter, no default host exposure, explicit demo SMTP only | pending | pending | |
| Protected state | Exact owners, modes, filesystems, generations, capabilities, keys and sockets | pending | pending | |
| Postfix | SMTP/non-SMTP mode assignment, tempfail, queue lifecycle and real E2E | pending | pending | |
| Lifecycle | Startup, probes, shutdown, restart, upgrade, rollback, backup and restore | pending | pending | |
| Documentation | API/config/provider/replay/observability/Milter/operator docs match implementation | pending | pending | |
| Privacy | Images, metadata, evidence, output and runtime remain secret-safe and bounded | pending | pending | |
| Exim | Exactly incomplete/deferred M17 with no fabricated packaging/evidence | pending | pending | |
| M22 | LDAP/SQL execution and migration remain deferred with no early dependencies | pending | pending | |
| Gates | Release, deployment, security, conformance and guardrails all pass | pending | pending | |
| Evidence | Two approvals bind one unchanged candidate and exact image/report subjects | pending | pending | |
| Commit | One exact project-formatted commit after approval | pending | pending | |

## Settled Decisions And Deferred Work

- Settled: packaging and deployment do not change Draft-04 or DNS-04 behavior.
- Settled: product images are Linux amd64/arm64, pure Go, digest-pinned,
  non-root, minimal, read-only-root compatible, and capability-free.
- Settled: the default Compose deployment exposes no host port.
- Settled: the only demo publication is explicit Postfix SMTP on canonical host
  loopback; daemon HTTP, metrics, and Milter remain internal.
- Settled: Milter containers preserve the daemon's loopback-only contract by
  sharing the required loopback namespace, not by widening daemon listen
  policy.
- Settled: Postfix reaches only owned Unix Milter sockets and never receives
  daemon signing/replay/protected material.
- Settled: production protected generations are operator-created immutable
  host state; product containers do not repair ownership or generate keys.
- Settled: SBOM, provenance, vulnerability, multi-architecture, and
  reproducibility evidence are release gates.
- Settled: registry publication is not implied by local/CI artifact
  production and requires separate publication authority.
- Deferred: Exim fixes, implementation, packaging, and live compatibility
  evidence remain M17.
- Deferred: LDAP/SQL providers, schema/DDL, pools, generation loading, and
  legacy OpenDKIM migration remain M22.
- Deferred: external implementation comparison, draft issue closure, final API
  polish, and release-candidate declaration remain M21.
