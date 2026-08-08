# Native Datasource Rotation Campaign, Retention, And Scale

Status: implementation candidate; release approval blocked pending disposable
provider evidence, consumer adoption, and fresh independent review.

This specification defines one provider-neutral global DKIM key-rotation
campaign, bounded generation retention and destruction, and production-scale
datasource limits for LDAP, PostgreSQL, MySQL, and MariaDB. It corrects the
operationally unsafe shape in which rotating one binding can publish one whole
datasource generation and retained generations have no repository-owned purge
workflow.

The normal path prepares one complete immutable candidate for the complete
frozen campaign, publishes and proves its DNS records in bounded batches, and
advances `current` exactly once after every frozen binding is complete. A
separate explicit emergency path may rotate one binding immediately. Neither
path edits an active or committed generation in place.

## Source Documents

This specification is governed by:

- `AGENTS.md`;
- `POLICY.md`;
- `docs/ARCHITECTURE.md`, especially the datasource-provider and native-domain
  administration sections;
- `docs/specs/spec-and-prompt-template.md`;
- `docs/specs/implementation/datasource-providers.md`;
- `docs/specs/implementation/ldap-sql-datasource-legacy-migration.md`;
- `docs/specs/implementation/native-datasource-key-custody.md`;
- `docs/specs/implementation/native-domain-onboarding.md`;
- `docs/specs/implementation/mysql-mariadb-datasource.md`;
- `docs/operator/datasource-key-rotation.md`;
- `docs/operator/native-domain-onboarding.md`;
- `docs/operator/datasource-backends.md`;
- `docs/operator/ldap-schema-reference.md`;
- the deployed LDAP schema/ACL and PostgreSQL/MySQL/MariaDB DDL under
  `contrib/schema/`;
- `Makefile` and the repository-owned provider, security, documentation, and
  release gates.

If implementation evidence conflicts with this specification or a governing
source, stop and reconcile the durable contract before broadening code.

## Original Gap

The current native administration model can create one complete higher
generation for one domain operation. A caller that applies this model to a
normal scheduled rotation one binding at a time can therefore duplicate the
complete datasource once per binding. For an installation with thousands of
domains this multiplies LDAP/SQL rows and private-key copies by the number of
bindings before any retention policy is considered.

The backend contracts retain old generations but expose no provider-neutral
destruction authority. `MaxGenerations` and outstanding-candidate ceilings are
read/allocation safety bounds, not retention. Reaching such a bound stops new
work; it does not reclaim storage. The operator documentation explicitly
leaves deletion to a future separately reviewed procedure.

The current compiled datasource ceilings are also below the intended large
installation shape: 1024 profiles, 2048 handles, 4096 policies, 9216 aggregate
public records, a 4096-row administrative default, and a fixed 16 MiB runtime
load budget. Additionally, administrative snapshot construction currently
contains a profile lookup nested inside credential iteration. Raising counts
without removing such nonlinear work would replace a hard limit with latency
and memory exhaustion.

Finally, `opendkim-manage-go` cannot import `cmd/dkim2d/internal/*`. Without an
explicit owner-writer or conformance boundary, two repositories can implement
similar generation semantics and drift on fencing, digest, retention, or
destruction behavior.

## Goal

Normal scheduled rotation has the following externally observable result:

1. read and freeze one exact complete current generation `N` and its complete
   eligible binding set;
2. allocate one operation and one strictly higher candidate generation `C`;
3. prepare exactly one complete immutable `C` containing the replacement key
   material for every frozen binding and the unchanged nonrotated content;
4. stage, read back, validate, and seal that complete candidate once while
   leaving `current=N`;
5. publish and prove the candidate DNS records in finite configurable batches;
6. refuse activation until every frozen binding has exact durable completion
   evidence and a final fresh bounded DNS proof policy passes;
7. atomically change `current` from exact `N` to exact `C` once; and
8. apply bounded retention independently, never as an implicit side effect of
   activation.

The number of complete datasource generations produced by one successful
normal campaign is one, independent of its domain or binding count.

## Delivery Shape

1. Freeze campaign, retention, scale, compatibility, and owner-writer
   contracts.
2. Make datasource limits configurable and linearize large-snapshot work.
3. Implement provider-neutral immutable campaign planning and preparation.
4. Implement bounded DNS batches, journal/resume, activation, and emergency
   separation.
5. Implement LDAP campaign and exact readback parity.
6. Implement PostgreSQL/MySQL/MariaDB campaign and exact readback parity.
7. Implement provider-neutral retention classification and protected purge
   plans.
8. Implement LDAP and SQL destruction authorities with reconciliation.
9. Add CLI/config/report/observability and cross-repository conformance.
10. Prove large-corpus provider parity, runtime reload, signing, documentation,
    guardrails, and independent review.

## Implementation Effort

Planning estimate:

| Field | Value |
| --- | --- |
| Estimated size | very large |
| Estimated wall-clock effort | 2 to 5 agent-days plus disposable-provider and release evidence |
| Highest-risk areas | immutable all-binding preparation, LDAP partial-failure recovery, destructive authorization, large-snapshot memory behavior, cross-repository ownership |
| Expected prompt count | ten implementation prompts plus one independent review/fix prompt |
| Required final gate | full repository guardrails plus disposable four-provider campaign/purge evidence and repeated unchanged candidate identity |

Risk notes:

- Lower risk: closed CLI vocabulary, bounded reports, documentation navigation.
- Medium risk: configurable limits, indexed snapshot construction, paged DNS
  export/proof, compact audit records.
- Highest risk: private-key ownership while constructing one large immutable
  candidate, LDAP stage/purge ambiguity, SQL/LDAP least privilege, exactly-once
  activation, and an authoritative contract consumable by another repository.

Measured effort is filled during closeout:

| Prompt | Started At | Completed At | Wall-Clock Duration | Active Engineering Time | Notes |
| --- | --- | --- | --- | --- | --- |
| Prompt 01-10 |  |  |  |  | implementation ledger owns exact spans |
| Prompt 11 |  |  |  |  | fresh independent review and fixes |

## Scope

In scope:

- normal all-eligible-binding rotation as one global frozen campaign;
- one immutable candidate prepared and staged once per normal campaign;
- bounded DNS publication/proof batches over that unchanged candidate;
- one exact final `current` transition after complete campaign evidence;
- an explicit separately named emergency one-binding rotation path;
- provider-neutral retention classification, purge planning, destruction, and
  reconciliation across LDAP, PostgreSQL, MySQL, and MariaDB;
- compact retained audit metadata without retained full private snapshots;
- configurable finite datasource, administration, DNS-batch, generation, and
  load limits under non-widenable hard maxima;
- linear or documented `O(n log n)` algorithms for large datasource work;
- schema/DDL forward migrations, least privilege, provider parity, operator
  docs, and protected reports;
- a DKIM2-owned writer or conformance contract that `opendkim-manage-go` can
  consume without importing an internal package.

Out of scope:

- changing DKIM2 protocol, OpenAPI signing semantics, Milter behavior, or Exim
  behavior;
- automatic DNS mutation by DKIM2;
- in-place mutation of active or committed candidate content;
- implicit deletion during activation;
- moving `current` backward;
- treating a normal campaign as thousands of onboarding operations;
- HSM/KMS custody, online REST administration, or unbounded work;
- retaining old full generations merely for generic audit convenience.

## Rotation Modes

### Normal Global Campaign

The normal mode is the default for scheduled or automatic rotation. Its frozen
work item is the canonical active signing binding, not an arbitrary LDAP row:

```text
(tenant, domain, profile use, current profile, ordered active algorithms)
```

The implementation must account for every active binding in the stable source
snapshot. A domain with multiple profile uses has multiple work items; a work
item with RSA and Ed25519 still belongs to the same campaign. Disabled/off
records are retained unchanged unless an explicit settled policy says they are
eligible.

Planning binds source schema/generation, authority, operation, candidate
generation, canonical frozen-work digest, item count, algorithm counts,
rotation policy, DNS policy, retention-policy version, and limit profile. The
frozen digest is key-free. A changed source or changed policy requires a new
operation; the work set is never silently expanded during resume.

The frozen source generation is immutable campaign evidence. New campaign
envelopes include it in their candidate digest and providers must persist and
read it from the candidate root; it is never inferred from a later `current`
pointer. A legacy candidate without this field is unknown for terminal/purge
recovery and remains retained.

Preparation constructs one complete immutable candidate. Implementations may
use bounded memory or a protected owner-only temporary spool when necessary,
but the spool is not the journal, is never generic output, is never committed,
has the same filesystem and erasure protections as native private-key custody,
and is destroyed after exact backend readback or terminal failure. The
candidate digest is finalized before backend publication. Backend publication
then stages and seals that one candidate using the existing complete-snapshot
principle. Candidate content is never mutated between DNS batches.

If preparation loses not-yet-durable private keys, it must not invent a
different candidate under the same digest. An exact staged or committed
candidate may resume after canonical readback. A partial candidate that cannot
be proven equal enters reconciliation/abort and later explicit purge; it never
activates.

### DNS Batches

DNS batching limits external work, not datasource generations. Every batch is
a deterministic ordered slice of the frozen candidate credential set. A batch
records only bounded progress evidence in the protected campaign journal:
batch ordinal/range, candidate binding, algorithm/count classes, proof
completion time, proof-policy version, and a domain-separated digest. General
reports expose only counts and closed classes.

Batch completion does not alter candidate content or `current`. Resume
recomputes the same batch boundaries from the frozen candidate and rejects
missing, duplicate, overlapping, reordered, foreign, or changed records.

DKIM2 does not mutate DNS. It may write one bounded, owner-only deterministic
batch artifact for a separately authorized external publisher, then performs
fresh resolver-path proof through its configured recursive resolver policy.
Export is neither proof nor publication evidence and never advances `current`;
activation remains unavailable until every exact candidate batch is freshly
proven under the campaign's existing datasource fence.

Activation performs the specification's final proof policy. The policy must be
finite and explicit: either every candidate record is re-proven within a
bounded final window, or every persisted batch proof must remain within a
configured maximum age and a final drift sample/full pass required by policy
must succeed. An old journal bit alone never authorizes activation.

### Emergency One-Binding Rotation

Emergency rotation is explicit and never selected by the normal automatic
path. Its command/config/report mode is named `emergency`, requires one exact
binding and a closed reason class such as compromise, and retains the same
complete-generation, DNS proof, readback, and expected-current fences. It may
therefore create one immediate higher generation, but it must not masquerade
as progress in a normal global campaign.

Starting emergency rotation while a normal campaign is open, or vice versa,
fails closed unless an explicit reconciliation first terminates the stale
operation. After an emergency activation, any campaign frozen from the older
generation conflicts and must be replanned.

## Campaign State And Exactly-Once Activation

The public closed state progression is:

```text
planned -> preparing -> prepared -> staged -> dns_in_progress -> dns_complete
        -> activating -> activated
```

`conflict`, `failed`, and `aborted` are terminal. `reconcile_required` permits
only read-only status, reconciliation, or explicitly authorized abort/purge
planning. Internal write-ahead phases may be more detailed but cannot be
reported as public success.

Required invariants:

- one campaign has exactly one source generation and one candidate generation;
- successful prepare creates one immutable content digest;
- every DNS batch binds that digest and frozen-work digest;
- all frozen work items are accounted for exactly once before activation;
- `current` remains `N` through `dns_complete`;
- activation uses exact expected-current, schema, generation, operation,
  candidate digest, administration-lock revision, and final DNS evidence;
- at most one concurrent activation wins;
- an ambiguous backend result is never retried automatically and becomes
  `reconcile_required`;
- successful reconciliation may record activation only from exact prior
  activating write-ahead lineage and authoritative current/readback evidence;
- runtime reload and mailflow/signing proof remain external postconditions.

## Provider-Neutral Retention And Purge

Retention is a selection policy; purge is a separate destructive operation.
Neither is an implicit tail of rotation or startup.

The configuration exposes finite values under hard maxima, including:

- maximum total retained generations;
- minimum active rollback generations to retain;
- maximum closed never-active/aborted generations to retain;
- purge batch size;
- optional minimum retention interval when trustworthy lifecycle timestamps
  are implemented; and
- whether legacy v2 history is eligible. The restrictive default keeps legacy
  v2 history and requires explicit compatibility authorization to destroy it.

At minimum, purge selection must classify:

- current generation: never eligible;
- open campaign candidate: never eligible;
- unknown, malformed, partial, or foreign-owned generation: never eligible;
- newest configured count of committed `was_active=true` rollback generations:
  retained;
- older exact committed `was_active=true` generations: eligible only after all
  count/time/backup policy predicates pass;
- exact closed never-active or aborted candidates: separately eligible under
  their own limit/grace policy;
- noncurrent v2 without exact activation history: retained by default;
- already absent generation: idempotent success only for the exact purge plan.

A purge plan binds authority, stable inventory/current, retention-policy
version, exact ordered targets, reason classes, expected row/byte counts when
available, and a domain-separated plan digest. Planning is read-only. Apply
requires an explicit destructive flag, the protected plan artifact, exact
digest/readback, and the separate purge authority. Generic output reports only
counts and closed reason/result classes.

Purge keeps a compact key-free audit receipt containing generation number,
schema class, prior lifecycle class, operation class where safe, content-digest
commitment, destruction time/result, policy version, and purge-plan
commitment. It retains no domain, selector, handle, DNS TXT, private PKCS#8,
password, DN, SQL text, or full generation snapshot. Audit metadata has its own
bounded retention policy so it also cannot grow without limit.

### Recovery Inventory And Closure Evidence

Retention recovery has a separate provider-owned read contract. It is not an
allocation read and must not inherit `MaxGenerations`: LDAP and SQL readers
page a stable, exact inventory up to 16,384 roots, bind an exact current
reread, and independently verify every referenced generation before it becomes
complete trusted retention evidence. Root metadata alone is not proof of a
complete sealed content set. A missing child, partial record set, mismatched
content commitment, foreign owner, changed current, page gap, duplicate, or
unstable reread is unresolved and never eligible.

The recovery inventory commitment includes the policy version, current pointer,
and every observed generation lifecycle and content fact. Apply recomputes that
commitment; a non-target change makes the purge artifact stale. Exact
all-target absence is handled only through the already bound target facts and a
provider receipt/reconciliation path.

Never-active or aborted removal requires forward-only immutable closure
evidence. Each provider records exactly one terminal closure class and the
sealed content commitment under the dedicated lifecycle authority. The v3
candidate root also persists its frozen `source_generation`; recovery carries
the exact operation, source, candidate generation, and digest to a dedicated
terminal read and accepts closure only when all fields and the terminal-current
fence match. It cannot be altered, applied to current or active history, or
inferred from root order, age, or an absent operation. Legacy v2 and unmarked
v3 records remain retained.

### LDAP Destruction

LDAP uses a fourth distinct purge bind. Snapshot, stager, activator, runtime,
legacy publisher, and purger permissions remain noninterchangeable. The purger
has no current-pointer write permission and cannot stage or activate.

Apply holds the revisioned administration lock, rereads exact current and
target metadata, and deletes a selected noncurrent generation leaf-first with
the root last. A crash can leave an inert partial noncurrent tree; exact retry
or reconcile enumerates and removes only descendants still bound to the purge
plan. The root's absence is the durable completion fence. ACL/schema tests must
prove the current subtree cannot be deleted through the purge role, including
direct-bind abuse rather than application-only claims.

### SQL Destruction

PostgreSQL and the MySQL/MariaDB family use a fourth distinct purge role and
fixed schema-owned routine. One transaction locks the publication/admin fence,
checks exact expected current and target classification, deletes only the
selected generation through foreign-key-owned cleanup, writes the compact
receipt, and commits once. Public table delete privileges remain revoked.
Uncertain commit is reconciled by exact target/receipt readback and is never
blindly retried.

## Scale And Complexity Contract

Compiled hard maxima protect the process; operator configuration chooses lower
finite deployment limits. Runtime and offline administration must use the same
selected logical count profile when validating a candidate. Configurable
limits include profiles, handles, policies, aggregate records, decoded bytes,
backend load bytes, page size, load deadline, campaign work items, DNS batch
records/concurrency, generations, and protected report/document sizes.

The protected offline command has a finite deployment deadline no greater
than 24 hours. This whole-campaign bound is deliberately separate from the
shorter per-provider operation deadlines: a large RSA campaign may require
more than five minutes even though every LDAP or SQL request remains narrowly
bounded. Zero, negative, unparsable, and longer values fail closed.

The supported production profile must include at least 10,000 domains with two
algorithms for one active use, plus documented headroom for multiple uses. The
exact hard maxima and defaults are settled during implementation from measured
memory/load evidence; they must not be guessed by multiplying current constants
without proof.

Large-snapshot construction, validation, digesting, mapping, and lookup are
linear or `O(n log n)` for canonical sorting. In particular, profile lookup is
map-indexed once rather than scanning every profile for each credential.
Checked arithmetic precedes allocation. Duplicate maps and canonical sort keys
remain bounded by the selected limits. No test or implementation builds a
quadratic all-pairs structure.

Provider loaders remain paged and context-aware. A page limit is not a total
limit. Runtime refresh either owns a complete validated snapshot or retains
the prior immutable snapshot and reports degraded state; it never publishes a
partial large generation.

## Package Boundaries

- `lib/internal/datasource` and `lib/provider`: authoritative datasource
  limits, canonical validation, immutable runtime model, and large-corpus
  complexity fixes; no LDAP/SQL/CLI dependencies.
- `cmd/dkim2d/internal/datasourceadmin`: provider-neutral protected snapshots,
  immutable campaign envelope, generation inventory, retention/purge plans,
  typed evidence, and narrow backend interfaces.
- `cmd/dkim2d/internal/rotationadmin`: campaign intent, frozen plan, protected
  journal, DNS batch state, emergency separation, retention orchestration, and
  report facts.
- `cmd/dkim2d/internal/datasource/{ldap,sqlsnapshot,postgresql,mysql}`: concrete
  stage/readback/activate/purge implementations and transport error mapping.
- `cmd/dkim2d/internal/command` and an offline runtime owner: thin CLI,
  protected config construction, and dependency wiring.
- `cmd/dkim2d/internal/domainadmin`: existing one-domain onboarding semantics;
  reusable primitives may be factored downward, but global campaigns are not
  disguised as repeated onboarding.
- `cmd/dkim2-milter`, `cmd/dkim2-exim`, `cmd/dkim2ctl`, REST/OpenAPI: unchanged
  except documentation or generated-boundary proof where directly required.

## Owner-Writer And Cross-Repository Contract

DKIM2 owns generation schema, campaign digest grammar, publication states,
fencing, retention classification, and purge semantics. Because another Go
repository cannot import `cmd/dkim2d/internal/*`, implementation must choose
and document one authoritative integration boundary before
`opendkim-manage-go` writes campaign state:

1. DKIM2 CLI is the sole backend writer and exposes a protected deterministic
   machine contract consumed by `opendkim-manage-go`; or
2. DKIM2 publishes a deliberately public, narrow administration/conformance
   package that contains no concrete provider or service dependency; or
3. DKIM2 publishes versioned canonical conformance fixtures and schemas, while
   `opendkim-manage-go` implements the adapter and must pass byte-exact shared
   plan/digest/state/purge vectors before release.

Silent source copying is forbidden. The selected contract has an explicit
version, compatibility policy, golden vectors, negative vectors, and a release
gate in both repositories. DKIM2 schema/DDL remains the owner; Mailstack owns
only deployment pins and rollout.

## Schema And Migration Compatibility

- Existing committed native v2 and v3 generations remain runtime-readable.
- Existing `001`-`003` SQL migration files are historical artifacts and are
  not rewritten. Add forward `004` migrations for campaign/retention/purge.
- New LDAP attributes/object classes receive new permanent OIDs below the
  allocated RNS DKIM2 subtree. Existing descriptors/OIDs are unchanged.
- Prefer keeping the final committed campaign snapshot compatible with the
  existing v3 runtime contract. New provisional metadata must not require a
  progressively mutable committed candidate.
- Schema/DDL is deployed before enabling a campaign or purge writer.
- Mixed binary/schema versions fail closed. Rollout documentation states the
  safe order and readback proof for every role.
- Direct old administrative clients encountering new open campaign metadata
  must stop rather than allocate a second candidate or infer absence.

## Security And Privacy

Operational availability and bounded storage are security properties here.
Unbounded private-key snapshots are both a capacity risk and unnecessary key
exposure.

Private keys, passwords, TSIG material, CA bytes, protected paths, raw DNS,
tenant/domain/selector/handle/profile identities, LDAP DNs, SQL values,
operation IDs, campaign digests usable as correlators, and purge targets never
appear in logs, traces, metrics labels, generic reports, errors, panics, or test
failure formatting. Protected journals/plans contain only the explicitly
specified resumability facts and never private keys. A temporary protected
candidate spool, if used, is separately owned, link/symlink/race hardened,
bounded, synchronously erased where practical, and excluded from generic
serialization.

TLS verification, separate authorities, candidate readback, DNS proof,
current fencing, fail-closed ambiguity, and dry-run no-write behavior are not
weakened to improve throughput. Destructive apply requires explicit operator
intent and never follows from retention config alone.

## Observability

Offline observations use only low-cardinality classes: command/mode, campaign
state, backend class, algorithm family, result/failure class, count bucket,
batch bucket, purge reason class, and duration bucket. No endpoint is created.

Reports expose bounded totals such as frozen, prepared, DNS-complete, retained,
eligible, purged, and unresolved counts. They do not enumerate identities or
emit raw digests. Runtime keeps existing generation/readiness semantics; a
campaign activation is not called verified until external reload and signing
evidence succeeds.

## Required Tests

Unit tests:

- deterministic frozen binding inventory and key-free plan digest;
- exactly one immutable candidate for one through at least 10,000 domains;
- linear profile/credential mapping and checked limit boundaries;
- deterministic batch slicing with no gaps, duplicates, overlaps, or reorder;
- state/command matrix, resume, abort, conflict, and activating lineage;
- normal versus emergency separation;
- retention classification for current, newest rollback history, old history,
  never-active, aborted, open, partial, unknown, absent, and legacy v2;
- protected purge plan digest, exact apply fence, compact receipt, and privacy;
- toxic formatting/JSON/log/metric/report markers;
- cancellation, deadlines, integer exhaustion, and erasure.

Integration and E2E tests:

- disposable LDAP/PostgreSQL/MySQL/MariaDB normal campaign parity;
- thousands of frozen work items produce one candidate and one current move;
- crash/resume before and after prepare, stage, every DNS-batch transition,
  activating write-ahead, backend commit, and journal update;
- changed current, foreign operation, stale digest, missing/extra row, DNS
  drift/expiry, and concurrent activation fail closed;
- separate emergency rotation invalidates a stale normal campaign;
- purge-role least privilege, never-current proof, retained-count edges,
  partial LDAP delete reconciliation, SQL uncertain commit reconciliation, and
  idempotent exact-plan retry;
- runtime reload of a large snapshot and controlled signing from first,
  middle, and last bindings;
- exact DKIM2/`opendkim-manage-go` conformance vectors and negative drift
  detection;
- existing native onboarding, OpenDKIM bootstrap, and higher-generation
  rollback regressions.

Generated and documentation checks:

- LDAP schema/OIDs/ACL/index/layout and SQL `004` migrations install cleanly;
- provider service scripts apply forward `005` terminal-closure and `006`
  source-binding migrations in order and prove all five isolated roles
  (snapshot, staging, activation, purge, and closer);
- CLI help/config examples, architecture, backend, rotation, onboarding,
  retention, backup, rollback, and release docs agree;
- OpenAPI/generated client outputs remain unchanged unless the durable boundary
  explicitly changes;
- owner-writer/conformance manifests are current and byte exact.

Final gate:

```text
make check-datasource-schema
make check-datasource-postgresql
make check-datasource-mysql
make test-datasource-services
make test-opendkim-bootstrap
make check-operator-docs
make check-openapi
make check-boundaries
make check-security
make test
make race
make lint
make govulncheck
make guardrails
git diff --check
git status --short
```

The final candidate identity is reproduced twice unchanged. Any required skip,
stale schema, missing disposable provider, unavailable conformance peer, or
unresolved finding prevents approval.

## Acceptance Criteria

- A normal campaign over any supported frozen binding count creates exactly one
  complete candidate generation and advances `current` exactly once.
- Candidate content is prepared once and never mutated between DNS batches.
- Activation is impossible until every frozen binding and final DNS policy is
  complete and exact.
- Emergency one-binding rotation is explicit, separately reported, and never
  selected by the normal automatic path.
- Retention and purge are provider-neutral, bounded, explicit, dry-run first,
  least-privileged, never-current, and independently reconcilable.
- Audit continuity does not retain full old private-key snapshots.
- At least 10,000 domains with realistic credentials load, validate, refresh,
  and sign within measured finite limits without quadratic work.
- LDAP, PostgreSQL, MySQL, and MariaDB implement the same lifecycle decisions.
- Existing committed v2/v3 data and onboarding/rollback behavior remain
  compatible.
- `opendkim-manage-go` consumes a versioned DKIM2-owned writer or conformance
  contract; duplicated unversioned lifecycle rules are absent.
- Full gates and fresh independent review report no unresolved in-scope issue.

## Completion Evidence

Prompt 10 closeout recorded the following exact candidate evidence:

- Focused campaign, retention/purge, LDAP, PostgreSQL, MySQL/MariaDB, command,
  runtime, race, large-profile, bootstrap, schema, documentation, boundary,
  security, conformance, lint, test, and vulnerability checks passed where
  executable. The 10,000-domain two-algorithm profile corpus passed in 4.533s
  in Prompt 02.
- The final conformance repair updated three stale manifest bindings only after
  tracing each to an earlier source change. `make check-conformance` then
  passed; the runner was not weakened.
- The candidate snapshot identity was reproduced twice unchanged; its exact
  digest is retained only in the ignored execution ledger to avoid a
  self-referential durable candidate change.
- Disposable LDAP/PostgreSQL/MySQL/MariaDB proof remains blocked because the
  harness's `openldap_runtime` exits before any provider test. No cleanup or
  test-environment workaround was authorized.
- Generated-output/aggregate guardrails remain blocked on the intentionally
  dirty-candidate `module_base` reference check before `check-openapi` can
  execute. The public contract fixture passes, but `opendkim-manage-go` has not
  yet adopted it, so consumer conformance is unavailable.
- The working tree is intentionally uncommitted for independent review. The
  unrelated untracked `.codex/agents/` directory was preserved; it is included
  by the repository candidate-snapshot tool and prevents treating that digest
  as a source-only implementation identity.

## Review Matrix

| Area | Soll | Ist | Status | Notes |
| --- | --- | --- | --- | --- |
| Normal campaign | One frozen campaign, one immutable candidate, one activation | provider-neutral coordinator and LDAP/SQL composition | partial | disposable four-provider proof pending |
| DNS batching | Bounded work over unchanged candidate | canonical journal, parser-valid export/proof and final fence | done | runtime service proof remains a separate blocked gate |
| Emergency | Explicit separate one-binding path | closed CLI/config/intent and shared lock exclusion | done | fresh independent review pending |
| Retention/purge | Four-provider explicit safe destruction and compact audit | protected classifier/plan/receipt and concrete adapter paths | partial | disposable least-privilege/reconciliation proof pending |
| Scale | Configurable finite limits and linear large-snapshot work | production profile and 10,000-domain two-algorithm corpus | done | 4.533s measured in Prompt 02 |
| Compatibility | Forward migrations and v2/v3 read compatibility | forward LDAP/SQL v3 fences and `004` migrations | partial | service migration proof pending |
| Ownership | Versioned DKIM2 writer/conformance boundary | public stdlib-only `admincontract` v1 and strict fixture | partial | consumer adoption pending |
| Tests/review | Full parity, large corpus, guardrails, fresh review | local focused/full gates and repeated candidate snapshot | partial | service, dirty-candidate generated gate, consumer, fresh review block approval |
| Effort | Exact prompt spans retained | ignored execution ledger | done | Prompt 10 records known timing limitations |

## Decisions And Open Questions

- Settled: normal automatic rotation is global and produces one candidate,
  never one generation per binding.
- Settled: the complete candidate is prepared once before DNS batching; DNS
  batching does not progressively mutate candidate content.
- Settled: `current` changes once only after all frozen bindings complete.
- Settled: emergency one-binding rotation exists but is explicit and separate.
- Settled: retention does not imply destruction; purge is a separate apply
  operation with its own authority.
- Settled: compact audit commitments replace indefinite full private-snapshot
  retention.
- Settled: all limits remain finite, configurable below hard maxima, and backed
  by large-corpus measurement.
- Settled: `github.com/croessner/dkim2/admincontract` is the narrow public,
  standard-library-only owner boundary. It freezes versioned campaign, frozen
  work, DNS batch, purge plan, and compact audit commitments. Synthetic
  positive and negative fixtures live with that package and participate in
  `make check-conformance`. Concrete LDAP/SQL providers, private candidate
  rows, command wiring, and protected journals remain daemon-internal.
- Open for measured implementation: exact default/hard count, byte, deadline,
  batch, and retention values. Measurement may narrow them but cannot remove
  the 10,000-domain acceptance profile.
