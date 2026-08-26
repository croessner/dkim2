# DKIM2 Draft-05 Semantics Audit — 2026-08-26

Status: complete.

This report records the repository-wide migration to
`draft-ietf-dkim-dkim2-spec-05`. The implemented and tested DNS behavior
remains `draft-chuang-dkim2-dns-04`. The working-group DNS successor has a
normatively identical body, but its identifier and vector migration is
deliberately deferred to a separate reviewed baseline update.

The durable source-diff and occurrence authority is
[`../specs/draft-05-migration-disposition.md`](../specs/draft-05-migration-disposition.md).
Completed implementation specifications and reports that name Draft-04 are
historical records; they do not override the current architecture, OpenAPI,
vectors, conformance manifest, or this audit.

## Semantic result

The current implementation has these intentional tightening boundaries:

- duplicate Message-Instance hash-algorithm names, including case-equivalent
  extension names, are rejected;
- decoded Recipe header keys must be lowercase, including names represented by
  JSON escapes;
- selectors are unique case-insensitively; and
- one signing algorithm occurs at most twice in a field, with distinct
  selectors, while the existing total-set limit still applies.

It has these intentional acceptance expansions:

- Message-Instance verification supports SHA-256, SHA-512, and agreeing dual
  advertisements and checks every supplied supported tuple;
- two signatures using the same algorithm and different selectors are valid;
- a non-origin Message-Instance without a Recipe is an unchanged-state
  transition when every supported predecessor hash agrees; and
- a valid SHA-512-only history can be revised even though deterministic local
  signing output continues to emit SHA-256 Message-Instance hashes.

The unsigned-header set changes canonical input in both directions. The eight
new exact names and every `Received-*` field are unsigned. ARC exclusion is
narrowed to `ARC-Authentication-Results`, `ARC-Message-Signature`, and
`ARC-Seal`; an unknown `ARC-*` field remains signed. The conformance suite
therefore contains fixed Draft-04-to-Draft-05 and Draft-05-to-Draft-04 failure
oracles rather than claiming wire compatibility for affected mail.

Unknown syntactically valid hash and signature algorithm tokens remain
forward-compatible parser input. They are never executed. Verification still
requires at least one supported hash tuple and aggregates unsupported
signature algorithms through the existing fail-closed result model.

## Public result and adapter contract

The sole active `DraftVersion` value is
`draft-ietf-dkim-dkim2-spec-05`. These four new verification reasons are
distinct PERMERROR outcomes:

| Reason | Protocol condition |
| --- | --- |
| `duplicate_hash_algorithm` | One Message-Instance repeats a hash name case-insensitively |
| `invalid_recipe_json` | A present Recipe does not decode and validate as the required JSON form |
| `duplicate_selector` | One DKIM2-Signature repeats a selector case-insensitively |
| `too_many_signatures` | One signing algorithm occurs more than twice |

These reasons remain normal verification responses. They are not the HTTP
request-decode `invalid_json` error and do not become SMTP 4xx, Milter
temporary failure, or Exim defer outcomes. REST, generated clients, CLI,
Milter, and Exim adapters reject unknown draft, reason, and result-state enums.

Public `signature_sets` rows are positional. Repeated algorithms retain their
wire occurrence order and are never merged, deduplicated, keyed, or reordered
by algorithm. Selectors remain internal resolution evidence and are not added
to public output as discriminators.

## Replay migration

Replay projection remains a fixed 32-byte local SHA-256 projection computed
from canonical header input only after every advertised supported
Message-Instance tuple passes. The HMAC frame now includes the Draft-05
identifier, which intentionally makes Draft-04 replay records unreachable.

Deployment is drain-only. Draft-04 and Draft-05 instances must not process
replay traffic concurrently; rolling, mixed-version, fallback, and dual-epoch
migration are unsupported. The old epoch is drained for the configured
retention period before Draft-05 admission. Because old records are
unreachable after activation, the possible replay-detection gap is bounded by
that retention period. Key width, namespace, privileges, topology, and Valkey
`SET NX PX` ownership are unchanged. The complete runbook is
[`../replay-store-valkey.md`](../replay-store-valkey.md).

## Exim evidence state

The source-linked Exim implementation and qualification runner remain in the
repository, but the current capability is exactly `unqualified_draft05`. The
dated five-row Linux matrix is candidate-bound Draft-04 evidence and is not
relabeled, imported, or treated as Draft-05 security evidence.

Portable and full Draft-05 conformance contain no Exim suite or case and reject
an Exim evidence root. The security report also rejects `qualified_linux`, an
Exim result, or imported evidence. Restoring qualification requires a fresh,
separately authorized five-row Draft-05 run bound to unchanged candidate bytes
and a reviewed capability-state migration.

## Resource and security invariants

The migration retains bounded message, header, recipe, signature-set, DNS,
history, result-retention, replay, HTTP, Milter, datasource, and telemetry
owners. SHA-512 uses fixed-size digest storage and does not introduce
input-sized labels or raw-value diagnostics. Every selector/key lookup remains
independent and bounded by the admissible signature-set count.

Cancellation and deadlines remain context-aware at parser orchestration,
resolver, datasource, replay, daemon, adapter, and external-process
boundaries. Ambiguous keys, providers, histories, evidence, enum values, and
replay outcomes fail closed. Errors, logs, traces, metrics, REST, CLI, reports,
and test output do not add raw messages, recipes, recipients, selectors,
digests, replay keys, DNS records, credentials, private keys, protected paths,
or unbounded errors.

The closed security inventory binds every first-party fuzz target and every
cross-product resource proof to its package owner. Prometheus labels retain the
documented low-cardinality allowlist; SHA-512, selector, recipe, and header
classification changes add no identity-bearing label.

## Architecture review

The standalone library remains free of OpenAPI, daemon, Milter, Cobra, Viper,
Fx, Prometheus, and exporter dependencies. Canonical bytes, hash algorithms,
header relevance, Recipe rules, signature cardinality, verification history,
replay identity, policy projection, OpenAPI mapping, and adapter translation
each retain one owning abstraction. Generated REST types remain at HTTP and
adapter boundaries. No Draft-05 rule was copied into an MTA adapter or
observability channel.

All changed hand-written named functions and methods were audited for concise
English doc comments. Historical Draft-04 implementation records are marked as
historical rather than rewritten as if their original acceptance evidence had
tested Draft-05.

## Validation record

The pre-edit `make check-operator-docs` unexpectedly passed. This exposed a
guard defect: the old check positively required the stale Draft-04 baseline
and `qualified_linux`, so the earlier runtime/evidence migration could not make
it red. The guard now requires Draft-05 and `unqualified_draft05`, rejects the
old active claims, verifies all four reasons and positional results, and binds
the replay, DNS, and historical-report boundaries above.

The exact combined pre-05 sweep returned 396 matching lines on 63 paths. The
full message-draft form returned 101 occurrences on 36 paths. Every occurrence
was checked against the Prompt-01 disposition: all are historical,
cross-version, negative-proof, migration, authority, external-source, or
unrelated vendored JSON-Schema context. There are zero unexplained active stale
occurrences. The DNS sweep found 93 approved DNS-04 occurrences and seven full
working-group DNS-00 occurrences: the five deferred external-source sites plus
the disposition's two self-audit references. No new full DNS-00 site was
introduced.

The documentation shell syntax and operator guard, `make check-reference`,
the OpenAPI Make-contract test, `make check-boundaries`, the complete tools
module tests, `make check-conformance`, `make conformance`,
`make conformance-all`, `make check-security`, real Valkey 9.1.0 replay,
closed-inventory fuzz, sequential race, vulnerability, and the complete
`make guardrails` aggregate all passed. The OpenAPI/reference and vulnerability
sandbox runs that require loopback or network were repeated unchanged outside
the sandbox and passed.

One initially parallel race-security execution conflicted with fuzz-security
on their proof-owned cache/proxy state and reported `race_failure_02`. The
failing Milter module passed visibly on direct reproduction, and the unchanged
aggregate race gate passed when rerun alone after fuzz completed. Security
proof runners must therefore remain sequential; this is an execution
constraint, not a candidate defect.

The approved migration specification remained unchanged at SHA-256
`e68154e858d1e55f0fd3b6715df48c36ebfd6ed9ead740594a265687607b98c3`.
No remaining Prompt-06 or Prompt-07 remediation finding was identified.
