# Security Testing And Evidence

DKIM2 security evidence is a repository-owned local security profile. It does
not add requirements to `draft-ietf-dkim-dkim2-spec-06`, the historical
`draft-chuang-dkim2-dns-04` behavior baseline, or the incorporated RFCs.
Normative, documented-interpretation, OpenAPI, adapter, and local-policy
assertions remain separately classified.

The profile treats raw messages, SMTP envelopes, protocol fields, recipes, DNS
and datasource records, replay responses, HTTP and Milter peers, protected
files, configuration, and all tool/report inputs as hostile. It protects exact
message and envelope evidence, protocol authority, private signing material,
capabilities, provider generations, replay identity, process availability,
trusted `Authentication-Results`, and telemetry privacy. Delivery-status
propagation extends the same profile: an inbound notification, its embedded
original, and the reconstructed previous state are hostile input; locality is
datasource authority and never an address in `mf=`; the previous hop's
signature is verified over the reconstructed state before its `mf=` may become
a recipient; the regenerated report carries no destination-specific data
beyond the status code and the original envelope identifier; and the
propagation coordinate is reserved before signing and committed only after
re-injection. The propagation adapter's LMTP peer is hostile: it may pipeline,
send unadvertised commands and parameters, exceed the advertised `SIZE`, offer
a non-null sender or a second recipient, and drop mid-transfer.

## Closed Inventories

`tools/internal/security` owns two non-extensible inventories:

- every first-party Go fuzz target outside `vendor/`, including its exact
  module, package, function, source, boundary, evidence class, seed source,
  properties, bounding strategy, external-I/O policy, regression owner, and
  minimum duration;
- every cross-product resource-limit owner, its dimensions, and representative
  exact/one-over proof tests.

The inventory deliberately records no second copy of numeric production
limits. Each cohesive production package remains the authority for its limit
values. The security inventory records only ownership, dimension names, and
exact proof source/function pairs, and fails when independently parsed fuzz
functions or proof locations drift.

Delivery-status propagation contributes two `draft_normative` fuzz targets to
that inventory, `FuzzReceivedDSN` over the received-notification parser path
and `FuzzRebuild` over the Section 12.1.1 rebuild input. The
received-notification and rebuild bounds are owned by the existing
`verification`, `recipe`, `raw-message`, `tag-fields`, and `signing` entries.
The propagation adapter's transport bounds, the LMTP message, command, data
line, forward path, recipient, connection, and in-flight limits together with
the daemon response, next-hop, and re-injection reply bounds, are the
`propagator` resource owner, proven by the adapter's oversized-data,
second-recipient, invalid-limit, and connection-limit tests.

The fuzz runner accepts no caller-selected target, package, command, flag,
environment, URL, endpoint, output location, or duration. It maps the closed
inventory to fixed `go test` invocations and runs every target individually for
at least ten seconds.

## Evidence

Generated evidence is written only below ignored `.artifacts/security/`.
Reports contain bounded identifiers, tool identities, digests, platform facts,
closed states, and finding counts. They do not contain corpus bytes, messages,
envelopes, identities, paths from protected inputs, provider records, replay
keys, DNS data, capabilities, secrets, raw commands, or raw errors.

The complete report binds:

- the exact candidate revision and durable snapshot, after admission as a descendant of the fixed Git trust anchor;
- the pinned DKIM2 and DNS draft identifiers;
- the closed fuzz/resource inventory digest;
- Go, platform, fuzz, race, and vulnerability state;
- current portable and full conformance reports;
- two current real-Postfix qualification reports, including the
  delivery-status propagation lane;
- zero unresolved findings; and
- the exact `unqualified_draft06` Exim capability through the candidate-bound
  full conformance report, with no Exim suite, case, or evidence import.

Evidence readers reject duplicate JSON members, symlinked paths, partial
identity-only reports, unexpected evidence paths, and reports that fail their
complete conformance or real-Postfix validation contract. Fuzz, race, and
vulnerability subprocesses use a closed Go environment; the vulnerability
database is explicitly pinned to `https://vuln.go.dev`.

Any durable change invalidates prior fuzz, vulnerability, conformance, Postfix,
security, and review evidence.

Offline native-domain administration additionally treats protected admin,
intent, receipt/journal, DNS export, candidate readback, and datasource report
inputs as hostile. Package-owned abuse and race tests prove bounded parsing,
receipt-before-Claim recovery, no-mutation ambiguity handling, canonical
private readback, role separation, and secret-safe observations. The
digest-pinned four-backend report is separate candidate-bound evidence under
the closed `dkim2.datasource-integration-report.v2` producer, JSON Schema, Go
validator, CLI, and collector chain. It requires four qualification runs, 54 unique allowlisted checks,
and exactly twelve backend-by-result-class PASS objects. It does not expose
protected identities, raw DNS, private material, or service logs and does not
replace or extend the repository security-report closure.

## Commands

Run the deterministic inventory and abuse checks without network or Docker:

```text
make check-security
```

Run every first-party fuzz target for the required unchanged-candidate
duration:

```text
make fuzz-security
```

Run the complete release-blocking profile, including vulnerability,
conformance, Valkey, and real Postfix evidence:

```text
make security
```

The ordinary repository gates remain mandatory:

```text
make race
make govulncheck
make guardrails
```

The security runner does not execute or import Exim while
`unqualified_draft06` is active. It requires the current evidence-free full
conformance report and rejects `qualified_linux`, an Exim result, or imported
matrix evidence. The historical Draft-04 five-row report remains a dated
record, not Draft-06 security evidence.
