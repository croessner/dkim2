# Security Testing And Evidence

DKIM2 security evidence is a repository-owned local security profile. It does
not add requirements to `draft-ietf-dkim-dkim2-spec-04`, the historical
`draft-chuang-dkim2-dns-04` behavior baseline, or the incorporated RFCs.
Normative, documented-interpretation, OpenAPI, adapter, and local-policy
assertions remain separately classified.

The profile treats raw messages, SMTP envelopes, protocol fields, recipes, DNS
and datasource records, replay responses, HTTP and Milter peers, protected
files, configuration, and all tool/report inputs as hostile. It protects exact
message and envelope evidence, protocol authority, private signing material,
capabilities, provider generations, replay identity, process availability,
trusted `Authentication-Results`, and telemetry privacy.

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

- the fixed Git base and exact durable candidate snapshot;
- the pinned DKIM2 and DNS draft identifiers;
- the closed fuzz/resource inventory digest;
- Go, platform, fuzz, race, and vulnerability state;
- current portable and full conformance reports;
- two current real-Postfix qualification reports;
- zero unresolved findings; and
- the exact `deferred_m17` Exim capability.

Evidence readers reject duplicate JSON members, symlinked paths, partial
identity-only reports, unexpected evidence paths, and reports that fail their
complete conformance or real-Postfix validation contract. Fuzz, race, and
vulnerability subprocesses use a closed Go environment; the vulnerability
database is explicitly pinned to `https://vuln.go.dev`.

Any durable change invalidates prior fuzz, vulnerability, conformance, Postfix,
security, and review evidence.

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

Exim execution is not part of this profile. Its adapter and live evidence
remain deferred until the taint-safe envelope-authority design is resolved.
