# DKIM2 companion qualification

Status: repository qualification, 2026-09-14. This is not a production deployment
receipt or a claim that every recommendation is implemented. The message
baseline remains `draft-ietf-dkim-dkim2-spec-06`. The DNS baseline is
`draft-ietf-dkim-dkim2-dns-00`. The individual Sender Policy
proposal is outside this change and supplies no behavior or configuration.

The subsequent [API and mail-flow review](../reports/api-and-mailflow-review-2026-09-14.md)
records read-only production observations: synchronized time, originator dual
signing configuration and protected prepared forwarding. The initial suspected
post-signing MIME rewrite was disproved by the mailstack owner's real Postfix
test and live MIME-check settings; the review explicitly records that correction.
This evidence does not establish full production compliance.

## Sources and decisions

| Document | Version | Disposition |
| --- | --- | --- |
| [Message specification](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-spec/06/) | 2026-08-28, `-06` | Existing behavior baseline |
| [DNS specification](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-dns/00/) | 2026-07-20, `-00` | Active identifiers and vectors migrated; no DNS behavior change |
| [Best Practices](https://datatracker.ietf.org/doc/draft-ietf-dkim-dkim2-bcp/01/) | 2026-09-09, `-01` | Section matrix below; deployment evidence remains separate |
| [Authentication-Results](https://datatracker.ietf.org/doc/draft-gondwana-dkim2-authres/00/) | individual `-00`, announced 2026-09-05 | Bounded implementation profile below; not a claim of WG adoption |

## DNS migration evidence

The old `draft-chuang-dkim2-dns-04` and new WG document have byte-identical
ElementTree-serialized XML `middle` elements. This comparison excludes document
front matter and references; it does not prove unspecified behavior or settle
existing draft ambiguities. The parser and DNS policy are unchanged.

| Input | SHA-256 |
| --- | --- |
| Archived individual XML | `47eeaf5c2d5a6f6352ffcad402cb7a2ede23606eb90faac3e6b3ac987c37c06e` |
| Archived WG XML | `f3d9cb8daeb963a76eebfcca6c57b5a3b8d0b3246de83898169af18f74568c57` |
| Identical serialized middle | `f7231a02edeb5130160e4b3cece3dd28ec826cfc06df9b9509a7e735fec72524` |

Reproduce with the public `.xml` archives downloaded from
`https://www.ietf.org/archive/id/` into an ignored directory:

```sh
python3 tools/check-dns-draft-equivalence.py temp/companion-audit
```

Active source references, schemas, conformance metadata and the DNS golden
vector directory now name the WG draft. Historical dated reports and migration
disposition records retain their original identifiers. DNS vectors are exercised
by `lib/dns_provider_vector_test.go`; record parsing and resolution remain owned
by `lib/internal/keyresolver`. Renaming a baseline does not constitute new live
DNS, MTA, or external interoperability qualification.

## Authentication-Results profile

`lib/authresults` owns an immutable canonical report and the shared parser used
by the daemon, Milter and Exim clients, Milter EOM admission, and CLI. It imports
no HTTP DTOs or adapter dependencies. The daemon remains the sole report author.
Adapters bind reports to the configured authority and final authentication
outcome. Where a final reason is available, a contradictory diagnostic is also
rejected. A bare legacy report is still admitted for rolling compatibility.

Examples:

```text
mx.example; dkim2=pass
mx.example; dkim2=fail (reason=signature_mismatch)
mx.example; dkim2=temperror (reason=replay_indeterminate)
```

Comments are for people, never a policy interface. Consumers must use the
structured API fields for machine decisions. The parser recognizes only this
local wire profile; it is not a general RFC 8601 parser for arbitrary external
mail. Unknown comments, additional methods/properties, control characters,
forged authorities, contradictory outcomes, and unbounded values are rejected.
The accepted grammar cannot contain attacker-controlled parentheses, backslashes,
addresses, selectors, message content, or credentials in diagnostics.

| Authres section | Coverage / deliberate disposition |
| --- | --- |
| 3, single result | One daemon-owned action for eligible inbound accept/continue results. Authentication is separate from local delivery policy. |
| 3.1, four states | Existing final authentication/replay mapping retained; lowercase wire spelling. |
| 3.1, `none` recommendation | **Documented exception:** both protocol families absent keep the stable bodyless HTTP 204 and no mutation. Adapters can distinguish this from an unexecuted call via HTTP status. A partial claim still undergoes verification and cannot become unsigned. Changing this would require a separately versioned applicability/action contract. |
| 3.2.1, optional origin | Omitted. This profile does not disclose a historical identity or assert that current-only verification authenticated the origin. No highest-hop-to-origin substitution. |
| 3.2.2, optional failure index | Omitted. Public presentation caps and message-wide failures do not always identify a unique signature; the current target must not be substituted for a historical failure. |
| 3.3, diagnostics | Bounded closed reason comments added to delivered failures. **Documented exception:** substituted verbatim failure text and hop/domain lists are omitted to preserve repository privacy rules. Structured protected diagnostics remain separate. |
| 3.3.2, escaping/limits | The allowlisted alphabet needs no escaping; the parser also imposes a 384-byte ceiling. No arbitrary comment API is exposed. |
| 4.1, reporting | Enabled only with configured local reporting authority; rejecting/tempfailing outcomes carry no mutation because the message is not delivered. |
| 4.2–4.3, trust | Existing local-authority ingress sanitization remains in the Milter/Exim integration. External Authentication-Results are never DKIM2 proof. Operators must configure their complete ADMD trust boundary. |
| 5–6 | Examples/registration are not additional wire capabilities. The individual draft is not treated as an IANA registration or WG adoption. |
| 7 | No content-quality claim, no reputation from diagnostics, no raw message metadata in the new output. |

The diagnostic profile is an additive wire change. Old adapters that compare
exact bare strings will reject enriched reports. Upgrade daemon and generated
client/admission consumers together; bare reports remain accepted by the new
consumers. No existing configuration key was renamed. The OpenAPI source
records the profile and generation propagates that contract to every SDK.

Regression evidence: `lib/authresults/report_test.go` includes spoofing,
contradiction, injection and canonical round-trip cases;
`cmd/dkim2d/internal/httpjson/response_scalar_test.go` covers final-reason
formatting; `cmd/dkim2-milter/internal/milter/actions_test.go` covers EOM
admission. Existing socket suites exercise HTTP/generated clients and adapters.

## BCP qualification matrix

Labels: **covered** means code/test evidence exists for the bounded feature;
**operator** needs a deployment receipt; **partial** identifies a concrete gap;
**open** leaves unsettled guidance outside protocol semantics. None of these
labels alone proves a production installation complies.

| BCP section | Status | Repository evidence and remaining work |
| --- | --- | --- |
| 1–2, terminology | covered | Architecture pins Draft-06; no second protocol model introduced. |
| 3.1, key size | covered/operator | `lib/internal/keyresolver`, signing tests, native onboarding. Verify deployed profiles independently. |
| 3.2, multiple algorithms | covered/operator | `lib/signing_facade_test.go`, `lib/signing_datasource_integration_test.go`; actual selected profiles need inspection. |
| 3.3, DKIM1 coexistence | operator | DKIM1 is explicitly outside the library. Prove both signatures after the final filter in the owning mailstack. |
| 3.4, egress | operator | Adapter supports signing; topology determines the last hop. Prove no later signed-content mutation. |
| 3.5, rotation | covered/operator | `docs/operator/datasource-key-rotation.md`; generations, selectors, retirement and testing semantics. Obtain live schedule and retained-key evidence. |
| 3.6, time | operator | Timestamp verification exists; host clock synchronization must be checked separately. |
| 4.1, flags | covered/operator | Signing profiles and `lib/internal/policy/compliance_test.go`. Select flags per workload; defaults are not rewritten here. |
| 5.1, inbound checks | partial/operator | DKIM2 verifier exists. DKIM1 verification and ordering belong to the surrounding mail pipeline. |
| 5.2, unchanged forwarding | covered/operator | Signing/revision supports unchanged instances; `lib/signing_facade_test.go`. Prove every forwarding route invokes it. |
| 5.3, From handling | operator | Revision records header changes; DMARC lookup and automatic From rewriting are outside this library. Existing modification prohibitions remain intact. |
| 5.4, recipient privacy | partial/operator | `feedhere` intent exists. Per-subscriber recipient alias provisioning is not implemented in this repository. Never describe normal `rt=` emission as anonymous. |
| 5.5, request enforcement | covered/operator | Policy compliance and signing/revision tests; prove the outbound route cannot bypass enforcement. |
| 5.6, imaginary hops | covered/operator | `lib/internal/signature/custody_test.go`, `lib/signing_next_domain_regression_test.go`; out-of-band business authority requires documentation. |
| 5.7, recipe privacy | partial/operator | `lib/internal/recipe/generation_contract_test.go`, `generation_privacy_test.go`, null-body representation and bounded generation. No automatic DLP/AV classifier; sanitizer must select a non-reconstructable policy. |
| 5.8, DSN rebuild | covered/operator | `lib/dsn_propagation_test.go`, `lib/internal/dsn/rebuild_test.go`; deployment and private-route proof remain necessary. |
| 6.1.1, continuous chain | covered | Chain scope, historical coverage, custody and replay remain separate authenticated facts. |
| 6.1.2, interrupted chain | partial/open | No automatic DKIM1 bridge or inferred trust from missing hops. Local policy owns any explicit compatibility decision. |
| 6.1.3, unsigned | covered/operator | Existing HTTP 204 applicability contract; independent spam/SPF/DKIM1 policy must still run. |
| 6.2, result handling | covered/operator | Daemon outcome matrix, Milter EOM and Exim admission; verify SMTP replies on the deployed adapters. |
| 6.3, inbound DSNs | covered/operator | `lib/received_dsn_policy_test.go`, `lib/received_dsn_vector_test.go`; locality and production routing require external evidence. |
| 7.1, coexistence | operator | Same mailstack-owned DKIM1 and DKIM2 proof as 3.3 and 5.1. |
| 7.2, DMARC | open | No new authentication or alignment policy inferred from this discussion. |
| 7.3, feedback | partial/open | Bounded intent/routing exists, no feedback sender. Do not claim delivery of reports. |
| 7.4, Authentication-Results | covered with exceptions | Explicit profile above; optional metadata intentionally absent. |
| 7.5, limits | covered | Parser, signature, recipe and history limits with abuse tests. Deployment values remain operator choices. |
| 7.6, sanitizers | partial/operator | Null-body capability exists; automatic DLP/AV policy and legal decisions do not. Removed content must not be reconstructed accidentally. |
| 7.7–7.8, future DMARC/SPF | open/operator | Retain surrounding controls. This change retires neither mechanism. |
| 8, security | covered/operator | Resource limits, custody, key lifecycle and redaction have tests; DNSSEC resolver deployment, downgrade monitoring and reputation require external evidence. |
| 9, registration | informational | No local registration action. |

## Operator acceptance record

For each deployment, record the image/revision, route, observation date and owner:

- Final egress: both DKIM1 and DKIM2 verify after every content-changing filter.
- Ingress: DKIM1/SPF/DMARC and spam policy continue; forged local reports are
  removed; a received external result cannot authorize a downstream hop.
- Clock and DNS: time synchronization, resolver validation, key publication,
  rotation/retention and rollback are demonstrated on the actual path.
- Forwarding: no bypass of request enforcement; alias/privacy policy is explicit;
  DLP/AV removal does not reappear in content-bearing recipes.
- DSNs: locality, previous-hop proof, routing and emitted SMTP replies are tested.

No production mutation or production conformance claim is authorized by this
repository report. Missing external receipts remain unqualified.

## Validation

See `docs/reports/companion-qualification-2026-09-14.md` for commands and results
on the implementation snapshot. Historical receipts are not relabeled as new
qualification evidence.
