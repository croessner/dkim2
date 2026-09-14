# Companion qualification, 2026-09-14

Follow-up: the inherited API-reference failure was reconciled and production
mail-flow configuration was inspected in the
[API and mail-flow review](api-and-mailflow-review-2026-09-14.md).
The observations below describe the original implementation run.

## Change

DNS source identifiers, schemas and golden-vector paths now use
`draft-ietf-dkim-dkim2-dns-00`. The archived normative XML bodies are identical;
there is no DNS parser or policy change. The message baseline remains Draft-06.

The daemon adds bounded closed-reason comments to delivered authentication
failures. A shared library-safe report type validates the same wire profile in
HTTP, Milter, Exim and CLI consumers. Bare legacy reports remain accepted.
The complete coverage and exception decisions are in
[companion-conformance.md](../specs/companion-conformance.md).

The BCP matrix distinguishes implemented capabilities, operational obligations,
known gaps, and open discussion. No Sender Policy behavior, deployment, release,
commit, or publication was performed.

## Validation evidence

All qualifying Go checks use `GOTOOLCHAIN=go1.27.0` and
`GOEXPERIMENT=runtimesecret`. `make` exports both internally.

| Check | Result |
| --- | --- |
| `make check-go-toolchain-contract` | Passed |
| `python3 tools/check-dns-draft-equivalence.py temp/companion-audit` | Identical normative bodies; hashes recorded in the specification |
| Focused authresults, daemon HTTP, Milter daemon/EOM, Exim daemon and CLI packages | Passed under exact Go 1.27.0, including local sockets |
| `make generate-openapi` | Completed for all generated server/client artifacts |
| `make generate-conformance-manifest` | Refreshed the renamed and changed fixture/source hashes |
| `make check-conformance check-interop govulncheck` | Passed; no known vulnerabilities reported across product and tools modules |
| Root `reference check-api` | Existing `api_changed` failure; root API manifests from HEAD and working tree are byte-identical |
| `make guardrails` | Passed on the final implementation; formatting, vet, lint, tests, race, builds, generated artifacts, vendor, platform, boundaries and operator documentation |
| `make check-operator-docs` after correction | Passed; historical and current authorities are checked separately |
| 10-second authresults fuzz run | Passed, 1,535,091 executions |
| `GOWORK=off go -C lib test -mod=readonly ./authresults` with the exact toolchain/experiment | Passed; independent library package, no metadata writes |
| `make check-workspace` | Blocked by private candidate archive / recorded library checksum mismatch; reproduced outside sandbox |

The initial unqualified direct test invocation used the host-selected Go 1.27.1
and could not bind local sockets inside the sandbox. Its results are excluded
from qualification; the exact-toolchain run with local socket permission passed.
The new formatter tests initially failed to compile before implementation, then
passed. Existing tests and failure expectations were not weakened. The first guardrail
run reached the final operator-document check and exposed an assertion against
a historical report that had been migrated incorrectly. Restoring its original
assertion and adding separate current-authority checks fixed the cause; the
complete guardrail rerun passed.

## Limits

No production mail flow, DNSSEC deployment, NTP state, DKIM1 integration or
external MTA installation was probed. Existing Exim qualification limits remain;
local Go adapter tests do not imply new real-Exim qualification. The reporting
profile intentionally omits unsigned `none`, origin/failure-index properties,
and verbatim metadata-bearing diagnostics; each decision is documented with its
normative strength and rationale. Diagnostic comments never supply policy input.

The root API check is outside `make guardrails`. Its recorded base predates this
change: the HEAD and working-tree API manifests both hash to
`5958926bb0b972d164d6d6dee00c372cc8966b30f1b0906c2c494262577fd2b2`,
while the stored baseline is `ddf0ef36cdc47bac57495a5d14fd5c56243d1bc9b82f68c80e14a48c95c45748`.
The checker covers the root package, not the new `authresults` subpackage.
No baseline was weakened or silently regenerated to hide this inherited gap.

The workspace probe uses a temporary Go source overlay only to reveal the
otherwise redacted `workspace_sync` diagnostic. The private file proxy serves
a candidate-built `github.com/croessner/dkim2@v0.1.0-rc.1` archive, whereas the
committed sum authenticates different bytes for that version. This is not an
external network download. No checksum, version pin or authentication check was
removed. Isolated module/workspace qualification therefore remains incomplete;
workspace-mode tests and builds must not be presented as that proof. The Milter,
Exim and CLI modules now explicitly require the shared library, matching their
new reporting import; no external dependency was added.
