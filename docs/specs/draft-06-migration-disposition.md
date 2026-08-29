# DKIM2 Draft-06 Migration Disposition

Status: implemented baseline disposition

Message baseline: `draft-ietf-dkim-dkim2-spec-06`

DNS companion baseline: `draft-chuang-dkim2-dns-04` (unchanged)

## Substantive Changes

| Draft-06 delta | Disposition |
| --- | --- |
| Section 11.9 unexpected replay | Implemented as one message-wide identity over independently verified reconstructed `m=1` canonical header and body inputs. The first unmarked observation is retained; a later unmarked observation is final `FAIL` with `duplicate_message_without_exploded`. |
| Authenticated `exploded` | Implemented as complete-chain OR. Enabled authentication still performs the single store mutation; successful first-seen or replayed storage maps to accepted `exploded` unless a proven `donotexplode` violation removes the exemption. |
| Final result ownership | `VerifyResult` remains immutable message-local evidence. `AuthenticationResult` owns the final replay-aware state. OpenAPI exposes both fields. |
| `PERMFAIL` correction | No active `PERMFAIL` state exists; permanent protocol errors remain `PERMERROR`, while supported integrity and replay failures use `FAIL`. |
| All-signature and mixed-signature failure | Existing aggregate failure behavior retained. Selector-specific diagnostics remain bounded to explicit result output and are not telemetry. |
| Mixed supported Message-Instance hashes | Existing all-supported-hash agreement behavior retained and covered by verification tests. |
| Excessive selector wording | Machine reason `too_many_signatures` remains stable; operator text uses “has more selectors than allowed”. |
| `nonotmodify` typo | No behavior change. The implemented authenticated flag remains `donotmodify`. |
| Key-fetch wording | Existing verifier fetches keys for supported signature algorithms only; unsupported algorithms remain ignored for lookup. |
| RFC 9228 reference class | Reference-only; no `Delivered-To` behavior change. |
| `multipart/report` authority | Active terminology now cites RFC 6522; RFC 3464 continues to own delivery-status fields. Parser behavior is unchanged. |

Metadata, pagination, typo-only wording, reference ordering, and the orphan
“Thse states” fragment require no code change. Historical Draft-05 audit and
migration documents retain their original identifiers. Active repository
surfaces and versioned fixtures identify Draft-06.

## Replay Interpretation And Limits

Draft-06 does not define the equality algorithm for copies identified through
`m=1`. This implementation hashes the exact reconstructed canonical hash inputs
using the frozen `dkim2-replay-origin-v1` frame, then pseudonymizes that digest
using `dkim2-replay-hmac-sha256-v2`. Recipients, routes, terminal signatures,
selectors, and the sender's choice of supported hash set are not equality
inputs.

This is a synchronous first-copy implementation. Retention expiry, process-local
memory, asynchronous Valkey replication, restore, and cross-site separation
bound detection. An ambiguous post-dispatch write remains fail-closed and is
not retried. Draft-05 to Draft-06 deployment requires the documented full
retention drain, a new epoch, and a new secret; mixed live generations are not
supported.
