# DKIM2 Conformance Report

- Message draft: `draft-ietf-dkim-dkim2-spec-04`
- DNS draft: `draft-chuang-dkim2-dns-04`
- Base revision: `2222222222222222222222222222222222222222`
- Candidate snapshot: `3333333333333333333333333333333333333333333333333333333333333333`
- Profile: `portable`
- Platform: `portable`
- Overall: `pass`

## Scope

- Supported surfaces: library `supported`; daemon `supported`; Milter `partial`; Postfix `partial_linux`; Exim `deferred_m17`.
- Tested suites: `exim`, `verification`.
- Claim limit: results apply only to the exact base revision, candidate snapshot, pinned drafts, manifest, producers, profile, and case inventory shown by this report.
- A pass is not a claim of original SMTP-wire fidelity, external interoperability, DNSSEC validation, or unexecuted platform behavior.

## Results

| Class | State | Count |
| --- | --- | ---: |
| `adapter_contract` | `deferred` | 1 |
| `draft_normative` | `pass` | 1 |

## Limitations and interpretations

- Milter evidence uses byte-exact callback reconstruction, not an original SMTP wire image. Postfix prepends its own `Received` field outside Milter-visible message bytes.
- Postfix execution is Linux-only and covers the pinned qualification image, explicit Milter-v6 timeouts, SMTP intake, and simulated non-SMTP callbacks.
- Replay detection is a restrictive local security policy layered after protocol verification; it is not a DKIM2 cryptographic result.
- Exim execution is deferred; no live Exim conformance or compatibility claim is made.
- Draft-04 architecture references, EAI considerations, IANA considerations, and security considerations remain `TBA`; implemented interpretations are reported separately from normative claims.

## Reproduce

```text
make check-conformance
make conformance
```
