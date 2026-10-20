// Package policy owns deterministic local decisions over sealed DKIM2
// verification facts. Policy verdicts remain separate from the authoritative
// PASS, FAIL, PERMERROR, and TEMPERROR verification states.
//
// Strict policy is the default. Permissive and testing modes are explicit, and
// continue is a non-terminal disposition rather than accept or PASS. Current
// verifier projections authenticate only the current passing hop. Draft-07
// Section 10.10 removed the donotmodify and donotexplode flags; received
// spellings are inert unknown flags, so authenticated hop flags never produce
// compliance findings or change the verdict. Authenticated exploded markers are
// reported as informational findings only.
//
// Feedback is bounded intent only. Feedhere requires an authenticated feedback
// request at the same or a lower sequence and exposes no route. The DNS key
// record t= tag is retired by draft-ietf-dkim-dkim2-dns-01 Section 3.4.1 and
// carries no policy meaning; only the explicitly configured local testing mode
// relaxes the verdict. Evaluation
// never reparses messages or public facts, returns exactly one action on
// success, and exposes no message, identity, key, provider, or route material.
package policy
