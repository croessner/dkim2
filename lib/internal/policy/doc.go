// Package policy owns deterministic local decisions over sealed DKIM2
// verification facts. Policy verdicts remain separate from the authoritative
// PASS, FAIL, PERMERROR, and TEMPERROR verification states.
//
// Strict policy is the default. Permissive and testing modes are explicit, and
// continue is a non-terminal disposition rather than accept or PASS. Current
// verifier projections authenticate only the current passing hop, so historical
// donotmodify and donotexplode compliance remains not_evaluated. Synthetic
// complete-history projections enforce strictly later-hop ordering: header
// additions alone do not violate donotmodify, and donotexplode requires a later
// authenticated exploded report.
//
// Feedback is bounded intent only. Feedhere requires an authenticated feedback
// request at the same or a lower sequence and exposes no route. DNS t=y is
// sealed key metadata independent of local testing mode and applies only to the
// closed eligible set rows. An effective testing PASS continues without
// applying authenticated flags, feedback intent, or exploded reports because
// testing mail receives no DKIM2 authentication policy weight. Evaluation
// never reparses messages or public facts, returns exactly one action on
// success, and exposes no message, identity, key, provider, or route material.
package policy
