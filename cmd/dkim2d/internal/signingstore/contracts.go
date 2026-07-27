package signingstore

import signingflatfile "github.com/croessner/dkim2/provider/flatfile"

// PolicyUse identifies one closed signing-policy selection at the store
// boundary.
type PolicyUse = signingflatfile.PolicyUse

const (
	// PolicyOriginator selects the originator policy.
	PolicyOriginator = signingflatfile.PolicyOriginator
	// PolicyOrdinaryTransit selects the ordinary-transit policy.
	PolicyOrdinaryTransit = signingflatfile.PolicyOrdinaryTransit
)
