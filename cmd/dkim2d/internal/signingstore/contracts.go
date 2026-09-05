package signingstore

import (
	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/provider"
	signingflatfile "github.com/croessner/dkim2/provider/flatfile"
)

// PolicyUse identifies one closed signing-policy selection at the store
// boundary.
type PolicyUse = signingflatfile.PolicyUse

const (
	// PolicyOriginator selects the originator policy.
	PolicyOriginator = signingflatfile.PolicyOriginator
	// PolicyOrdinaryTransit selects the ordinary-transit policy.
	PolicyOrdinaryTransit = signingflatfile.PolicyOrdinaryTransit
	// PolicyDeliveryStatus selects the delivery-status policy.
	PolicyDeliveryStatus = signingflatfile.PolicyDeliveryStatus
)

// PermanentProfileAbsence is the single daemon-wide classification of a
// signing-policy resolution failure. It reports true only for an
// authoritative absence: an invalid request, a missing or inactive profile,
// or malformed provider data. Every other condition, including an unavailable
// or degraded provider, is temporary and must never be reported as an
// authoritative answer.
func PermanentProfileAbsence(err error) (permanent bool) {
	defer func() {
		if recover() != nil {
			permanent = false
		}
	}()
	if err == nil {
		return false
	}
	if _, granular := err.(interface{ Code() provider.ErrorCode }); granular {
		switch provider.ErrorCodeOf(err) {
		case provider.ErrorCodeInvalidRequest, provider.ErrorCodeNotFound,
			provider.ErrorCodeInactive, provider.ErrorCodeMalformedData:
			return true
		default:
			return false
		}
	}
	return dkim2.ProviderErrorClassOf(err) == dkim2.ProviderErrorClassPermanent
}
