package dkim2

import (
	"fmt"
	"io"
)

const verificationAssessmentRedactedText = "dkim2.VerificationAssessment{redacted}"

// VerificationAssessment separates DKIM2 applicability from the four verification states.
type VerificationAssessment struct {
	state *verificationAssessmentState
}

type verificationAssessmentState struct {
	applicable   bool
	verification VerifyResult
}

// newVerificationAssessment constructs one immutable closed applicability variant.
func newVerificationAssessment(applicable bool, verification VerifyResult) VerificationAssessment {
	if applicable != verification.Valid() {
		return VerificationAssessment{}
	}
	return VerificationAssessment{state: &verificationAssessmentState{
		applicable: applicable, verification: VerifyResult{state: verification.cloneState()},
	}}
}

// Valid reports whether this is exactly one closed applicability variant.
func (a VerificationAssessment) Valid() bool {
	return a.state != nil && a.state.applicable == a.state.verification.Valid()
}

// Applicable reports whether DKIM2 protocol fields started a verification.
func (a VerificationAssessment) Applicable() bool {
	return a.Valid() && a.state.applicable
}

// Verification returns an immutable four-state result only for applicable input.
func (a VerificationAssessment) Verification() (VerifyResult, bool) {
	if !a.Applicable() {
		return VerifyResult{}, false
	}
	return VerifyResult{state: a.state.verification.cloneState()}, true
}

// String returns a constant content-free assessment representation.
func (VerificationAssessment) String() string { return verificationAssessmentRedactedText }

// GoString returns a constant content-free assessment representation.
func (VerificationAssessment) GoString() string { return verificationAssessmentRedactedText }

// Format prevents formatting verbs from traversing verification facts.
func (VerificationAssessment) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, verificationAssessmentRedactedText)
}

// MarshalJSON rejects serialization outside an owning transport adapter.
func (VerificationAssessment) MarshalJSON() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}

// MarshalText rejects diagnostic serialization of retained verification facts.
func (VerificationAssessment) MarshalText() ([]byte, error) {
	return nil, newAPIError(APIErrorCodeInvalidRequest)
}
