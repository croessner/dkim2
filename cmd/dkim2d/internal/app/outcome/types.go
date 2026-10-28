// Package outcome owns transport-neutral daemon outcome vocabularies.
package outcome

// ReplayClass identifies one privacy-minimal replay aggregate.
type ReplayClass uint8

const (
	// ReplayNotChecked means the verification and policy gate skipped replay.
	ReplayNotChecked ReplayClass = iota + 1
	// ReplayDisabled means explicit local configuration disabled replay.
	ReplayDisabled
	// ReplayFirstSeen means every authenticated identity was newly retained.
	ReplayFirstSeen
	// ReplayExploded means authenticated exploded made a remembered copy expected.
	ReplayExploded
	// ReplayReplayed means at least one authenticated identity already existed.
	ReplayReplayed
	// ReplayIndeterminate means replay storage cannot be classified safely.
	ReplayIndeterminate
	// ReplayNotEligible means a passing direct i=1-only delivery is outside
	// Draft-08 Section 15.1 replay counting and touched no store.
	ReplayNotEligible
)

// Known reports whether the class belongs to the closed replay vocabulary.
func (c ReplayClass) Known() bool {
	return c >= ReplayNotChecked && c <= ReplayNotEligible
}

// FinalDisposition identifies the daemon outcome after independent replay policy.
type FinalDisposition uint8

const (
	// DispositionAccept permits normal continuation.
	DispositionAccept FinalDisposition = iota + 1
	// DispositionReject reports permanent local rejection.
	DispositionReject
	// DispositionTempfail requests a retryable deferral.
	DispositionTempfail
	// DispositionContinue withholds a terminal daemon decision.
	DispositionContinue
)

// Known reports whether the disposition belongs to the closed daemon vocabulary.
func (d FinalDisposition) Known() bool {
	return d >= DispositionAccept && d <= DispositionContinue
}
