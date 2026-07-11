package verify

import "errors"

// ProviderFailureClass identifies a typed provider failure without raw cause data.
type ProviderFailureClass string

const (
	// ProviderFailureTemporary identifies retryable provider unavailability.
	ProviderFailureTemporary ProviderFailureClass = "temporary"
	// ProviderFailurePermanent identifies unrecoverable provider failure.
	ProviderFailurePermanent ProviderFailureClass = "permanent"
	// ProviderFailureContract identifies an inconsistent or unclassified provider outcome.
	ProviderFailureContract ProviderFailureClass = "contract"
)

// Known reports whether the provider failure class belongs to the closed vocabulary.
func (c ProviderFailureClass) Known() bool {
	switch c {
	case ProviderFailureTemporary, ProviderFailurePermanent, ProviderFailureContract:
		return true
	default:
		return false
	}
}

type classifiedProviderFailure interface {
	error
	ProviderFailureClass() ProviderFailureClass
}

type providerFailure struct{ class ProviderFailureClass }

// NewProviderFailure constructs a cause-free typed provider failure.
func NewProviderFailure(class ProviderFailureClass) error {
	if !class.Known() {
		class = ProviderFailureContract
	}
	return &providerFailure{class: class}
}

// Error returns a bounded provider diagnostic.
func (e *providerFailure) Error() string {
	if e == nil || !e.class.Known() {
		return "key provider failure"
	}
	return "key provider failure: " + string(e.class)
}

// ProviderFailureClass returns the typed provider failure class.
func (e *providerFailure) ProviderFailureClass() ProviderFailureClass {
	if e == nil {
		return ""
	}
	return e.class
}

// ProviderFailureClassOf returns a known typed class without inspecting error text.
func ProviderFailureClassOf(err error) ProviderFailureClass {
	var failure classifiedProviderFailure
	if !errors.As(err, &failure) || !failure.ProviderFailureClass().Known() {
		return ""
	}
	return failure.ProviderFailureClass()
}
