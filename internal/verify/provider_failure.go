package verify

import "github.com/croessner/dkim2/internal/provider"

// ProviderFailureClass identifies a typed provider failure without raw cause data.
type ProviderFailureClass = provider.FailureClass

const (
	// ProviderFailureTemporary identifies retryable provider unavailability.
	ProviderFailureTemporary = provider.FailureTemporary
	// ProviderFailurePermanent identifies unrecoverable provider failure.
	ProviderFailurePermanent = provider.FailurePermanent
	// ProviderFailureContract identifies an inconsistent or unclassified provider outcome.
	ProviderFailureContract = provider.FailureContract
)

// NewProviderFailure constructs a cause-free typed provider failure.
func NewProviderFailure(class ProviderFailureClass) error {
	return provider.NewFailure(class)
}

// ProviderFailureClassOf returns a known typed class without inspecting error text.
func ProviderFailureClassOf(err error) ProviderFailureClass {
	return provider.ClassOf(err)
}
