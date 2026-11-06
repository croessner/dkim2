// Package provider owns the shared, cause-free classification for injected
// DKIM2 providers and authorizers.
package provider

import (
	"errors"

	"github.com/croessner/dkim2/internal/niliface"
)

const failureMessage = "provider failure"

// FailureClass identifies one closed external dependency failure.
type FailureClass string

const (
	// FailureTemporary identifies retryable provider unavailability.
	FailureTemporary FailureClass = "temporary"
	// FailurePermanent identifies unrecoverable provider failure.
	FailurePermanent FailureClass = "permanent"
	// FailureContract identifies inconsistent or unclassified provider behavior.
	FailureContract FailureClass = "contract"
)

// Known reports whether the class belongs to the closed provider vocabulary.
func (c FailureClass) Known() bool {
	return c == FailureTemporary || c == FailurePermanent || c == FailureContract
}

type classifiedFailure interface {
	error
	ProviderFailureClass() FailureClass
}

type failure struct{ class FailureClass }

// NewFailure constructs a cause-free typed provider failure.
func NewFailure(class FailureClass) error {
	if !class.Known() {
		class = FailureContract
	}
	return &failure{class: class}
}

// Error returns a bounded provider diagnostic.
func (e *failure) Error() string {
	if e == nil || !e.class.Known() {
		return failureMessage
	}
	return failureMessage + ": " + string(e.class)
}

// ProviderFailureClass returns the typed provider failure class.
func (e *failure) ProviderFailureClass() FailureClass {
	if e == nil {
		return ""
	}
	return e.class
}

// ClassOf returns a known typed class without inspecting error text.
func ClassOf(err error) FailureClass {
	if nilInterfaceValue(err) {
		return ""
	}
	var classified classifiedFailure
	if !errors.As(err, &classified) || nilInterfaceValue(classified) {
		return ""
	}
	class := classified.ProviderFailureClass()
	if !class.Known() {
		return ""
	}
	return class
}

// nilInterfaceValue detects nil and typed-nil interface values without invoking methods.
func nilInterfaceValue(value any) bool {
	return niliface.IsNil(value)
}
