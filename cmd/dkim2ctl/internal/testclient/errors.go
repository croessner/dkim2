package testclient

import (
	"errors"
	"fmt"
)

// ExitClass is the stable process exit status for one closed failure class.
type ExitClass uint8

const (
	// ExitOK reports that every requested case matched.
	ExitOK ExitClass = 0
	// ExitUsage reports command shape or flag validation failure.
	ExitUsage ExitClass = 2
	// ExitFixture reports fixture loading or validation failure.
	ExitFixture ExitClass = 3
	// ExitCapability reports protected capability loading failure.
	ExitCapability ExitClass = 4
	// ExitTransport reports local transport or deadline failure.
	ExitTransport ExitClass = 5
	// ExitContract reports malformed or unsupported response contracts.
	ExitContract ExitClass = 6
	// ExitMismatch reports a valid response that did not match expectations.
	ExitMismatch ExitClass = 7
	// ExitInternal reports an internal invariant failure.
	ExitInternal ExitClass = 8
)

// classError carries only one stable content-free failure class.
type classError struct {
	class    ExitClass
	reported bool
}

// Error returns a bounded content-free diagnostic.
func (e classError) Error() string {
	return fmt.Sprintf("dkim2ctl_error_%d", e.class)
}

// Class returns the stable process class.
func (e classError) Class() ExitClass {
	return e.class
}

// Reported indicates whether stable case output already represents this failure.
func (e classError) Reported() bool {
	return e.reported
}

// NewExitError constructs a content-free classified error.
func NewExitError(class ExitClass) error {
	if !class.ValidFailure() {
		class = ExitInternal
	}
	return classError{class: class}
}

// newReportedError constructs a classified error already represented in JSONL.
func newReportedError(class ExitClass) error {
	if !class.ValidFailure() {
		class = ExitInternal
	}
	return classError{class: class, reported: true}
}

// ErrorWasReported reports whether JSONL output already represents the failure.
func ErrorWasReported(err error) bool {
	var reported interface{ Reported() bool }
	return errors.As(err, &reported) && reported.Reported()
}

// HasExitClass reports whether an error originated from the stable class boundary.
func HasExitClass(err error) bool {
	var classified interface{ Class() ExitClass }
	return errors.As(err, &classified)
}

// ExitClassOf returns the stable class or the internal class for unknown errors.
func ExitClassOf(err error) ExitClass {
	if err == nil {
		return ExitOK
	}
	var classified interface{ Class() ExitClass }
	if errors.As(err, &classified) && classified.Class().ValidFailure() {
		return classified.Class()
	}
	return ExitInternal
}

// ValidFailure reports whether the class is one of the declared nonzero exits.
func (c ExitClass) ValidFailure() bool {
	return c >= ExitUsage && c <= ExitInternal
}
