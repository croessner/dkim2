package provider

import (
	"errors"
	"fmt"
	"testing"
)

const testFailureMessage = "provider failure"

// TestFailureClassificationIsClosedAndSecretSafe proves shared typed classification.
func TestFailureClassificationIsClosedAndSecretSafe(t *testing.T) {
	for _, class := range []FailureClass{FailureTemporary, FailurePermanent, FailureContract} {
		err := NewFailure(class)
		if ClassOf(err) != class {
			t.Fatalf("ClassOf() = %q, want %q", ClassOf(err), class)
		}
		if got := fmt.Sprintf("%v", err); got != testFailureMessage+": "+string(class) {
			t.Fatalf("failure formatting = %q", got)
		}
	}
	if ClassOf(errors.New("temporary SECRET")) != "" {
		t.Fatal("raw error text was classified")
	}
	toggling := &togglingFailure{}
	if got := ClassOf(toggling); got != FailureTemporary || toggling.calls != 1 {
		t.Fatalf("stateful classification = %q calls=%d", got, toggling.calls)
	}
}

// TestFailureClassificationRejectsTypedNilErrors proves direct and wrapped typed nils are never invoked.
func TestFailureClassificationRejectsTypedNilErrors(t *testing.T) {
	var typedNil *panickingClassifiedFailure
	for _, err := range []error{typedNil, classifiedFailureWrapper{target: typedNil}} {
		if class := ClassOf(err); class != "" {
			t.Fatalf("ClassOf(typed nil) = %q", class)
		}
	}
}

type togglingFailure struct{ calls int }

// Error returns one bounded stateful test diagnostic.
func (*togglingFailure) Error() string { return testFailureMessage }

// ProviderFailureClass changes after the first read to expose duplicate classification calls.
func (e *togglingFailure) ProviderFailureClass() FailureClass {
	e.calls++
	if e.calls == 1 {
		return FailureTemporary
	}
	return FailureContract
}

type panickingClassifiedFailure struct{}

// Error panics if typed-nil classification dereferences its receiver.
func (e *panickingClassifiedFailure) Error() string {
	if e == nil {
		panic("typed-nil Error invoked")
	}
	return testFailureMessage
}

// ProviderFailureClass panics if typed-nil classification dereferences its receiver.
func (e *panickingClassifiedFailure) ProviderFailureClass() FailureClass {
	if e == nil {
		panic("typed-nil ProviderFailureClass invoked")
	}
	return FailureContract
}

type classifiedFailureWrapper struct{ target error }

// Error returns a constant diagnostic without formatting its wrapped target.
func (classifiedFailureWrapper) Error() string { return "provider failure wrapper" }

// Unwrap exposes the wrapped typed-nil classified error.
func (e classifiedFailureWrapper) Unwrap() error { return e.target }
