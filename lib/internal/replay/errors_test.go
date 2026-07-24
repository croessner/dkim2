package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestErrorTaxonomyIsClosed verifies all ten exact stable codes.
func TestErrorTaxonomyIsClosed(t *testing.T) {
	if got := allErrorCodes(); len(got) != 10 {
		t.Fatalf("error-code count = %d", len(got))
	}
	for _, code := range allErrorCodes() {
		if !code.Known() || code.String() != string(code) {
			t.Fatalf("known code %q rejected", code)
		}
		err := NewError(code)
		if err == nil || !IsTypedError(err) || ErrorCodeOf(err) != code || err.Error() != string(code) {
			t.Fatalf("NewError(%q) = %v code=%q", code, err, ErrorCodeOf(err))
		}
		assertClosedValueEncoding(t, code, string(code))
		assertErrorEncoding(t, err, string(code))
	}
	for _, unknown := range []ErrorCode{"", "future"} {
		if unknown.Known() || unknown.String() != unknownValueText {
			t.Fatalf("unknown code %q accepted", unknown)
		}
		if text, err := unknown.MarshalText(); text != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("ErrorCode(%q).MarshalText() = %q, %v", unknown, text, err)
		}
		if encoded, err := json.Marshal(unknown); encoded != nil || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("json.Marshal(ErrorCode(%q)) = %s, %v", unknown, encoded, err)
		}
		err := NewError(unknown)
		if ErrorCodeOf(err) != ErrorCodeInternalInvariant || err.Error() != string(ErrorCodeInternalInvariant) {
			t.Fatalf("NewError(%q) = %v", unknown, err)
		}
	}
}

// TestErrorsPreserveOnlyPreflightContextIdentity verifies controlled unwrapping.
func TestErrorsPreserveOnlyPreflightContextIdentity(t *testing.T) {
	cancelled := NewError(ErrorCodeCancelled)
	deadline := NewError(ErrorCodeDeadlineExceeded)
	if !errors.Is(cancelled, context.Canceled) || errors.Is(cancelled, context.DeadlineExceeded) {
		t.Fatalf("cancelled identity = canceled:%t deadline:%t", errors.Is(cancelled, context.Canceled), errors.Is(cancelled, context.DeadlineExceeded))
	}
	if !errors.Is(deadline, context.DeadlineExceeded) || errors.Is(deadline, context.Canceled) {
		t.Fatalf("deadline identity = canceled:%t deadline:%t", errors.Is(deadline, context.Canceled), errors.Is(deadline, context.DeadlineExceeded))
	}
	for _, code := range allErrorCodes() {
		if code == ErrorCodeCancelled || code == ErrorCodeDeadlineExceeded {
			continue
		}
		err := NewError(code)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%q unexpectedly unwraps context", code)
		}
	}
}

// TestPreflightContextUsesExactValidationPrecedence verifies nil, live, cancelled, and deadline states.
func TestPreflightContextUsesExactValidationPrecedence(t *testing.T) {
	if code := ErrorCodeOf(PreflightContext(nil)); code != ErrorCodeInvalidRequest { //nolint:staticcheck // Nil is the contract case under test.
		t.Fatalf("PreflightContext(nil) code = %q", code)
	}
	var typedNil *typedNilContext
	if code := ErrorCodeOf(PreflightContext(typedNil)); code != ErrorCodeInvalidRequest {
		t.Fatalf("PreflightContext(typed nil) code = %q", code)
	}
	if err := PreflightContext(context.Background()); err != nil {
		t.Fatalf("PreflightContext(live) = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := PreflightContext(cancelled); ErrorCodeOf(err) != ErrorCodeCancelled || !errors.Is(err, context.Canceled) {
		t.Fatalf("PreflightContext(cancelled) = %v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	if err := PreflightContext(deadline); ErrorCodeOf(err) != ErrorCodeDeadlineExceeded || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PreflightContext(deadline) = %v", err)
	}
}

// TestPreflightContextContainsPanicsAndUnknownErrors verifies hostile contexts fail closed.
func TestPreflightContextContainsPanicsAndUnknownErrors(t *testing.T) {
	const marker = "TOXIC-CONTEXT-MARKER"
	for _, ctx := range []context.Context{
		hostileContext{panicOnErr: true},
		hostileContext{err: errors.New(marker)},
	} {
		err := PreflightContext(ctx)
		if ErrorCodeOf(err) != ErrorCodeInternalInvariant || err.Error() != string(ErrorCodeInternalInvariant) ||
			strings.Contains(err.Error(), marker) {
			t.Fatalf("PreflightContext(%T) = %v", ctx, err)
		}
	}
}

// typedNilContext is a practical typed-nil context implementation.
type typedNilContext struct{}

// Deadline reports no deadline.
func (*typedNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no cancellation channel.
func (*typedNilContext) Done() <-chan struct{} { return nil }

// Err reports a live context.
func (*typedNilContext) Err() error { return nil }

// Value reports no associated value.
func (*typedNilContext) Value(any) any { return nil }

// hostileContext supplies malformed or panicking context state.
type hostileContext struct {
	err        error
	panicOnErr bool
}

// Deadline reports no deadline.
func (hostileContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no cancellation channel.
func (hostileContext) Done() <-chan struct{} { return nil }

// Err returns hostile state or panics to test the boundary.
func (c hostileContext) Err() error {
	if c.panicOnErr {
		panic("hostile context panic")
	}
	return c.err
}

// Value reports no associated value.
func (hostileContext) Value(any) any { return nil }

// TestErrorClassificationRejectsRawWrappedAndTypedNilErrors verifies no cause escapes the boundary.
func TestErrorClassificationRejectsRawWrappedAndTypedNilErrors(t *testing.T) {
	const marker = "protected-raw-marker"
	var typedNil *Error
	for _, err := range []error{
		errors.New(marker),
		fmt.Errorf("%s: %w", marker, NewError(ErrorCodeUnavailable)),
		typedNil,
		hostileError{},
	} {
		if IsTypedError(err) || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("classification accepted %T", err)
		}
	}
}

// hostileError panics if classification performs provider-controlled traversal.
type hostileError struct{}

// Error returns a constant hostile diagnostic.
func (hostileError) Error() string { return "hostile-error" }

// As panics if classification invokes an attacker-controlled error traversal.
func (hostileError) As(any) bool { panic("hostile As invoked") }

// assertErrorEncoding verifies every formatting and serialization surface is code-only.
func assertErrorEncoding(t *testing.T, err error, want string) {
	t.Helper()
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", err, err, err, err, err, err)
	if strings.Count(formatted, want) != 6 {
		t.Fatalf("%q formatting = %q", want, formatted)
	}
	textMarshaler, ok := err.(interface{ MarshalText() ([]byte, error) })
	if !ok {
		t.Fatalf("%T lacks MarshalText", err)
	}
	text, marshalErr := textMarshaler.MarshalText()
	if marshalErr != nil || string(text) != want {
		t.Fatalf("MarshalText(%q) = %q, %v", want, text, marshalErr)
	}
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil || string(encoded) != `"`+want+`"` {
		t.Fatalf("json.Marshal(%q) = %s, %v", want, encoded, marshalErr)
	}
	if strings.Contains(formatted+string(text)+string(encoded), "protected") {
		t.Fatalf("%q leaked protected content", want)
	}
}

// allErrorCodes returns the frozen taxonomy for exhaustive tests.
func allErrorCodes() []ErrorCode {
	return []ErrorCode{
		ErrorCodeInvalidRequest,
		ErrorCodeMisconfigured,
		ErrorCodeLimitExceeded,
		ErrorCodeUnavailable,
		ErrorCodeIndeterminate,
		ErrorCodeInconsistent,
		ErrorCodeCancelled,
		ErrorCodeDeadlineExceeded,
		ErrorCodeClosed,
		ErrorCodeInternalInvariant,
	}
}
