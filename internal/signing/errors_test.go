package signing

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const signingSecretMarker = "recipient-secret-marker@example.test"

// TestErrorVocabularyIsClosedAndSecretSafe verifies stable bounded diagnostics.
func TestErrorVocabularyIsClosedAndSecretSafe(t *testing.T) {
	err := newError(ErrorCodeLimitExceeded, ErrorLocation{
		Phase: PhasePreflight, Resource: ResourceGeneratedRecipients,
		Algorithm: Algorithm(signingSecretMarker), Sequence: 2, Instance: 3,
	}, ErrorDetails{Class: ErrorClassLimit, LimitName: LimitName(signingSecretMarker), Limit: 128, Actual: 129})
	if !err.Code().Known() || !err.Class().Known() || !err.Location().Phase.Known() {
		t.Fatal("error exposed an open vocabulary value")
	}
	location := err.Location()
	details := err.Details()
	if location.Algorithm != "" || location.Resource != ResourceGeneratedRecipients || strings.Contains(string(details.LimitName), signingSecretMarker) {
		t.Fatal("structured diagnostics retained unsafe input")
	}
	for _, formatted := range []string{
		err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err),
	} {
		if strings.Contains(formatted, signingSecretMarker) {
			t.Fatal("error formatting leaked marker")
		}
	}
}

// testErrorCode returns a closed code without formatting arbitrary errors.
func testErrorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ""
}
