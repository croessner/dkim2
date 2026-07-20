package signature

import (
	"fmt"
	"strings"
	"testing"
)

const signatureTestSecretMarker = "allowlistedsecretmarker"

// TestErrorMetadataRejectsAllowlistShapedUnknownValues proves diagnostics use closed names.
func TestErrorMetadataRejectsAllowlistShapedUnknownValues(t *testing.T) {
	marker := signatureTestSecretMarker
	err := newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
		TagName: TagName(marker), LimitName: LimitName(marker), Limit: 1, Count: 2,
	}, nil)
	if err.TagName() != "" || err.LimitName() != "" {
		t.Fatal("error accessors retained unknown metadata")
	}
	for _, formatted := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(formatted, marker) {
			t.Fatal("error formatting retained unknown metadata")
		}
	}
}

// TestErrorCodeAndClassRejectUnknownValues proves arbitrary closed tokens cannot survive.
func TestErrorCodeAndClassRejectUnknownValues(t *testing.T) {
	marker := signatureTestSecretMarker
	err := newError(ErrorCode(marker), ErrorLocation{}, ErrorDetails{Class: ErrorClass(marker)}, nil)
	if err.Code() != ErrorCodeRenderInvariant || err.Class() != ErrorClassInvariant {
		t.Fatal("unknown error code or class survived normalization")
	}
	if strings.Contains(err.Error(), marker) {
		t.Fatal("unknown error code or class reached formatting")
	}
}
