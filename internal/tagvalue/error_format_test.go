package tagvalue

import (
	"fmt"
	"strings"
	"testing"
)

// TestErrorFormattingNeverDumpsStoredFields proves every fmt form uses the bounded diagnostic.
func TestErrorFormattingNeverDumpsStoredFields(t *testing.T) {
	marker := "allowlistedsecretmarker"
	err := NewError(ErrorCode(marker), ErrorLocation{}, ErrorDetails{Class: ErrorClass(marker), LimitName: LimitName(marker)})
	if err.Code() != ErrorCodeInvalidOptions || err.Class() != ErrorClassInvariant || err.TagName() != "" || err.LimitName() != "" {
		t.Fatal("tagvalue error retained unknown closed metadata")
	}
	for _, formatted := range []string{fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), err.GoString()} {
		if strings.Contains(formatted, marker) {
			t.Fatal("tagvalue error formatting exposed stored fields")
		}
	}
}
