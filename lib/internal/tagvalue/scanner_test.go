package tagvalue

import (
	"errors"
	"strings"
	"testing"
)

var scannerKnownTags = MustKnownTags("m", "h", "r", "empty")

// TestScanRejectsMissingFinalSemicolon reproduces the draft-04 tag terminator requirement.
func TestScanRejectsMissingFinalSemicolon(t *testing.T) {
	if _, err := ScanTerminated([]byte("m=1; h=abc"), scannerKnownTags, Limits{}); !IsErrorCode(err, ErrorCodeMissingTagTerminator) {
		t.Fatalf("Scan() error = %v, want missing tag terminator", err)
	}
}

// TestScanAcceptsTagListsWithOptionalFinalSemicolon verifies DNS-compatible shared separators.
func TestScanAcceptsTagListsWithOptionalFinalSemicolon(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "without final semicolon", input: "m=1; h=abc"},
		{name: "with final semicolon", input: "m=1; h=abc;"},
		{name: "with final semicolon and wsp", input: "m=1; h=abc; \t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field, err := Scan([]byte(tt.input), scannerKnownTags, Limits{})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if field.Len() != 2 {
				t.Fatalf("Len() = %d, want 2", field.Len())
			}
			if tag, ok := field.Get("h"); !ok || tag.Value() != "abc" {
				t.Fatalf("Get(h) = %#v, %v", tag, ok)
			}
		})
	}
}

// TestScanCanonicalizesNamesAndPreservesValues verifies case-sensitive values.
func TestScanCanonicalizesNamesAndPreservesValues(t *testing.T) {
	field, err := ScanTerminated([]byte("M = 1; H = AbC+/==; X_Ext = ValueWithCASE;"), scannerKnownTags, Limits{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	tag, ok := field.Get("m")
	if !ok {
		t.Fatal("missing canonical m tag")
	}
	if tag.Name() != "m" || tag.RawName() != "M" || tag.Value() != "1" || !tag.Known() {
		t.Fatalf("m tag = %#v", tag)
	}

	tag, ok = field.Get("h")
	if !ok {
		t.Fatal("missing canonical h tag")
	}
	if tag.Value() != "AbC+/==" {
		t.Fatalf("h value = %q, want case-sensitive value", tag.Value())
	}

	unknown := field.UnknownTags()
	if len(unknown) != 1 {
		t.Fatalf("UnknownTags length = %d, want 1", len(unknown))
	}
	if unknown[0].Name() != "x_ext" || unknown[0].RawName() != "X_Ext" || unknown[0].Value() != "ValueWithCASE" || unknown[0].Known() {
		t.Fatalf("unknown tag = %#v", unknown[0])
	}
}

// TestScanTreatsDNSCompatibleTagNamesCaseSensitively verifies DNS-04 Section 3.2 name matching.
func TestScanTreatsDNSCompatibleTagNamesCaseSensitively(t *testing.T) {
	field, err := Scan([]byte("m=1; M=2;"), scannerKnownTags, Limits{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if field.Len() != 2 {
		t.Fatalf("Len() = %d, want distinct case-sensitive tags", field.Len())
	}
	lower, lowerOK := field.Get("m")
	upper, upperOK := field.Get("M")
	if !lowerOK || !upperOK || lower.Value() != "1" || upper.Value() != "2" {
		t.Fatalf("case-sensitive tags = lower %#v/%v upper %#v/%v", lower, lowerOK, upper, upperOK)
	}
	if !lower.Known() || upper.Known() {
		t.Fatalf("known states = lower %v upper %v, want true/false", lower.Known(), upper.Known())
	}
	if upper.Name() != "M" || lower.Name() != "m" {
		t.Fatalf("Name() = upper %q lower %q, want exact DNS spelling", upper.Name(), lower.Name())
	}

	_, err = ScanTerminated([]byte("m=1; M=2;"), scannerKnownTags, Limits{})
	if !IsErrorCode(err, ErrorCodeDuplicateTag) {
		t.Fatalf("ScanTerminated() error = %v, want case-insensitive duplicate", err)
	}
}

// TestKnownTagsUsesExactDNSAndFoldedHeaderLookup verifies coherent mode-specific classification.
func TestKnownTagsUsesExactDNSAndFoldedHeaderLookup(t *testing.T) {
	known := MustKnownTags("m", "X_Ext")
	if !known.Contains("m") || !known.Contains("X_Ext") || known.Contains("M") || known.Contains("x_ext") {
		t.Fatalf("Contains() did not use exact case-sensitive lookup")
	}
	if _, err := NewKnownTags("m", "M"); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("NewKnownTags() error = %v, want folded duplicate rejection", err)
	}

	dnsField, err := Scan([]byte("X_Ext=value;"), known, Limits{})
	if err != nil || !dnsField.Tags()[0].Known() {
		t.Fatalf("Scan() field/error = %#v/%v, want exact known tag", dnsField, err)
	}
	headerField, err := ScanTerminated([]byte("x_EXT=value;"), known, Limits{})
	if err != nil || !headerField.Tags()[0].Known() || headerField.Tags()[0].Name() != "x_ext" {
		t.Fatalf("ScanTerminated() field/error = %#v/%v, want folded known tag", headerField, err)
	}
}

// TestScanHandlesDNSFWS verifies DNS-04 folding around specs and within values.
func TestScanHandlesDNSFWS(t *testing.T) {
	field, err := Scan([]byte("m=1;\r\n\th=abc; x_ext=one\r\n two;"), scannerKnownTags, Limits{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if tag, ok := field.Get("h"); !ok || tag.Value() != "abc" {
		t.Fatalf("Get(h) = %#v/%v, want folded tag", tag, ok)
	}
	if tag, ok := field.Get("x_ext"); !ok || tag.Value() != "one two" {
		t.Fatalf("Get(x_ext) = %#v/%v, want retained unfolded WSP", tag, ok)
	}
}

// TestScanRejectsMalformedDNSFWS verifies bare or incomplete line breaks fail closed.
func TestScanRejectsMalformedDNSFWS(t *testing.T) {
	for _, input := range [][]byte{
		[]byte("m=1;\rh=2;"),
		[]byte("m=1;\nh=2;"),
		[]byte("m=1;\r\nh=2;"),
		[]byte("m=1;\r\n"),
	} {
		_, err := Scan(input, scannerKnownTags, Limits{})
		if !IsErrorCode(err, ErrorCodeInvalidTagValue) {
			t.Fatalf("Scan(%q) error = %v, want invalid tag value", input, err)
		}
	}
	if _, err := ScanTerminated([]byte("m=1;\r\n h=2;"), scannerKnownTags, Limits{}); !IsErrorCode(err, ErrorCodeInvalidTagValue) {
		t.Fatalf("ScanTerminated() error = %v, want already-unfolded input enforcement", err)
	}
}

// TestScanRejectsInvalidUnknownTagValues verifies extension values satisfy printable non-semicolon ABNF.
func TestScanRejectsInvalidUnknownTagValues(t *testing.T) {
	for _, input := range [][]byte{
		[]byte("m=1; x_ext=has\x00nul;"),
		[]byte("m=1; x_ext=has\x1fcontrol;"),
		[]byte("m=1; x_ext=has\x7fdelete;"),
	} {
		_, err := Scan(input, scannerKnownTags, Limits{})
		if !IsErrorCode(err, ErrorCodeInvalidTagValue) {
			t.Fatalf("Scan(%q) error = %v, want invalid tag value", input, err)
		}
	}
}

// TestScanDistinguishesEmptyValuesFromOmittedTags verifies empty value presence.
func TestScanDistinguishesEmptyValuesFromOmittedTags(t *testing.T) {
	field, err := Scan([]byte("m=1; empty=;"), scannerKnownTags, Limits{})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	tag, ok := field.Get("empty")
	if !ok {
		t.Fatal("empty tag is omitted")
	}
	if tag.Value() != "" {
		t.Fatalf("empty tag value = %q, want empty string", tag.Value())
	}
	if field.Has("h") {
		t.Fatal("omitted h tag reported as present")
	}
}

// TestScanRejectsMalformedTagLists verifies shared fail-closed syntax behavior.
func TestScanRejectsMalformedTagLists(t *testing.T) {
	tests := []struct {
		name string
		in   string
		code ErrorCode
	}{
		{name: "empty field", in: " \t ", code: ErrorCodeEmptyTagSpec},
		{name: "leading empty spec", in: ";m=1;", code: ErrorCodeEmptyTagSpec},
		{name: "interior empty spec", in: "m=1;;h=abc;", code: ErrorCodeEmptyTagSpec},
		{name: "wsp interior empty spec", in: "m=1; \t ;h=abc;", code: ErrorCodeEmptyTagSpec},
		{name: "missing equals", in: "m=1;h;", code: ErrorCodeMissingEquals},
		{name: "unencoded semicolon in value", in: "m=one;two;h=abc;", code: ErrorCodeMissingEquals},
		{name: "empty name", in: "=value;", code: ErrorCodeInvalidTagName},
		{name: "digit first name", in: "1m=value;", code: ErrorCodeInvalidTagName},
		{name: "hyphen name", in: "x-test=value;", code: ErrorCodeInvalidTagName},
		{name: "non ascii name", in: "ü=value;", code: ErrorCodeInvalidTagName},
		{name: "control name", in: "m\n=value;", code: ErrorCodeInvalidTagValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Scan([]byte(tt.in), scannerKnownTags, Limits{})
			if !IsErrorCode(err, tt.code) {
				t.Fatalf("Scan() error = %v, want code %s", err, tt.code)
			}
		})
	}
}

// TestScanRejectsDuplicateKnownAndExtensionTags verifies duplicate detection.
func TestScanRejectsDuplicateKnownAndExtensionTags(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantTag string
	}{
		{name: "known", in: "m=1; m=2;", wantTag: "m"},
		{name: "extension", in: "x_ext=1; x_ext=2;", wantTag: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Scan([]byte(tt.in), scannerKnownTags, Limits{})
			if !IsErrorCode(err, ErrorCodeDuplicateTag) {
				t.Fatalf("Scan() error = %v, want duplicate", err)
			}

			var scannerErr *Error
			if !errors.As(err, &scannerErr) {
				t.Fatal("errors.As did not expose tagvalue Error")
			}
			if scannerErr.TagName() != tt.wantTag {
				t.Fatalf("TagName() = %q, want %q", scannerErr.TagName(), tt.wantTag)
			}
		})
	}
}

// TestScanRejectsConfiguredLimitViolations verifies bounded resource failures.
func TestScanRejectsConfiguredLimitViolations(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		limits    Limits
		limitName string
	}{
		{name: "field bytes", in: "m=12345;", limits: Limits{MaxFieldValueBytes: 3}, limitName: "max_field_value_bytes"},
		{name: "tag count", in: "m=1;h=2;r=3;", limits: Limits{MaxTags: 2}, limitName: "max_tags"},
		{name: "name bytes", in: "long=1;", limits: Limits{MaxTagNameBytes: 3}, limitName: "max_tag_name_bytes"},
		{name: "value bytes", in: "m=1234;", limits: Limits{MaxTagValueBytes: 3}, limitName: "max_tag_value_bytes"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Scan([]byte(tt.in), scannerKnownTags, tt.limits)
			if !IsErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("Scan() error = %v, want limit exceeded", err)
			}

			var scannerErr *Error
			if !errors.As(err, &scannerErr) {
				t.Fatal("errors.As did not expose tagvalue Error")
			}
			if scannerErr.LimitName() != tt.limitName {
				t.Fatalf("LimitName() = %q, want %q", scannerErr.LimitName(), tt.limitName)
			}
		})
	}
}

// TestScannerErrorStringIsBoundedAndSecretSafe verifies diagnostics omit values.
func TestScannerErrorStringIsBoundedAndSecretSafe(t *testing.T) {
	secretValue := "mf=<secret@example.test>; token=password"
	err := NewError(ErrorCode(secretValue), ErrorLocation{Offset: 8, TagIndex: 1}, ErrorDetails{
		Class:     ErrorClassMalformed,
		TagName:   secretValue,
		LimitName: secretValue,
		Limit:     64,
		Count:     128,
	})

	message := err.Error()
	for _, forbidden := range []string{"secret@example.test", "password", secretValue} {
		if strings.Contains(message, forbidden) {
			t.Fatalf("error string leaked raw context %q in %q", forbidden, message)
		}
	}
	if !strings.Contains(message, "code=redacted") {
		t.Fatalf("error string %q does not redact unsafe code", message)
	}
	if !strings.Contains(message, "offset=8") || !strings.Contains(message, "count=128") {
		t.Fatalf("error string %q does not contain bounded metadata", message)
	}
}

// TestKnownTagsRejectsInvalidNames verifies allowlists use DKIM2 tag syntax.
func TestKnownTagsRejectsInvalidNames(t *testing.T) {
	if _, err := NewKnownTags("valid", "bad-name"); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("NewKnownTags() error = %v, want invalid options", err)
	}
}
