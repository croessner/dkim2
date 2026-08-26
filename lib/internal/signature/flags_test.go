package signature

import "testing"

// TestParseFlagsPreservesKnownAndUnknown verifies f= flag parser data.
func TestParseFlagsPreservesKnownAndUnknown(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", "donotmodify, X-Unknown")))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	flags := parsed.Flags()
	if !flags.HasKnown(FlagDoNotModify) {
		t.Fatalf("Flags().HasKnown(%q) = false", FlagDoNotModify)
	}
	values := flags.Values()
	if len(values) != 2 {
		t.Fatalf("Flags().Values() length = %d, want 2", len(values))
	}
	if values[1].Name() != "x-unknown" || values[1].Known() {
		t.Fatalf("unknown flag = %#v", values[1])
	}
}

// TestParseFlagsRecognizesFeedHere reproduces the Draft-05 feedhere flag contract.
func TestParseFlagsRecognizesFeedHere(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", "feedhere")))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !parsed.Flags().HasKnown(FlagFeedHere) {
		t.Fatal("Flags().HasKnown(feedhere) = false")
	}
}

// TestParseRejectsDuplicateKnownFlags verifies f= ambiguity handling.
func TestParseRejectsDuplicateKnownFlags(t *testing.T) {
	_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", "feedback, Feedback")))
	if !IsErrorCode(err, ErrorCodeDuplicateKnownFlag) {
		t.Fatalf("Parse() error = %v, want duplicate known flag", err)
	}
}

// TestParseRejectsMalformedFlags verifies f= flag token syntax.
func TestParseRejectsMalformedFlags(t *testing.T) {
	tests := []string{"", "donotmodify,", "bad flag", "bad:flag"}
	for _, value := range tests {
		t.Run("flag", func(t *testing.T) {
			_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", value)))
			if !IsErrorCode(err, ErrorCodeMalformedFlag) {
				t.Fatalf("Parse() error = %v, want malformed flag", err)
			}
		})
	}
}

// TestParserRejectsFlagLimit verifies f= count limits.
func TestParserRejectsFlagLimit(t *testing.T) {
	parser, err := NewParser(Limits{MaxFlags: 1})
	if err != nil {
		t.Fatalf("NewParser() error = %v", err)
	}

	_, err = parser.ParseField(dkim2SignatureField(t, 0, signatureValueWith("f", "feedback, unknown")))
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("ParseField() error = %v, want limit exceeded", err)
	}
}
