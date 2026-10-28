package signature

import "testing"

// Draft-06 flag spellings that Draft-07 Section 10.10 removed; they must parse
// as inert unknown flags and must never be generated.
const (
	removedFlagDoNotModify  = "donotmodify"
	removedFlagDoNotExplode = "donotexplode"
)

// TestParseFlagsPreservesKnownAndUnknown verifies f= flag parser data.
func TestParseFlagsPreservesKnownAndUnknown(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", "feedback, X-Unknown")))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	flags := parsed.Flags()
	if !flags.HasKnown(FlagFeedback) {
		t.Fatalf("Flags().HasKnown(%q) = false", FlagFeedback)
	}
	values := flags.Values()
	if len(values) != 2 {
		t.Fatalf("Flags().Values() length = %d, want 2", len(values))
	}
	if values[1].Name() != "X-Unknown" || values[1].Known() {
		t.Fatalf("unknown flag = %#v", values[1])
	}
}

// TestParseFlagsTreatsRemovedDraft06FlagsAsUnknown reproduces the Draft-07
// Section 10.10 removal of donotmodify and donotexplode: both spellings parse
// as inert unknown flags, may repeat without a duplicate-known error, and are
// never reported as known.
func TestParseFlagsTreatsRemovedDraft06FlagsAsUnknown(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", removedFlagDoNotModify+", "+removedFlagDoNotExplode+", "+removedFlagDoNotModify)))
	if err != nil {
		t.Fatalf("Parse() error = %v, want inert unknown flags", err)
	}
	flags := parsed.Flags()
	for _, name := range []string{removedFlagDoNotModify, removedFlagDoNotExplode} {
		if flags.HasKnown(name) {
			t.Fatalf("Flags().HasKnown(%q) = true, want removed flag to be unknown", name)
		}
	}
	values := flags.Values()
	if len(values) != 3 {
		t.Fatalf("Flags().Values() length = %d, want 3", len(values))
	}
	for index, want := range []string{removedFlagDoNotModify, removedFlagDoNotExplode, removedFlagDoNotModify} {
		if values[index].Name() != want || values[index].Known() {
			t.Fatalf("Flags().Values()[%d] = %#v, want unknown %q", index, values[index], want)
		}
	}
}

// TestParseFlagsRecognizesFeedHere reproduces the Draft-08 feedhere flag contract.
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
	_, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", "feedback, feedback")))
	if !IsErrorCode(err, ErrorCodeDuplicateKnownFlag) {
		t.Fatalf("Parse() error = %v, want duplicate known flag", err)
	}
}

// TestParseFlagsAreCaseSensitive reproduces the Draft-08 Sections 2.14 and
// 10.10 rule that flag names are case-sensitive: an uppercase spelling of a
// known flag is an unknown flag with no effect.
func TestParseFlagsAreCaseSensitive(t *testing.T) {
	parsed, err := Parse(dkim2SignatureField(t, 0, signatureValueWith("f", "Exploded, feedback, Feedback")))
	if err != nil {
		t.Fatalf("Parse() error = %v, want distinct case-sensitive flags", err)
	}
	flags := parsed.Flags()
	if flags.HasKnown(FlagExploded) || !flags.HasKnown(FlagFeedback) {
		t.Fatalf("HasKnown(exploded/feedback) = %t/%t, want false/true", flags.HasKnown(FlagExploded), flags.HasKnown(FlagFeedback))
	}
	values := flags.Values()
	if len(values) != 3 || values[0].Name() != "Exploded" || values[0].Known() || values[2].Name() != "Feedback" || values[2].Known() {
		t.Fatalf("Flags().Values() = %#v, want unknown uppercase spellings", values)
	}
}

// TestParseRejectsMalformedFlags verifies f= flag token syntax.
func TestParseRejectsMalformedFlags(t *testing.T) {
	tests := []string{"", "feedback,", "bad flag", "bad:flag"}
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
