package dkim2

import (
	"errors"
	"testing"
)

// TestDefaultVerificationLimitsEqualHardMaxima proves all six defaults are restrictive hard maxima.
func TestDefaultVerificationLimitsEqualHardMaxima(t *testing.T) {
	limits := DefaultVerificationLimits()
	if limits.MaxRawMessageBytes() != HardMaxRawMessageBytes ||
		limits.MaxRecipients() != HardMaxRecipients ||
		limits.MaxInstanceHashSets() != HardMaxInstanceHashSets ||
		limits.MaxSignatureSets() != HardMaxSignatureSets ||
		limits.MaxCheckFacts() != HardMaxCheckFacts ||
		limits.MaxSignatureFacts() != HardMaxSignatureFacts {
		t.Fatalf("default limits do not equal hard maxima: %#v", limits)
	}
}

// TestVerifierOptionsAllowOnlyPositiveNarrowing proves exact maxima and narrower values are accepted atomically.
func TestVerifierOptionsAllowOnlyPositiveNarrowing(t *testing.T) {
	options := []VerifierOption{
		WithMaxRawMessageBytes(HardMaxRawMessageBytes - 1),
		WithMaxRecipients(HardMaxRecipients - 1),
		WithMaxInstanceHashSets(HardMaxInstanceHashSets - 1),
		WithMaxSignatureSets(HardMaxSignatureSets - 1),
		WithMaxCheckFacts(HardMaxCheckFacts - 1),
		WithMaxSignatureFacts(HardMaxSignatureFacts - 1),
	}
	config, err := applyVerifierOptions(options...)
	if err != nil {
		t.Fatalf("applyVerifierOptions() error = %v", err)
	}
	limits := config.limits
	if limits.MaxRawMessageBytes() != HardMaxRawMessageBytes-1 ||
		limits.MaxRecipients() != HardMaxRecipients-1 ||
		limits.MaxInstanceHashSets() != HardMaxInstanceHashSets-1 ||
		limits.MaxSignatureSets() != HardMaxSignatureSets-1 ||
		limits.MaxCheckFacts() != HardMaxCheckFacts-1 ||
		limits.MaxSignatureFacts() != HardMaxSignatureFacts-1 {
		t.Fatalf("narrowed limits were not applied: %#v", limits)
	}

	if _, err := applyVerifierOptions(
		WithMaxRawMessageBytes(HardMaxRawMessageBytes),
		WithMaxRecipients(HardMaxRecipients),
		WithMaxInstanceHashSets(HardMaxInstanceHashSets),
		WithMaxSignatureSets(HardMaxSignatureSets),
		WithMaxCheckFacts(HardMaxCheckFacts),
		WithMaxSignatureFacts(HardMaxSignatureFacts),
	); err != nil {
		t.Fatalf("exact hard maxima were rejected: %v", err)
	}
}

// TestVerifierOptionsRejectInvalidValues proves zero, negative, widening, and nil options fail with a bounded code.
func TestVerifierOptionsRejectInvalidValues(t *testing.T) {
	tests := []struct {
		name   string
		option VerifierOption
	}{
		{"raw zero", WithMaxRawMessageBytes(0)},
		{"raw negative", WithMaxRawMessageBytes(-1)},
		{"raw wider", WithMaxRawMessageBytes(HardMaxRawMessageBytes + 1)},
		{"recipients zero", WithMaxRecipients(0)},
		{"recipients negative", WithMaxRecipients(-1)},
		{"recipients wider", WithMaxRecipients(HardMaxRecipients + 1)},
		{"hash sets zero", WithMaxInstanceHashSets(0)},
		{"hash sets negative", WithMaxInstanceHashSets(-1)},
		{"hash sets wider", WithMaxInstanceHashSets(HardMaxInstanceHashSets + 1)},
		{"signature sets zero", WithMaxSignatureSets(0)},
		{"signature sets negative", WithMaxSignatureSets(-1)},
		{"signature sets wider", WithMaxSignatureSets(HardMaxSignatureSets + 1)},
		{"check facts zero", WithMaxCheckFacts(0)},
		{"check facts negative", WithMaxCheckFacts(-1)},
		{"check facts wider", WithMaxCheckFacts(HardMaxCheckFacts + 1)},
		{"signature facts zero", WithMaxSignatureFacts(0)},
		{"signature facts negative", WithMaxSignatureFacts(-1)},
		{"signature facts wider", WithMaxSignatureFacts(HardMaxSignatureFacts + 1)},
		{"nil clock", WithVerificationClock(nil)},
		{"nil option", nil},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := applyVerifierOptions(test.option)
			if !errors.Is(err, newAPIError(APIErrorCodeInvalidOption)) {
				t.Fatalf("applyVerifierOptions() error = %v, want invalid_option", err)
			}
		})
	}
}

// TestVerifierOptionsAreAtomic proves a later invalid option cannot expose partially applied configuration.
func TestVerifierOptionsAreAtomic(t *testing.T) {
	config, err := applyVerifierOptions(
		WithMaxRecipients(10),
		WithMaxRawMessageBytes(HardMaxRawMessageBytes+1),
	)
	if !errors.Is(err, newAPIError(APIErrorCodeInvalidOption)) {
		t.Fatalf("applyVerifierOptions() error = %v, want invalid_option", err)
	}
	if config != (verifierConfig{}) {
		t.Fatalf("failed option application exposed partial config: %#v", config)
	}
}
