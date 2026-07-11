package policy

import (
	"errors"
	"strings"
	"testing"
)

// TestConfigValidation verifies defaults, narrowing, and hard maxima.
func TestConfigValidation(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() error = %v", err)
	}
	narrow := DefaultConfig()
	narrow.Limits.MaxAuthenticatedHops = 1
	narrow.Limits.MaxFindings = 1
	if err := narrow.Validate(); err != nil {
		t.Fatalf("narrow config error = %v", err)
	}
	if got := DefaultLimits(); got != (Limits{MaxAuthenticatedHops: 128, MaxFindings: 128, MaxActions: 1}) {
		t.Fatalf("DefaultLimits() = %#v", got)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "empty mode", mutate: func(config *Config) { config.Mode = "" }},
		{name: "unknown mode", mutate: func(config *Config) { config.Mode = "future" }},
		{name: "hops zero", mutate: func(config *Config) { config.Limits.MaxAuthenticatedHops = 0 }},
		{name: "hops negative", mutate: func(config *Config) { config.Limits.MaxAuthenticatedHops = -1 }},
		{name: "hops over", mutate: func(config *Config) { config.Limits.MaxAuthenticatedHops = 129 }},
		{name: "findings zero", mutate: func(config *Config) { config.Limits.MaxFindings = 0 }},
		{name: "findings negative", mutate: func(config *Config) { config.Limits.MaxFindings = -1 }},
		{name: "findings over", mutate: func(config *Config) { config.Limits.MaxFindings = 129 }},
		{name: "actions zero", mutate: func(config *Config) { config.Limits.MaxActions = 0 }},
		{name: "actions negative", mutate: func(config *Config) { config.Limits.MaxActions = -1 }},
		{name: "actions over", mutate: func(config *Config) { config.Limits.MaxActions = 2 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultConfig()
			tt.mutate(&config)
			if err := config.Validate(); !IsErrorCode(err, ErrorInvalidConfig) {
				t.Fatalf("invalid config error = %v", err)
			}
		})
	}
}

// TestPolicyErrorsAreTypedAndSecretSafe verifies bounded diagnostic contracts.
func TestPolicyErrorsAreTypedAndSecretSafe(t *testing.T) {
	err := newLimitError(limitNameFindings, 1, 2)
	if !IsErrorCode(err, ErrorLimitExceeded) || !errors.Is(err, &Error{code: ErrorLimitExceeded}) {
		t.Fatalf("typed limit error = %v", err)
	}
	if err.Error() != "policy failure: limit_exceeded "+limitNameFindings || len(err.Error()) > 128 {
		t.Fatalf("unsafe policy error = %q", err.Error())
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.LimitName() != limitNameFindings || typed.ConfiguredLimit() != 1 || typed.ObservedCount() != 2 {
		t.Fatalf("limit metadata = %#v", typed)
	}
	for _, name := range []string{limitNameAuthenticatedHops, limitNameFindings, limitNameActions} {
		if limitErr := newLimitError(name, 1, 2); !IsErrorCode(limitErr, ErrorLimitExceeded) {
			t.Fatalf("allowlisted limit %q error = %v", name, limitErr)
		}
	}
	if unknown := newLimitError("toxic-limit-name", 1, 2); !IsErrorCode(unknown, ErrorInternalContract) || strings.Contains(unknown.Error(), "toxic") {
		t.Fatalf("unknown limit error = %v", unknown)
	}
	for _, counts := range [][2]int{{0, 1}, {-1, 1}, {1, 1}, {2, 1}, {1, 0}, {1, -1}} {
		if invalid := newLimitError(limitNameFindings, counts[0], counts[1]); !IsErrorCode(invalid, ErrorInternalContract) {
			t.Fatalf("invalid limit counts %v accepted: %v", counts, invalid)
		}
	}
	var nilTarget *Error
	if errors.Is(err, nilTarget) {
		t.Fatal("typed nil error target matched")
	}
	evaluator, evaluatorErr := NewEvaluator(DefaultConfig())
	if evaluatorErr != nil {
		t.Fatalf("NewEvaluator() error = %v", evaluatorErr)
	}
	_, toxicErr := evaluator.evaluateBase(ProtocolClass("TOXIC-POLICY-INPUT"))
	if toxicErr == nil || strings.Contains(toxicErr.Error(), "TOXIC") || toxicErr.Error() != "policy failure: invalid_input" {
		t.Fatalf("invalid-input error = %q", toxicErr)
	}
}
