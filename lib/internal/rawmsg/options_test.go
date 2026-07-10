package rawmsg

import (
	"errors"
	"testing"
)

// TestDefaultParserOptionsAreRestrictive verifies the M1 fail-closed defaults.
func TestDefaultParserOptionsAreRestrictive(t *testing.T) {
	opts := DefaultParserOptions()

	if opts.LineEndingPolicy != LineEndingPolicyStrictCRLF {
		t.Fatalf("LineEndingPolicy = %q, want %q", opts.LineEndingPolicy, LineEndingPolicyStrictCRLF)
	}
	if opts.MaxMessageBytes != 32*1024*1024 {
		t.Fatalf("MaxMessageBytes = %d, want 32 MiB", opts.MaxMessageBytes)
	}
	if opts.MaxHeaderBytes != 1024*1024 {
		t.Fatalf("MaxHeaderBytes = %d, want 1 MiB", opts.MaxHeaderBytes)
	}
	if opts.MaxHeaderFields != 2000 {
		t.Fatalf("MaxHeaderFields = %d, want 2000", opts.MaxHeaderFields)
	}
	if opts.MaxHeaderFieldBytes != 64*1024 {
		t.Fatalf("MaxHeaderFieldBytes = %d, want 64 KiB", opts.MaxHeaderFieldBytes)
	}
	if opts.MaxHeaderLineBytes != 998 {
		t.Fatalf("MaxHeaderLineBytes = %d, want 998", opts.MaxHeaderLineBytes)
	}
	if opts.MaxBodyLineBytes != 998 {
		t.Fatalf("MaxBodyLineBytes = %d, want 998", opts.MaxBodyLineBytes)
	}
	if opts.RecordNormalizedInput {
		t.Fatal("RecordNormalizedInput must be false by default")
	}
	if err := opts.Validate(); err != nil {
		t.Fatalf("default options did not validate: %v", err)
	}
}

// TestParserOptionsValidateSafeLimits verifies unsafe option values fail typed validation.
func TestParserOptionsValidateSafeLimits(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*ParserOptions)
		code ErrorCode
	}{
		{
			name: "message size",
			mut:  func(opts *ParserOptions) { opts.MaxMessageBytes = 0 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "header bytes",
			mut:  func(opts *ParserOptions) { opts.MaxHeaderBytes = -1 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "header fields",
			mut:  func(opts *ParserOptions) { opts.MaxHeaderFields = 0 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "header field bytes",
			mut:  func(opts *ParserOptions) { opts.MaxHeaderFieldBytes = 0 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "header line bytes",
			mut:  func(opts *ParserOptions) { opts.MaxHeaderLineBytes = 0 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "body line bytes",
			mut:  func(opts *ParserOptions) { opts.MaxBodyLineBytes = 0 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "wider header line compatibility",
			mut:  func(opts *ParserOptions) { opts.MaxHeaderLineBytes = 999 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "wider body line compatibility",
			mut:  func(opts *ParserOptions) { opts.MaxBodyLineBytes = 999 },
			code: ErrorCodeLimitExceeded,
		},
		{
			name: "line ending policy",
			mut:  func(opts *ParserOptions) { opts.LineEndingPolicy = "loose" },
			code: ErrorCodeUnsupportedPolicy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := DefaultParserOptions()
			tt.mut(&opts)

			err := opts.Validate()
			if err == nil {
				t.Fatal("Validate returned nil")
			}
			if !IsParserErrorCode(err, tt.code) {
				t.Fatalf("Validate error code mismatch: %v", err)
			}
		})
	}
}

// TestParserOptionsRejectUnavailableCompatibilityPolicies verifies reserved modes fail validation.
func TestParserOptionsRejectUnavailableCompatibilityPolicies(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*ParserOptions)
		policyName string
	}{
		{
			name: "line ending normalization",
			mutate: func(options *ParserOptions) {
				options.LineEndingPolicy = LineEndingPolicyNormalizeLF
			},
			policyName: string(LineEndingPolicyNormalizeLF),
		},
		{
			name: "normalized input metadata",
			mutate: func(options *ParserOptions) {
				options.RecordNormalizedInput = true
			},
			policyName: "record-normalized-input",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options := DefaultParserOptions()
			test.mutate(&options)

			err := options.Validate()
			if !IsParserErrorCode(err, ErrorCodeUnsupportedPolicy) {
				t.Fatalf("Validate error = %v, want unsupported policy", err)
			}
			var parserErr *ParserError
			if !errors.As(err, &parserErr) {
				t.Fatalf("Validate error = %T, want ParserError", err)
			}
			if parserErr.PolicyName() != test.policyName {
				t.Fatalf("PolicyName = %q, want %q", parserErr.PolicyName(), test.policyName)
			}

			_, parseErr := ParseWithOptions([]byte("X: value\r\n\r\nbody"), options)
			if !IsParserErrorCode(parseErr, ErrorCodeUnsupportedPolicy) {
				t.Fatalf("ParseWithOptions error = %v, want unsupported policy", parseErr)
			}
		})
	}
}
