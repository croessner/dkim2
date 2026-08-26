package canonical

import (
	"errors"
	"strings"
	"testing"
)

func TestDefaultLimitsMatchCanonicalContract(t *testing.T) {
	limits := DefaultLimits()
	if limits.MaxBodyInputBytes != 32*1024*1024 {
		t.Fatalf("MaxBodyInputBytes = %d, want 32 MiB", limits.MaxBodyInputBytes)
	}
	if limits.MaxHeaderInputBytes != 2*1024*1024 {
		t.Fatalf("MaxHeaderInputBytes = %d, want 2 MiB", limits.MaxHeaderInputBytes)
	}
	if limits.MaxSignatureInputBytes != 2*1024*1024 {
		t.Fatalf("MaxSignatureInputBytes = %d, want 2 MiB", limits.MaxSignatureInputBytes)
	}
	if limits.MaxFieldBytes != 128*1024 {
		t.Fatalf("MaxFieldBytes = %d, want 128 KiB", limits.MaxFieldBytes)
	}
	if limits.MaxFieldCount != 4000 {
		t.Fatalf("MaxFieldCount = %d, want 4000", limits.MaxFieldCount)
	}
	if limits.MaxExcludedHeaderCounters != 10 || defaultExcludedCounterCount != 10 {
		t.Fatalf("MaxExcludedHeaderCounters = %d, constant = %d, want concrete schema count 10", limits.MaxExcludedHeaderCounters, defaultExcludedCounterCount)
	}
	if err := limits.Validate(); err != nil {
		t.Fatalf("DefaultLimits().Validate() error = %v", err)
	}
}

func TestOptionsRejectUnsafeValues(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxFieldCount = 0
	if err := limits.Validate(); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("Limits.Validate() error = %v, want invalid options", err)
	}

	if _, err := NewCanonicalizer(WithHashAlgorithm("sha999")); !IsErrorCode(err, ErrorCodeUnsupportedAlgorithm) {
		t.Fatalf("NewCanonicalizer() error = %v, want unsupported algorithm", err)
	}
}

func TestCanonicalizerUsesValidatedDefaults(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	options := canonicalizer.Options()
	if options.HashAlgorithm != HashAlgorithmSHA256 {
		t.Fatalf("HashAlgorithm = %q, want sha256", options.HashAlgorithm)
	}
	if options.Limits.MaxFieldCount != DefaultLimits().MaxFieldCount {
		t.Fatalf("MaxFieldCount = %d, want default", options.Limits.MaxFieldCount)
	}
}

func TestErrorStringIsBoundedAndSecretSafe(t *testing.T) {
	err := newError(ErrorCodeLimitExceeded, ErrorLocation{
		Kind:         KindHeaderHashInput,
		FieldIndex:   -10,
		TargetNumber: 7,
	}, ErrorDetails{
		Class:      ErrorClassLimit,
		Algorithm:  "sha256:raw-body-secret",
		LimitName:  "max_header_input_bytes:secret",
		Limit:      -1,
		Count:      -2,
		TargetName: "Message-Instance: secret header value",
	}, errors.New("raw body secret should remain wrapped only"))

	text := err.Error()
	for _, forbidden := range []string{
		"raw-body-secret",
		"secret header value",
		"raw body secret",
		"max_header_input_bytes:secret",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("Error() leaked %q in %q", forbidden, text)
		}
	}
	if !strings.Contains(text, "code=limit_exceeded") || !strings.Contains(text, "class=limit") {
		t.Fatalf("Error() = %q, want stable code and class", text)
	}
	if err.Location().FieldIndex != 0 {
		t.Fatalf("Location().FieldIndex = %d, want clamped zero", err.Location().FieldIndex)
	}
	if err.Limit() != 0 || err.Count() != 0 {
		t.Fatalf("Limit/Count = %d/%d, want clamped zero", err.Limit(), err.Count())
	}
	if !errors.Is(err, &Error{code: ErrorCodeLimitExceeded}) {
		t.Fatal("errors.Is did not match canonical error code")
	}
	if !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatal("IsErrorCode did not match canonical error code")
	}
}
