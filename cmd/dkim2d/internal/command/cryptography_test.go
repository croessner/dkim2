package command

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

// TestServeAndValidateRefuseRuntimeWithoutMLDSA44 proves dkim2d fails closed
// before loading configuration when the runtime cannot provide mldsa44 (a
// FIPS 140-3 Go Cryptographic Module v1.0.0 build) and reports one fixed,
// secret-free diagnostic.
func TestServeAndValidateRefuseRuntimeWithoutMLDSA44(t *testing.T) {
	t.Parallel()
	loads := 0
	deps := commandDependencies{
		load: func(string, config.FlagValues) (bootstrapOwner, error) {
			loads++
			return &commandOwnerFake{}, nil
		},
		build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
			return nil, errCommandRuntime
		},
		withTimeout:  context.WithTimeout,
		cryptography: func() error { return errors.New("unavailable") },
	}
	if err := runValidate(testConfigPath, deps); !errors.Is(err, errMLDSA44Unavailable) {
		t.Fatalf("runValidate() error = %v", err)
	}
	if err := runServe(context.Background(), testConfigPath, config.NewFlagValues("", false, "", false, "", false), deps); !errors.Is(err, errMLDSA44Unavailable) {
		t.Fatalf("runServe() error = %v", err)
	}
	if loads != 0 {
		t.Fatalf("configuration loaded %d times before the runtime check", loads)
	}
	var stdout, stderr bytes.Buffer
	if code := executeWithDependencies([]string{validateCommandName, "--config", testConfigPath}, &stdout, &stderr, deps); code != 1 ||
		!strings.Contains(stderr.String(), "FIPS 140-3 Go Cryptographic Module v1.0.0") {
		t.Fatalf("Execute() code=%d stderr=%q", code, stderr.String())
	}
	deps.cryptography = func() error { return nil }
	if err := runValidate(testConfigPath, deps); err != nil {
		t.Fatalf("runValidate() with ML-DSA error = %v", err)
	}
}
