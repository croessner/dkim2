package dkim2

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type publicProviderFunc func(context.Context, PublicKeyQuery) (PublicKeyResult, error)

// LookupPublicKey invokes the provider test function.
func (f publicProviderFunc) LookupPublicKey(ctx context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	return f(ctx, query)
}

// TestVerifierSupportsConcurrentReuse verifies immutable facade wiring under shared use.
func TestVerifierSupportsConcurrentReuse(t *testing.T) {
	raw := publicProviderFixture(t)
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}), WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	var group sync.WaitGroup
	for range 16 {
		group.Go(func() {
			result, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if verifyErr != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonMissingKey {
				t.Errorf("Verify() = %q, %v", result.State(), verifyErr)
			}
		})
	}
	group.Wait()
}

type pointerPublicProvider struct{}

// LookupPublicKey returns a bounded missing-key result.
func (*pointerPublicProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	return MissingPublicKey(query.Algorithm()), nil
}

// TestAssessUnsignedReturnsNoVerificationAndMakesNoProviderCall proves the public applicability boundary.
func TestAssessUnsignedReturnsNoVerificationAndMakesNoProviderCall(t *testing.T) {
	calls := 0
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		calls++
		return PublicKeyResult{}, errors.New("unexpected lookup")
	}))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	assessment, err := verifier.Assess(context.Background(), NewVerifyRequest(
		[]byte("From: sender@example.test\r\n\r\nunsigned\r\n"),
		[]byte("<sender@example.test>"),
		[][]byte{[]byte("<recipient@example.test>")},
	))
	if err != nil || !assessment.Valid() || assessment.Applicable() || calls != 0 {
		t.Fatalf("Assess() = valid=%t applicable=%t calls=%d err=%v", assessment.Valid(), assessment.Applicable(), calls, err)
	}
	if _, ok := assessment.Verification(); ok {
		t.Fatal("unsigned assessment exposed a verification result")
	}
}

// TestNewVerifierRejectsInvalidDependencies verifies constructor-only valid state.
func TestNewVerifierRejectsInvalidDependencies(t *testing.T) {
	var typedNil *pointerPublicProvider
	for _, provider := range []PublicKeyProvider{nil, typedNil} {
		verifier, err := NewVerifier(provider)
		if verifier != nil || !errors.Is(err, newAPIError(APIErrorCodeInvalidProvider)) {
			t.Fatalf("NewVerifier() = %#v, %v", verifier, err)
		}
	}
	provider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) { return PublicKeyResult{}, nil })
	verifier, err := NewVerifier(provider, WithMaxRecipients(HardMaxRecipients+1))
	if verifier != nil || !errors.Is(err, newAPIError(APIErrorCodeInvalidOption)) {
		t.Fatalf("NewVerifier(invalid option) = %#v, %v", verifier, err)
	}
}

// TestVerifyPreservesResultErrorDisjointness verifies API misuse and protocol outcomes remain separate.
func TestVerifyPreservesResultErrorDisjointness(t *testing.T) {
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, errors.New("must not be reached")
	}), WithMaxRawMessageBytes(8))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest([]byte("123456789"), nil, nil))
	if err != nil || result.State() != ResultStatePERMERROR || result.CustodyStructure() != CustodyStructureNotEvaluated {
		t.Fatalf("limit result/error = %q/%q/%v", result.State(), result.CustodyStructure(), err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	result, err = verifier.Verify(canceled, VerifyRequest{})
	if !errors.Is(err, context.Canceled) || result.State() != "" || result.Draft() != "" {
		t.Fatalf("canceled result/error = %#v/%v", result, err)
	}
	deadline, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelDeadline()
	result, err = verifier.Verify(deadline, VerifyRequest{})
	if !errors.Is(err, context.DeadlineExceeded) || result.State() != "" {
		t.Fatalf("deadline result/error = %#v/%v", result, err)
	}
	result, err = (*Verifier)(nil).Verify(context.Background(), VerifyRequest{})
	if !errors.Is(err, newAPIError(APIErrorCodeInvalidRequest)) || result.State() != "" {
		t.Fatalf("nil verifier result/error = %#v/%v", result, err)
	}
	result, err = (&Verifier{}).Verify(context.Background(), VerifyRequest{})
	if !errors.Is(err, newAPIError(APIErrorCodeInvalidRequest)) || result.State() != "" {
		t.Fatalf("zero verifier result/error = %#v/%v", result, err)
	}
}

// TestVerifyPreflightsConstructorOwnedLengths verifies over-limit input is rejected before provider work.
func TestVerifyPreflightsConstructorOwnedLengths(t *testing.T) {
	calls := 0
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		calls++
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}), WithMaxRawMessageBytes(8), WithMaxRecipients(1))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	request := NewVerifyRequest(make([]byte, 9), nil, [][]byte{nil, nil})
	result, err := verifier.Verify(context.Background(), request)
	if err != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonLimitExceeded || result.CustodyStructure() != CustodyStructureNotEvaluated || calls != 0 {
		t.Fatalf("Verify() = %q/%q/%q calls=%d err=%v", result.State(), result.PrimaryReason(), result.CustodyStructure(), calls, err)
	}
}
