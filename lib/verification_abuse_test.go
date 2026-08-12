package dkim2

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

const publicSignatureSetsTestName = "signature sets"

type abuseCountingProvider struct{ calls int }

// LookupPublicKey counts bounded test lookups and returns a missing result.
func (p *abuseCountingProvider) LookupPublicKey(_ context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	p.calls++
	return MissingPublicKey(query.Algorithm()), nil
}

// TestPublicExtractionHardLimits proves 16/17 hash and signature-set boundaries before provider work.
func TestPublicExtractionHardLimits(t *testing.T) {
	base := publicProviderFixture(t)
	for _, testCase := range []struct {
		name       string
		marker     []byte
		exactCalls int
		exactFacts int
	}{
		{name: "instance hash sets", marker: []byte("h="), exactCalls: 1, exactFacts: 1},
		{name: publicSignatureSetsTestName, marker: []byte("s="), exactCalls: 0, exactFacts: HardMaxSignatureFacts},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			provider := &abuseCountingProvider{}
			verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
			if err != nil {
				t.Fatal("extraction-limit verifier construction failed")
			}
			exactRaw := repeatPublicProtocolSet(t, base, testCase.marker, HardMaxSignatureSets)
			exact, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(exactRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if verifyErr != nil || exact.PrimaryReason() == ReasonLimitExceeded || provider.calls != testCase.exactCalls || exact.SignatureSetCount() != testCase.exactFacts {
				t.Fatalf("exact extraction mismatch: state=%q reason=%q calls=%d facts=%d", exact.State(), exact.PrimaryReason(), provider.calls, exact.SignatureSetCount())
			}
			provider.calls = 0
			overRaw := repeatPublicProtocolSet(t, base, testCase.marker, HardMaxSignatureSets+1)
			over, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(overRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
			if verifyErr != nil || over.State() != ResultStatePERMERROR || over.PrimaryReason() != ReasonLimitExceeded || over.CustodyStructure() != CustodyStructureNotEvaluated || provider.calls != 0 {
				t.Fatal("one-over extraction hard limit reached provider or escaped bounded result")
			}
		})
	}
}

// repeatPublicProtocolSet repeats one comma-list item without changing surrounding raw bytes.
func repeatPublicProtocolSet(t *testing.T, raw, marker []byte, count int) []byte {
	t.Helper()
	start := bytes.Index(raw, marker)
	if start < 0 {
		t.Fatal("protocol set marker absent")
	}
	start += len(marker)
	endOffset := bytes.IndexByte(raw[start:], ';')
	if endOffset < 0 {
		t.Fatal("protocol set terminator absent")
	}
	end := start + endOffset
	items := make([]string, count)
	for index := range items {
		items[index] = string(raw[start:end])
		if bytes.Equal(marker, []byte("h=")) && index > 0 {
			items[index] = strings.Replace(items[index], "sha256", fmt.Sprintf("future-sha%03d", index), 1)
		}
		if bytes.Equal(marker, []byte("s=")) {
			items[index] = fmt.Sprintf("selector%02d.test:future-sha%03d:AA==", index, index)
		}
	}
	separator := ",\r\n "
	if bytes.Equal(marker, []byte("s=")) {
		separator = ","
	}
	result := bytes.Clone(raw[:start])
	result = append(result, strings.Join(items, separator)...)
	return append(result, raw[end:]...)
}

// TestPublicHardLimitBoundaries proves exact defaults enter verification and one-over fails before lookup.
func TestPublicHardLimitBoundaries(t *testing.T) {
	base := publicProviderFixture(t)
	exactRaw := rawAtHardLimit(base)
	exactRecipients := make([][]byte, HardMaxRecipients)
	for index := range exactRecipients {
		exactRecipients[index] = []byte("<rcpt@example.test>")
	}

	provider := &abuseCountingProvider{}
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("hard-limit verifier construction failed")
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(exactRaw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || publicResultHasCheck(result, CheckClassMessage, ReasonLimitExceeded) || provider.calls != 1 {
		t.Fatal("exact raw hard limit did not pass public preflight")
	}
	provider.calls = 0
	result, err = verifier.Verify(context.Background(), NewVerifyRequest(append(exactRaw, 'x'), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || result.PrimaryReason() != ReasonLimitExceeded || !publicResultHasCheck(result, CheckClassMessage, ReasonLimitExceeded) || provider.calls != 0 {
		t.Fatal("one-over raw hard limit reached provider")
	}
	provider.calls = 0
	result, err = verifier.Verify(context.Background(), NewVerifyRequest(base, []byte("<>"), exactRecipients))
	if err != nil || result.PrimaryReason() == ReasonLimitExceeded || provider.calls != 1 {
		t.Fatal("exact recipient hard limit did not reach provider")
	}
	provider.calls = 0
	result, err = verifier.Verify(context.Background(), NewVerifyRequest(base, []byte("<>"), append(exactRecipients, []byte("<extra@example.test>"))))
	if err != nil || result.PrimaryReason() != ReasonLimitExceeded || provider.calls != 0 {
		t.Fatal("one-over recipient hard limit reached provider")
	}
}

// rawAtHardLimit pads a message with parser-valid bounded CRLF body lines.
func rawAtHardLimit(base []byte) []byte {
	result := make([]byte, 0, HardMaxRawMessageBytes)
	result = append(result, base...)
	for len(result) < HardMaxRawMessageBytes {
		remaining := HardMaxRawMessageBytes - len(result)
		if remaining > 1000 {
			result = append(result, make([]byte, 998)...)
			for index := len(result) - 998; index < len(result); index++ {
				result[index] = 'x'
			}
			result = append(result, '\r', '\n')
			continue
		}
		lineBytes := remaining - 2
		start := len(result)
		result = append(result, make([]byte, lineBytes)...)
		for index := start; index < len(result); index++ {
			result[index] = 'x'
		}
		result = append(result, '\r', '\n')
	}
	return result
}

// publicResultHasCheck reports an exact bounded check fact.
func publicResultHasCheck(result VerifyResult, class CheckClass, reason ReasonCode) bool {
	for _, fact := range result.Checks() {
		if fact.Class() == class && fact.Reason() == reason {
			return true
		}
	}
	return false
}

// TestPublicPermanentProviderFailureIsStructured proves the real facade preserves permanent provider state.
func TestPublicPermanentProviderFailureIsStructured(t *testing.T) {
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, NewPermanentProviderError()
	}), WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("provider verifier construction failed")
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonProviderPermanent || result.Draft() == "" {
		t.Fatal("permanent provider failure violated structured result contract")
	}
}

// TestPublicUnclassifiedProviderFailureIsStructured proves raw provider errors fail closed without escaping.
func TestPublicUnclassifiedProviderFailureIsStructured(t *testing.T) {
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return PublicKeyResult{}, errors.New("opaque provider failure")
	}), WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("unclassified provider verifier construction failed")
	}
	result, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if verifyErr != nil || result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonProviderContract {
		t.Fatal("unclassified provider failure escaped bounded contract result")
	}
}

// TestPublicCallerContextErrorsRemainDisjoint proves cancel and deadline are zero-result Go control flow.
func TestPublicCallerContextErrorsRemainDisjoint(t *testing.T) {
	verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		return MissingPublicKey(AlgorithmRSASHA256), nil
	}))
	if err != nil {
		t.Fatal("context verifier construction failed")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, deadlineCancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer deadlineCancel()
	for _, testCase := range []struct {
		ctx context.Context
		err error
	}{{canceled, context.Canceled}, {deadline, context.DeadlineExceeded}} {
		result, verifyErr := verifier.Verify(testCase.ctx, VerifyRequest{})
		if !errors.Is(verifyErr, testCase.err) || result.Draft() != "" || result.State() != "" {
			t.Fatal("caller context returned a populated result")
		}
	}
}

// TestPublicProviderTriggeredCallerCancellationRemainsGoControlFlow proves in-flight context identity end to end.
func TestPublicProviderTriggeredCallerCancellationRemainsGoControlFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
		cancel()
		return PublicKeyResult{}, context.Canceled
	})
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("in-flight cancellation verifier construction failed")
	}
	result, verifyErr := verifier.Verify(ctx, NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if !errors.Is(verifyErr, context.Canceled) || result.Draft() != "" || result.State() != "" {
		t.Fatal("in-flight caller cancellation returned populated protocol state")
	}
}

// TestPublicProviderModelCannotRepresentPrivateOrSignerMaterial proves the closed compile-time key boundary.
func TestPublicProviderModelCannotRepresentPrivateOrSignerMaterial(t *testing.T) {
	resultType := reflect.TypeFor[PublicKeyResult]()
	signerType := reflect.TypeFor[crypto.Signer]()
	privateType := reflect.TypeFor[rsa.PrivateKey]()
	privatePointerType := reflect.PointerTo(privateType)
	for field := range resultType.Fields() {
		fieldType := field.Type
		if fieldType.Kind() == reflect.Interface || fieldType == privateType || fieldType == privatePointerType || fieldType.Implements(signerType) || reflect.PointerTo(fieldType).Implements(signerType) {
			t.Fatal("public provider result exposes open, private, or signer material")
		}
	}
}

// TestPublicProviderClassificationIgnoresErrorText proves typed class alone controls mapping.
func TestPublicProviderClassificationIgnoresErrorText(t *testing.T) {
	errorsByText := []error{NewTemporaryProviderError(), toxicTemporaryProviderError{}}
	var baseline publicFuzzSnapshot
	for index, providerErr := range errorsByText {
		verifier, err := NewVerifier(publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
			return PublicKeyResult{}, providerErr
		}), WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
		if err != nil {
			t.Fatal("text-independent provider verifier construction failed")
		}
		result, verifyErr := verifier.Verify(context.Background(), NewVerifyRequest(publicProviderFixture(t), []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
		if verifyErr != nil || result.State() != ResultStateTEMPERROR || result.PrimaryReason() != ReasonProviderTemporary {
			t.Fatal("typed provider class depended on error text")
		}
		snapshot := snapshotPublicFuzzResult(result)
		if index == 0 {
			baseline = snapshot
		} else if !reflect.DeepEqual(baseline, snapshot) {
			t.Fatal("equivalent provider classes produced different public results")
		}
	}
}
