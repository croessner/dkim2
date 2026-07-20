package signing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	revisionTestDomain    = "example.test"
	revisionTestSelector  = "revision.test"
	revisionTestTimestamp = uint64(1_700_000_000)
)

type revisionTestFixture struct {
	message   rawmsg.Message
	envelope  verify.Envelope
	publicKey ed25519.PublicKey
}

type revisionProviderFunc func(context.Context, verify.KeyQuery) (verify.PublicKey, error)

// LookupKey delegates one test provider lookup.
func (f revisionProviderFunc) LookupKey(ctx context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
	return f(ctx, query)
}

// TestVerifyForRevisionOutcomeCapabilityErrorMatrix locks the dedicated closed API lanes.
func TestVerifyForRevisionOutcomeCapabilityErrorMatrix(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	valid := newRevisionTestVerifier(t, fixture, nil)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	missingProvider, err := verify.NewStaticKeyProvider(nil)
	if err != nil {
		t.Fatalf("verify.NewStaticKeyProvider(nil) error = %v", err)
	}
	missingVerifier, err := verify.NewVerifier(missingProvider, revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier(missing) error = %v", err)
	}
	missing := newRevisionVerifierForProof(t, missingVerifier)

	temporaryProvider := revisionProviderFunc(func(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
		return verify.PublicKey{}, verify.NewProviderFailure(verify.ProviderFailureTemporary)
	})
	temporaryVerifier, err := verify.NewVerifier(temporaryProvider, revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier(temporary) error = %v", err)
	}
	temporary := newRevisionVerifierForProof(t, temporaryVerifier)

	contractProvider := revisionProviderFunc(func(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
		return verify.PublicKey{Algorithm: verify.AlgorithmRSASHA256, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
	})
	contractVerifier, err := verify.NewVerifier(contractProvider, revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier(contract) error = %v", err)
	}
	contract := newRevisionVerifierForProof(t, contractVerifier)

	limitedOptions := verify.DefaultRevisionLimits()
	limitedOptions.MaxProtocolFields = 1
	limitedProof, err := verify.NewVerifier(
		mustRevisionStaticProvider(t, fixture),
		revisionTestClockOption(),
		verify.WithRevisionLimits(limitedOptions),
	)
	if err != nil {
		t.Fatalf("verify.NewVerifier(limited) error = %v", err)
	}
	limited := newRevisionVerifierForProof(t, limitedProof)

	unsupportedRaw := strings.Replace(
		string(fixture.message.RawBytes()),
		string(verify.AlgorithmEd25519SHA256),
		"future-sha256",
		1,
	)
	unsupported := mustParseRevisionMessage(t, []byte(unsupportedRaw))
	wrongRaw := strings.Replace(string(fixture.message.RawBytes()), "current body", "wrong current body", 1)
	wrongMessage := mustParseRevisionMessage(t, []byte(wrongRaw))
	terminalFixture := newRevisionTestFixture(t, nil, true)
	terminal := newRevisionTestVerifier(t, terminalFixture, nil)

	tests := []struct {
		name      string
		verifier  RevisionVerifier
		ctx       context.Context
		request   RevisionRequest
		status    RevisionVerificationStatus
		wantCap   bool
		wantGoErr bool
	}{
		{
			name: "verified", verifier: valid, ctx: context.Background(),
			request: RevisionRequest{Message: fixture.message, Envelope: fixture.envelope},
			status:  RevisionVerificationVerified, wantCap: true,
		},
		{
			name: "terminal next domain", verifier: terminal, ctx: context.Background(),
			request: RevisionRequest{Message: terminalFixture.message},
			status:  RevisionVerificationTerminalNextDomainAuthorizationRequired, wantCap: true,
		},
		{
			name: "protocol rejected", verifier: valid, ctx: context.Background(),
			request: RevisionRequest{
				Message:  fixture.message,
				Envelope: verify.NewEnvelope([]byte("<>"), [][]byte{[]byte("<wrong@example.test>")}),
			},
			status: RevisionVerificationProtocolRejected,
		},
		{
			name: "wrong raw content", verifier: valid, ctx: context.Background(),
			request: RevisionRequest{Message: wrongMessage, Envelope: fixture.envelope},
			status:  RevisionVerificationProtocolRejected,
		},
		{
			name: "unsupported", verifier: valid, ctx: context.Background(),
			request: RevisionRequest{Message: unsupported, Envelope: fixture.envelope},
			status:  RevisionVerificationUnsupported,
		},
		{
			name: "provider temporary", verifier: temporary, ctx: context.Background(),
			request: RevisionRequest{Message: fixture.message, Envelope: fixture.envelope},
			status:  RevisionVerificationProviderTemporary,
		},
		{
			name: "provider rejected", verifier: missing, ctx: context.Background(),
			request: RevisionRequest{Message: fixture.message, Envelope: fixture.envelope},
			status:  RevisionVerificationProviderRejected,
		},
		{
			name: "provider contract", verifier: contract, ctx: context.Background(),
			request: RevisionRequest{Message: fixture.message, Envelope: fixture.envelope},
			status:  RevisionVerificationProviderContract,
		},
		{
			name: "limit exceeded", verifier: limited, ctx: context.Background(),
			request: RevisionRequest{Message: fixture.message, Envelope: fixture.envelope},
			status:  RevisionVerificationLimitExceeded,
		},
		{
			name: "caller misuse", verifier: valid, ctx: context.Background(),
			request: RevisionRequest{}, wantGoErr: true,
		},
		{
			name: "context cancellation", verifier: valid, ctx: canceled,
			request: RevisionRequest{Message: fixture.message, Envelope: fixture.envelope}, wantGoErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, capability, verifyErr := test.verifier.VerifyForRevision(test.ctx, test.request)
			if test.wantGoErr {
				if verifyErr == nil || result.Valid() || capability.Valid() {
					t.Fatalf("error lane = valid:%t cap:%t err:%v", result.Valid(), capability.Valid(), verifyErr)
				}
				return
			}
			if verifyErr != nil || !result.Valid() || result.Status() != test.status || capability.Valid() != test.wantCap {
				t.Fatalf("result = %q valid:%t cap:%t err:%v", result.Status(), result.Valid(), capability.Valid(), verifyErr)
			}
		})
	}
}

// TestVerifiedRevisionInputSealsExactEvidenceAndPreservesRevisedContent locks capability fidelity.
func TestVerifiedRevisionInputSealsExactEvidenceAndPreservesRevisedContent(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	verifier := newRevisionTestVerifier(t, fixture, nil)
	result, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || result.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision() = %q/%t/%v", result.Status(), capability.Valid(), err)
	}

	revisedRaw := strings.Replace(string(fixture.message.RawBytes()), "Subject: current", "Subject: freely revised", 1)
	revisedRaw = strings.Replace(revisedRaw, "current body", "arbitrary later body", 1)
	revised := mustParseRevisionMessage(t, []byte(revisedRaw))
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), capability, revised); err != nil {
		t.Fatalf("ConsumeVerifiedRevisionInput(revised) error = %v", err)
	}

	zero := VerifiedRevisionInput{}
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), zero, revised); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("zero capability error = %v", err)
	}
	forged := cloneVerifiedRevisionInput(capability)
	forged.seal[0] ^= 1
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), forged, revised); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("forged capability error = %v", err)
	}
	rawTamper := cloneVerifiedRevisionInput(capability)
	rawTamper.raw[0] ^= 1
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), rawTamper, revised); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("sealed raw tamper error = %v", err)
	}
	reversePathTamper := cloneVerifiedRevisionInput(capability)
	reversePathTamper.reversePath = []byte("<changed@example.test>")
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), reversePathTamper, revised); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("sealed reverse-path tamper error = %v", err)
	}

	other := newRevisionTestVerifier(t, fixture, bytes.NewReader(bytes.Repeat([]byte{0x5a}, sha256.Size)))
	if err := other.ConsumeVerifiedRevisionInput(context.Background(), capability, revised); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("cross-verifier capability error = %v", err)
	}

	tamperedRaws := map[string][]byte{
		"case":      []byte(strings.Replace(revisedRaw, "Message-Instance:", "MESSAGE-INSTANCE:", 1)),
		"order":     reorderRevisionProtocolFields(t, []byte(revisedRaw)),
		"delete":    deleteRevisionProtocolField(t, []byte(revisedRaw)),
		"add":       addRevisionProtocolField(t, []byte(revisedRaw)),
		"refolding": []byte(strings.Replace(revisedRaw, "; m=1;", ";\r\n m=1;", 1)),
	}
	for name, raw := range tamperedRaws {
		t.Run("protocol "+name, func(t *testing.T) {
			tampered := mustParseRevisionMessage(t, raw)
			if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), capability, tampered); !IsErrorCode(err, ErrorCodeProtocolTampering) {
				t.Fatalf("protocol-field tamper error = %v", err)
			}
		})
	}

	twoRecipients := verify.NewEnvelope([]byte("<>"), [][]byte{
		[]byte("<rcpt@example.test>"), []byte("<other@example.test>"),
	})
	_, orderedCapability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: twoRecipients,
	})
	if err != nil || !orderedCapability.Valid() {
		t.Fatalf("two-recipient capability issuance = %t/%v", orderedCapability.Valid(), err)
	}
	recipientOrderTamper := cloneVerifiedRevisionInput(orderedCapability)
	recipientOrderTamper.forwardPaths[0], recipientOrderTamper.forwardPaths[1] =
		recipientOrderTamper.forwardPaths[1], recipientOrderTamper.forwardPaths[0]
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), recipientOrderTamper, revised); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("sealed recipient-order tamper error = %v", err)
	}
}

// TestVerifiedRevisionInputCrossesExplicitNullBodyHistory locks truthful b:null sealing and consumption.
func TestVerifiedRevisionInputCrossesExplicitNullBodyHistory(t *testing.T) {
	nullRecipe := `{"h":{"Subject":[{"d":["previous"]}]},"b":null}`
	fixture := newRevisionTestFixture(t, &nullRecipe, false)
	verifier := newRevisionTestVerifier(t, fixture, nil)
	result, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || result.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("b:null VerifyForRevision() = %q/%t/%v", result.Status(), capability.Valid(), err)
	}
	if !capability.proof.Facts().HistoryHasUnavailableBody() {
		t.Fatal("b:null capability lost explicit body-unavailable history fact")
	}
	revisedRaw := strings.Replace(string(fixture.message.RawBytes()), "current body", "new body after unavailable boundary", 1)
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), capability, mustParseRevisionMessage(t, []byte(revisedRaw))); err != nil {
		t.Fatalf("b:null ConsumeVerifiedRevisionInput() error = %v", err)
	}

	malformedRaw := replaceRevisionRecipe(t, fixture.message.RawBytes(), []byte(`{`))
	malformed := mustParseRevisionMessage(t, malformedRaw)
	rejected, zero, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{Message: malformed, Envelope: fixture.envelope})
	if err != nil || rejected.Status() != RevisionVerificationProtocolRejected || zero.Valid() {
		t.Fatalf("malformed history = %q/%t/%v", rejected.Status(), zero.Valid(), err)
	}

	undeclaredRaw := removeRevisionRecipe(t, fixture.message.RawBytes())
	undeclared := mustParseRevisionMessage(t, undeclaredRaw)
	rejected, zero, err = verifier.VerifyForRevision(context.Background(), RevisionRequest{Message: undeclared, Envelope: fixture.envelope})
	if err != nil || rejected.Status() != RevisionVerificationProtocolRejected || zero.Valid() {
		t.Fatalf("undeclared history = %q/%t/%v", rejected.Status(), zero.Valid(), err)
	}
}

// TestVerifiedRevisionInputRechecksFourteenDayExpiryAtConsumption locks capability lifetime.
func TestVerifiedRevisionInputRechecksFourteenDayExpiryAtConsumption(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	now := time.Unix(int64(revisionTestTimestamp), 0).Add(time.Hour)
	proof, err := verify.NewVerifier(
		mustRevisionStaticProvider(t, fixture),
		verify.WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	verifier := newRevisionVerifierForProof(t, proof)
	result, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || result.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("capability issuance = %q/%t/%v", result.Status(), capability.Valid(), err)
	}
	now = time.Unix(int64(revisionTestTimestamp), 0).Add(14*24*time.Hour + time.Second)
	if err := verifier.ConsumeVerifiedRevisionInput(context.Background(), capability, fixture.message); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("expired capability consumption error = %v", err)
	}
}

// TestPreparedSigningRevalidationSharesOneInstantAndDefersProviderCalls locks the signing two-phase seam.
func TestPreparedSigningRevalidationSharesOneInstantAndDefersProviderCalls(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	clockCalls, providerCalls := 0, 0
	provider := revisionProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		providerCalls++
		return verify.PublicKey{
			Algorithm: query.Algorithm,
			Material:  fixture.publicKey,
			Metadata:  verify.KeyMetadata{Status: verify.KeyStatusFound},
		}, nil
	})
	proof, err := verify.NewVerifier(
		provider,
		verify.WithClock(func() time.Time {
			clockCalls++
			return time.Unix(int64(revisionTestTimestamp), 0).Add(time.Hour)
		}),
	)
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	verifier := newRevisionVerifierForProof(t, proof)
	result, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || result.Status() != RevisionVerificationVerified || !capability.Valid() ||
		clockCalls != 1 || providerCalls != 1 {
		t.Fatalf("capability issuance = %q/%t/%v clock:%d provider:%d",
			result.Status(), capability.Valid(), err, clockCalls, providerCalls)
	}

	instant, err := verifier.CaptureOperationInstant()
	if err != nil || !instant.Valid() || clockCalls != 2 {
		t.Fatalf("CaptureOperationInstant() = valid:%t error:%v clock:%d", instant.Valid(), err, clockCalls)
	}
	copied := verifier
	prepared, err := copied.PrepareRevalidationForSigningAt(context.Background(), capability, instant)
	if err != nil || !prepared.Valid() || clockCalls != 2 || providerCalls != 1 {
		t.Fatalf("PrepareRevalidationForSigningAt() = valid:%t error:%v clock:%d provider:%d",
			prepared.Valid(), err, clockCalls, providerCalls)
	}
	if usage := prepared.Usage(); !usage.Valid() || usage.ProviderCalls() != 1 {
		t.Fatalf("prepared usage = %#v", usage)
	}
	if err := verifier.ExecuteRevalidationForSigning(context.Background(), prepared); err != nil ||
		clockCalls != 2 || providerCalls != 2 {
		t.Fatalf("ExecuteRevalidationForSigning() error:%v clock:%d provider:%d", err, clockCalls, providerCalls)
	}
	if err := verifier.ExecuteRevalidationForSigning(context.Background(), prepared); !verify.IsErrorCode(err, verify.ErrorCodeInternalMisuse) ||
		clockCalls != 2 || providerCalls != 2 {
		t.Fatalf("second ExecuteRevalidationForSigning() error:%v clock:%d provider:%d", err, clockCalls, providerCalls)
	}

	zeroPrepared, err := verifier.PrepareRevalidationForSigningAt(context.Background(), capability, verify.RevisionInstant{})
	if !IsErrorCode(err, ErrorCodeInvalidRequest) || zeroPrepared.Valid() || clockCalls != 2 || providerCalls != 2 {
		t.Fatalf("zero instant prepare = valid:%t error:%v clock:%d provider:%d",
			zeroPrepared.Valid(), err, clockCalls, providerCalls)
	}
}

// TestRevisionCapabilityTranscriptIsUnambiguousImmutableConcurrentAndRedacted locks capability hardening.
func TestRevisionCapabilityTranscriptIsUnambiguousImmutableConcurrentAndRedacted(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	secretKey := bytes.Repeat([]byte("S"), sha256.Size)
	verifier := newRevisionTestVerifier(t, fixture, bytes.NewReader(secretKey))
	result, capability, err := verifier.VerifyForRevision(context.Background(), RevisionRequest{
		Message: fixture.message, Envelope: fixture.envelope,
	})
	if err != nil || result.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatalf("VerifyForRevision() = %q/%t/%v", result.Status(), capability.Valid(), err)
	}

	left := cloneVerifiedRevisionInput(capability)
	left.forwardPaths = [][]byte{[]byte("a"), []byte("bc")}
	right := cloneVerifiedRevisionInput(capability)
	right.forwardPaths = [][]byte{[]byte("ab"), []byte("c")}
	if leftSeal, rightSeal := verifier.seal(left), verifier.seal(right); leftSeal == rightSeal {
		t.Fatal("length/count transcript accepted ambiguous concatenation")
	}

	rawBefore := capability.raw[0]
	fieldsBefore := capability.protocolFields[0][0]
	inputRaw := fixture.message.RawBytes()
	inputEnvelope := fixture.envelope.ForwardPaths()
	inputRaw[0] ^= 1
	inputEnvelope[0][0] ^= 1
	if capability.raw[0] != rawBefore || capability.protocolFields[0][0] != fieldsBefore {
		t.Fatal("capability aliases caller-owned message or envelope bytes")
	}

	rendered := fmt.Sprintf("%v %#v %+v %s %q", verifier, verifier, verifier, verifier, verifier)
	if strings.Contains(rendered, strings.Repeat("83 ", 4)) || strings.Contains(rendered, "sealKey") ||
		rendered != strings.TrimSpace(strings.Repeat("signing.RevisionVerifier{redacted} ", 5)) {
		t.Fatalf("RevisionVerifier formatting leaked state: %q", rendered)
	}
	request := RevisionRequest{Message: fixture.message, Envelope: fixture.envelope}
	for _, value := range []any{capability, result, request} {
		text := fmt.Sprintf("%v %#v %+v %s %q", value, value, value, value, value)
		if strings.Contains(text, "current body") || strings.Contains(text, "example.test") || strings.Contains(text, "seal") {
			t.Fatalf("revision value formatting leaked protected state: %q", text)
		}
	}

	const workers = 24
	var wait sync.WaitGroup
	failures := make(chan string, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			got, issued, verifyErr := verifier.VerifyForRevision(context.Background(), RevisionRequest{
				Message: fixture.message, Envelope: fixture.envelope,
			})
			if verifyErr != nil || got.Status() != RevisionVerificationVerified || !issued.Valid() ||
				verifier.ConsumeVerifiedRevisionInput(context.Background(), issued, fixture.message) != nil {
				failures <- "revision"
			}
		}()
	}
	wait.Wait()
	close(failures)
	for failure := range failures {
		t.Fatalf("concurrent revision verification failed: %s", failure)
	}
}

// TestRevisionProofOutcomeMappingIsClosedAndExhaustive locks every provider/protocol result mapping.
func TestRevisionProofOutcomeMappingIsClosedAndExhaustive(t *testing.T) {
	tests := map[verify.RevisionProofOutcome]RevisionVerificationStatus{
		verify.RevisionProofVerified:                                RevisionVerificationVerified,
		verify.RevisionProofTerminalNextDomainAuthorizationRequired: RevisionVerificationTerminalNextDomainAuthorizationRequired,
		verify.RevisionProofProtocolRejected:                        RevisionVerificationProtocolRejected,
		verify.RevisionProofUnsupported:                             RevisionVerificationUnsupported,
		verify.RevisionProofProviderTemporary:                       RevisionVerificationProviderTemporary,
		verify.RevisionProofProviderRejected:                        RevisionVerificationProviderRejected,
		verify.RevisionProofProviderContract:                        RevisionVerificationProviderContract,
		verify.RevisionProofLimitExceeded:                           RevisionVerificationLimitExceeded,
	}
	for input, want := range tests {
		if got, ok := mapRevisionProofOutcome(input); !ok || got != want {
			t.Fatalf("mapRevisionProofOutcome(%q) = %q/%t", input, got, ok)
		}
	}
	if got, ok := mapRevisionProofOutcome("future"); ok || got != "" || newRevisionVerification("future").Valid() {
		t.Fatalf("unknown outcome mapped = %q/%t", got, ok)
	}
}

// TestRevisionPreflightRejectsInherentlyUnextendableEvidenceBeforeKeyLookup proves capacity ordering.
func TestRevisionPreflightRejectsInherentlyUnextendableEvidenceBeforeKeyLookup(t *testing.T) {
	fixture := newRevisionTestFixture(t, nil, false)
	headerFields := fixture.message.Metadata().HeaderFields
	for _, test := range []struct {
		name       string
		limits     Limits
		wantStatus RevisionVerificationStatus
		wantCalls  int64
	}{
		{
			name: "header count exact remains revisable", limits: Limits{MaxHeaderFields: headerFields},
			wantStatus: RevisionVerificationVerified, wantCalls: 1,
		},
		{
			name: "header count one over", limits: Limits{MaxHeaderFields: headerFields - 1},
			wantStatus: RevisionVerificationLimitExceeded,
		},
		{
			name: "signature has no append capacity", limits: Limits{MaxSignatures: 1},
			wantStatus: RevisionVerificationLimitExceeded,
		},
		{
			name: "protocol fields have no append capacity", limits: Limits{MaxProtocolFields: 2},
			wantStatus: RevisionVerificationLimitExceeded,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &countingPlanKeyProvider{delegate: mustRevisionStaticProvider(t, fixture)}
			proof, err := verify.NewVerifier(provider, revisionTestClockOption())
			if err != nil {
				t.Fatalf("verify.NewVerifier() error = %v", err)
			}
			revision, err := newRevisionVerifier(
				proof, test.limits, bytes.NewReader(bytes.Repeat([]byte{0x72}, sha256.Size)),
			)
			if err != nil {
				t.Fatalf("newRevisionVerifier() error = %v", err)
			}
			outcome, capability, err := revision.VerifyForRevision(context.Background(), RevisionRequest{
				Message: fixture.message, Envelope: fixture.envelope,
			})
			if err != nil || outcome.Status() != test.wantStatus ||
				capability.Valid() != (test.wantStatus == RevisionVerificationVerified) ||
				provider.calls.Load() != test.wantCalls {
				t.Fatalf("status=%q capability=%t calls=%d error=%v",
					outcome.Status(), capability.Valid(), provider.calls.Load(), err)
			}
		})
	}
}

// newRevisionTestFixture creates one cryptographically valid ordinary or terminal revision fixture.
func newRevisionTestFixture(t *testing.T, recipeJSON *string, terminal bool) revisionTestFixture {
	return newRevisionTestFixtureWithFlags(t, recipeJSON, terminal, nil)
}

// newRevisionTestFixtureWithFlags creates one valid fixture with controlled authenticated flags.
func newRevisionTestFixtureWithFlags(t *testing.T, recipeJSON *string, terminal bool, flags []string) revisionTestFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("dkim2 revision verifier test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	currentContent := []byte("From: sender@example.test\r\nSubject: current\r\n\r\ncurrent body\r\n")
	currentHeader, currentBody := revisionTestDigests(t, currentContent)
	instanceFields := []string{"Message-Instance: m=1; h=sha256:" + currentHeader + ":" + currentBody + ";\r\n"}
	signatureFields := []string{}
	envelope := verify.NewEnvelope([]byte("<>"), [][]byte{[]byte("<rcpt@example.test>")})

	if recipeJSON != nil {
		previousContent := []byte("From: sender@example.test\r\nSubject: previous\r\n\r\nolder body\r\n")
		previousHeader, previousBody := revisionTestDigests(t, previousContent)
		instanceFields[0] = "Message-Instance: m=1; h=sha256:" + previousHeader + ":" + previousBody + ";\r\n"
		instanceFields = append(instanceFields,
			"Message-Instance: m=2; h=sha256:"+currentHeader+":"+currentBody+"; r="+base64.StdEncoding.EncodeToString([]byte(*recipeJSON))+";\r\n",
		)
	}

	placeholder := revisionTestSelector + ":" + string(verify.AlgorithmEd25519SHA256) + ":" +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, ed25519.SignatureSize))
	if terminal {
		signatureFields = append(signatureFields, revisionTestSignatureFieldWithFlags(1, 1, "nd=next.example.test", placeholder, flags))
		envelope = verify.Envelope{}
	} else if recipeJSON == nil {
		signatureFields = append(signatureFields, revisionTestSignatureFieldWithFlags(1, 1,
			"mf="+base64.StdEncoding.EncodeToString([]byte("<>"))+"; rt="+revisionTestRecipientTags(),
			placeholder, flags,
		))
	} else {
		firstUnsigned := revisionTestMessage(t, currentContent, instanceFields[:1], []string{
			revisionTestSignatureFieldWithFlags(1, 1,
				"mf="+base64.StdEncoding.EncodeToString([]byte("<>"))+"; rt="+base64.StdEncoding.EncodeToString([]byte("<sender@example.test>")),
				placeholder, flags,
			),
		})
		firstSet := revisionTestSignedSet(t, privateKey, firstUnsigned, 1)
		signatureFields = append(signatureFields,
			revisionTestSignatureFieldWithFlags(1, 1,
				"mf="+base64.StdEncoding.EncodeToString([]byte("<>"))+"; rt="+base64.StdEncoding.EncodeToString([]byte("<sender@example.test>")),
				firstSet, flags,
			),
			revisionTestSignatureFieldWithFlags(2, 2,
				"mf="+base64.StdEncoding.EncodeToString([]byte("<sender@example.test>"))+"; rt="+revisionTestRecipientTags(),
				placeholder, flags,
			),
		)
		envelope = verify.NewEnvelope([]byte("<sender@example.test>"), [][]byte{[]byte("<rcpt@example.test>")})
	}

	unsigned := revisionTestMessage(t, currentContent, instanceFields, signatureFields)
	target := uint64(len(signatureFields))
	signedSet := revisionTestSignedSet(t, privateKey, unsigned, target)
	signatureFields[len(signatureFields)-1] = strings.Replace(signatureFields[len(signatureFields)-1], placeholder, signedSet, 1)
	return revisionTestFixture{
		message:  revisionTestMessage(t, currentContent, instanceFields, signatureFields),
		envelope: envelope, publicKey: publicKey,
	}
}

// revisionTestRecipientTags renders the signed current-recipient superset.
func revisionTestRecipientTags() string {
	return base64.StdEncoding.EncodeToString([]byte("<rcpt@example.test>")) + "," +
		base64.StdEncoding.EncodeToString([]byte("<other@example.test>"))
}

// revisionTestMessage inserts exact protocol fields before one controlled body.
func revisionTestMessage(t *testing.T, content []byte, instances, signatures []string) rawmsg.Message {
	t.Helper()
	separator := bytes.Index(content, []byte("\r\n\r\n"))
	if separator < 0 {
		t.Fatal("revision test content lacks separator")
	}
	var raw strings.Builder
	raw.Write(content[:separator+2])
	for _, field := range instances {
		raw.WriteString(field)
	}
	for _, field := range signatures {
		raw.WriteString("DKIM2-Signature: ")
		raw.WriteString(field)
		raw.WriteString("\r\n")
	}
	raw.Write(content[separator+2:])
	return mustParseRevisionMessage(t, []byte(raw.String()))
}

// revisionTestSignatureFieldWithFlags renders one controlled field with fixed known flags.
func revisionTestSignatureFieldWithFlags(sequence, messageInstance uint64, envelopeTags, signatureSet string, flags []string) string {
	flagTag := ""
	if len(flags) > 0 {
		flagTag = "; f=" + strings.Join(flags, ",")
	}
	return "i=" + strconv.FormatUint(sequence, 10) + "; m=" + strconv.FormatUint(messageInstance, 10) +
		"; t=" + strconv.FormatUint(revisionTestTimestamp, 10) + "; " + envelopeTags +
		flagTag + "; d=" + revisionTestDomain + "; s=" + signatureSet + ";"
}

// revisionTestSignedSet signs one target's Section 9.6 digest.
func revisionTestSignedSet(t *testing.T, privateKey ed25519.PrivateKey, message rawmsg.Message, sequence uint64) string {
	t.Helper()
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("canonical.NewCanonicalizer() error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers: message.Headers(), TargetSequence: sequence,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	return revisionTestSelector + ":" + string(verify.AlgorithmEd25519SHA256) + ":" +
		base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))
}

// revisionTestDigests computes current draft-04 Section 6 digest strings.
func revisionTestDigests(t *testing.T, raw []byte) (string, string) {
	t.Helper()
	message := mustParseRevisionMessage(t, raw)
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("canonical.NewCanonicalizer() error = %v", err)
	}
	header, err := canonicalizer.HeaderHashFromMessage(message)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	body, err := canonicalizer.BodyHashFromMessage(message)
	if err != nil {
		t.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	headerDigest, headerOK := header.Digest()
	bodyDigest, bodyOK := body.Digest()
	if !headerOK || !bodyOK {
		t.Fatal("revision test digest missing")
	}
	return headerDigest.Base64(), bodyDigest.Base64()
}

// mustParseRevisionMessage parses one controlled RFC 5322 test message.
func mustParseRevisionMessage(t *testing.T, raw []byte) rawmsg.Message {
	t.Helper()
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	return message
}

// mustRevisionStaticProvider creates the fixture's deterministic static provider.
func mustRevisionStaticProvider(t *testing.T, fixture revisionTestFixture) verify.StaticKeyProvider {
	t.Helper()
	provider, err := verify.NewStaticKeyProvider([]verify.StaticKey{{
		Domain: revisionTestDomain, Selector: revisionTestSelector,
		Algorithm: verify.AlgorithmEd25519SHA256, Material: fixture.publicKey,
	}})
	if err != nil {
		t.Fatalf("verify.NewStaticKeyProvider() error = %v", err)
	}
	return provider
}

// newRevisionTestVerifier constructs a deterministic sealed revision verifier.
func newRevisionTestVerifier(t *testing.T, fixture revisionTestFixture, entropy *bytes.Reader) RevisionVerifier {
	t.Helper()
	proof, err := verify.NewVerifier(mustRevisionStaticProvider(t, fixture), revisionTestClockOption())
	if err != nil {
		t.Fatalf("verify.NewVerifier() error = %v", err)
	}
	if entropy == nil {
		entropy = bytes.NewReader(bytes.Repeat([]byte{0x41}, sha256.Size))
	}
	verifier, err := newRevisionVerifier(proof, Limits{}, entropy)
	if err != nil {
		t.Fatalf("newRevisionVerifier() error = %v", err)
	}
	return verifier
}

// newRevisionVerifierForProof wraps one controlled proof verifier.
func newRevisionVerifierForProof(t *testing.T, proof verify.Verifier) RevisionVerifier {
	t.Helper()
	verifier, err := newRevisionVerifier(proof, Limits{}, bytes.NewReader(bytes.Repeat([]byte{0x42}, sha256.Size)))
	if err != nil {
		t.Fatalf("newRevisionVerifier() error = %v", err)
	}
	return verifier
}

// revisionTestClockOption keeps the fixed timestamp inside the exact policy window.
func revisionTestClockOption() verify.Option {
	return verify.WithClock(func() time.Time {
		return time.Unix(int64(revisionTestTimestamp), 0).Add(time.Hour)
	})
}

// cloneVerifiedRevisionInput deep-clones mutable capability storage for tamper tests.
func cloneVerifiedRevisionInput(input VerifiedRevisionInput) VerifiedRevisionInput {
	clone := input
	clone.raw = bytes.Clone(input.raw)
	clone.reversePath = bytes.Clone(input.reversePath)
	clone.forwardPaths = cloneRevisionByteSlices(input.forwardPaths)
	clone.protocolFields = cloneRevisionByteSlices(input.protocolFields)
	return clone
}

// cloneRevisionByteSlices deep-clones one byte-slice collection.
func cloneRevisionByteSlices(input [][]byte) [][]byte {
	output := make([][]byte, len(input))
	for index := range input {
		output[index] = bytes.Clone(input[index])
	}
	return output
}

// replaceRevisionRecipe replaces the highest decoded recipe without preserving its signature.
func replaceRevisionRecipe(t *testing.T, raw, decoded []byte) []byte {
	t.Helper()
	text := string(raw)
	start := strings.LastIndex(text, "; r=")
	if start < 0 {
		t.Fatal("revision fixture lacks r=")
	}
	start += len("; r=")
	end := strings.IndexByte(text[start:], ';')
	if end < 0 {
		t.Fatal("revision fixture lacks r= terminator")
	}
	return []byte(text[:start] + base64.StdEncoding.EncodeToString(decoded) + text[start+end:])
}

// removeRevisionRecipe removes the highest declared recipe for a negative history fixture.
func removeRevisionRecipe(t *testing.T, raw []byte) []byte {
	t.Helper()
	text := string(raw)
	start := strings.LastIndex(text, "; r=")
	if start < 0 {
		t.Fatal("revision fixture lacks r=")
	}
	end := strings.IndexByte(text[start+1:], ';')
	if end < 0 {
		t.Fatal("revision fixture lacks r= terminator")
	}
	return []byte(text[:start] + text[start+1+end:])
}

// reorderRevisionProtocolFields swaps the first two inherited protocol fields.
func reorderRevisionProtocolFields(t *testing.T, raw []byte) []byte {
	t.Helper()
	lines := strings.SplitAfter(string(raw), "\r\n")
	first, second := -1, -1
	for index, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "message-instance:") || strings.HasPrefix(strings.ToLower(line), "dkim2-signature:") {
			if first < 0 {
				first = index
			} else {
				second = index
				break
			}
		}
	}
	if first < 0 || second < 0 {
		t.Fatal("revision fixture lacks two protocol fields")
	}
	lines[first], lines[second] = lines[second], lines[first]
	return []byte(strings.Join(lines, ""))
}

// deleteRevisionProtocolField removes the first inherited protocol occurrence.
func deleteRevisionProtocolField(t *testing.T, raw []byte) []byte {
	t.Helper()
	lines := strings.SplitAfter(string(raw), "\r\n")
	for index, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "message-instance:") {
			return []byte(strings.Join(append(lines[:index], lines[index+1:]...), ""))
		}
	}
	t.Fatal("revision fixture lacks Message-Instance field")
	return nil
}

// addRevisionProtocolField adds one inherited-looking occurrence before the separator.
func addRevisionProtocolField(t *testing.T, raw []byte) []byte {
	t.Helper()
	text := string(raw)
	separator := strings.Index(text, "\r\n\r\n")
	if separator < 0 {
		t.Fatal("revision fixture lacks header separator")
	}
	field := "\r\nMessage-Instance: m=99; h=sha256:" +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, sha256.Size)) + ":" +
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, sha256.Size)) + ";"
	return []byte(text[:separator] + field + text[separator:])
}
