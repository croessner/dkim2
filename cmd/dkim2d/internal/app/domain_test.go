package app

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

type noLookupProvider struct{}

// LookupPublicKey fails the test when malformed-message processing reaches DNS.
func (noLookupProvider) LookupPublicKey(context.Context, dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	return dkim2.PublicKeyResult{}, errors.New("unexpected lookup")
}

type countingNoLookupProvider struct{ calls int }

// LookupPublicKey records an unexpected unsigned-message DNS lookup.
func (p *countingNoLookupProvider) LookupPublicKey(context.Context, dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	p.calls++
	return dkim2.PublicKeyResult{}, errors.New("unexpected lookup")
}

type rejectingReplayService struct{ calls int }

// Coordinate records forbidden replay work for a non-applicable message.
func (s *rejectingReplayService) Coordinate(context.Context, DomainResult) (ReplayOutcome, error) {
	s.calls++
	return ReplayOutcome{}, errors.New("unexpected replay coordination")
}

// TestUnsignedInboundSkipsPolicyReplayAndDNSInEveryMode proves the daemon applicability contract.
func TestUnsignedInboundSkipsPolicyReplayAndDNSInEveryMode(t *testing.T) {
	for _, mode := range []config.PolicyMode{config.PolicyStrict, config.PolicyPermissive, config.PolicyTesting} {
		t.Run(string(mode), func(t *testing.T) {
			snapshot, err := config.Load([]byte(`config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /secure/0123456789abcdef0123456789abcdef/capability
replay:
  backend: disabled
observability:
  logging:
    level: debug
  debug:
    replay: true
`), config.FlagValues{})
			if err != nil {
				t.Fatalf("config.Load() error = %v", err)
			}
			var logs bytes.Buffer
			runtime, err := observability.NewRuntime(
				context.Background(),
				snapshot.Observability(),
				&logs,
				config.TracingStartupMaterial{},
			)
			if err != nil {
				t.Fatalf("observability.NewRuntime() error = %v", err)
			}
			t.Cleanup(func() { _ = runtime.Shutdown(context.Background()) })
			provider := &countingNoLookupProvider{}
			verifier, err := dkim2.NewVerifier(provider)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			domain, err := NewDomainProcessor(verifier, mode)
			if err != nil {
				t.Fatalf("NewDomainProcessor() error = %v", err)
			}
			replay := &rejectingReplayService{}
			processor, err := NewInboundProcessor(domain, replay)
			if err != nil {
				t.Fatalf("NewInboundProcessor() error = %v", err)
			}
			processor.attachObservability(runtime)
			result, err := processor.Process(context.Background(), dkim2.NewVerifyRequest(
				[]byte("From: sender@example.test\r\nSubject: unsigned\r\n\r\nbody\r\n"),
				[]byte("<sender@example.test>"),
				[][]byte{[]byte("<recipient@example.test>")},
			))
			if err != nil || !result.Valid() || result.Applicable() || provider.calls != 0 || replay.calls != 0 {
				t.Fatalf("Process() = valid=%t applicable=%t DNS=%d replay=%d err=%v", result.Valid(), result.Applicable(), provider.calls, replay.calls, err)
			}
			domainResult, err := result.Domain()
			if err != nil {
				t.Fatal("valid non-applicable result lost its domain owner")
			}
			verification, verificationErr := domainResult.Verification()
			policy, policyErr := domainResult.Policy()
			if verification.Valid() || policy.Valid() || !IsDomainError(verificationErr) || !IsDomainError(policyErr) {
				t.Fatal("non-applicable domain result exposed absent verification or policy values")
			}
			replayResult, err := result.Replay()
			if err != nil || replayResult.Class() != ReplayResultNotChecked || replayResult.Disposition() != FinalDispositionContinue {
				t.Fatalf("Replay() = %q/%q err=%v", replayResult.Class(), replayResult.Disposition(), err)
			}
			metrics, err := runtime.Metrics().Gather()
			if err != nil {
				t.Fatalf("Metrics().Gather() error = %v", err)
			}
			if !bytes.Contains(metrics, []byte(`dkim2d_process_total{disposition="continue",replay_state="not_checked",result="success",verdict="neutral"} 1`)) {
				t.Fatal("unsigned inbound processing omitted the process outcome metric")
			}
			if bytes.Contains(metrics, []byte("dkim2d_replay_coordinates_total")) ||
				bytes.Contains(logs.Bytes(), []byte(`"event_id":"replay.coordinate.completed"`)) {
				t.Fatal("unsigned inbound processing emitted replay telemetry")
			}
		})
	}
}

// TestPartialInboundProtocolRemainsApplicableInEveryMode proves absence handling is not fail-open.
func TestPartialInboundProtocolRemainsApplicableInEveryMode(t *testing.T) {
	tests := []struct {
		mode    config.PolicyMode
		verdict dkim2.PolicyVerdict
	}{
		{config.PolicyStrict, dkim2.PolicyVerdictReject},
		{config.PolicyPermissive, dkim2.PolicyVerdictAccept},
		{config.PolicyTesting, dkim2.PolicyVerdictContinue},
	}
	for _, testCase := range tests {
		t.Run(string(testCase.mode), func(t *testing.T) {
			provider := &countingNoLookupProvider{}
			verifier, err := dkim2.NewVerifier(provider)
			if err != nil {
				t.Fatalf("NewVerifier() error = %v", err)
			}
			processor, err := NewDomainProcessor(verifier, testCase.mode)
			if err != nil {
				t.Fatalf("NewDomainProcessor() error = %v", err)
			}
			result, err := processor.Process(context.Background(), dkim2.NewVerifyRequest(
				[]byte("From: sender@example.test\r\nMessage-Instance: m=1; h=sha256:AA==:AA==;\r\n\r\nbody\r\n"),
				nil,
				nil,
			))
			verification, verificationErr := result.Verification()
			policy, policyErr := result.Policy()
			if err != nil || !result.Applicable() || verificationErr != nil || policyErr != nil ||
				verification.State() != dkim2.ResultStatePERMERROR || policy.Verdict() != testCase.verdict || provider.calls != 0 {
				t.Fatalf("Process() = applicable=%t state=%q verdict=%q calls=%d errors=%v/%v/%v", result.Applicable(), verification.State(), policy.Verdict(), provider.calls, err, verificationErr, policyErr)
			}
		})
	}
}

// TestDomainProcessorMapsServerOwnedPolicyModes proves request data cannot select policy.
func TestDomainProcessorMapsServerOwnedPolicyModes(t *testing.T) {
	t.Parallel()
	verifier, err := dkim2.NewVerifier(noLookupProvider{})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	request := dkim2.NewVerifyRequest([]byte("not-rfc5322"), []byte{}, [][]byte{[]byte("<δοκιμή@example.test>")})
	tests := []struct {
		configMode config.PolicyMode
		wantMode   dkim2.PolicyMode
	}{
		{config.PolicyStrict, dkim2.PolicyModeStrict},
		{config.PolicyPermissive, dkim2.PolicyModePermissive},
		{config.PolicyTesting, dkim2.PolicyModeTesting},
	}
	for _, test := range tests {
		processor, constructErr := NewDomainProcessor(verifier, test.configMode)
		if constructErr != nil {
			t.Fatalf("NewDomainProcessor() error = %v", constructErr)
		}
		result, processErr := processor.Process(context.Background(), request)
		if processErr != nil {
			t.Fatalf("Process() error = %v", processErr)
		}
		verification, verificationErr := result.Verification()
		policy, policyErr := result.Policy()
		if verificationErr != nil || policyErr != nil || verification.State() != dkim2.ResultStatePERMERROR ||
			policy.Mode() != test.wantMode || policy.VerificationState() != verification.State() {
			t.Fatalf("domain result = %q/%q, errors %v/%v", verification.State(), policy.Mode(), verificationErr, policyErr)
		}
	}
}

// TestDomainProcessorFailsClosed proves nil, typed-nil, canceled, and zero results cannot proceed.
func TestDomainProcessorFailsClosed(t *testing.T) {
	t.Parallel()
	var typedNil *dkim2.Verifier
	if _, err := NewDomainProcessor(typedNil, config.PolicyStrict); !IsDomainError(err) {
		t.Fatalf("typed-nil constructor error = %v", err)
	}
	if _, err := NewDomainProcessor(nil, config.PolicyStrict); !IsDomainError(err) {
		t.Fatalf("nil constructor error = %v", err)
	}
	if _, err := NewDomainProcessor(zeroVerifier{}, config.PolicyStrict); err != nil {
		t.Fatalf("zero verifier constructor error = %v", err)
	}
	processor, _ := NewDomainProcessor(zeroVerifier{}, config.PolicyStrict)
	if _, err := processor.Process(context.Background(), dkim2.VerifyRequest{}); !IsDomainError(err) {
		t.Fatalf("zero result error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := processor.Process(ctx, dkim2.VerifyRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
}

type zeroVerifier struct{}

// Assess returns a zero assessment for fail-closed service tests.
func (zeroVerifier) Assess(context.Context, dkim2.VerifyRequest) (dkim2.VerificationAssessment, error) {
	return dkim2.VerificationAssessment{}, nil
}

type errorVerifier struct{ err error }

// Assess returns one injected toxic dependency error for privacy tests.
func (v errorVerifier) Assess(context.Context, dkim2.VerifyRequest) (dkim2.VerificationAssessment, error) {
	return dkim2.VerificationAssessment{}, v.err
}

type cancelingVerifier struct {
	inner  VerificationService
	cancel context.CancelFunc
}

// Assess returns an authentic assessment while making cancellation visible at the next stage boundary.
func (v cancelingVerifier) Assess(ctx context.Context, request dkim2.VerifyRequest) (dkim2.VerificationAssessment, error) {
	result, err := v.inner.Assess(ctx, request)
	v.cancel()
	return result, err
}

type nilContext struct{}

// Deadline implements context.Context for typed-nil rejection tests.
func (*nilContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done implements context.Context for typed-nil rejection tests.
func (*nilContext) Done() <-chan struct{} { return nil }

// Err implements context.Context for typed-nil rejection tests.
func (*nilContext) Err() error { return nil }

// Value implements context.Context for typed-nil rejection tests.
func (*nilContext) Value(any) any { return nil }

type panicFormattingContext struct {
	context.Context
	marker string
}

// String panics if construction attempts to render the protected parent.
func (panicFormattingContext) String() string {
	panic("protected parent context was formatted")
}

// Format panics if any formatting verb traverses the protected parent.
func (panicFormattingContext) Format(fmt.State, rune) {
	panic("protected parent context was formatted")
}

// TestNewDNSVerifierUsesOnlyValidatedOverrides proves exact instance-local DNS construction.
func TestNewDNSVerifierUsesOnlyValidatedOverrides(t *testing.T) {
	t.Parallel()
	snapshot, err := config.Load([]byte(`
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /protected/0123456789abcdef0123456789abcdef/capability
policy:
  mode: strict
dns:
  lookup_timeout: 7s
  max_concurrent_lookups: 17
  cache:
    max_entries: 2048
    positive_ttl_cap: 2h
    negative_ttl_cap: 10m
    stable_error_ttl_cap: 2m
replay:
  backend: disabled
`), config.FlagValues{})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	providerConfig, err := dnsProviderConfig(ctx, snapshot.DNS())
	if err != nil {
		t.Fatalf("dnsProviderConfig() error = %v", err)
	}
	defaults := dkim2.DefaultDNSProviderConfig()
	wantLimits := defaults.Limits
	wantLimits.LookupTimeout = 7 * time.Second
	wantLimits.MaxConcurrentLookups = 17
	wantLimits.MaxCacheEntries = 2048
	wantLimits.MaxPositiveTTL = 2 * time.Hour
	wantLimits.MaxNegativeTTL = 10 * time.Minute
	wantLimits.MaxStableErrorTTL = 2 * time.Minute
	if providerConfig.Parent != ctx || providerConfig.Clock == nil || providerConfig.Limits != wantLimits {
		t.Fatal("DNS provider configuration changed a non-overridable default")
	}
	verifier, err := NewDNSVerifier(ctx, snapshot.DNS())
	if err != nil || verifier == nil {
		t.Fatalf("NewDNSVerifier() = %v, %v", verifier, err)
	}
	cancel()
	var nilParent context.Context
	if _, err := NewDNSVerifier(nilParent, snapshot.DNS()); !IsDomainError(err) {
		t.Fatalf("nil parent error = %v", err)
	}
	if _, err := NewDNSVerifier(context.Background(), config.DNSConfig{}); !IsDomainError(err) {
		t.Fatalf("zero config error = %v", err)
	}
	var typedNil *nilContext
	if _, err := NewDNSVerifier(typedNil, snapshot.DNS()); !IsDomainError(err) {
		t.Fatalf("typed-nil parent error = %v", err)
	}
}

// TestDNSConstructionNeverFormatsParentContext proves transient dependencies stay out of diagnostics.
func TestDNSConstructionNeverFormatsParentContext(t *testing.T) {
	const marker = "TOXIC-DNS-PARENT-CONTEXT"
	snapshot, err := config.Load([]byte(`
config:
  version: dkim2d-config-v1
protected:
  generation: 0123456789abcdef0123456789abcdef
server:
  capability_file: /protected/0123456789abcdef0123456789abcdef/capability
policy:
  mode: strict
dns:
  lookup_timeout: 7s
  max_concurrent_lookups: 17
replay:
  backend: disabled
`), config.FlagValues{})
	if err != nil {
		t.Fatal("DNS privacy config fixture failed")
	}
	parent := panicFormattingContext{Context: context.Background(), marker: marker}
	providerConfig, err := dnsProviderConfig(parent, snapshot.DNS())
	if err != nil || providerConfig.Parent != parent {
		t.Fatal("DNS provider config rejected the protected parent")
	}
	verifier, err := NewDNSVerifier(parent, snapshot.DNS())
	if err != nil || verifier == nil {
		t.Fatal("DNS verifier rejected the protected parent")
	}
	values := []any{
		*verifier,
		verifier,
		any(*verifier),
		[]DNSVerifier{*verifier},
		map[DNSVerifier]bool{*verifier: true},
	}
	var formatted strings.Builder
	for _, value := range values {
		fmt.Fprintf(&formatted, "%s|%q|%v|%+v|%#v|%x|%p\n", value, value, value, value, value, value, value)
	}
	if strings.Contains(formatted.String(), marker) {
		t.Fatal("DNS verifier formatting exposed the parent context")
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	canceledParent := panicFormattingContext{Context: canceled, marker: marker}
	if _, configErr := dnsProviderConfig(canceledParent, snapshot.DNS()); !IsDomainError(configErr) ||
		fmt.Sprint(configErr) != domainErrorText {
		t.Fatal("DNS provider config did not collapse parent failure")
	}
	if _, constructErr := NewDNSVerifier(canceledParent, snapshot.DNS()); !IsDomainError(constructErr) ||
		fmt.Sprint(constructErr) != domainErrorText {
		t.Fatal("DNS verifier did not collapse parent failure")
	}
}

// TestDomainResultFormattingIsContentFree proves result ownership never opens a diagnostic path.
func TestDomainResultFormattingIsContentFree(t *testing.T) {
	t.Parallel()
	formatted := fmt.Sprintf("%s %q %v %+v %#v %x %p", DomainResult{}, DomainResult{}, DomainResult{}, DomainResult{}, DomainResult{}, DomainResult{}, &DomainResult{})
	if !strings.Contains(formatted, domainResultRedacted) || strings.Contains(formatted, "raw") {
		t.Fatalf("domain result formatting = %s", formatted)
	}
}

type appGoldenCorpus struct {
	Draft       string `json:"draft"`
	RSAModulus  string `json:"rsa_modulus_base64"`
	RSAExponent int    `json:"rsa_exponent"`
	Vectors     map[string]struct {
		Raw     string   `json:"raw_base64"`
		Reverse string   `json:"reverse_path_base64"`
		Forward []string `json:"forward_paths_base64"`
	} `json:"vectors"`
}

type appGoldenProvider struct {
	key *rsa.PublicKey
}

// LookupPublicKey returns the frozen RSA test key.
func (p appGoldenProvider) LookupPublicKey(_ context.Context, query dkim2.PublicKeyQuery) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(p.key), nil
}

// TestDomainOwnersHideAuthenticSelectedStateAndDependencies proves structural opacity at the app boundary.
func TestDomainOwnersHideAuthenticSelectedStateAndDependencies(t *testing.T) {
	const ownershipMarker = "TOXIC-DOMAIN-PROCESSOR-OWNER"
	corpusBytes, err := os.ReadFile("../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/public-golden.json")
	if err != nil {
		t.Fatal("golden app fixture unavailable")
	}
	var corpus appGoldenCorpus
	if json.Unmarshal(corpusBytes, &corpus) != nil || corpus.Draft != dkim2.DraftIdentifier {
		t.Fatal("golden app fixture invalid")
	}
	vector, ok := corpus.Vectors["rsa_pass"]
	if !ok {
		t.Fatal("golden app PASS fixture unavailable")
	}
	modulus := decodeAppGolden(t, corpus.RSAModulus)
	verifier, err := dkim2.NewVerifier(
		appGoldenProvider{key: &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: corpus.RSAExponent}},
		dkim2.WithVerificationClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatal("golden app verifier construction failed")
	}
	processor, err := NewDomainProcessor(verifier, config.PolicyStrict)
	if err != nil {
		t.Fatal("golden app processor construction failed")
	}
	forward := make([][]byte, len(vector.Forward))
	for index, value := range vector.Forward {
		forward[index] = decodeAppGolden(t, value)
	}
	result, err := processor.Process(context.Background(), dkim2.NewVerifyRequest(
		decodeAppGolden(t, vector.Raw), decodeAppGolden(t, vector.Reverse), forward,
	))
	if err != nil || !result.valid() {
		t.Fatal("authentic selected domain processing failed")
	}
	verification, _ := result.Verification()
	if verification.Target().Sequence() == 0 || verification.SignatureSetCount() == 0 {
		t.Fatal("authentic selected domain result omitted target facts")
	}
	markerProcessor, err := NewDomainProcessor(errorVerifier{err: errors.New(ownershipMarker)}, config.PolicyStrict)
	if err != nil {
		t.Fatal("marker processor construction failed")
	}

	values := []any{
		result, &result, any(result), []DomainResult{result}, map[DomainResult]bool{result: true},
		*processor, processor, any(*processor), []DomainProcessor{*processor}, map[DomainProcessor]bool{*processor: true},
		*markerProcessor, markerProcessor, any(*markerProcessor), []DomainProcessor{*markerProcessor},
		map[DomainProcessor]bool{*markerProcessor: true},
	}
	var formatted strings.Builder
	for _, value := range values {
		fmt.Fprintf(&formatted, "%s|%q|%v|%+v|%#v|%x|%p\n", value, value, value, value, value, value, value)
	}
	if strings.Contains(formatted.String(), "example.test") ||
		strings.Contains(formatted.String(), "body line") ||
		strings.Contains(formatted.String(), ownershipMarker) ||
		!strings.Contains(formatted.String(), domainResultRedacted) ||
		!strings.Contains(formatted.String(), domainProcessorRedacted) {
		t.Fatal("domain owner formatting exposed retained state")
	}
	for _, value := range []interface {
		MarshalText() ([]byte, error)
	}{result, *processor} {
		if encoded, marshalErr := value.MarshalText(); marshalErr == nil || len(encoded) != 0 {
			t.Fatal("domain owner allowed text serialization")
		}
	}
	if encoded, marshalErr := json.Marshal(result); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("domain result allowed JSON serialization")
	}
	if encoded, marshalErr := json.Marshal(*processor); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("domain processor allowed JSON serialization")
	}
}

// decodeAppGolden decodes one frozen app vector field.
func decodeAppGolden(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal("golden app fixture base64 invalid")
	}
	return decoded
}

// TestMapPolicyModeRejectsUnknownValues proves construction accepts no future configuration value.
func TestMapPolicyModeRejectsUnknownValues(t *testing.T) {
	t.Parallel()
	for _, mode := range []config.PolicyMode{0, 255} {
		if mapped, ok := mapPolicyMode(mode); ok || mapped != "" {
			t.Fatalf("mapPolicyMode(%d) = %q/%t", mode, mapped, ok)
		}
	}
}

// TestDomainProcessorConcurrentReuse proves immutable service state is race-safe.
func TestDomainProcessorConcurrentReuse(t *testing.T) {
	t.Parallel()
	verifier, err := dkim2.NewVerifier(noLookupProvider{})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	processor, err := NewDomainProcessor(verifier, config.PolicyStrict)
	if err != nil {
		t.Fatalf("NewDomainProcessor() error = %v", err)
	}
	request := dkim2.NewVerifyRequest(nil, nil, [][]byte{nil})
	done := make(chan error, 16)
	for range 16 {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, processErr := processor.Process(ctx, request)
			done <- processErr
		}()
	}
	for range 16 {
		if processErr := <-done; processErr != nil {
			t.Errorf("Process() error = %v", processErr)
		}
	}
}

// TestDomainProcessorStopsAtCancellationBoundary proves policy cannot run after visible cancellation.
func TestDomainProcessorStopsAtCancellationBoundary(t *testing.T) {
	t.Parallel()
	verifier, err := dkim2.NewVerifier(noLookupProvider{})
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	processor, err := NewDomainProcessor(cancelingVerifier{inner: verifier, cancel: cancel}, config.PolicyStrict)
	if err != nil {
		t.Fatalf("NewDomainProcessor() error = %v", err)
	}
	request := dkim2.NewVerifyRequest([]byte("not-rfc5322"), nil, [][]byte{nil})
	if result, processErr := processor.Process(ctx, request); !errors.Is(processErr, context.Canceled) ||
		result.valid() {
		t.Fatalf("Process() = %v, %v", result, processErr)
	}

	var typedNil *nilContext
	if _, processErr := processor.Process(typedNil, request); !IsDomainError(processErr) {
		t.Fatalf("typed-nil context error = %v", processErr)
	}
}

// TestDomainProcessorCollapsesToxicDependencyErrors proves raw provider diagnostics never escape.
func TestDomainProcessorCollapsesToxicDependencyErrors(t *testing.T) {
	t.Parallel()
	const marker = "RAW-RECIPIENT-PROVIDER-MARKER"
	processor, err := NewDomainProcessor(errorVerifier{err: errors.New(marker)}, config.PolicyStrict)
	if err != nil {
		t.Fatalf("NewDomainProcessor() error = %v", err)
	}
	_, processErr := processor.Process(context.Background(), dkim2.VerifyRequest{})
	if !IsDomainError(processErr) || strings.Contains(fmt.Sprint(processErr), marker) {
		t.Fatal("dependency error escaped")
	}
}
