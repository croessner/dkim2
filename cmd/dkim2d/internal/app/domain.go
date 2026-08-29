package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/dnstxt"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
)

const (
	domainErrorText         = "dkim2d domain service failure"
	domainResultRedacted    = "dkim2d_domain_result"
	domainProcessorRedacted = "dkim2d_domain_processor"
)

// DomainError reports a content-free construction or processing failure.
type DomainError struct{}

// Error returns a constant content-free domain diagnostic.
func (*DomainError) Error() string { return domainErrorText }

// Is recognizes the bounded domain error type.
func (*DomainError) Is(target error) bool {
	_, ok := target.(*DomainError)
	return ok
}

// VerificationService is the narrow public-library applicability and verification boundary.
type VerificationService interface {
	Assess(context.Context, dkim2.VerifyRequest) (dkim2.VerificationAssessment, error)
}

// AuthenticationService is the narrow library-owned final Draft-06 boundary.
type AuthenticationService interface {
	AuthenticateVerified(context.Context, dkim2.VerifyResult) (dkim2.AuthenticationResult, error)
}

// DNSVerifier owns one bounded DNS provider and the verifier built from that
// exact provider so revision signing cannot drift to a second resolver model.
type DNSVerifier struct {
	verifier *dkim2.Verifier
	provider dkim2.PublicKeyProvider
}

// String returns a constant content-free DNS verifier summary.
func (DNSVerifier) String() string { return "dkim2d_dns_verifier" }

// GoString returns a constant content-free DNS verifier representation.
func (DNSVerifier) GoString() string { return "dkim2d_dns_verifier" }

// Format prevents formatting verbs from traversing resolver dependencies.
func (DNSVerifier) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d_dns_verifier")
}

// DomainProcessor owns current verification followed by server-selected local policy.
type DomainProcessor struct {
	state *domainProcessorState
}

type domainProcessorState struct {
	verifier VerificationService
	auth     AuthenticationService
	mode     dkim2.PolicyMode
	runtime  *observability.Runtime
}

// attachObservability binds the already acquired instance runtime before publication.
func (p *DomainProcessor) attachObservability(runtime *observability.Runtime) {
	if p != nil && p.state != nil {
		p.state.runtime = runtime
	}
}

// DomainResult keeps verification and local policy separate for replay coordination.
type DomainResult struct {
	initialized    bool
	applicable     bool
	verification   dkim2.VerifyResult
	authentication dkim2.AuthenticationResult
	policy         dkim2.PolicyDecision
}

// NewDNSVerifier constructs one instance-owned bounded DNS verifier.
func NewDNSVerifier(
	parent context.Context,
	dnsConfig config.DNSConfig,
	sinks ...dkim2.ObservationSink,
) (*DNSVerifier, error) {
	providerConfig, err := dnsProviderConfig(parent, dnsConfig)
	if err != nil {
		return nil, &DomainError{}
	}
	transport, err := dnstxt.New()
	if err != nil {
		return nil, &DomainError{}
	}
	provider, err := dkim2.NewDNSPublicKeyProviderWithConfig(transport, providerConfig)
	if err != nil {
		return nil, &DomainError{}
	}
	options := make([]dkim2.VerifierOption, 0, 1)
	if len(sinks) == 1 && !nilInterface(sinks[0]) {
		options = append(options, dkim2.WithObservationSink(sinks[0]))
	}
	verifier, err := dkim2.NewVerifier(provider, options...)
	if err != nil {
		return nil, &DomainError{}
	}
	return &DNSVerifier{verifier: verifier, provider: provider}, nil
}

// Verify delegates one immutable request to the instance verifier.
func (v *DNSVerifier) Verify(
	ctx context.Context,
	request dkim2.VerifyRequest,
) (dkim2.VerifyResult, error) {
	if v == nil || v.verifier == nil {
		return dkim2.VerifyResult{}, &DomainError{}
	}
	return v.verifier.Verify(ctx, request)
}

// Assess delegates applicability classification and verification to the instance verifier.
func (v *DNSVerifier) Assess(
	ctx context.Context,
	request dkim2.VerifyRequest,
) (dkim2.VerificationAssessment, error) {
	if v == nil || v.verifier == nil {
		return dkim2.VerificationAssessment{}, &DomainError{}
	}
	return v.verifier.Assess(ctx, request)
}

// LookupPublicKey delegates revision publication checks to the same bounded
// DNS provider used by verification.
func (v *DNSVerifier) LookupPublicKey(
	ctx context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if v == nil || nilInterface(v.provider) {
		return dkim2.PublicKeyResult{}, dkim2.NewTemporaryProviderError()
	}
	return v.provider.LookupPublicKey(ctx, query)
}

// NewDomainProcessor constructs one immutable verification and policy service.
func NewDomainProcessor(verifier VerificationService, mode config.PolicyMode, authentication ...AuthenticationService) (*DomainProcessor, error) {
	policyMode, ok := mapPolicyMode(mode)
	if nilVerificationService(verifier) || !ok || len(authentication) > 1 ||
		len(authentication) == 1 && nilInterface(authentication[0]) {
		return nil, &DomainError{}
	}
	var auth AuthenticationService
	if len(authentication) == 1 {
		auth = authentication[0]
	}
	return &DomainProcessor{state: &domainProcessorState{verifier: verifier, auth: auth, mode: policyMode}}, nil
}

// Process performs current verification and server-owned local policy evaluation.
func (p *DomainProcessor) Process(ctx context.Context, request dkim2.VerifyRequest) (DomainResult, error) {
	if p == nil || p.state == nil || nilVerificationService(p.state.verifier) || nilInterface(ctx) {
		return DomainResult{}, &DomainError{}
	}
	if err := domainContextError(ctx); err != nil {
		return DomainResult{}, err
	}
	assessment, err := p.state.verifier.Assess(ctx, request)
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return DomainResult{}, contextErr
		}
		return DomainResult{}, &DomainError{}
	}
	if contextErr := domainContextError(ctx); contextErr != nil {
		return DomainResult{}, contextErr
	}
	if !assessment.Valid() {
		return DomainResult{}, &DomainError{}
	}
	if !assessment.Applicable() {
		return DomainResult{initialized: true}, nil
	}
	verification, ok := assessment.Verification()
	if !ok || !verification.Valid() {
		return DomainResult{}, &DomainError{}
	}
	_, policySpan := startAppSpan(ctx, p.state.runtime, "dkim2.policy.evaluate")
	policyFinished := false
	finishPolicy := func(
		outcome observability.SpanOutcome,
		facts ...observability.SpanFact,
	) {
		if !policyFinished {
			policyFinished = true
			observability.EndSpanWithFacts(policySpan, outcome, facts...)
		}
	}
	defer finishPolicy(observability.SpanInternalError)
	policyStarted := time.Now()
	var authentication dkim2.AuthenticationResult
	if !nilInterface(p.state.auth) {
		authentication, err = p.state.auth.AuthenticateVerified(ctx, verification)
		if err != nil || !authentication.Valid() || authentication.Verification().State() != verification.State() {
			finishPolicy(observability.SpanInternalError)
			return DomainResult{}, &DomainError{}
		}
	}
	var policy dkim2.PolicyDecision
	if authentication.Valid() {
		policy, err = dkim2.EvaluateAuthenticationPolicy(authentication, dkim2.WithPolicyMode(p.state.mode))
	} else {
		policy, err = dkim2.EvaluatePolicy(verification, dkim2.WithPolicyMode(p.state.mode))
	}
	if contextErr := domainContextError(ctx); contextErr != nil && !authentication.Valid() {
		finishPolicy(observability.SpanInternalError)
		return DomainResult{}, contextErr
	}
	expectedState := verification.State()
	if authentication.Valid() {
		expectedState = authentication.State()
	}
	if err != nil || !policy.Valid() || policy.VerificationState() != expectedState || policy.Mode() != p.state.mode {
		finishPolicy(observability.SpanInternalError)
		return DomainResult{}, &DomainError{}
	}
	_, verdict := verificationObservationState(policy.VerificationState())
	policyVerdict, _ := observability.TextSpanFact("dkim2.verdict", verdict)
	policyMode, _ := observability.TextSpanFact(
		"dkim2.policy_mode",
		policyModeClass(policy.Mode()),
	)
	policyReason, _ := observability.TextSpanFact(
		"dkim2.reason_class",
		policyReasonClass(policy.VerificationState()),
	)
	finishPolicy(
		observability.SpanCompleted,
		policyVerdict,
		policyMode,
		policyReason,
	)
	observePolicy(p.state.runtime, policy, time.Since(policyStarted))
	result := DomainResult{initialized: true, applicable: true, verification: verification, authentication: authentication, policy: policy}
	if !result.valid() {
		return DomainResult{}, &DomainError{}
	}
	return result, nil
}

// Applicable reports whether protocol fields caused a DKIM2 verification.
func (r DomainResult) Applicable() bool { return r.valid() && r.applicable }

// String returns a content-free domain-processor representation.
func (DomainProcessor) String() string { return domainProcessorRedacted }

// GoString returns a content-free Go-syntax representation.
func (DomainProcessor) GoString() string { return domainProcessorRedacted }

// Format prevents formatting from traversing the injected verification service.
func (DomainProcessor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, domainProcessorRedacted)
}

// MarshalJSON rejects serialization of retained domain dependencies.
func (DomainProcessor) MarshalJSON() ([]byte, error) {
	return nil, &DomainError{}
}

// MarshalText rejects diagnostic serialization of retained domain dependencies.
func (DomainProcessor) MarshalText() ([]byte, error) {
	return nil, &DomainError{}
}

// Verification returns the immutable current-verification result only when applicable.
func (r DomainResult) Verification() (dkim2.VerifyResult, error) {
	if !r.valid() || !r.applicable {
		return dkim2.VerifyResult{}, &DomainError{}
	}
	return r.verification, nil
}

// Authentication returns the authoritative final Draft-06 result when configured.
func (r DomainResult) Authentication() (dkim2.AuthenticationResult, bool) {
	return r.authentication, r.valid() && r.applicable && r.authentication.Valid()
}

// Policy returns the immutable server-owned local-policy result only when applicable.
func (r DomainResult) Policy() (dkim2.PolicyDecision, error) {
	if !r.valid() || !r.applicable {
		return dkim2.PolicyDecision{}, &DomainError{}
	}
	return r.policy, nil
}

// valid reports whether verification and policy form one coherent immutable pair.
func (r DomainResult) valid() bool {
	if !r.initialized {
		return false
	}
	if !r.applicable {
		return !r.verification.Valid() && !r.authentication.Valid() && !r.policy.Valid()
	}
	if !r.verification.Valid() || !r.policy.Valid() {
		return false
	}
	if r.authentication.Valid() {
		return r.authentication.Verification().State() == r.verification.State() &&
			r.policy.VerificationState() == r.authentication.State()
	}
	return r.policy.VerificationState() == r.verification.State()
}

// String returns a content-free domain-result representation.
func (DomainResult) String() string { return domainResultRedacted }

// GoString returns a content-free Go-syntax representation.
func (DomainResult) GoString() string { return domainResultRedacted }

// Format prevents formatting verbs from traversing domain results.
func (DomainResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, domainResultRedacted)
}

// MarshalJSON rejects serialization outside the package-owned response mapper.
func (DomainResult) MarshalJSON() ([]byte, error) {
	return nil, &DomainError{}
}

// MarshalText rejects diagnostic serialization of verification and policy state.
func (DomainResult) MarshalText() ([]byte, error) {
	return nil, &DomainError{}
}

// mapPolicyMode maps the closed server configuration into library policy.
func mapPolicyMode(mode config.PolicyMode) (dkim2.PolicyMode, bool) {
	switch mode {
	case config.PolicyStrict:
		return dkim2.PolicyModeStrict, true
	case config.PolicyPermissive:
		return dkim2.PolicyModePermissive, true
	case config.PolicyTesting:
		return dkim2.PolicyModeTesting, true
	default:
		return "", false
	}
}

// nilVerificationService detects nil and typed-nil verifier dependencies.
func nilVerificationService(verifier VerificationService) bool {
	return nilInterface(verifier)
}

// nilInterface reports nil and typed-nil interface values without invoking methods.
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// dnsProviderConfig applies the validated daemon DNS lookup and cache controls.
func dnsProviderConfig(parent context.Context, dnsConfig config.DNSConfig) (dkim2.DNSProviderConfig, error) {
	if nilInterface(parent) || dnsConfig.LookupTimeout() <= 0 || dnsConfig.MaxConcurrentLookups() == 0 {
		return dkim2.DNSProviderConfig{}, &DomainError{}
	}
	if err := domainContextError(parent); err != nil {
		return dkim2.DNSProviderConfig{}, &DomainError{}
	}
	providerConfig := dkim2.DefaultDNSProviderConfig()
	providerConfig.Parent = parent
	providerConfig.Limits.LookupTimeout = dnsConfig.LookupTimeout()
	providerConfig.Limits.MaxConcurrentLookups = int(dnsConfig.MaxConcurrentLookups())
	providerConfig.Limits.MaxCacheEntries = int(dnsConfig.MaxCacheEntries())
	providerConfig.Limits.MaxPositiveTTL = dnsConfig.PositiveTTLCap()
	providerConfig.Limits.MaxNegativeTTL = dnsConfig.NegativeTTLCap()
	providerConfig.Limits.MaxStableErrorTTL = dnsConfig.StableErrorTTLCap()
	return providerConfig, nil
}

// IsDomainError reports whether an error is a bounded service contract failure.
func IsDomainError(err error) bool {
	return errors.Is(err, &DomainError{})
}

// domainContextError returns only exact terminal context identity or a bounded domain failure.
func domainContextError(ctx context.Context) error {
	valid, terminal := boundedContextState(ctx)
	if !valid {
		return &DomainError{}
	}
	return terminal
}
