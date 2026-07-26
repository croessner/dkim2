package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
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

// VerificationService is the narrow public-library verification boundary.
type VerificationService interface {
	Verify(context.Context, dkim2.VerifyRequest) (dkim2.VerifyResult, error)
}

// DomainProcessor owns current verification followed by server-selected local policy.
type DomainProcessor struct {
	state *domainProcessorState
}

type domainProcessorState struct {
	verifier VerificationService
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
	verification dkim2.VerifyResult
	policy       dkim2.PolicyDecision
}

// NewDNSVerifier constructs one instance-owned bounded DNS verifier.
func NewDNSVerifier(
	parent context.Context,
	dnsConfig config.DNSConfig,
	sinks ...dkim2.ObservationSink,
) (*dkim2.Verifier, error) {
	providerConfig, err := dnsProviderConfig(parent, dnsConfig)
	if err != nil {
		return nil, &DomainError{}
	}
	resolver := &net.Resolver{PreferGo: true, StrictErrors: true}
	transport, err := dkim2.NewNetTXTTransport(resolver)
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
	return verifier, nil
}

// NewDomainProcessor constructs one immutable verification and policy service.
func NewDomainProcessor(verifier VerificationService, mode config.PolicyMode) (*DomainProcessor, error) {
	policyMode, ok := mapPolicyMode(mode)
	if nilVerificationService(verifier) || !ok {
		return nil, &DomainError{}
	}
	return &DomainProcessor{state: &domainProcessorState{verifier: verifier, mode: policyMode}}, nil
}

// Process performs current verification and server-owned local policy evaluation.
func (p *DomainProcessor) Process(ctx context.Context, request dkim2.VerifyRequest) (DomainResult, error) {
	if p == nil || p.state == nil || nilVerificationService(p.state.verifier) || nilInterface(ctx) {
		return DomainResult{}, &DomainError{}
	}
	if err := domainContextError(ctx); err != nil {
		return DomainResult{}, err
	}
	verifyContext, verifySpan := startAppSpan(ctx, p.state.runtime, "dkim2.verify")
	verifyFinished := false
	finishVerify := func(
		outcome observability.SpanOutcome,
		facts ...observability.SpanFact,
	) {
		if !verifyFinished {
			verifyFinished = true
			observability.EndSpanWithFacts(verifySpan, outcome, facts...)
		}
	}
	defer finishVerify(observability.SpanInternalError)
	verification, err := p.state.verifier.Verify(verifyContext, request)
	if err != nil {
		finishVerify(observability.SpanInternalError)
		if contextErr := domainContextError(ctx); contextErr != nil {
			return DomainResult{}, contextErr
		}
		return DomainResult{}, &DomainError{}
	}
	if contextErr := domainContextError(ctx); contextErr != nil {
		finishVerify(observability.SpanInternalError)
		return DomainResult{}, contextErr
	}
	if !verification.Valid() {
		finishVerify(observability.SpanInternalError)
		return DomainResult{}, &DomainError{}
	}
	verifyResultClass, _ := verificationObservationState(verification.State())
	verifyResult, _ := observability.TextSpanFact(
		"dkim2.result",
		verifyResultClass,
	)
	finishVerify(observability.SpanCompleted, verifyResult)
	_, policySpan := startAppSpan(verifyContext, p.state.runtime, "dkim2.policy.evaluate")
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
	policy, err := dkim2.EvaluatePolicy(verification, dkim2.WithPolicyMode(p.state.mode))
	if contextErr := domainContextError(ctx); contextErr != nil {
		finishPolicy(observability.SpanInternalError)
		return DomainResult{}, contextErr
	}
	if err != nil || !policy.Valid() || policy.VerificationState() != verification.State() || policy.Mode() != p.state.mode {
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
	result := DomainResult{verification: verification, policy: policy}
	if !result.valid() {
		return DomainResult{}, &DomainError{}
	}
	return result, nil
}

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

// Verification returns the immutable current-verification result.
func (r DomainResult) Verification() (dkim2.VerifyResult, error) {
	if !r.valid() {
		return dkim2.VerifyResult{}, &DomainError{}
	}
	return r.verification, nil
}

// Policy returns the immutable server-owned local-policy result.
func (r DomainResult) Policy() (dkim2.PolicyDecision, error) {
	if !r.valid() {
		return dkim2.PolicyDecision{}, &DomainError{}
	}
	return r.policy, nil
}

// valid reports whether verification and policy form one coherent immutable pair.
func (r DomainResult) valid() bool {
	return r.verification.Valid() && r.policy.Valid() &&
		r.policy.VerificationState() == r.verification.State()
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

// dnsProviderConfig applies exactly the two validated daemon DNS overrides.
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
