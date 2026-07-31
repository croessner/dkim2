package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
	"golang.org/x/sys/unix"
)

const (
	signingServiceOriginDomain    = "origin.example.test"
	signingServiceTransitDomain   = signingServiceOriginDomain
	signingServiceTestTenant      = "tenant-a"
	signingServiceOriginHandle    = "origin-key"
	signingServiceTransitHandle   = "transit-key"
	signingServiceOriginSelector  = "origin"
	signingServiceTransitSelector = "transit"
	signingServiceDomainField     = "domain"
	signingServiceStrictValue     = "strict"
)

type signingServicePublicKeys struct {
	keys map[string]*rsa.PublicKey
}

// LookupPublicKey returns the exact selector-bound public fixture credential.
func (p signingServicePublicKeys) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	key, found := p.keys[query.Selector()]
	expectedDomain := signingServiceOriginDomain
	if query.Selector() == signingServiceTransitSelector {
		expectedDomain = signingServiceTransitDomain
	}
	if !found || query.SigningDomain() != expectedDomain ||
		query.Algorithm() != dkim2.AlgorithmRSASHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundRSAPublicKey(key), nil
}

type signingServiceFixture struct {
	runtime    *signingstore.Runtime
	publicKeys signingServicePublicKeys
}

type policyFailureAuthority struct {
	err error
}

// Acquire returns one lease whose policy resolution exposes the configured failure.
func (a policyFailureAuthority) Acquire(context.Context) (signingLease, error) {
	return policyFailureLease(a), nil
}

type policyFailureLease struct {
	err error
}

type hostilePolicyFailure struct{}

// Error returns a bounded diagnostic for the hostile traversal fixture.
func (hostilePolicyFailure) Error() string { return "hostile policy failure" }

// As panics if production attempts open-interface error traversal.
func (hostilePolicyFailure) As(any) bool { panic("hostile error traversal") }

// ResolvePolicy returns the configured storage-neutral resolution failure.
func (l policyFailureLease) ResolvePolicy(
	context.Context,
	string,
	string,
	signingstore.PolicyUse,
	time.Time,
) (dkim2.SigningProfile, error) {
	return dkim2.SigningProfile{}, l.err
}

// SignDigest fails if a policy-resolution regression reaches private signing.
func (policyFailureLease) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
}

// Close releases the stateless test lease.
func (policyFailureLease) Close() error { return nil }

type recordingExactAuthorizer struct {
	exact    exactSigningAuthorizer
	purposes []dkim2.SigningAuthorizationPurpose
}

// Authorize records the closed purpose and delegates the exact request-local decision.
func (a *recordingExactAuthorizer) Authorize(
	ctx context.Context,
	query dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	a.purposes = append(a.purposes, query.Purpose())
	return a.exact.Authorize(ctx, query)
}

// TestSigningServiceRejectsRecipientGroupBeforeStoreAccess proves the
// configuration gate precedes generation acquisition and policy resolution.
func TestSigningServiceRejectsRecipientGroupBeforeStoreAccess(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	if err := fixture.runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close(runtime) error = %v", err)
	}
	if service, err := NewSigningService(
		fixture.publicKeys,
		fixture.runtime,
		true,
	); err == nil || service != nil {
		t.Fatal("recipient-group compatibility switch was accepted")
	}
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatalf("NewSigningService() error = %v", err)
	}
	request := newSigningServiceRequest(
		t,
		OperationSign,
		signingServiceRawMessage(),
		[][]byte{
			[]byte("<first@example.net>"),
			[]byte("<second@example.net>"),
		},
	)
	result, signErr := service.Sign(context.Background(), request)
	if signErr != nil {
		t.Fatalf("Sign() error = %v", signErr)
	}
	if !result.Valid() || result.Result() != OperationPermerror ||
		result.Disposition() != OperationReject || len(result.Fields()) != 0 {
		t.Fatalf(
			"Sign() valid=%t result=%q disposition=%q fields=%d",
			result.Valid(), result.Result(), result.Disposition(), len(result.Fields()),
		)
	}
}

// TestSigningServiceMapsMissingPolicyToPermanentRefusal proves static
// datasource selection failures cannot cause indefinite SMTP deferral.
func TestSigningServiceMapsMissingPolicyToPermanentRefusal(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatalf("NewSigningService() error = %v", err)
	}
	request, err := NewOperationRequest(
		OperationSign,
		signingServiceRawMessage(),
		[]byte("<sender@origin.example.test>"),
		[][]byte{[]byte("<recipient@example.net>")},
		"missing-tenant",
		signingServiceOriginDomain,
		FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatalf("NewOperationRequest() error = %v", err)
	}
	result, err := service.Sign(context.Background(), request)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if !result.Valid() || result.Result() != OperationPermerror ||
		result.Disposition() != OperationReject || len(result.Fields()) != 0 {
		t.Fatalf(
			"Sign() valid=%t result=%q disposition=%q fields=%d",
			result.Valid(),
			result.Result(),
			result.Disposition(),
			len(result.Fields()),
		)
	}
}

// TestSigningServiceClassifiesDatasourcePolicyFailures proves an absent exact
// network policy is permanent while an unavailable datasource remains retryable.
func TestSigningServiceClassifiesDatasourcePolicyFailures(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	request := newSigningServiceRequest(
		t,
		OperationSign,
		signingServiceRawMessage(),
		[][]byte{[]byte("<recipient@example.net>")},
	)
	tests := []struct {
		name        string
		err         error
		result      OperationResultClass
		disposition OperationDisposition
	}{
		{
			name: "not found", err: provider.NewError(provider.ErrorCodeNotFound),
			result: OperationPermerror, disposition: OperationReject,
		},
		{
			name: "inactive", err: provider.NewError(provider.ErrorCodeInactive),
			result: OperationPermerror, disposition: OperationReject,
		},
		{
			name: "explicit permanent provider", err: dkim2.NewPermanentProviderError(),
			result: OperationPermerror, disposition: OperationReject,
		},
		{
			name: "explicit temporary provider", err: dkim2.NewTemporaryProviderError(),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "unavailable", err: provider.NewError(provider.ErrorCodeUnavailable),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "invalid request", err: provider.NewError(provider.ErrorCodeInvalidRequest),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "ambiguous", err: provider.NewError(provider.ErrorCodeAmbiguous),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "malformed data", err: provider.NewError(provider.ErrorCodeMalformedData),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "limit exceeded", err: provider.NewError(provider.ErrorCodeLimitExceeded),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "unsupported platform", err: provider.NewError(provider.ErrorCodeUnsupportedPlatform),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "cancelled", err: provider.NewError(provider.ErrorCodeCancelled),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "deadline exceeded", err: provider.NewError(provider.ErrorCodeDeadlineExceeded),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "internal invariant", err: provider.NewError(provider.ErrorCodeInternalInvariant),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name:   "wrapped not found",
			err:    fmt.Errorf("wrapped policy failure: %w", provider.NewError(provider.ErrorCodeNotFound)),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name:   "wrapped inactive",
			err:    fmt.Errorf("wrapped policy failure: %w", provider.NewError(provider.ErrorCodeInactive)),
			result: OperationTemperror, disposition: OperationTempfail,
		},
		{
			name: "hostile traversal", err: hostilePolicyFailure{},
			result: OperationTemperror, disposition: OperationTempfail,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			service := &SigningService{
				publicKeys: fixture.publicKeys,
				store:      policyFailureAuthority{err: testCase.err},
				clock:      time.Now,
			}
			result, err := service.Sign(context.Background(), request)
			if err != nil || !result.Valid() || result.Result() != testCase.result ||
				result.Disposition() != testCase.disposition || len(result.Fields()) != 0 {
				t.Fatalf(
					"Sign() error=%v valid=%t result=%q disposition=%q fields=%d",
					err,
					result.Valid(),
					result.Result(),
					result.Disposition(),
					len(result.Fields()),
				)
			}
		})
	}
}

// TestExactSigningAuthorizerRequestMatrix proves the application authorizer
// admits policy and only the exact ordered recipient-disclosure query.
func TestExactSigningAuthorizerRequestMatrix(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	recipients := [][]byte{
		[]byte("<first@example.net>"),
		[]byte("<second@example.net>"),
	}
	tests := []struct {
		name         string
		expected     [][]byte
		wantError    bool
		wantPurposes []dkim2.SigningAuthorizationPurpose
	}{
		{
			name:     "exact ordered group",
			expected: recipients,
			wantPurposes: []dkim2.SigningAuthorizationPurpose{
				dkim2.SigningAuthorizationRecipientDisclosure,
			},
		},
		{
			name: "reordered group denied",
			expected: [][]byte{
				recipients[1],
				recipients[0],
			},
			wantError: true,
			wantPurposes: []dkim2.SigningAuthorizationPurpose{
				dkim2.SigningAuthorizationRecipientDisclosure,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &recordingExactAuthorizer{
				exact: exactSigningAuthorizer{recipients: test.expected},
			}
			err := signSigningServiceOriginator(
				t, fixture, recipients, authorizer,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("originator signing error = %v, wantError=%t", err, test.wantError)
			}
			if !slices.Equal(authorizer.purposes, test.wantPurposes) {
				t.Fatalf(
					"authorization purposes = %v, want %v",
					authorizer.purposes, test.wantPurposes,
				)
			}
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (exactSigningAuthorizer{}).Authorize(
		cancelled, dkim2.SigningAuthorizationQuery{},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Authorize(cancelled) error = %v", err)
	}
}

// TestSigningServiceSelectsPoliciesAndFailsClosedOnRevisionVerification proves
// originator and ordinary-transit selection through complete service calls.
func TestSigningServiceSelectsPoliciesAndFailsClosedOnRevisionVerification(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatalf("NewSigningService() error = %v", err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	raw := signingServiceRawMessage()
	recipients := [][]byte{[]byte("<recipient@origin.example.test>")}
	signRequest := newSigningServiceRequest(t, OperationSign, raw, recipients)
	signed, err := service.Sign(context.Background(), signRequest)
	assertSigningServicePass(t, signed, err, signingServiceOriginSelector)

	inherited := insertSigningServiceFields(signed.Fields(), raw)
	reviseRequest := newSigningServiceRequest(
		t, OperationRevise, inherited, recipients,
	)
	revised, err := service.Revise(context.Background(), reviseRequest)
	assertSigningServicePass(t, revised, err, signingServiceTransitSelector)

	outgoingReverse := []byte("<forwarded@origin.example.test>")
	outgoingRecipients := [][]byte{[]byte("<forwarded@example.net>")}
	changedEnvelope, err := NewRevisionOperationRequest(
		inherited,
		signRequest.ReversePath(),
		recipients,
		outgoingReverse,
		outgoingRecipients,
		signingServiceTestTenant,
		signingServiceTransitDomain,
		FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatalf("NewRevisionOperationRequest() error = %v", err)
	}
	forwarded, err := service.Revise(context.Background(), changedEnvelope)
	assertSigningServicePass(t, forwarded, err, signingServiceTransitSelector)
	wantOutgoing := []byte(base64.StdEncoding.EncodeToString(outgoingRecipients[0]))
	forwardedFields := forwarded.Fields()
	if !slices.ContainsFunc(forwardedFields, func(field CompletedField) bool {
		return bytes.HasPrefix(field.Bytes(), []byte("DKIM2-Signature:")) &&
			bytes.Contains(field.Bytes(), wantOutgoing)
	}) {
		t.Fatal("revision signature omitted distinct outgoing envelope authority")
	}

	corrupted := bytes.Replace(
		inherited,
		[]byte("s="+signingServiceOriginSelector+":rsa-sha256:"),
		[]byte("s=unknown:rsa-sha256:"),
		1,
	)
	if bytes.Equal(corrupted, inherited) {
		t.Fatal("revision fixture omitted the inherited selector")
	}
	failedRequest := newSigningServiceRequest(
		t, OperationRevise, corrupted, recipients,
	)
	failed, err := service.Revise(context.Background(), failedRequest)
	if err != nil {
		t.Fatalf("Revise(corrupted) error = %v", err)
	}
	if !failed.Valid() || failed.Result() != OperationPermerror ||
		failed.Disposition() != OperationReject || len(failed.Fields()) != 0 {
		t.Fatalf(
			"Revise(corrupted) valid=%t result=%q disposition=%q fields=%d",
			failed.Valid(), failed.Result(), failed.Disposition(), len(failed.Fields()),
		)
	}
}

// TestSigningServiceRevisesDistinctEximEnvelopeAfterReceivedAddition proves an
// excluded Exim receipt header does not block a distinct-envelope revision.
func TestSigningServiceRevisesDistinctEximEnvelopeAfterReceivedAddition(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatalf("NewSigningService() error = %v", err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	incomingReverse := []byte("<sender@origin.example.test>")
	incomingRecipients := [][]byte{[]byte("<recipient@origin.example.test>")}
	raw := signingServiceRawMessage()
	signRequest, err := NewOperationRequest(
		OperationSign,
		raw,
		incomingReverse,
		incomingRecipients,
		signingServiceTestTenant,
		signingServiceOriginDomain,
		FidelityEximTransportFilterCRLF,
	)
	if err != nil {
		t.Fatalf("NewOperationRequest() error = %v", err)
	}
	signed, err := service.Sign(context.Background(), signRequest)
	assertSigningServicePass(t, signed, err, signingServiceOriginSelector)
	inherited := insertSigningServiceFields(signed.Fields(), raw)
	withReceived := append(
		[]byte("Received: from matrix.example.test by mx.example.test; Tue, 30 Jul 2026 20:00:00 +0000\r\n"),
		inherited...,
	)
	outgoingReverse := []byte("<forwarded@origin.example.test>")
	outgoingRecipients := [][]byte{[]byte("<forwarded@revise.test>")}
	reviseRequest, err := NewRevisionOperationRequest(
		withReceived,
		incomingReverse,
		incomingRecipients,
		outgoingReverse,
		outgoingRecipients,
		signingServiceTestTenant,
		signingServiceTransitDomain,
		FidelityEximTransportFilterCRLF,
	)
	if err != nil {
		t.Fatalf("NewRevisionOperationRequest() error = %v", err)
	}
	lease, err := fixture.runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = lease.Close() }()
	signer, err := dkim2.NewSigner(
		fixture.publicKeys,
		dkim2.NewRequestRouteAuthority(),
		exactSigningAuthorizer{recipients: outgoingRecipients},
		lease,
		dkim2.WithSigningClock(func() time.Time { return time.Unix(1_700_000_000, 0) }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	verification, capability, verifyErr := signer.VerifyForRevision(
		context.Background(),
		dkim2.NewVerifyRequest(withReceived, incomingReverse, incomingRecipients),
	)
	if verifyErr != nil || verification.Status() != dkim2.RevisionVerificationVerified ||
		!capability.Valid() {
		t.Fatalf(
			"VerifyForRevision() status=%q capability=%t error=%v",
			verification.Status(), capability.Valid(), verifyErr,
		)
	}
	profile, err := lease.ResolvePolicy(
		context.Background(),
		signingServiceTestTenant,
		signingServiceTransitDomain,
		signingstore.PolicyOrdinaryTransit,
		time.Unix(1_700_000_000, 0).UTC(),
	)
	if err != nil {
		t.Fatalf("ResolvePolicy() error = %v", err)
	}
	source, err := dkim2.NewSigningSource(withReceived)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := dkim2.NewExistingRouteEntry(
		capability,
		source,
		outgoingReverse,
		outgoingRecipients,
		dkim2.RouteDisclosureSingle,
		[]byte(signingRouteScope),
	)
	if err != nil {
		t.Fatalf("NewExistingRouteEntry() error = %v", err)
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	_, _, err = signer.SignExisting(
		context.Background(),
		dkim2.NewExistingSigningRequest(
			capability,
			withReceived,
			outgoingReverse,
			outgoingRecipients,
			tickets[0],
			profile,
			dkim2.SigningMetadata{},
			dkim2.SigningTransportFinalNetworkPreDotStuffing,
			dkim2.RejectUnavailableBody,
			dkim2.RecipeCopyOnly,
		),
	)
	if err != nil {
		var signingErr *dkim2.SigningError
		if errors.As(err, &signingErr) {
			t.Fatalf("SignExisting() code=%q", signingErr.Code())
		}
		t.Fatalf("SignExisting() error = %v", err)
	}
	revised, err := service.Revise(context.Background(), reviseRequest)
	assertSigningServicePass(t, revised, err, signingServiceTransitSelector)
}

// signSigningServiceOriginator runs one group-signing request through a supplied authorizer.
func signSigningServiceOriginator(
	t *testing.T,
	fixture signingServiceFixture,
	recipients [][]byte,
	authorizer dkim2.SigningAuthorizer,
) error {
	t.Helper()
	lease, err := fixture.runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer func() { _ = lease.Close() }()
	at := time.Unix(1_700_000_000, 0).UTC()
	profile, err := lease.ResolvePolicy(
		context.Background(),
		signingServiceTestTenant,
		signingServiceOriginDomain,
		signingstore.PolicyOriginator,
		at,
	)
	if err != nil {
		t.Fatalf("ResolvePolicy() error = %v", err)
	}
	signer, err := dkim2.NewSigner(
		fixture.publicKeys,
		dkim2.NewRequestRouteAuthority(),
		authorizer,
		lease,
		dkim2.WithSigningClock(func() time.Time { return at }),
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	raw := signingServiceRawMessage()
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := dkim2.NewOriginatorRouteEntry(
		source,
		[]byte("<sender@origin.example.test>"),
		recipients,
		dkim2.RouteDisclosureAuthorizedGroup,
		[]byte(signingRouteScope),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	_, _, err = signer.SignOriginator(
		context.Background(),
		dkim2.NewOriginatorSigningRequest(
			raw,
			[]byte("<sender@origin.example.test>"),
			recipients,
			tickets[0],
			profile,
			dkim2.SigningMetadata{},
			dkim2.SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	return err
}

// assertSigningServicePass validates one successful selector-specific service outcome.
func assertSigningServicePass(
	t *testing.T,
	result OperationResult,
	err error,
	selector string,
) {
	t.Helper()
	if err != nil {
		t.Fatalf("operation error = %v", err)
	}
	fields := result.Fields()
	if !result.Valid() || result.Result() != OperationPass ||
		result.Disposition() != OperationAccept || len(fields) == 0 {
		t.Fatalf(
			"operation valid=%t result=%q disposition=%q fields=%d",
			result.Valid(), result.Result(), result.Disposition(), len(fields),
		)
	}
	selectorTag := []byte("s=" + selector + ":rsa-sha256:")
	found := false
	for _, field := range fields {
		if bytes.HasPrefix(field.Bytes(), []byte("DKIM2-Signature:")) &&
			bytes.Contains(field.Bytes(), selectorTag) {
			found = true
		}
	}
	if !found {
		t.Fatalf("operation omitted selector %q", selector)
	}
}

// insertSigningServiceFields reproduces validated end-of-header field insertion.
func insertSigningServiceFields(fields []CompletedField, raw []byte) []byte {
	separator := bytes.Index(raw, []byte("\r\n\r\n"))
	if separator < 0 {
		return nil
	}
	insertion := separator + len("\r\n")
	output := make([]byte, 0, len(raw)+1024)
	output = append(output, raw[:insertion]...)
	for _, field := range fields {
		output = append(output, field.Bytes()...)
	}
	return append(output, raw[insertion:]...)
}

// newSigningServiceRequest constructs one exact application request fixture.
func newSigningServiceRequest(
	t *testing.T,
	operation Operation,
	raw []byte,
	recipients [][]byte,
) OperationRequest {
	t.Helper()
	reverse := []byte("<sender@origin.example.test>")
	var request OperationRequest
	var err error
	if operation == OperationRevise {
		request, err = NewRevisionOperationRequest(
			raw,
			reverse,
			recipients,
			reverse,
			recipients,
			signingServiceTestTenant,
			signingServiceOperationDomain(operation),
			FidelityRawRFC5322,
		)
	} else {
		request, err = NewOperationRequest(
			operation,
			raw,
			reverse,
			recipients,
			signingServiceTestTenant,
			signingServiceOperationDomain(operation),
			FidelityRawRFC5322,
		)
	}
	if err != nil {
		t.Fatalf("NewOperationRequest() error = %v", err)
	}
	return request
}

// signingServiceOperationDomain selects the exact local policy domain for one operation.
func signingServiceOperationDomain(operation Operation) string {
	if operation == OperationSign {
		return signingServiceOriginDomain
	}
	return signingServiceTransitDomain
}

// signingServiceRawMessage returns one stable byte-exact RFC 5322 fixture.
func signingServiceRawMessage() []byte {
	return []byte(
		"From: sender@origin.example.test\r\n" +
			"To: recipient@origin.example.test\r\n" +
			"Subject: signing service\r\n" +
			"\r\n" +
			"body\r\n",
	)
}

// newSigningServiceFixture publishes protected originator and transit policies.
func newSigningServiceFixture(t *testing.T) signingServiceFixture {
	t.Helper()
	root := t.TempDir()
	originKey := newSigningServiceRSAKey(t)
	transitKey := newSigningServiceRSAKey(t)
	originSPKI := signingServiceSPKI(t, &originKey.PublicKey)
	transitSPKI := signingServiceSPKI(t, &transitKey.PublicKey)
	datasource := map[string]any{
		"version": "dkim2-datasource-v1",
		"handles": []any{
			map[string]any{"id": signingServiceOriginHandle},
			map[string]any{"id": signingServiceTransitHandle},
		},
		"profiles": []any{
			signingServiceProfile(
				"origin-profile",
				signingServiceOriginDomain,
				signingServiceOriginHandle,
				signingServiceOriginSelector,
				originSPKI,
			),
			signingServiceProfile(
				"transit-profile",
				signingServiceTransitDomain,
				signingServiceTransitHandle,
				signingServiceTransitSelector,
				transitSPKI,
			),
		},
		"policies": []any{
			signingServicePolicy(
				signingServiceOriginDomain, "originator", "origin-profile",
			),
			signingServicePolicy(
				signingServiceTransitDomain, "ordinary_transit", "transit-profile",
			),
		},
	}
	manifest := map[string]any{
		"version": "dkim2-private-keys-v1",
		"entries": []any{
			signingServiceManifestEntry(
				signingServiceOriginDomain,
				signingServiceOriginHandle,
				"originator",
				"origin.pem",
				originSPKI,
			),
			signingServiceManifestEntry(
				signingServiceTransitDomain,
				signingServiceTransitHandle,
				"ordinary_transit",
				"transit.pem",
				transitSPKI,
			),
		},
	}
	writeSigningServiceJSON(t, filepath.Join(root, "datasource.json"), datasource)
	writeSigningServiceJSON(t, filepath.Join(root, "manifest.json"), manifest)
	writeSigningServicePrivateKey(t, filepath.Join(root, "origin.pem"), originKey)
	writeSigningServicePrivateKey(t, filepath.Join(root, "transit.pem"), transitKey)
	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("os.Chmod(root) error = %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatalf("unix.Open(root) error = %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(rootFD) })
	runtime, err := signingstore.NewRuntime(
		rootFD, "datasource.json", "manifest.json",
	)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	return signingServiceFixture{
		runtime: runtime,
		publicKeys: signingServicePublicKeys{keys: map[string]*rsa.PublicKey{
			signingServiceOriginSelector:  &originKey.PublicKey,
			signingServiceTransitSelector: &transitKey.PublicKey,
		}},
	}
}

// newSigningServiceRSAKey generates one independent protected test credential.
func newSigningServiceRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

// signingServiceSPKI returns one canonical public credential encoding.
func signingServiceSPKI(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	return spki
}

// signingServiceProfile returns one exact datasource profile document.
func signingServiceProfile(
	id string,
	domain string,
	handle string,
	selector string,
	spki []byte,
) map[string]any {
	return map[string]any{
		"id":                      id,
		signingServiceDomainField: domain,
		"status":                  "active",
		"credentials": []any{map[string]any{
			"algorithm":       "rsa-sha256",
			"selector":        selector,
			"public_key_spki": base64.StdEncoding.EncodeToString(spki),
			"handle_id":       handle,
		}},
	}
}

// signingServicePolicy returns one exact datasource policy document.
func signingServicePolicy(domain string, use string, profile string) map[string]any {
	return map[string]any{
		"tenant_id":               signingServiceTestTenant,
		signingServiceDomainField: domain,
		"use":                     use,
		"profile_id":              profile,
		"status":                  "active",
		"rollout":                 "enforce",
		"compatibility":           signingServiceStrictValue,
	}
}

// signingServiceManifestEntry binds one protected key to one exact policy use.
func signingServiceManifestEntry(
	domain string,
	handle string,
	use string,
	privateFile string,
	spki []byte,
) map[string]any {
	digest := sha256.Sum256(spki)
	return map[string]any{
		"tenant_id":               signingServiceTestTenant,
		signingServiceDomainField: domain,
		"use":                     use,
		"handle_id":               handle,
		"algorithm":               "rsa-sha256",
		"public_spki_sha256":      base64.StdEncoding.EncodeToString(digest[:]),
		"private_key_file":        privateFile,
	}
}

// writeSigningServiceJSON creates one owner-only protected JSON fixture child.
func writeSigningServiceJSON(t *testing.T, path string, value any) {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("os.WriteFile(JSON) error = %v", err)
	}
}

// writeSigningServicePrivateKey creates one owner-only PKCS8 fixture child.
func writeSigningServicePrivateKey(
	t *testing.T,
	path string,
	key *rsa.PrivateKey,
) {
	t.Helper()
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	defer clear(pkcs8)
	document := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	defer clear(document)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("os.WriteFile(private key) error = %v", err)
	}
}
