package app

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

type deliveryStatusAcquireSpy struct{ calls int }

// Acquire records forbidden profile access from an invalid DSN evidence request.
func (s *deliveryStatusAcquireSpy) Acquire(context.Context) (signingLease, error) {
	s.calls++
	return nil, &DomainError{}
}

type deliveryStatusPolicyRecorder struct {
	next     signingAuthority
	acquires int
	domains  []string
	uses     []signingstore.PolicyUse
}

func (r *deliveryStatusPolicyRecorder) Acquire(ctx context.Context) (signingLease, error) {
	r.acquires++
	lease, err := r.next.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return deliveryStatusRecordingLease{next: lease, recorder: r}, nil
}

type deliveryStatusRecordingLease struct {
	next     signingLease
	recorder *deliveryStatusPolicyRecorder
}

func (l deliveryStatusRecordingLease) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use signingstore.PolicyUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	l.recorder.domains = append(l.recorder.domains, domain)
	l.recorder.uses = append(l.recorder.uses, use)
	return l.next.ResolvePolicy(ctx, tenant, domain, use, at)
}

func (l deliveryStatusRecordingLease) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return l.next.SignDigest(ctx, handle, request)
}

func (l deliveryStatusRecordingLease) Close() error { return l.next.Close() }

type deliveryStatusFixedProfileAuthority struct {
	profile dkim2.SigningProfile
	signs   int
}

func (a *deliveryStatusFixedProfileAuthority) Acquire(context.Context) (signingLease, error) {
	return a, nil
}

func (a *deliveryStatusFixedProfileAuthority) ResolvePolicy(
	context.Context,
	string,
	string,
	signingstore.PolicyUse,
	time.Time,
) (dkim2.SigningProfile, error) {
	return a.profile, nil
}

func (a *deliveryStatusFixedProfileAuthority) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	a.signs++
	return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
}

func (*deliveryStatusFixedProfileAuthority) Close() error { return nil }

// TestNewPostfixDeliveryStatusRequestRejectsUntrustedShapes proves the dedicated
// daemon request cannot be used as a generic null-sender signing wrapper.
func TestNewPostfixDeliveryStatusRequestRejectsUntrustedShapes(t *testing.T) {
	validOuterRecipient := [][]byte{[]byte("<postmaster@example.test>")}
	valid := func() (DeliveryStatusRequest, error) {
		return NewPostfixDeliveryStatusRequest(
			[]byte("From: postmaster@example.test\r\n\r\n"),
			[]byte("<>"),
			validOuterRecipient,
			"tenant-a",
		)
	}
	request, err := valid()
	if err != nil {
		t.Fatalf("NewPostfixDeliveryStatusRequest() error = %v", err)
	}
	if !bytes.Equal(request.OuterReversePath(), []byte("<>")) || len(request.OuterRecipients()) != 1 {
		t.Fatal("valid request did not retain exact outer DSN envelope")
	}
	for _, testCase := range []struct {
		name   string
		mutate func() (DeliveryStatusRequest, error)
	}{
		{
			name: "non-null outer reverse path",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewPostfixDeliveryStatusRequest([]byte("x"), []byte("<sender@example.test>"), validOuterRecipient, "tenant-a")
			},
		},
		{
			name: "multiple outer recipients",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewPostfixDeliveryStatusRequest([]byte("x"), []byte("<>"), [][]byte{[]byte("<one@example.test>"), []byte("<two@example.test>")}, "tenant-a")
			},
		},
		{
			name: "missing raw message",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewPostfixDeliveryStatusRequest(nil, []byte("<>"), validOuterRecipient, "tenant-a")
			},
		},
		{
			name: "missing tenant",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewPostfixDeliveryStatusRequest([]byte("x"), []byte("<>"), validOuterRecipient, "")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := testCase.mutate(); err == nil {
				t.Fatal("NewPostfixDeliveryStatusRequest() accepted unsafe request")
			}
		})
	}
}

// TestNewPostfixDeliveryStatusRequestNeedsNoCallerDomain proves the daemon request
// admits only tenant routing before authenticated embedded d= evidence exists.
func TestNewPostfixDeliveryStatusRequestNeedsNoCallerDomain(t *testing.T) {
	request, err := NewPostfixDeliveryStatusRequest(
		[]byte("From: postmaster@example.test\r\n\r\n"),
		[]byte("<>"),
		[][]byte{[]byte("<postmaster@example.test>")},
		"tenant-a",
	)
	if err != nil || request.Tenant() != "tenant-a" {
		t.Fatalf("NewPostfixDeliveryStatusRequest() request=%v error=%v", request, err)
	}
}

// TestSigningServiceRejectsInvalidDSNBeforePolicyAccess proves malformed DSN
// bytes cannot probe a delivery-status profile or private-key source.
func TestSigningServiceRejectsInvalidDSNBeforePolicyAccess(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	spy := &deliveryStatusAcquireSpy{}
	service := &SigningService{
		publicKeys: fixture.publicKeys,
		store:      spy,
		clock:      time.Now,
	}
	request, err := NewPostfixDeliveryStatusRequest(
		[]byte("From: postmaster@example.test\r\n\r\nnot a DSN\r\n"),
		[]byte("<>"),
		[][]byte{[]byte("<alice@example.test>")},
		"tenant-a",
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignDeliveryStatus(context.Background(), request)
	if err != nil || !result.Valid() || result.Result() != OperationPermerror ||
		result.Disposition() != OperationReject || spy.calls != 0 {
		t.Fatalf(
			"SignDeliveryStatus() result=%v error=%v policy_calls=%d",
			result, err, spy.calls,
		)
	}
}

// TestSigningServiceRejectsTamperedEmbeddedDomainBeforePolicyAccess proves an
// unauthenticated replacement d= cannot choose a tenant delivery-status
// profile or cause private-key source access.
func TestSigningServiceRejectsTamperedEmbeddedDomainBeforePolicyAccess(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	base, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	base.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	authenticated := authenticatedDeliveryStatusRequest(t, base)
	tamperedRaw := bytes.Replace(
		authenticated.RawMessage(),
		[]byte("d="+signingServiceOriginDomain),
		[]byte("d="+signingServiceAlternateDomain),
		1,
	)
	if bytes.Equal(tamperedRaw, authenticated.RawMessage()) {
		t.Fatal("fixture contained no embedded signing domain to tamper")
	}
	tampered, err := NewPostfixDeliveryStatusRequest(
		tamperedRaw,
		authenticated.OuterReversePath(),
		authenticated.OuterRecipients(),
		authenticated.Tenant(),
	)
	if err != nil {
		t.Fatal(err)
	}
	spy := &deliveryStatusAcquireSpy{}
	service := &SigningService{publicKeys: fixture.publicKeys, store: spy, clock: base.clock}
	result, err := service.SignDeliveryStatus(context.Background(), tampered)
	if err != nil || !result.Valid() || result.Result() != OperationPermerror ||
		result.Disposition() != OperationReject || spy.calls != 0 {
		t.Fatalf(
			"SignDeliveryStatus() result=%v error=%v policy_calls=%d",
			result, err, spy.calls,
		)
	}
}

// TestSigningServiceSignsAuthenticatedDeliveryStatus proves the daemon uses a
// real delivery-status policy only after exact embedded evidence succeeds.
func TestSigningServiceSignsAuthenticatedDeliveryStatus(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := authenticatedDeliveryStatusRequest(t, service)
	recorder := &deliveryStatusPolicyRecorder{next: service.store}
	service.store = recorder
	result, err := service.SignDeliveryStatus(context.Background(), request)
	assertSigningServicePass(t, result, err, signingServiceDSNSelector)
	if recorder.acquires != 1 || len(recorder.domains) != 1 ||
		recorder.domains[0] != signingServiceOriginDomain ||
		len(recorder.uses) != 1 || recorder.uses[0] != signingstore.PolicyDeliveryStatus {
		t.Fatalf("derived policy route domains=%v uses=%v acquires=%d", recorder.domains, recorder.uses, recorder.acquires)
	}
}

// TestSigningServiceSignsPostfixOrderedDeliveryStatus reproduces the exact
// field order emitted by Postfix bounce(8): its long-standing DSN form places
// Postfix extension fields before Arrival-Date and Original-Recipient after
// Final-Recipient. Only the Postfix-qualified fidelity may admit this form.
func TestSigningServiceSignsPostfixOrderedDeliveryStatus(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := authenticatedDeliveryStatusRequest(t, service)
	postfixRaw := bytes.Replace(
		request.RawMessage(),
		[]byte("Reporting-MTA: dns; "+signingServiceOriginDomain+"\r\n\r\n"+
			"Final-Recipient: rfc822; recipient@"+signingServiceOriginDomain+"\r\n"),
		[]byte("Reporting-MTA: dns; "+signingServiceOriginDomain+"\r\n"+
			"Original-Envelope-Id: synthetic-envid\r\n"+
			"X-Postfix-Queue-ID: synthetic-queue-id\r\n"+
			"X-Postfix-Sender: rfc822; sender@"+signingServiceOriginDomain+"\r\n"+
			"Arrival-Date: Tue, 14 Nov 2023 22:13:20 +0000 (UTC)\r\n\r\n"+
			"Final-Recipient: rfc822; recipient@"+signingServiceOriginDomain+"\r\n"+
			"Original-Recipient: rfc822; recipient@"+signingServiceOriginDomain+"\r\n"),
		1,
	)
	postfixRaw = bytes.Replace(
		postfixRaw,
		[]byte("Action: failed\r\nStatus: 5.1.1\r\n"),
		[]byte("Action: failed\r\nStatus: 5.1.1\r\n"+
			"Diagnostic-Code: smtp; 550 5.1.1 synthetic recipient rejected\r\n"),
		1,
	)
	if bytes.Equal(postfixRaw, request.RawMessage()) {
		t.Fatal("fixture did not acquire the Postfix delivery-status field order")
	}
	postfixRequest, err := NewPostfixDeliveryStatusRequest(
		postfixRaw,
		request.OuterReversePath(),
		request.OuterRecipients(),
		request.Tenant(),
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignDeliveryStatus(context.Background(), postfixRequest)
	assertSigningServicePass(t, result, err, signingServiceDSNSelector)
}

// TestSigningServiceSelectsTwoDerivedDSNDomains proves one daemon instance
// resolves independent delivery_status profiles from authenticated embedded
// d= values without any caller-selected domain.
func TestSigningServiceSelectsTwoDerivedDSNDomains(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	baseStore := service.store
	for _, testCase := range []struct {
		domain         string
		originSelector string
		dsnSelector    string
	}{
		{domain: signingServiceOriginDomain, originSelector: signingServiceOriginSelector, dsnSelector: signingServiceDSNSelector},
		{domain: signingServiceAlternateDomain, originSelector: signingServiceAlternateOriginSelector, dsnSelector: signingServiceAlternateDSNSelector},
	} {
		t.Run(testCase.domain, func(t *testing.T) {
			service.store = baseStore
			request := authenticatedDeliveryStatusRequestForDomain(
				t, service, testCase.domain, testCase.originSelector,
			)
			recorder := &deliveryStatusPolicyRecorder{next: baseStore}
			service.store = recorder
			result, err := service.SignDeliveryStatus(context.Background(), request)
			assertSigningServicePass(t, result, err, testCase.dsnSelector)
			if recorder.acquires != 1 || len(recorder.domains) != 1 ||
				recorder.domains[0] != testCase.domain || len(recorder.uses) != 1 ||
				recorder.uses[0] != signingstore.PolicyDeliveryStatus {
				t.Fatalf("derived policy route domains=%v uses=%v acquires=%d", recorder.domains, recorder.uses, recorder.acquires)
			}
		})
	}
}

// TestSigningServiceClassifiesDerivedDSNPolicyFailures proves policy lookup
// happens only after authentication and retains fail-closed resolution classes.
func TestSigningServiceClassifiesDerivedDSNPolicyFailures(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	base, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	base.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := authenticatedDeliveryStatusRequest(t, base)
	for _, testCase := range []struct {
		name        string
		err         error
		result      OperationResultClass
		disposition OperationDisposition
	}{
		{name: "missing", err: provider.NewError(provider.ErrorCodeNotFound), result: OperationPermerror, disposition: OperationReject},
		{name: "ambiguous", err: provider.NewError(provider.ErrorCodeAmbiguous), result: OperationTemperror, disposition: OperationTempfail},
		{name: "provider unavailable", err: provider.NewError(provider.ErrorCodeUnavailable), result: OperationTemperror, disposition: OperationTempfail},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			service := &SigningService{
				publicKeys: fixture.publicKeys,
				store:      policyFailureAuthority{err: testCase.err},
				clock:      base.clock,
			}
			result, err := service.SignDeliveryStatus(context.Background(), request)
			if err != nil || !result.Valid() || result.Result() != testCase.result ||
				result.Disposition() != testCase.disposition || len(result.Fields()) != 0 {
				t.Fatalf("SignDeliveryStatus() result=%v error=%v", result, err)
			}
		})
	}
}

// TestSigningServiceRejectsMismatchedDerivedDSNProfile proves a datasource
// cannot substitute a profile for any domain other than authenticated d=.
func TestSigningServiceRejectsMismatchedDerivedDSNProfile(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	base, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	base.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := authenticatedDeliveryStatusRequest(t, base)
	key := newSigningServiceRSAKey(t)
	handle, err := dkim2.NewPrivateKeyHandle([]byte("mismatched-dsn-key"))
	if err != nil {
		t.Fatal(err)
	}
	credential, err := dkim2.NewRSASigningCredential("mismatch", &key.PublicKey, handle)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := dkim2.NewRSASigningProfile("other.example.test", credential)
	if err != nil {
		t.Fatal(err)
	}
	authority := &deliveryStatusFixedProfileAuthority{profile: profile}
	service := &SigningService{publicKeys: fixture.publicKeys, store: authority, clock: base.clock}
	result, err := service.SignDeliveryStatus(context.Background(), request)
	if err != nil || !result.Valid() || result.Result() != OperationPermerror ||
		result.Disposition() != OperationReject || authority.signs != 0 {
		t.Fatalf("SignDeliveryStatus() result=%v error=%v signs=%d", result, err, authority.signs)
	}
}

func authenticatedDeliveryStatusRequest(t *testing.T, service *SigningService) DeliveryStatusRequest {
	return authenticatedDeliveryStatusRequestForDomain(
		t, service, signingServiceOriginDomain, signingServiceOriginSelector,
	)
}

func authenticatedDeliveryStatusRequestForDomain(
	t *testing.T,
	service *SigningService,
	domain string,
	originSelector string,
) DeliveryStatusRequest {
	t.Helper()
	originalRaw := []byte("From: sender@" + domain + "\r\nTo: recipient@" + domain + "\r\n\r\noriginal body\r\n")
	originalRecipients := [][]byte{[]byte("<recipient@" + domain + ">")}
	originalRequest, err := NewOperationRequest(
		OperationSign,
		originalRaw,
		[]byte("<sender@"+domain+">"),
		originalRecipients,
		signingServiceTestTenant,
		domain,
		FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal(err)
	}
	originalAssessment, err := service.Sign(context.Background(), originalRequest)
	if err != nil {
		t.Fatal(err)
	}
	original, applicable := originalAssessment.Result()
	if !applicable {
		t.Fatal("originator signing was not applicable")
	}
	assertSigningServicePass(t, original, nil, originSelector)
	embedded := insertSigningServiceFields(original.Fields(), originalRaw)
	outer := []byte("From: postmaster@" + domain + "\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; " + domain + "\r\n\r\nFinal-Recipient: rfc822; recipient@" + domain + "\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(embedded) + "\r\n--dsn--\r\n")
	request, err := NewPostfixDeliveryStatusRequest(
		outer,
		[]byte("<>"),
		[][]byte{[]byte("<sender@" + domain + ">")},
		signingServiceTestTenant,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
