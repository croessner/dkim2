//nolint:goconst // Exact envelope fixtures remain local to independent mapper assertions.
package httpjson

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
)

type noOperationPublicKeyProvider struct{ calls int }

// LookupPublicKey records any forbidden lookup from unsigned wire processing.
func (p *noOperationPublicKeyProvider) LookupPublicKey(
	context.Context,
	dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	p.calls++
	return dkim2.PublicKeyResult{}, errors.New("unexpected public key lookup")
}

// TestMapOperationRequestPreservesExactBytes proves generated DTO isolation and fidelity.
func TestMapOperationRequestPreservesExactBytes(t *testing.T) {
	raw := []byte("From: sender@example.test\r\n\r\nbody\r\n")
	request := operationRequestFixture(t, raw)
	mapped, err := MapSignRequest(request)
	if err != nil {
		t.Fatalf("MapSignRequest() error = %v", err)
	}
	if mapped.Operation() != app.OperationSign ||
		string(mapped.RawMessage()) != string(raw) ||
		string(mapped.ReversePath()) != "<sender@example.test>" ||
		len(mapped.Recipients()) != 1 ||
		string(mapped.Recipients()[0]) != "<recipient@example.net>" ||
		mapped.Fidelity() != app.FidelityMilterReconstructedCRLF {
		t.Fatal("mapped operation changed exact request evidence")
	}
}

// TestMapOperationRequestAdmitsOnlyTransportFilterEximFidelity proves route compatibility.
func TestMapOperationRequestAdmitsOnlyTransportFilterEximFidelity(t *testing.T) {
	request := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\nbody\r\n"))
	transport := generated.EximTransportFilterCrlf
	request.Message.Fidelity = &transport
	if mapped, err := MapSignRequest(request); err != nil ||
		mapped.Fidelity() != app.FidelityEximTransportFilterCRLF {
		t.Fatal("Exim transport-filter fidelity was not mapped")
	}
	localScan := generated.EximLocalScanObservedCrlf
	request.Message.Fidelity = &localScan
	if _, err := MapSignRequest(request); !IsMappingError(err, MappingInvalidContract) {
		t.Fatal("Exim local-scan fidelity crossed into sign")
	}
}

// TestGenericOperationRequestsRejectNullReversePath reserves null paths for DSN operations.
func TestGenericOperationRequestsRejectNullReversePath(t *testing.T) {
	request := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\nbody\r\n"))
	nullPath, err := wire.NewProtectedString("<>")
	if err != nil {
		t.Fatal(err)
	}
	request.Smtp.MailFrom = nullPath
	if _, err := MapSignRequest(request); !IsMappingError(err, MappingInvalidContract) {
		t.Fatalf("MapSignRequest(null) error = %v", err)
	}

	revise := generated.ReviseRequest{
		ApiVersion: request.ApiVersion, Draft: request.Draft, Message: request.Message,
		Smtp: request.Smtp, IncomingSmtp: request.Smtp, Context: request.Context,
	}
	if _, err := MapReviseRequest(revise); !IsMappingError(err, MappingInvalidContract) {
		t.Fatalf("MapReviseRequest(null) error = %v", err)
	}
}

// TestMapDeliveryStatusRequestReservesExactNullSenderEvidence proves the
// Postfix-exclusive route admits no caller-selected representation and keeps
// the exact outer DSN envelope before profile resolution.
func TestMapDeliveryStatusRequestReservesExactNullSenderEvidence(t *testing.T) {
	base := operationRequestFixture(t, []byte("From: postmaster@example.test\r\n\r\nDSN\r\n"))
	request := generated.DSNSignRequest{
		ApiVersion: base.ApiVersion,
		Draft:      base.Draft,
		Message: generated.DSNMessageInput{
			RawRfc5322Base64: base.Message.RawRfc5322Base64,
		},
		OuterSmtp: generated.SMTPInput{
			MailFrom: mustProtectedString(t, "<>"),
			RcptTo:   []wire.ProtectedString{mustProtectedString(t, "<postmaster@example.test>")},
		},
		Context: generated.DeliveryStatusContext{Tenant: base.Context.Tenant},
	}
	mapped, err := MapDeliveryStatusRequest(request)
	if err != nil || string(mapped.OuterReversePath()) != "<>" {
		t.Fatalf("MapDeliveryStatusRequest() request=%v error=%v", mapped, err)
	}
	request.OuterSmtp.MailFrom = mustProtectedString(t, "<sender@example.test>")
	if _, err := MapDeliveryStatusRequest(request); !IsMappingError(err, MappingInvalidContract) {
		t.Fatalf("non-null outer path error = %v", err)
	}
	request.OuterSmtp.MailFrom = mustProtectedString(t, "<>")
	request.OuterSmtp.RcptTo = append(request.OuterSmtp.RcptTo, mustProtectedString(t, "<second@example.test>"))
	if _, err := MapDeliveryStatusRequest(request); !IsMappingError(err, MappingInvalidContract) {
		t.Fatalf("multiple outer recipients error = %v", err)
	}
}

// TestMapReviseRequestPreservesDistinctEnvelopeEvidence proves inherited
// verification evidence cannot be replaced by the outgoing signing envelope.
func TestMapReviseRequestPreservesDistinctEnvelopeEvidence(t *testing.T) {
	sign := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\nbody\r\n"))
	incomingReverse, err := wire.NewProtectedString("<original@example.test>")
	if err != nil {
		t.Fatal("incoming reverse fixture construction failed")
	}
	incomingRecipient, err := wire.NewProtectedString("<original@example.net>")
	if err != nil {
		t.Fatal("incoming recipient fixture construction failed")
	}
	request := generated.ReviseRequest{
		ApiVersion: sign.ApiVersion,
		Context:    sign.Context,
		Draft:      sign.Draft,
		Message:    sign.Message,
		IncomingSmtp: generated.SMTPInput{
			MailFrom: incomingReverse,
			RcptTo:   []wire.ProtectedString{incomingRecipient},
		},
		Smtp: sign.Smtp,
	}
	mapped, err := MapReviseRequest(request)
	if err != nil {
		t.Fatalf("MapReviseRequest() error = %v", err)
	}
	if mapped.Operation() != app.OperationRevise ||
		string(mapped.IncomingReversePath()) != "<original@example.test>" ||
		len(mapped.IncomingRecipients()) != 1 ||
		string(mapped.IncomingRecipients()[0]) != "<original@example.net>" ||
		string(mapped.ReversePath()) != "<sender@example.test>" ||
		len(mapped.Recipients()) != 1 ||
		string(mapped.Recipients()[0]) != "<recipient@example.net>" {
		t.Fatal("revision mapper conflated incoming and outgoing envelope evidence")
	}
}

// TestMapOperationRequestFailsClosedOnSMTPUTF8Signing proves current signing bounds.
func TestMapOperationRequestFailsClosedOnSMTPUTF8Signing(t *testing.T) {
	request := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\n"))
	protected, err := wire.NewProtectedString("<séndér@example.test>")
	if err != nil {
		t.Fatal("protected fixture construction failed")
	}
	request.Smtp.MailFrom = protected
	if _, err := MapSignRequest(request); !IsMappingError(err, MappingInvalidContract) {
		t.Fatalf("SMTPUTF8 signing error = %v", err)
	}
}

// TestMapOperationRequestRejectsInvalidDNSDomainsBeforeServiceWork proves
// signing identity uses the authoritative ASCII DNS label grammar.
func TestMapOperationRequestRejectsInvalidDNSDomainsBeforeServiceWork(t *testing.T) {
	for _, domain := range []string{
		"example..test",
		"a-.example",
		strings.Repeat("a", 64) + ".example",
	} {
		request := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\n"))
		request.Context.Domain = domain
		if _, err := MapSignRequest(request); !IsMappingError(err, MappingInvalidContract) {
			t.Fatalf("MapSignRequest(domain=%q) error = %v", domain, err)
		}
	}
}

// TestMapOperationResultRequiresExactActionOrder proves full-plan admission.
func TestMapOperationResultRequiresExactActionOrder(t *testing.T) {
	instance, _ := app.NewCompletedField([]byte("Message-Instance: m=1; h=sha256:AA==\r\n"))
	signature, _ := app.NewCompletedField([]byte("DKIM2-Signature: i=1;\r\n b=AA==\r\n"))
	result, err := app.NewOperationResult(
		app.OperationSign, app.OperationPass, app.OperationAccept,
		[]app.CompletedField{instance, signature},
	)
	if err != nil {
		t.Fatal("operation fixture construction failed")
	}
	mapped, err := MapOperationResult(result)
	if err != nil || len(mapped.Actions) != 2 ||
		mapped.Actions[0].Name != generated.MessageInstance ||
		mapped.Actions[1].Name != generated.DKIM2Signature ||
		strings.ContainsAny(mapped.Actions[1].Value, "\r\n") {
		t.Fatalf("mapped action result = %#v/%v", mapped, err)
	}
	reversed, _ := app.NewOperationResult(
		app.OperationSign, app.OperationPass, app.OperationAccept,
		[]app.CompletedField{signature, instance},
	)
	if _, err := MapOperationResult(reversed); !IsMappingError(err, MappingInternalContract) {
		t.Fatalf("reversed plan error = %v", err)
	}
	incoherent, err := app.NewOperationResult(
		app.OperationSign, app.OperationTemperror, app.OperationAccept,
		[]app.CompletedField{instance, signature},
	)
	if err == nil {
		t.Fatal("temperror plus accepting mutation constructed")
	}
	if _, mapErr := MapOperationResult(incoherent); !IsMappingError(
		mapErr,
		MappingInternalContract,
	) {
		t.Fatalf("incoherent result mapping error = %v", mapErr)
	}
}

// TestStrictAdapterUsesInjectedOperationService proves HTTP status alone is not authority.
func TestStrictAdapterUsesInjectedOperationService(t *testing.T) {
	service := &operationServiceStub{}
	adapter, err := newStrictAdapter(&adapterReadinessStub{}, &adapterProcessorStub{}, service)
	if err != nil {
		t.Fatalf("newStrictAdapter() error = %v", err)
	}
	request := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\n"))
	response, err := adapter.SignMessage(context.Background(), generated.SignMessageRequestObject{Body: &request})
	if err != nil || response == nil || service.signCalls != 1 {
		t.Fatalf("SignMessage() response/calls/error = %v/%d/%v", response, service.signCalls, err)
	}
	service.err = errors.New("private marker must not escape")
	if response, err = adapter.SignMessage(context.Background(), generated.SignMessageRequestObject{Body: &request}); response != nil || err == nil || strings.Contains(err.Error(), "private marker") {
		t.Fatalf("failed SignMessage() response/error = %v/%v", response, err)
	}
}

// TestStrictAdapterReturnsBodylessOriginatorNotApplicable proves the distinct
// absent-policy wire variant cannot carry a result or mutation plan.
func TestStrictAdapterReturnsBodylessOriginatorNotApplicable(t *testing.T) {
	service := &operationServiceStub{notApplicable: true}
	adapter, err := newStrictAdapter(&adapterReadinessStub{}, &adapterProcessorStub{}, service)
	if err != nil {
		t.Fatalf("newStrictAdapter() error = %v", err)
	}
	request := operationRequestFixture(t, []byte("From: sender@example.test\r\n\r\n"))
	response, err := adapter.SignMessage(context.Background(), generated.SignMessageRequestObject{Body: &request})
	if err != nil || service.signCalls != 1 {
		t.Fatalf("SignMessage() response/calls/error = %v/%d/%v", response, service.signCalls, err)
	}
	if _, ok := response.(generated.SignMessage204Response); !ok {
		t.Fatalf("SignMessage() response type = %T", response)
	}
}

// TestGeneratedStrictHandlerWritesBodylessNotApplicableResponses crosses the
// real HTTP transport for both inbound and originator applicability variants.
func TestGeneratedStrictHandlerWritesBodylessNotApplicableResponses(t *testing.T) {
	provider := &noOperationPublicKeyProvider{}
	verifier, err := dkim2.NewVerifier(provider)
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	domain, err := app.NewDomainProcessor(verifier, config.PolicyStrict)
	if err != nil {
		t.Fatalf("NewDomainProcessor() error = %v", err)
	}
	processor, err := app.NewInboundProcessor(domain, app.NewDisabledReplayCoordinator())
	if err != nil {
		t.Fatalf("NewInboundProcessor() error = %v", err)
	}
	operations := &operationServiceStub{notApplicable: true}
	adapter, err := newStrictAdapter(&adapterReadinessStub{}, processor, operations)
	if err != nil {
		t.Fatalf("newStrictAdapter() error = %v", err)
	}
	workingSetMiddleware := func(
		next generated.StrictHandlerFunc,
		_ string,
	) generated.StrictHandlerFunc {
		return func(
			ctx context.Context,
			writer http.ResponseWriter,
			request *http.Request,
			input any,
		) (any, error) {
			ledger, ledgerErr := newWorkingSetLedger(processWorkingSetUnitBytes)
			if ledgerErr != nil {
				return nil, &strictAdapterError{class: strictFailureInternal}
			}
			defer ledger.ReleaseAll()
			if ledgerErr = ledger.Claim(
				workingSetFixedStorage,
				maximumFixedRequestStorageBytes,
			); ledgerErr != nil {
				return nil, &strictAdapterError{class: strictFailureInternal}
			}
			for _, transition := range []func() error{
				ledger.BeginBodyRead,
				ledger.FinishBodyRead,
				ledger.BeginValidation,
				ledger.FinishValidation,
				ledger.BeginGeneratedProcessing,
			} {
				if ledgerErr = transition(); ledgerErr != nil {
					return nil, &strictAdapterError{class: strictFailureInternal}
				}
			}
			workingContext, holder, contextErr := withWorkingSetContext(ctx, ledger)
			if contextErr != nil {
				return nil, &strictAdapterError{class: strictFailureInternal}
			}
			defer holder.Clear()
			return next(workingContext, writer, request, input)
		}
	}
	server := httptest.NewServer(generated.Handler(generated.NewStrictHandler(
		adapter,
		[]generated.StrictMiddlewareFunc{workingSetMiddleware},
	)))
	t.Cleanup(server.Close)

	raw := base64.StdEncoding.EncodeToString(
		[]byte("From: sender@example.test\r\nSubject: unsigned\r\n\r\nbody\r\n"),
	)
	processBody := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"message":{"raw_rfc5322_base64":"` + raw + `","fidelity":"milter_reconstructed_crlf"},` +
		`"smtp":{"mail_from":"<sender@example.test>","rcpt_to":["<recipient@example.test>"]}}`
	signBody := `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
		`"message":{"raw_rfc5322_base64":"` + raw + `","fidelity":"milter_reconstructed_crlf"},` +
		`"smtp":{"mail_from":"<sender@example.test>","rcpt_to":["<recipient@example.test>"]},` +
		`"context":{"tenant":"tenant-a","domain":"example.test"}}`
	for _, testCase := range []struct {
		name string
		path string
		body string
	}{
		{name: "inbound", path: "/v1/process", body: processBody},
		{name: "originator", path: "/v1/sign", body: signBody},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request, requestErr := http.NewRequestWithContext(
				t.Context(), http.MethodPost, server.URL+testCase.path,
				strings.NewReader(testCase.body),
			)
			if requestErr != nil {
				t.Fatalf("NewRequestWithContext() error = %v", requestErr)
			}
			request.Header.Set("Content-Type", "application/json")
			response, requestErr := server.Client().Do(request)
			if requestErr != nil {
				t.Fatalf("Do() error = %v", requestErr)
			}
			body, readErr := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNoContent ||
				len(body) != 0 || response.Header.Get("Content-Type") != "" ||
				response.Header.Get("Content-Length") != "" ||
				response.Header.Get("Cache-Control") != cacheControlNoStore || !response.Close {
				t.Fatalf(
					"wire response status=%d body=%q type=%q length=%q cache=%q close=%t read=%v close_err=%v",
					response.StatusCode, body, response.Header.Get("Content-Type"),
					response.Header.Get("Content-Length"), response.Header.Get("Cache-Control"),
					response.Close, readErr, closeErr,
				)
			}
		})
	}
	if provider.calls != 0 || operations.signCalls != 1 {
		t.Fatalf("forbidden work: DNS calls=%d sign calls=%d", provider.calls, operations.signCalls)
	}
}

type operationServiceStub struct {
	signCalls     int
	err           error
	notApplicable bool
}

// Sign returns one deterministic signing result.
func (s *operationServiceStub) Sign(_ context.Context, _ app.OperationRequest) (app.SigningAssessment, error) {
	s.signCalls++
	if s.err != nil {
		return app.SigningAssessment{}, s.err
	}
	if s.notApplicable {
		return app.NewNotApplicableSigningAssessment(), nil
	}
	instance, _ := app.NewCompletedField([]byte("Message-Instance: m=1; h=sha256:AA==\r\n"))
	signature, _ := app.NewCompletedField([]byte("DKIM2-Signature: i=1; b=AA==\r\n"))
	result, err := app.NewOperationResult(
		app.OperationSign, app.OperationPass, app.OperationAccept,
		[]app.CompletedField{instance, signature},
	)
	if err != nil {
		return app.SigningAssessment{}, err
	}
	return app.NewApplicableSigningAssessment(result)
}

// Revise returns a closed unmodified completion for interface coverage.
func (*operationServiceStub) Revise(context.Context, app.OperationRequest) (app.OperationResult, error) {
	return app.NewOperationResult(
		app.OperationRevise, app.OperationPass, app.OperationContinue, nil,
	)
}

// SignDeliveryStatus keeps this focused ordinary-operation stub closed for DSN requests.
func (*operationServiceStub) SignDeliveryStatus(
	context.Context,
	app.DeliveryStatusRequest,
) (app.OperationResult, error) {
	return app.NewOperationResult(
		app.OperationDeliveryStatus, app.OperationPermerror, app.OperationReject, nil,
	)
}

// mustProtectedString constructs one test-only protected wire scalar.
func mustProtectedString(t *testing.T, value string) wire.ProtectedString {
	t.Helper()
	protected, err := wire.NewProtectedString(value)
	if err != nil {
		t.Fatal(err)
	}
	return protected
}

// operationRequestFixture constructs one exact generated signing request.
func operationRequestFixture(t *testing.T, raw []byte) generated.SignRequest {
	t.Helper()
	message, err := wire.NewProtectedString(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal("message fixture construction failed")
	}
	reverse, err := wire.NewProtectedString("<sender@example.test>")
	if err != nil {
		t.Fatal("reverse fixture construction failed")
	}
	recipient, err := wire.NewProtectedString("<recipient@example.net>")
	if err != nil {
		t.Fatal("recipient fixture construction failed")
	}
	fidelity := generated.MilterReconstructedCrlf
	return generated.SignRequest{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec04,
		Message: generated.MessageInput{
			RawRfc5322Base64: message,
			Fidelity:         &fidelity,
		},
		Smtp: generated.SMTPInput{
			MailFrom: reverse,
			RcptTo:   []wire.ProtectedString{recipient},
		},
		Context: generated.SigningContext{Tenant: "tenant-a", Domain: "example.test"},
	}
}
