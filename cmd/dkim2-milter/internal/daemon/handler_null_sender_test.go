package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/milter"
)

// nullSenderRecipient is the single ASCII forward path of every fixture.
const nullSenderRecipient = "<bob@example.net>"

// nullSenderAuthorDomain is the canonical From domain of the signed fixtures.
const nullSenderAuthorDomain = "author.example.test"

// nullSenderSignRecorder serves one sign route and records the exact null
// sender declaration, envelope sender, and context domain it received.
type nullSenderSignRecorder struct {
	calls      int
	mailFrom   any
	domain     any
	nullSender any
}

// server starts one recording sign endpoint answering a valid plan.
func (r *nullSenderSignRecorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		r.calls++
		if request.URL.String() != routeSign {
			t.Error("null-sender request escaped the originator route")
		}
		var document map[string]any
		if err := json.NewDecoder(request.Body).Decode(&document); err != nil {
			t.Error("generated request body was not JSON")
		}
		smtpInput, _ := document["smtp"].(map[string]any)
		contextValue, _ := document["context"].(map[string]any)
		r.mailFrom, r.domain, r.nullSender = smtpInput["mail_from"], contextValue["domain"], document["null_sender"]
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(validOperationResponse(generated.Sign))
	}))
	t.Cleanup(server.Close)
	return server
}

// newNullSenderHandler constructs one originator handler for a domain source
// and null-sender policy.
func newNullSenderHandler(t *testing.T, url string, source milter.DomainSource, policy milter.NullSenderPolicy) *Handler {
	t.Helper()
	domain := ""
	if source == milter.DomainSourceStatic {
		domain = testDomain
	}
	handler, err := NewHandler(
		url, testCapability(t), modeOriginator, testTenant, domain, source, testDSNDomain, "",
		WithNullSenderPolicy(policy),
	)
	if err != nil {
		t.Fatalf("NewHandler(%s, %s) failed", source, policy)
	}
	t.Cleanup(func() { _ = handler.Close() })
	return handler
}

// nullSenderMessage constructs one null reverse-path message.
func nullSenderMessage(t *testing.T, header string, recipient string) milter.Message {
	t.Helper()
	message, err := milter.NewMessage([]byte(header+"Subject: Auto: away\r\n\r\nbody\r\n"), []byte("<>"), [][]byte{[]byte(recipient)})
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// TestHandlerSignsNullSenderWithHeaderFromDomain proves the header_from
// policy derives the signing domain from the single From mailbox under both
// domain sources and declares the policy to the daemon.
func TestHandlerSignsNullSenderWithHeaderFromDomain(t *testing.T) {
	for _, source := range []milter.DomainSource{milter.DomainSourceEnvelopeSender, milter.DomainSourceStatic} {
		t.Run(string(source), func(t *testing.T) {
			recorder := &nullSenderSignRecorder{}
			handler := newNullSenderHandler(t, recorder.server(t).URL, source, milter.NullSenderHeaderFrom)
			message := nullSenderMessage(t, "From: Vacation <NoReply@Author.Example.TEST>\r\n", nullSenderRecipient)
			result, err := handler.Handle(t.Context(), message)
			if err != nil || recorder.calls != 1 || recorder.mailFrom != "<>" ||
				recorder.domain != nullSenderAuthorDomain || recorder.nullSender != string(generated.NullSenderHeaderFrom) ||
				result.Domains.Domains() != nullSenderAuthorDomain {
				t.Fatalf("Handle() result=%v error=%v calls=%d mail_from=%v domain=%v null_sender=%v",
					result, err, recorder.calls, recorder.mailFrom, recorder.domain, recorder.nullSender)
			}
		})
	}
}

// TestHandlerLeavesUnusableNullSenderAuthorsUnsigned proves an author that
// yields no canonical DNS domain is not applicable, like an unsupported
// envelope sender, and never reaches the daemon.
func TestHandlerLeavesUnusableNullSenderAuthorsUnsigned(t *testing.T) {
	recorder := &nullSenderSignRecorder{}
	handler := newNullSenderHandler(t, recorder.server(t).URL, milter.DomainSourceEnvelopeSender, milter.NullSenderHeaderFrom)
	for name, testCase := range map[string]struct {
		header, recipient string
		skip              milter.NullSenderSkip
	}{
		"missing From":       {header: "Sender: a@example.test\r\n", recipient: nullSenderRecipient, skip: milter.NullSenderSkipAuthorUnusable},
		"two From fields":    {header: "From: a@example.test\r\nFrom: b@example.test\r\n", recipient: nullSenderRecipient, skip: milter.NullSenderSkipAuthorUnusable},
		"two mailboxes":      {header: "From: a@example.test, b@example.test\r\n", recipient: nullSenderRecipient, skip: milter.NullSenderSkipAuthorUnusable},
		"group":              {header: "From: Team: a@example.test;\r\n", recipient: nullSenderRecipient, skip: milter.NullSenderSkipAuthorUnusable},
		"address literal":    {header: "From: a@[192.0.2.1]\r\n", recipient: nullSenderRecipient, skip: milter.NullSenderSkipAuthorUnusable},
		"SMTPUTF8 author":    {header: "From: a@b\xc3\xbccher.example\r\n", recipient: nullSenderRecipient, skip: milter.NullSenderSkipAuthorUnusable},
		"SMTPUTF8 recipient": {header: "From: a@example.test\r\n", recipient: "<b\xc3\xb6b@example.net>", skip: milter.NullSenderSkipEnvelopeUnsupported},
		"unsigned DSN": {
			header:    "From: MAILER-DAEMON@example.test\r\nContent-Type: Multipart/Report; Report-Type=\"Delivery-Status\"; boundary=b\r\n",
			recipient: nullSenderRecipient, skip: milter.NullSenderSkipDeliveryStatus,
		},
		"DKIM2-signed DSN": {
			header:    "Message-Instance: m=1; h=sha256:AA==\r\nDKIM2-Signature: i=1; d=example.test\r\nFrom: MAILER-DAEMON@example.test\r\nContent-Type: multipart/report; report-type=delivery-status; boundary=b\r\n",
			recipient: nullSenderRecipient, skip: milter.NullSenderSkipProtocolFields,
		},
		"forwarded DKIM2 field": {
			header:    "DKIM2-Signature: i=1; d=example.test\r\nFrom: a@example.test\r\n",
			recipient: nullSenderRecipient, skip: milter.NullSenderSkipProtocolFields,
		},
	} {
		result, err := handler.Handle(t.Context(), nullSenderMessage(t, testCase.header, testCase.recipient))
		if err != nil || result.Operation != operationSign || result.Result != verificationNone ||
			result.Outcome != milter.DispositionContinue || len(result.Actions) != 0 ||
			result.NullSenderSkip != testCase.skip {
			t.Fatalf("%s: Handle()=(%v,%v) skip=%q", name, result, err, result.NullSenderSkip)
		}
	}
	if recorder.calls != 0 {
		t.Fatalf("unusable null-sender authors reached the daemon: calls=%d", recorder.calls)
	}
}

// TestHandlerStillSignsNullSenderDispositionNotification proves an RFC 8098
// MDN, a multipart/report that is not a delivery-status report, keeps the
// header_from originator signing.
func TestHandlerStillSignsNullSenderDispositionNotification(t *testing.T) {
	recorder := &nullSenderSignRecorder{}
	handler := newNullSenderHandler(t, recorder.server(t).URL, milter.DomainSourceEnvelopeSender, milter.NullSenderHeaderFrom)
	message := nullSenderMessage(t,
		"From: alice@author.example.test\r\nContent-Type: multipart/report; report-type=disposition-notification; boundary=b\r\n",
		nullSenderRecipient,
	)
	result, err := handler.Handle(t.Context(), message)
	if err != nil || recorder.calls != 1 || recorder.domain != nullSenderAuthorDomain ||
		recorder.nullSender != string(generated.NullSenderHeaderFrom) || result.NullSenderSkip != "" {
		t.Fatalf("MDN Handle() result=%v error=%v calls=%d domain=%v", result, err, recorder.calls, recorder.domain)
	}
}

// TestHandlerKeepsNullSenderRejectByDefault proves the explicit reject policy
// and an omitted option keep the contract failure and never call the daemon,
// while ordinary senders never carry the declaration.
func TestHandlerKeepsNullSenderRejectByDefault(t *testing.T) {
	recorder := &nullSenderSignRecorder{}
	server := recorder.server(t)
	explicit := newNullSenderHandler(t, server.URL, milter.DomainSourceEnvelopeSender, milter.NullSenderReject)
	_, err := explicit.Handle(t.Context(), nullSenderMessage(t, "From: a@example.test\r\n", nullSenderRecipient))
	assertFailureClass(t, err, milter.FailureContract)
	if recorder.calls != 0 {
		t.Fatalf("reject policy reached the daemon: calls=%d", recorder.calls)
	}

	optIn := newNullSenderHandler(t, server.URL, milter.DomainSourceEnvelopeSender, milter.NullSenderHeaderFrom)
	ordinary, err := milter.NewMessage(
		[]byte("From: someone@other.example\r\n\r\nbody\r\n"), []byte("<sender@example.test>"),
		[][]byte{[]byte(nullSenderRecipient)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := optIn.Handle(t.Context(), ordinary); err != nil || recorder.calls != 1 ||
		recorder.nullSender != nil || recorder.domain != testDomain {
		t.Fatalf("ordinary sender error=%v calls=%d null_sender=%v domain=%v",
			err, recorder.calls, recorder.nullSender, recorder.domain)
	}
}

// TestNewHandlerConfinesNullSenderPolicyToOriginatorMode proves the opt-in
// cannot be attached to an inbound, transit, or Postfix DSN handler and that
// unknown or nil options are refused.
func TestNewHandlerConfinesNullSenderPolicyToOriginatorMode(t *testing.T) {
	for _, testCase := range []struct {
		mode, tenant, domain string
		source               milter.DomainSource
		authserv             string
	}{
		{mode: modeInbound, source: milter.DomainSourceStatic, authserv: testAuthservID},
		{mode: modeOrdinaryTransit, tenant: testTenant, domain: testDomain, source: milter.DomainSourceStatic},
		{mode: modePostfixDSN, tenant: testTenant, source: milter.DomainSourceVerifiedEmbedded},
	} {
		if handler, err := NewHandler(
			"http://127.0.0.1:1", testCapability(t), testCase.mode, testCase.tenant, testCase.domain,
			testCase.source, "", testCase.authserv, WithNullSenderPolicy(milter.NullSenderHeaderFrom),
		); err == nil || handler != nil {
			t.Fatalf("%s accepted the header_from null-sender policy", testCase.mode)
		}
	}
	for _, option := range []HandlerOption{WithNullSenderPolicy("accept"), WithNullSenderPolicy(""), nil} {
		if handler, err := NewHandler(
			"http://127.0.0.1:1", testCapability(t), modeOriginator, testTenant, testDomain,
			milter.DomainSourceStatic, testDSNDomain, "", option,
		); err == nil || handler != nil {
			t.Fatal("originator accepted an unknown or nil handler option")
		}
	}
}
