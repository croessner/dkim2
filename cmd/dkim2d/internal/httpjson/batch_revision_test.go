package httpjson

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const (
	batchNullViaCase     = "null via"
	batchValidViaCase    = "valid via"
	batchBoundaryDomain  = "hosted.test"
	batchCrossTenantCase = "cross tenant via"
	batchLocalViaCase    = "local via"
)

// batchBoundaryAuthority explicitly provisions originator, transit, and DSN policies for one fixture key.
type batchBoundaryAuthority struct {
	*propagationtest.Authority
	key propagationtest.SigningKey
}

// Acquire opens a provider-neutral signing lease for the real HTTP fixture.
func (a *batchBoundaryAuthority) Acquire(ctx context.Context) (app.SigningLease, error) {
	if err := a.Open(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

// ResolvePolicy resolves only the fixture's exact configured tenant and domain.
func (a *batchBoundaryAuthority) ResolvePolicy(ctx context.Context, tenant, domain string, use signingstore.PolicyUse, at time.Time) (dkim2.SigningProfile, error) {
	if err := a.ResolveAnyProfile(ctx, tenant, domain, at); err != nil {
		return dkim2.SigningProfile{}, err
	}
	if domain != a.key.Domain || use != signingstore.PolicyOriginator && use != signingstore.PolicyOrdinaryTransit && use != signingstore.PolicyDeliveryStatus {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeNotFound)
	}
	return a.key.Profile, nil
}

// batchBoundaryFixture carries only test-owned keys and exact original/current evidence.
type batchBoundaryFixture struct {
	address, capability string
	readiness           *boundaryReadiness
	provider            *propagationtest.Provider
	authority           *batchBoundaryAuthority
	request             generated.BatchRevisionRequest
	current             []byte
}

// newBatchBoundaryFixture runs the actual tracked HTTP boundary and production signing service.
func newBatchBoundaryFixture(t *testing.T) batchBoundaryFixture {
	t.Helper()
	keys := (&propagationtest.Corpus{}).Provider(t)
	key := propagationtest.NewSigningKey(t, batchBoundaryDomain)
	keys.Publish(key)
	authority := &batchBoundaryAuthority{Authority: propagationtest.NewAuthority().AddProfile(propagateRouteTenant, key), key: key}
	service, err := app.NewAuthoritySigningService(keys, authority, config.SigningPoliciesConfig{})
	if err != nil {
		t.Fatal("batch service construction failed")
	}
	raw := []byte("From: sender@hosted.test\r\nTo: alias@hosted.test\r\nX-Spacing:\t  exact\r\n\r\nbody\r\n")
	signRequest, err := app.NewOperationRequest(app.OperationSign, raw, []byte("<sender@hosted.test>"), [][]byte{[]byte("<alias@hosted.test>")}, propagateRouteTenant, batchBoundaryDomain, app.FidelityRawRFC5322)
	if err != nil {
		t.Fatal("original request invalid")
	}
	assessment, err := service.Sign(context.Background(), signRequest)
	signed, ok := assessment.Result()
	if err != nil || !ok || signed.Result() != app.OperationPass {
		t.Fatal("original signing failed")
	}
	offset := bytes.Index(raw, []byte("\r\n\r\n")) + 2
	original := append([]byte(nil), raw[:offset]...)
	for _, field := range signed.Fields() {
		original = append(original, field.Bytes()...)
	}
	original = append(original, raw[offset:]...)
	current := append([]byte("Received: by queue.hosted.test\r\n"), original...)
	request := generated.BatchRevisionRequest{ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec06, Binding: strings.Repeat("a", 64),
		Original: generated.BatchRevisionOriginal{Message: batchWireMessage(t, original), Smtp: batchWireSMTP(t, "<sender@hosted.test>", "<alias@hosted.test>")}}
	request.Copies = []generated.BatchRevisionCopy{
		{Id: "local", Delivery: generated.Local, Message: batchWireMessage(t, current), Smtp: batchWireSMTP(t, "<sender@hosted.test>", "<local@hosted.test>")},
		{Id: "external-1", Delivery: generated.External, Message: batchWireMessage(t, current), Smtp: batchWireSMTP(t, "<prepared-1@srs.hosted.test>", "<one@external.test>"), Context: &generated.SigningContext{Tenant: propagateRouteTenant, Domain: batchBoundaryDomain}},
		{Id: "external-2", Delivery: generated.External, Message: batchWireMessage(t, current), Smtp: batchWireSMTP(t, "<prepared-2@srs.hosted.test>", "<two@external.test>"), Context: &generated.SigningContext{Tenant: propagateRouteTenant, Domain: batchBoundaryDomain}},
	}
	address, readiness := startBatchBoundary(t, service)
	return batchBoundaryFixture{address: address, readiness: readiness, provider: keys, authority: authority, request: request, current: current,
		capability: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb5}, 32))}
}

// startBatchBoundary composes the production tracked socket, capability gate, and generated dispatcher.
func startBatchBoundary(t *testing.T, service *app.SigningService) (string, *boundaryReadiness) {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen failed")
	}
	tracked, err := newTrackedListener(raw, nil)
	if err != nil {
		_ = raw.Close()
		t.Fatal("tracked listener failed")
	}
	validator, err := NewRequestValidator()
	if err != nil {
		_ = tracked.Close()
		t.Fatal("validator failed")
	}
	ready := &boundaryReadiness{}
	ready.ready.Store(true)
	handler, err := NewHTTPBoundary(BoundaryConfig{Authority: raw.Addr().String(), RequestDeadline: 10 * time.Second, MaxInFlight: 1, MaxWaiters: 1, AdmissionWait: time.Second},
		&boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xa5}, 32)}, ready, &boundaryProcessor{}, &boundaryFatalNotifier{}, validator,
		service, batchReviseMatcherDependency{&boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xb5}, 32)}})
	if err != nil {
		_ = tracked.Close()
		t.Fatal("boundary construction failed")
	}
	server := &http.Server{Handler: handler, ConnContext: tracked.ConnContext, ErrorLog: log.New(io.Discard, "", 0), DisableGeneralOptionsHandler: true, MaxHeaderBytes: transportServerMaxHeaderBytes}
	go func() { _ = server.Serve(tracked) }()
	t.Cleanup(func() { handler.Close(); _ = server.Close(); _ = tracked.Close() })
	return raw.Addr().String(), ready
}

// batchWireMessage creates the generated protected message DTO with explicit fidelity.
func batchWireMessage(t *testing.T, raw []byte) generated.MessageInput {
	t.Helper()
	fidelity := generated.RawRfc5322
	return generated.MessageInput{RawRfc5322Base64: mustProtectedString(t, base64.StdEncoding.EncodeToString(raw)), Fidelity: &fidelity}
}

// batchWireSMTP creates the generated protected envelope DTO for exactly one recipient.
func batchWireSMTP(t *testing.T, reverse, recipient string) generated.SMTPInput {
	t.Helper()
	return generated.SMTPInput{MailFrom: mustProtectedString(t, reverse), RcptTo: []wire.ProtectedString{mustProtectedString(t, recipient)}}
}

// exchangeBatch sends generated JSON through a real HTTP socket without a parallel DTO model.
func exchangeBatch(t *testing.T, f batchBoundaryFixture, body []byte, capability string) (int, generated.BatchRevisionResponse) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://"+f.address+batchRevisePath, bytes.NewReader(body))
	if err != nil {
		t.Fatal("request failed")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(batchReviseCapabilityHeader, capability)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal("HTTP exchange failed")
	}
	defer func() { _ = response.Body.Close() }()
	var result generated.BatchRevisionResponse
	if response.StatusCode == http.StatusOK && json.NewDecoder(response.Body).Decode(&result) != nil {
		t.Fatal("batch result decode failed")
	}
	return response.StatusCode, result
}

// marshalBatch encodes only the authoritative generated request model.
func marshalBatch(t *testing.T, request generated.BatchRevisionRequest) []byte {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal("batch request encoding failed")
	}
	return body
}

// TestBatchRevisionHTTPRealCrypto verifies both actual external outputs after a real socket request.
func TestBatchRevisionHTTPRealCrypto(t *testing.T) {
	f := newBatchBoundaryFixture(t)
	status, result := exchangeBatch(t, f, marshalBatch(t, f.request), f.capability)
	if status != 200 || result.Result != generated.BatchRevisionResponseResultPass || len(result.Outputs) != 2 {
		t.Fatalf("HTTP batch status=%d result=%s outputs=%d", status, result.Result, len(result.Outputs))
	}
	verifier, err := dkim2.NewVerifier(f.provider)
	if err != nil {
		t.Fatal("verifier failed")
	}
	for index, output := range result.Outputs {
		raw := append([]byte(nil), f.current[:output.InsertionOffset]...)
		for _, field := range output.HeaderFieldsBase64 {
			encoded, err := field.Bytes()
			if err != nil {
				t.Fatal("field inaccessible")
			}
			value, err := base64.StdEncoding.DecodeString(string(encoded))
			if err != nil {
				t.Fatal("field base64 failed")
			}
			raw = append(raw, value...)
		}
		raw = append(raw, f.current[output.InsertionOffset:]...)
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != output.ResultSha256 {
			t.Fatal("wire output digest mismatch")
		}
		smtp := f.request.Copies[index+1].Smtp
		reverse, _ := smtp.MailFrom.Bytes()
		recipient, _ := smtp.RcptTo[0].Bytes()
		verified, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, reverse, [][]byte{recipient}))
		if err != nil || verified.State() != dkim2.ResultStatePASS {
			t.Fatalf("wire cryptography failed: %s/%s", verified.State(), verified.PrimaryReason())
		}
	}
}

// TestBatchRevisionHTTPCapabilityIsDistinctAndReadinessIsHonest proves zero-signing feature discovery.
func TestBatchRevisionHTTPCapabilityIsDistinctAndReadinessIsHonest(t *testing.T) {
	f := newBatchBoundaryFixture(t)
	lookups, signs := f.provider.Lookups(), f.authority.Signs.Load()
	for _, test := range []struct {
		name, method, suffix, headers, credential string
		ready                                     bool
		want                                      int
	}{
		{name: "ready", method: http.MethodGet, credential: f.capability, ready: true, want: 200},
		{name: "missing", method: http.MethodGet, ready: true, want: 403},
		{name: "process token", method: http.MethodGet, credential: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32)), ready: true, want: 403},
		{name: "not ready", method: http.MethodGet, credential: f.capability, want: 503},
		{name: "query", method: http.MethodGet, suffix: "?probe", credential: f.capability, ready: true, want: 400},
		{name: "conditional", method: http.MethodGet, headers: "If-None-Match: *\r\n", credential: f.capability, ready: true, want: 400},
		{name: "body", method: http.MethodGet, headers: "Content-Length: 2\r\n", credential: f.capability, ready: true, want: 400},
		{name: "expect", method: http.MethodGet, headers: "Expect: 100-continue\r\n", credential: f.capability, ready: true, want: 417},
		{name: "post", method: http.MethodPost, credential: f.capability, ready: true, want: 405},
	} {
		t.Run(test.name, func(t *testing.T) {
			f.readiness.ready.Store(test.ready)
			raw := rawBoundaryExchange(t, f.address, test.method+" "+batchCapabilitiesPath+test.suffix+" HTTP/1.1\r\nHost: "+f.address+"\r\n"+batchReviseCapabilityHeader+": "+test.credential+"\r\n"+test.headers+"Connection: close\r\n\r\n")
			response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
			if err != nil {
				t.Fatal("capability response malformed")
			}
			defer func() { _ = response.Body.Close() }()
			if response.StatusCode != test.want {
				t.Fatalf("capability status=%d want=%d", response.StatusCode, test.want)
			}
			if test.want == 200 {
				var value generated.BatchRevisionCapabilities
				if json.NewDecoder(response.Body).Decode(&value) != nil || value != batchCapabilities() {
					t.Fatal("capability contract mismatch")
				}
			}
		})
	}
	if f.provider.Lookups() != lookups || f.authority.Signs.Load() != signs {
		t.Fatal("capability discovery performed signing or DNS")
	}
}

// TestBatchRevisionHTTPRejectsAmbiguousAndManipulatedEvidence preserves spelling, authority, and all-output binding.
func TestBatchRevisionHTTPRejectsAmbiguousAndManipulatedEvidence(t *testing.T) {
	for _, name := range []string{"wrong capability", "removed evidence", "wrong envelope", "escaped base64", "duplicate id", "missing fidelity", batchLocalViaCase, batchCrossTenantCase, batchNullViaCase, batchValidViaCase} {
		t.Run(name, func(t *testing.T) {
			f := newBatchBoundaryFixture(t)
			want := 400
			capability := f.capability
			switch name {
			case "wrong capability":
				capability = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
				want = 403
			case "removed evidence":
				f.request.Copies[2].Message = batchWireMessage(t, []byte("From: sender@hosted.test\r\n\r\nbody\r\n"))
				want = 200
			case "wrong envelope":
				f.request.Original.Smtp.MailFrom = mustProtectedString(t, "<other@hosted.test>")
				want = 200
			case "duplicate id":
				f.request.Copies[2].Id = f.request.Copies[1].Id
			case "missing fidelity":
				f.request.Original.Message.Fidelity = nil
			case batchLocalViaCase, batchCrossTenantCase, batchNullViaCase, batchValidViaCase:
				via := &generated.BatchRevisionHop{Smtp: batchWireSMTP(t, "<alias@hosted.test>", "<router@hosted.test>"), Context: generated.SigningContext{Tenant: propagateRouteTenant, Domain: batchBoundaryDomain}}
				if name == batchCrossTenantCase {
					via.Context.Tenant = "tenant-b"
				}
				if name == batchNullViaCase {
					via.Smtp.MailFrom = mustProtectedString(t, "<>")
				}
				index := 1
				if name == batchLocalViaCase {
					index = 0
				}
				f.request.Copies[index].Via = via
				if name == batchValidViaCase {
					want = 200
				}
			}
			body := marshalBatch(t, f.request)
			if name == "escaped base64" {
				body = bytes.Replace(body, []byte(`"raw_rfc5322_base64":"R`), []byte(`"raw_rfc5322_base64":"\u0052`), 1)
			}
			status, result := exchangeBatch(t, f, body, capability)
			if status != want {
				t.Fatalf("negative HTTP status=%d want=%d", status, want)
			}
			if want == 200 && name != batchValidViaCase && (result.Result == generated.BatchRevisionResponseResultPass || len(result.Outputs) != 0) {
				t.Fatal("invalid evidence received partial output")
			}
			if name == batchValidViaCase && result.Result != generated.BatchRevisionResponseResultPass {
				t.Fatal("valid controlled wire hop rejected")
			}
		})
	}
}
