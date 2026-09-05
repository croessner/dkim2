package testclient

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/wire"
)

const (
	// propagationSignedNotification is the exact signed notification the oracle
	// returns; its SHA-256 digest is frozen in the propagation fixture.
	propagationSignedNotification = "TWVzc2FnZS1JbnN0YW5jZTogdj0xOyBpPTI7IGg9c2hhMjU2OnN5bnRoZXRpYw0KREtJTTItU2lnbmF0dXJlOiB2PTE7IGE9ZWQyNTUxOS1zaGEyNTY7IGQ9ZXhhbXBsZS50ZXN0OyBzPXRlc3Q7IGI9c3ludGhldGljDQpSZXR1cm4tUGF0aDogPD4NCkZyb206IE1BSUxFUi1EQUVNT05AbXguZXhhbXBsZS50ZXN0DQpUbzogPGJvdW5jZUBleGFtcGxlLnRlc3Q+DQpTdWJqZWN0OiBVbmRlbGl2ZXJlZCBNYWlsIFJldHVybmVkIHRvIFNlbmRlcg0KQ29udGVudC1UeXBlOiBtdWx0aXBhcnQvcmVwb3J0OyByZXBvcnQtdHlwZT1kZWxpdmVyeS1zdGF0dXM7IGJvdW5kYXJ5PSJiIg0KDQotLWINCkNvbnRlbnQtVHlwZTogdGV4dC9wbGFpbg0KDQpEZWxpdmVyeSBmYWlsZWQuDQotLWINCkNvbnRlbnQtVHlwZTogbWVzc2FnZS9kZWxpdmVyeS1zdGF0dXMNCg0KUmVwb3J0aW5nLU1UQTogZG5zOyBteC5leGFtcGxlLnRlc3QNCg0KQWN0aW9uOiBmYWlsZWQNClN0YXR1czogNS4xLjENCi0tYi0tDQo="
	// propagationCommitToken is the exact opaque token the oracle commits.
	propagationCommitToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	// propagationNextHop is the previous-hop forward path the oracle returns.
	propagationNextHop = "<previous-hop@relay.example>"
)

const alignedDeliveryStatus = `{"structure":"valid","embedded":"verified","outer_alignment":"aligned","recipient_linkage":"linked","local_hop":"local","propagation":"eligible"}`

const propagateAcceptResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","operation":"delivery_status_propagation","result":"pass","disposition":"accept","replay":{"class":"first_seen"},"delivery_status":` +
	alignedDeliveryStatus +
	`,"propagation":{"raw_rfc5322_base64":"` + propagationSignedNotification +
	`","next_hop_recipient":"` + propagationNextHop +
	`","commit_token":"` + propagationCommitToken +
	`","smtputf8_required":false,"eight_bit_mime_required":false}}`

const propagateDiscardResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","operation":"delivery_status_propagation","result":"pass","disposition":"discard","replay":{"class":"not_checked"},"delivery_status":{"structure":"valid","embedded":"verified","outer_alignment":"aligned","recipient_linkage":"linked","local_hop":"local","propagation":"not_failure"}}`

const propagatePermerrorResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","operation":"delivery_status_propagation","result":"permerror","disposition":"discard","replay":{"class":"not_checked"},"propagation_failure":"unprovisioned_domain","delivery_status":` +
	alignedDeliveryStatus + `}`

const propagateRejectResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","operation":"delivery_status_propagation","result":"fail","disposition":"reject","replay":{"class":"not_checked"},"delivery_status":{"structure":"valid","embedded":"verified","outer_alignment":"misaligned","recipient_linkage":"unlinked","local_hop":"not_local","propagation":"not_evaluated"}}`

const propagateCommitResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","state":"committed"}`

const receivedDSNProcessResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","authentication":{"state":"PASS","primary_reason":"none"},"verification":{"state":"PASS","primary_reason":"none","scope":"current","historical_content":"not_evaluated","historical_signatures":"not_evaluated","custody_structure":"not_evaluated","checks":[{"class":"protocol","reason":"none"}],"signature_sets":[]},"policy":{"mode":"strict","verdict":"accept","primary_reason":"protocol_pass","do_not_modify":"not_requested","do_not_explode":"not_requested","dns_testing_effective":false,"feedback":{"requested":false,"relay_required":false,"history_coverage":"not_evaluated"},"findings":[{"reason":"protocol_pass","severity":"info"}]},"replay":{"class":"first_seen"},"disposition":"accept","actions":[],"delivery_status":` +
	alignedDeliveryStatus + `}`

const unevaluatedDSNProcessResponse = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","authentication":{"state":"PASS","primary_reason":"none"},"verification":{"state":"PASS","primary_reason":"none","scope":"current","historical_content":"not_evaluated","historical_signatures":"not_evaluated","custody_structure":"not_evaluated","checks":[{"class":"protocol","reason":"none"}],"signature_sets":[]},"policy":{"mode":"strict","verdict":"accept","primary_reason":"protocol_pass","do_not_modify":"not_requested","do_not_explode":"not_requested","dns_testing_effective":false,"feedback":{"requested":false,"relay_required":false,"history_coverage":"not_evaluated"},"findings":[{"reason":"protocol_pass","severity":"info"}]},"replay":{"class":"first_seen"},"disposition":"accept","actions":[],"delivery_status":{"structure":"valid","embedded":"verified","outer_alignment":"aligned","recipient_linkage":"linked","local_hop":"not_evaluated","propagation":"not_evaluated"}}`

// propagationService is one daemon-compatible oracle for the propagation
// routes and for the received delivery-status projection of the process route.
type propagationService struct {
	processSecret   []byte
	propagateSecret []byte
	calls           atomic.Int32
}

// ServeHTTP answers each declared route after proving its exact credential.
func (s *propagationService) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.calls.Add(1)
	path := request.URL.EscapedPath()
	if path != processPath && path != dsnPropagatePath && path != dsnCommitPath {
		s.writeError(writer, http.StatusNotFound, "not_found")
		return
	}
	if request.Method != http.MethodPost {
		writer.Header().Set("Allow", http.MethodPost)
		s.writeError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !s.credentialAccepted(request, path) {
		s.writeError(writer, http.StatusForbidden, expectedForbiddenCode)
		return
	}
	if request.Header.Get(headerContentType) != mediaTypeJSON {
		s.writeError(writer, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return
	}
	if request.URL.RawQuery != "" {
		s.writeError(writer, http.StatusBadRequest, "invalid_contract")
		return
	}
	switch path {
	case processPath:
		s.serveProcess(writer, request)
	case dsnPropagatePath:
		s.servePropagate(writer, request)
	case dsnCommitPath:
		s.serveCommit(writer, request)
	}
}

// credentialAccepted proves each route sees exactly its own capability field.
func (s *propagationService) credentialAccepted(request *http.Request, path string) bool {
	header := capabilityHeader
	expected := s.processSecret
	if path != processPath {
		header = dsnPropagateCapabilityHeader
		expected = s.propagateSecret
	}
	values := request.Header.Values(header)
	if len(values) != 1 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	return err == nil && bytes.Equal(decoded, expected)
}

// serveProcess answers the inbound route with or without a resolved tenant.
func (s *propagationService) serveProcess(writer http.ResponseWriter, request *http.Request) {
	var input generated.ProcessRequest
	if !decodeGeneratedBody(request, &input) {
		s.writeError(writer, http.StatusBadRequest, expectedInvalidJSONCode)
		return
	}
	if input.Context == nil {
		s.writeJSON(writer, http.StatusOK, unevaluatedDSNProcessResponse)
		return
	}
	s.writeJSON(writer, http.StatusOK, receivedDSNProcessResponse)
}

// servePropagate selects one frozen propagation outcome per fixture tenant.
func (s *propagationService) servePropagate(writer http.ResponseWriter, request *http.Request) {
	var input generated.DSNPropagateRequest
	if !decodeGeneratedBody(request, &input) {
		s.writeError(writer, http.StatusBadRequest, "invalid_contract")
		return
	}
	switch input.Context.Tenant {
	case "tenant-not-failure":
		s.writeJSON(writer, http.StatusOK, propagateDiscardResponse)
	case "tenant-unprovisioned":
		s.writeJSON(writer, http.StatusOK, propagatePermerrorResponse)
	case "tenant-not-ours":
		s.writeJSON(writer, http.StatusOK, propagateRejectResponse)
	default:
		s.writeJSON(writer, http.StatusOK, propagateAcceptResponse)
	}
}

// serveCommit commits the known coordinate and refuses every other token.
func (s *propagationService) serveCommit(writer http.ResponseWriter, request *http.Request) {
	var input generated.DSNPropagateCommitRequest
	if !decodeGeneratedBody(request, &input) {
		s.writeError(writer, http.StatusBadRequest, "invalid_contract")
		return
	}
	token, err := input.CommitToken.Bytes()
	if err != nil || string(token) != propagationCommitToken {
		s.writeError(writer, http.StatusConflict, "propagation_commit_unresolved")
		return
	}
	s.writeJSON(writer, http.StatusOK, propagateCommitResponse)
}

// writeError emits one complete request-category OpenAPI error.
func (s *propagationService) writeError(
	writer http.ResponseWriter,
	status int,
	code string,
) {
	s.writeJSON(
		writer, status,
		`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","code":"`+
			code+`","category":"request"}`,
	)
}

// writeJSON emits exact daemon response metadata and one bounded body.
func (*propagationService) writeJSON(writer http.ResponseWriter, status int, body string) {
	writer.Header().Set(headerCacheControl, cacheNoStore)
	writer.Header().Set("X-Content-Type-Options", contentNoSniff)
	writer.Header().Set(headerContentType, mediaTypeJSON)
	writer.Header().Set(headerContentLength, itoa(len(body)))
	writer.Header().Set(headerConnection, connectionClose)
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, body)
}

// itoa renders one nonnegative length without importing a formatting verb.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

// TestPropagationFixturesRunOverLoopbackSocket crosses the protected propagation
// capability, the generated client, the real loopback transport, and the stable
// projection for both propagation routes and the received-DSN process cases.
func TestPropagationFixturesRunOverLoopbackSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("loopback listeners are unavailable in this test environment")
	}
	handler := &propagationService{
		processSecret:   bytes.Repeat([]byte{0xd8}, 32),
		propagateSecret: bytes.Repeat([]byte{0xe9}, 32),
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		<-done
	})

	directory := t.TempDir()
	processCapability := filepath.Join(directory, "process-capability")
	propagateCapability := filepath.Join(directory, "dsn-propagate-capability")
	for path, value := range map[string][]byte{
		processCapability:   handler.processSecret,
		propagateCapability: handler.propagateSecret,
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal("write protected propagation capability")
		}
	}

	options := DefaultOptions()
	options.ServerURL = "http://" + listener.Addr().String()
	options.CapabilityFile = processCapability
	options.DSNPropagateCapabilityFile = propagateCapability
	var output bytes.Buffer
	if err := NewApplication(&output).Run(options, propagationFixturePaths(t)); err != nil {
		t.Fatalf(
			"propagation fixture matrix failed with %s after %d calls",
			ExitClassOf(err).String(), handler.calls.Load(),
		)
	}
	text := output.String()
	if strings.Count(text, "\n") != 11 {
		t.Fatalf("propagation results = %d records, want 11", strings.Count(text, "\n"))
	}
	for _, marker := range []string{
		propagationSignedNotification, propagationCommitToken, propagationNextHop,
		"bounce@example.test", "MAILER-DAEMON",
		base64.RawURLEncoding.EncodeToString(handler.propagateSecret),
	} {
		if strings.Contains(text, marker) {
			t.Fatal("propagation results leaked protected notification material")
		}
	}
	if !strings.Contains(text, `"propagation_digest":"d92a12fb49d8f63e69357981cdb53dd3179fd7ad48c375a7231be2d2847e7474"`) ||
		!strings.Contains(text, `"propagation_disposition":"discard"`) ||
		!strings.Contains(text, `"propagation_failure":"unprovisioned_domain"`) ||
		!strings.Contains(text, `"propagation_state":"committed"`) ||
		!strings.Contains(text, `"local_hop":"not_evaluated"`) {
		t.Fatal("propagation results lost their stable closed projections")
	}
}

// propagationFixturePaths returns the deterministic propagation fixture set.
func propagationFixturePaths(t *testing.T) []string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source unavailable")
	}
	fixtures := filepath.Join(
		filepath.Dir(filepath.Dir(filepath.Dir(source))),
		"testdata", "fixtures", draftVersion,
	)
	return []string{
		filepath.Join(fixtures, "process-received-dsn.json"),
		filepath.Join(fixtures, "propagate-commit.json"),
		filepath.Join(fixtures, "propagate-negative.json"),
		filepath.Join(fixtures, "propagate.json"),
	}
}

// TestPropagationProjectionKeepsNotificationBytesOutOfOutput proves the stable
// record carries only the digest of a produced notification.
func TestPropagationProjectionKeepsNotificationBytesOutOfOutput(t *testing.T) {
	t.Parallel()
	var value generated.DSNPropagateResponse
	if err := json.Unmarshal([]byte(propagateAcceptResponse), &value); err != nil {
		t.Fatal("decoding the frozen propagation response failed")
	}
	if !validDSNPropagate(value) {
		t.Fatal("the frozen propagation response was rejected")
	}
	record := ResultRecord{Schema: outputSchema, Draft: draftVersion, Outcome: outcomeMatch}
	projectPropagation(&record, ResponseFact{DSNPropagate: &value})
	if record.PropagationDigest == nil ||
		!validNotificationDigest(*record.PropagationDigest) {
		t.Fatal("the propagation projection lost its notification digest")
	}
	var encoded bytes.Buffer
	if err := writeRecord(&encoded, record); err != nil {
		t.Fatal("writing the propagation record failed")
	}
	for _, marker := range []string{
		propagationSignedNotification, propagationCommitToken, propagationNextHop,
	} {
		if strings.Contains(encoded.String(), marker) {
			t.Fatal("the propagation record exposed protected notification material")
		}
	}
}

// TestPropagationResponseCoherenceFailsClosed proves every contradictory
// combination of result, disposition, and conditional member is refused.
func TestPropagationResponseCoherenceFailsClosed(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*generated.DSNPropagateResponse){
		"accept without propagation": func(value *generated.DSNPropagateResponse) {
			value.Propagation = nil
		},
		"discard with propagation": func(value *generated.DSNPropagateResponse) {
			value.Disposition = generated.PropagationDispositionDiscard
		},
		"pass with failure reason": func(value *generated.DSNPropagateResponse) {
			failure := generated.PropagationFailureUnprovisionedDomain
			value.PropagationFailure = &failure
		},
		"fail with accept": func(value *generated.DSNPropagateResponse) {
			value.Result = generated.PropagationResultFail
		},
		"unknown projection member": func(value *generated.DSNPropagateResponse) {
			value.DeliveryStatus = &generated.DeliveryStatusProjection{
				Embedded:         generated.DeliveryStatusEmbeddedVerified,
				LocalHop:         generated.DeliveryStatusLocalHopLocal,
				OuterAlignment:   generated.DeliveryStatusProjectionOuterAlignment("future"),
				Propagation:      generated.DeliveryStatusPropagationEligible,
				RecipientLinkage: generated.DeliveryStatusRecipientLinkageLinked,
				Structure:        generated.DeliveryStatusStructureValid,
			}
		},
		"unbracketed next hop": func(value *generated.DSNPropagateResponse) {
			var replacement generated.PropagationOutput
			if value.Propagation != nil {
				replacement = *value.Propagation
			}
			recipient, err := wire.NewProtectedString("previous-hop@relay.example")
			if err != nil {
				return
			}
			replacement.NextHopRecipient = recipient
			value.Propagation = &replacement
		},
	} {
		var value generated.DSNPropagateResponse
		if err := json.Unmarshal([]byte(propagateAcceptResponse), &value); err != nil {
			t.Fatal("decoding the frozen propagation response failed")
		}
		mutate(&value)
		if validDSNPropagate(value) {
			t.Fatalf("incoherent propagation response accepted: %s", name)
		}
	}
}
