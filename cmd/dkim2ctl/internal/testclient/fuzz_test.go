package testclient

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// FuzzFixtureDecoding exercises strict JSON, member, bound, and semantic handling.
func FuzzFixtureDecoding(f *testing.F) {
	f.Add([]byte(validHealthFixture))
	f.Add([]byte(`{"schema":"dkim2ctl.fixture.v1","schema":"duplicate"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFixtureBytes+1 {
			return
		}
		_, _, err := decodeFixture(data)
		if err != nil && ExitClassOf(err) != ExitFixture {
			t.Fatal("fixture decoder returned an unstable class")
		}
	})
}

// FuzzNegativeMutationConstruction proves arbitrary input cannot create a generic sender.
func FuzzNegativeMutationConstruction(f *testing.F) {
	f.Add(mutationMissingCapability)
	f.Add(mutationUnsupportedMedia)
	f.Add("arbitrary")
	f.Fuzz(func(t *testing.T, mutation string) {
		if len(mutation) > 128 {
			return
		}
		var value [32]byte
		value[0] = 1
		capability, _ := newCapability(value)
		defer func() { _ = capability.Close() }()
		request, err := buildNegativeRequest(
			t.Context(), "http://127.0.0.1:8080", mutation, capability,
		)
		if err != nil {
			if ExitClassOf(err) != ExitInternal {
				t.Fatal("invalid mutation returned an unstable class")
			}
			return
		}
		if !validNegativeMutation(mutation) || request.URL.Host != "127.0.0.1:8080" ||
			request.URL.Path != processPath {
			t.Fatal("negative mutation escaped the closed request boundary")
		}
	})
}

// FuzzResponseClassification exercises hostile bounded error representations.
func FuzzResponseClassification(f *testing.F) {
	f.Add(uint16(http.StatusForbidden), mediaTypeJSON, []byte(forbiddenResponseBody))
	f.Add(uint16(http.StatusOK), "text/plain", []byte("marker-private-response"))
	f.Fuzz(func(t *testing.T, status uint16, contentType string, body []byte) {
		if len(contentType) > 256 || len(body) > 32*1024 {
			return
		}
		response := buildHostileResponse(int(status%600), contentType, string(body))
		_, err := classifyNegativeResponse(OperationProcess, response)
		if err != nil && strings.Contains(err.Error(), "marker-private") {
			t.Fatal("response bytes escaped stable classification")
		}
	})
}

// FuzzOutputPrivacy proves rejected arbitrary fields emit no partial JSON.
func FuzzOutputPrivacy(f *testing.F) {
	f.Add("internal")
	f.Add("marker-private-output")
	f.Fuzz(func(t *testing.T, errorClass string) {
		if len(errorClass) > 1024 {
			return
		}
		var output bytes.Buffer
		record := ResultRecord{
			Schema: outputSchema, Draft: draftVersion,
			Outcome: outcomeError, ErrorClass: &errorClass,
		}
		err := writeRecord(&output, record)
		if !validErrorClass(errorClass) && (err == nil || output.Len() != 0) {
			t.Fatal("invalid output field emitted partial JSON")
		}
		if strings.Contains(output.String(), "marker-private") {
			t.Fatal("arbitrary marker escaped stable output")
		}
	})
}
