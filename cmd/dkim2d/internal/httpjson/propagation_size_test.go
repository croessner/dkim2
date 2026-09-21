package httpjson

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

// TestPropagationResponseCarriesMessageAboveFactResponseLimit exercises wire
// serialization with a complete notification, rather than the small header
// delta/fact budget used by other operations.
func TestPropagationResponseCarriesMessageAboveFactResponseLimit(t *testing.T) {
	harness := startPropagateRouteHarness(t)
	status, body := harness.propagate(t, propagationtest.CaseRunOfOne, propagateRouteTenant)
	requirePropagation(t, status, body, propagateRouteResultPass, testDispositionAccept)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var response generated.DSNPropagateResponse
	if err := json.Unmarshal(encoded, &response); err != nil {
		t.Fatal(err)
	}
	large := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), 1<<20))
	response.Propagation.RawRfc5322Base64, err = wire.NewProtectedString(large)
	if err != nil {
		t.Fatal(err)
	}
	framed, err := newJSONResponse(http.StatusOK, response, false, "", false)
	if err != nil || len(framed.body) <= maxSuccessResponseBytes {
		t.Fatal("complete propagation output was restricted to the fact response budget")
	}
	var decoded generated.DSNPropagateResponse
	if err := json.Unmarshal(framed.body, &decoded); err != nil {
		t.Fatal(err)
	}
	raw, err := decoded.Propagation.RawRfc5322Base64.Bytes()
	if err != nil || string(raw) != large {
		t.Fatal("propagation wire output was truncated")
	}
}
