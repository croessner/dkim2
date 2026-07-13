package canonical

import (
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestCanonicalizerDistinguishesZeroAndInitializedEmptyStates verifies reconstructed empty values remain valid.
func TestCanonicalizerDistinguishesZeroAndInitializedEmptyStates(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := canonicalizer.HeaderHashInput(rawmsg.HeaderBlock{}); !IsErrorCode(err, ErrorCodeMalformedState) {
		t.Fatalf("zero header error = %v", err)
	}
	if _, err := canonicalizer.BodyHashInput(rawmsg.Body{}); !IsErrorCode(err, ErrorCodeMalformedState) {
		t.Fatalf("zero body error = %v", err)
	}
	headers, err := rawmsg.NewReconstructedHeaderBlock(nil, rawmsg.DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	body, err := rawmsg.NewReconstructedBody(nil, rawmsg.DefaultParserOptions())
	if err != nil {
		t.Fatal(err)
	}
	headerInput, err := canonicalizer.HeaderHashInput(headers)
	if err != nil {
		t.Fatalf("empty header error = %v", err)
	}
	bodyInput, err := canonicalizer.BodyHashInput(body)
	if err != nil {
		t.Fatalf("empty body error = %v", err)
	}
	if len(headerInput.Bytes()) != 0 || string(bodyInput.Bytes()) != "\r\n" {
		t.Fatalf("canonical empty = %q/%q", headerInput.Bytes(), bodyInput.Bytes())
	}
}
