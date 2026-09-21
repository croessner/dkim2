package httpjson

import (
	"encoding/base64"
	"testing"
)

// TestConfiguredMessageSize covers exact decoded boundaries in all padding
// classes and complete-fanout requests without allocating an oversized DTO.
func TestConfiguredMessageSize(t *testing.T) {
	for limit := 1; limit <= 9; limit++ {
		for size := limit - 1; size <= limit+1; size++ {
			encoded := base64.StdEncoding.EncodeToString(make([]byte, size))
			body := []byte(validJSONPreflightPrefix() + `"message":{"raw_rfc5322_base64":"` + encoded + `"}}`)
			facts, err := preflightJSON(body)
			if err != nil {
				t.Fatal(err)
			}
			if err := preflightConfiguredMessageSize(body, facts, limit); (err != nil) != (size > limit) {
				t.Fatalf("limit=%d size=%d rejection=%t", limit, size, err != nil)
			}
			facts.batchRawMessages = append(facts.batchRawMessages, facts.rawMessage)
			facts.rawMessage = jsonRawMessageToken{}
			if err := preflightConfiguredMessageSize(body, facts, limit); (err != nil) != (size > limit) {
				t.Fatalf("batch limit=%d size=%d rejection=%t", limit, size, err != nil)
			}
		}
	}
}
