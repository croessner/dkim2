package httpjson

import (
	"fmt"
	"strings"
	"testing"
)

// knownFieldBody constructs one syntactically valid process envelope.
func knownFieldBody(mailFrom string, recipients []string, raw string) []byte {
	quotedRecipients := make([]string, len(recipients))
	for index, recipient := range recipients {
		quotedRecipients[index] = fmt.Sprintf("%q", recipient)
	}
	return fmt.Appendf(nil,
		`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-06","message":{"raw_rfc5322_base64":"%s"},"smtp":{"mail_from":%q,"rcpt_to":[%s]}}`,
		raw,
		mailFrom,
		strings.Join(quotedRecipients, ","),
	)
}

// TestKnownFieldPreflightEnforcesResourceLimitsBeforeSchema proves exact local maxima.
func TestKnownFieldPreflightEnforcesResourceLimitsBeforeSchema(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		wantClass  knownFieldFailure
		wantAccept bool
	}{
		{
			name:       "exact path",
			body:       knownFieldBody(strings.Repeat("a", maxSMTPPathBytes), []string{"b"}, ""),
			wantAccept: true,
		},
		{
			name:      "path one over",
			body:      knownFieldBody(strings.Repeat("a", maxSMTPPathBytes+1), []string{"b"}, ""),
			wantClass: knownFieldRequestTooLarge,
		},
		{
			name: "recipient count one over",
			body: knownFieldBody("", func() []string {
				values := make([]string, 2_001)
				for index := range values {
					values[index] = ""
				}
				return values
			}(), ""),
			wantClass: knownFieldRequestTooLarge,
		},
		{
			name:       "escaped raw spelling",
			body:       knownFieldBody("", []string{""}, `YQ\u003d\u003d`),
			wantAccept: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			constants, err := preflightJSON(test.body)
			if err != nil {
				t.Fatalf("preflightJSON() error = %v", err)
			}
			err = preflightKnownFields(test.body, constants)
			if test.wantAccept && err != nil {
				t.Fatalf("preflightKnownFields() error = %v", err)
			}
			if !test.wantAccept && !isKnownFieldFailure(err, test.wantClass) {
				t.Fatalf("failure = %v, want class %v", err, test.wantClass)
			}
		})
	}
}

// TestKnownFieldPreflightAcceptsExactEnvelopeAggregate proves aggregate accounting.
func TestKnownFieldPreflightAcceptsExactEnvelopeAggregate(t *testing.T) {
	recipients := make([]string, 2_000)
	for index := range recipients {
		recipients[index] = strings.Repeat("r", maxSMTPPathBytes)
	}
	body := knownFieldBody(strings.Repeat("m", maxSMTPPathBytes), recipients, "")
	constants, err := preflightJSON(body)
	if err != nil {
		t.Fatalf("preflightJSON() error = %v", err)
	}
	if err := preflightKnownFields(body, constants); err != nil {
		t.Fatalf("exact aggregate preflight error = %v", err)
	}
}

// TestKnownFieldPreflightEnforcesRawEncodedExactAndOneOver proves token spelling bound.
func TestKnownFieldPreflightEnforcesRawEncodedExactAndOneOver(t *testing.T) {
	if testing.Short() {
		t.Skip("exact encoded-message allocation proof is not a short test")
	}
	for _, test := range []struct {
		name      string
		size      int
		wantClass knownFieldFailure
	}{
		{name: testExactName, size: maxEncodedMessageBytes},
		{name: "one over", size: maxEncodedMessageBytes + 1, wantClass: knownFieldRequestTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := knownFieldBody("", []string{""}, strings.Repeat("A", test.size))
			constants, err := preflightJSON(body)
			if err != nil {
				t.Fatalf("preflightJSON() error = %v", err)
			}
			err = preflightKnownFields(body, constants)
			if test.wantClass == 0 && err != nil {
				t.Fatalf("exact preflight error = %v", err)
			}
			if test.wantClass != 0 && !isKnownFieldFailure(err, test.wantClass) {
				t.Fatalf("failure = %v, want class %v", err, test.wantClass)
			}
		})
	}
}

// TestKnownFieldPreflightIgnoresCaseVariantUnknownFields proves exact path ownership.
func TestKnownFieldPreflightIgnoresCaseVariantUnknownFields(t *testing.T) {
	body := []byte(`{
		"api_version":"v1",
		"draft":"draft-ietf-dkim-dkim2-spec-06",
		"message":{"raw_rfc5322_base64":""},
		"smtp":{"mail_from":"","rcpt_to":[""]},
		"SMTP":{"MAIL_FROM":"` + strings.Repeat("x", maxSMTPPathBytes+1) + `","RCPT_TO":[` +
		strings.Repeat(`"`+strings.Repeat("y", maxSMTPPathBytes+1)+`",`, 2_001) + `null]}
	}`)
	constants, err := preflightJSON(body)
	if err != nil {
		t.Fatalf("preflightJSON() error = %v", err)
	}
	if err := preflightKnownFields(body, constants); err != nil {
		t.Fatalf("case-variant unknown fields affected resource classification: %v", err)
	}
}

// TestRawMessageEscapingIsRejectedOnlyAfterResourceAndSchemaStages proves precedence.
func TestRawMessageEscapingIsRejectedOnlyAfterResourceAndSchemaStages(t *testing.T) {
	body := knownFieldBody("", []string{""}, `YQ\u003d\u003d`)
	constants, err := preflightJSON(body)
	if err != nil {
		t.Fatalf("preflightJSON() error = %v", err)
	}
	if err := preflightKnownFields(body, constants); err != nil {
		t.Fatalf("resource preflight rejected escaped spelling: %v", err)
	}
	if err := validateRawMessageSpelling(constants); !isKnownFieldFailure(err, knownFieldInvalidContract) {
		t.Fatalf("spelling failure = %v", err)
	}
}
