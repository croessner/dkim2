package dsn

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/verify"
)

const (
	evidenceTimestamp = uint64(1700000000)
	evidenceDomain    = "example.test"
)

// TestEvidenceEvaluatorAuthenticatesCompleteAndHeadersOnlyOriginals verifies
// both RFC 3462 representations use real DKIM2 cryptographic evidence without
// treating the headers-only representation as a complete message.
func TestEvidenceEvaluatorAuthenticatesCompleteAndHeadersOnlyOriginals(t *testing.T) {
	for _, form := range []struct {
		name        string
		contentType ContentType
		headersOnly bool
		wantForm    EvidenceForm
	}{
		{name: "complete", contentType: ContentTypeRFC822, wantForm: EvidenceFormComplete},
		{name: "headers only", contentType: ContentTypeRFC822Headers, headersOnly: true, wantForm: EvidenceFormHeadersOnly},
	} {
		t.Run(form.name, func(t *testing.T) {
			fixture := newEvidenceFixture(t, form.headersOnly)
			report := mustEvidenceReport(t, form.contentType, fixture.raw)
			evaluator, err := NewEvidenceEvaluator(fixture.verifier)
			if err != nil {
				t.Fatalf("NewEvidenceEvaluator() error=%v", err)
			}
			evidence, err := evaluator.Evaluate(context.Background(), EvidenceRequest{Report: report})
			if err != nil || !evidence.Valid() || evidence.Form() != form.wantForm || evidence.Target().Sequence != 1 || evidence.Target().InstanceNumber != 1 ||
				evidence.SigningDomain() != evidenceDomain || len(evidence.RecipientDomains()) != 1 || evidence.RecipientDomains()[0] != evidenceDomain {
				t.Fatalf("Evaluate() evidence=%#v error=%v", evidence, err)
			}
			domains := evidence.RecipientDomains()
			domains[0] = "mutated.invalid"
			if got := evidence.RecipientDomains()[0]; got != evidenceDomain {
				t.Fatalf("RecipientDomains() exposed mutable evidence: %q", got)
			}
		})
	}
}

// TestEvidenceEvaluatorRejectsHeadersOnlyWithInventedEmptyBody proves the
// DSN evaluator does not silently replace unavailable body evidence with an
// empty body when the MIME type promises retained headers only.
func TestEvidenceEvaluatorRejectsHeadersOnlyWithInventedEmptyBody(t *testing.T) {
	fixture := newEvidenceFixture(t, false)
	report := mustEvidenceReport(t, ContentTypeRFC822Headers, fixture.raw)
	evaluator, err := NewEvidenceEvaluator(fixture.verifier)
	if err != nil {
		t.Fatalf("NewEvidenceEvaluator() error=%v", err)
	}
	_, err = evaluator.Evaluate(context.Background(), EvidenceRequest{Report: report})
	if !IsEvidenceErrorCode(err, EvidenceErrorCodeVerificationFailed) {
		t.Fatalf("Evaluate() error=%v, want verification failed", err)
	}
}

// TestEvidenceEvaluatorRejectsChangedOriginalEvidence proves callers cannot
// authorize DSN signing with altered embedded bytes.
func TestEvidenceEvaluatorRejectsChangedOriginalEvidence(t *testing.T) {
	fixture := newEvidenceFixture(t, false)
	evaluator, err := NewEvidenceEvaluator(fixture.verifier)
	if err != nil {
		t.Fatalf("NewEvidenceEvaluator() error=%v", err)
	}
	const toxic = "TOXIC-ORIGINAL-MARKER"
	changed := strings.Replace(fixture.raw, "Subject: original", "Subject: "+toxic, 1)
	changedReport := mustEvidenceReport(t, ContentTypeRFC822, changed)
	_, err = evaluator.Evaluate(context.Background(), EvidenceRequest{Report: changedReport})
	if !IsEvidenceErrorCode(err, EvidenceErrorCodeVerificationFailed) {
		t.Fatalf("Evaluate(changed original) error=%v, want verification failed", err)
	}
	if strings.Contains(err.Error(), toxic) {
		t.Fatalf("Evaluate(changed original) leaked message content: %q", err)
	}
}

// TestDeliveryStatusRecipientLinkageRequiresRFC3464Structure proves a matching
// address cannot authorize DSN signing unless it occurs in a complete,
// unambiguous per-recipient field group.
func TestDeliveryStatusRecipientLinkageRequiresRFC3464Structure(t *testing.T) {
	const validStatus = "Reporting-MTA: dns; example.test\r\n\r\n" +
		"Final-Recipient: rfc822; recipient@example.test\r\n" +
		"Action: failed\r\nStatus: 5.1.1\r\n"
	const signedPlusPath = "<user+tag@example.test>"
	for _, testCase := range []struct {
		name   string
		status string
		signed string
		want   bool
	}{
		{name: "valid", status: validStatus, want: true},
		{name: "valid plus address", status: strings.Replace(validStatus,
			"recipient@example.test", "user+tag@example.test", 1),
			signed: signedPlusPath, want: true},
		{name: "quoted local part", status: strings.Replace(validStatus,
			"recipient@example.test", `"user name"@example.test`, 1),
			signed: `<"user name"@example.test>`, want: true},
		{name: "final recipient plus hex is literal", status: strings.Replace(validStatus,
			"recipient@example.test", "user+2Btag@example.test", 1),
			signed: "<user+2Btag@example.test>", want: true},
		{name: "final recipient plus hex is not xtext", status: strings.Replace(validStatus,
			"recipient@example.test", "user+2Btag@example.test", 1),
			signed: signedPlusPath},
		{name: "original recipient xtext encoded at", status: strings.Replace(validStatus,
			"Final-Recipient: rfc822; recipient@example.test",
			"Original-Recipient: rfc822; recipient+40example.test\r\nFinal-Recipient: rfc822; other@example.test", 1), want: true},
		{name: "original recipient xtext encoded plus", status: strings.Replace(validStatus,
			"Final-Recipient: rfc822; recipient@example.test",
			"Original-Recipient: rfc822; user+2Btag@example.test\r\nFinal-Recipient: rfc822; other@example.test", 1),
			signed: signedPlusPath, want: true},
		{name: "unknown extension tail", status: strings.Replace(validStatus,
			"Status: 5.1.1", "Status: 5.1.1\r\nX-Trace: opaque", 1), want: true},
		{name: "extension before mandatory", status: strings.Replace(validStatus,
			"Action:", "X-Trace: opaque\r\nAction:", 1)},
		{name: "original recipient links", status: strings.Replace(validStatus,
			"Final-Recipient: rfc822; recipient@example.test",
			"Original-Recipient: rfc822; recipient@example.test\r\nFinal-Recipient: rfc822; other@example.test", 1), want: true},
		{name: "missing reporting mta", status: strings.Replace(validStatus, "Reporting-MTA", "X-Reporting-MTA", 1)},
		{name: "duplicate reporting mta", status: strings.Replace(validStatus, "Reporting-MTA: dns; example.test",
			"Reporting-MTA: dns; example.test\r\nReporting-MTA: dns; duplicate.example", 1)},
		{name: "recipient field in message group", status: strings.Replace(validStatus,
			"Reporting-MTA: dns; example.test", "Reporting-MTA: dns; example.test\r\nFinal-Recipient: rfc822; recipient@example.test", 1)},
		{name: "reporting mta in recipient group", status: strings.Replace(validStatus,
			"Action: failed", "Reporting-MTA: dns; example.test\r\nAction: failed", 1)},
		{name: "missing recipient group", status: "Reporting-MTA: dns; example.test\r\n"},
		{name: "missing final recipient", status: strings.Replace(validStatus, "Final-Recipient", "X-Final-Recipient", 1)},
		{name: "missing action", status: strings.Replace(validStatus, "Action", "X-Action", 1)},
		{name: "matching recipient without action or status", status: "Reporting-MTA: dns; example.test\r\n\r\n" +
			"Final-Recipient: rfc822; recipient@example.test\r\n"},
		{name: "missing status", status: strings.Replace(validStatus, "Status", "X-Status", 1)},
		{name: "duplicate mandatory field", status: strings.Replace(validStatus, "Action: failed",
			"Action: failed\r\nAction: failed", 1)},
		{name: "invalid action", status: strings.Replace(validStatus, "Action: failed", "Action: unknown", 1)},
		{name: "valid delayed action", status: strings.Replace(validStatus, "Action: failed", "Action: delayed", 1), want: true},
		{name: "valid delivered action", status: strings.Replace(validStatus, "Action: failed", "Action: delivered", 1), want: true},
		{name: "valid relayed action", status: strings.Replace(validStatus, "Action: failed", "Action: relayed", 1), want: true},
		{name: "valid expanded action", status: strings.Replace(validStatus, "Action: failed", "Action: expanded", 1), want: true},
		{name: "invalid status", status: strings.Replace(validStatus, "Status: 5.1.1", "Status: 7.1.1", 1)},
		{name: "leading zero subject", status: strings.Replace(validStatus, "Status: 5.1.1", "Status: 5.01.1", 1)},
		{name: "leading zero detail", status: strings.Replace(validStatus, "Status: 5.1.1", "Status: 5.1.01", 1)},
		{name: "invalid reporting mta type", status: strings.Replace(validStatus, "dns; example.test", "dns.name; example.test", 1)},
		{name: "invalid reporting mta separator", status: strings.Replace(validStatus, "dns; example.test", "dns example.test", 1)},
		{name: "wrong recipient address type", status: strings.Replace(validStatus, "rfc822; recipient", "smtp; recipient", 1)},
		{name: "folded recipient", status: strings.Replace(validStatus,
			"Final-Recipient: rfc822; recipient@example.test",
			"Final-Recipient: rfc822;\r\n recipient@example.test", 1)},
		{name: "unsupported original recipient xtext control", status: strings.Replace(validStatus,
			"Final-Recipient: rfc822; recipient@example.test",
			"Original-Recipient: rfc822; recipient@example.test+0D\r\nFinal-Recipient: rfc822; other@example.test", 1)},
		{name: "malformed original recipient xtext escape", status: strings.Replace(validStatus,
			"Final-Recipient: rfc822; recipient@example.test",
			"Original-Recipient: rfc822; recipient+zz@example.test\r\nFinal-Recipient: rfc822; other@example.test", 1)},
		{name: "malformed group separation", status: strings.Replace(validStatus, "\r\n\r\nFinal-Recipient", "\r\nFinal-Recipient", 1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			report := mustEvidenceReportWithDeliveryStatus(t, ContentTypeRFC822Headers,
				"From: sender@example.test\r\n", testCase.status)
			signed := testCase.signed
			if signed == "" {
				signed = "<recipient@example.test>"
			}
			if got := deliveryStatusLinksRecipient(report, [][]byte{[]byte(signed)}, false); got != testCase.want {
				t.Fatalf("deliveryStatusLinksRecipient()=%t, want %t", got, testCase.want)
			}
		})
	}
}

// TestDeliveryStatusRecipientLinkageEnforcesFieldOrder proves all RFC 3464
// standard fields remain in their assigned block and ABNF order, occur at
// most once, and cannot follow an extension-field tail.
func TestDeliveryStatusRecipientLinkageEnforcesFieldOrder(t *testing.T) {
	const date = "Thu, 7 Jul 1994 17:15:49 -0400"
	const complete = "Original-Envelope-Id: envelope-id\r\n" +
		"Reporting-MTA: dns; example.test\r\n" +
		"DSN-Gateway: dns; gateway.example.test\r\n" +
		"Received-From-MTA: dns; source.example.test\r\n" +
		"Arrival-Date: " + date + "\r\n" +
		"X-Message-Extension: value\r\n\r\n" +
		"Original-Recipient: rfc822; recipient+40example.test\r\n" +
		"Final-Recipient: rfc822; recipient@example.test\r\n" +
		"Action: delayed\r\n" +
		"Status: 4.1.1\r\n" +
		"Remote-MTA: dns; remote.example.test\r\n" +
		"Diagnostic-Code: smtp; 450 mailbox unavailable\r\n" +
		"Last-Attempt-Date: " + date + "\r\n" +
		"Final-Log-ID: log-id\r\n" +
		"Will-Retry-Until: " + date + "\r\n" +
		"X-Recipient-Extension: value\r\n"
	for _, testCase := range []struct {
		name   string
		status string
		want   bool
	}{
		{name: "complete standard sequence", status: complete, want: true},
		{name: "raw text fields preserve plus equals spaces and tabs", status: strings.NewReplacer(
			"Original-Envelope-Id: envelope-id", "Original-Envelope-Id: id+2B=value with space\tand tab",
			"Final-Log-ID: log-id", "Final-Log-ID: log+40=value with space\tand tab",
		).Replace(complete), want: true},
		{name: "empty text fields are permitted", status: strings.NewReplacer(
			"Original-Envelope-Id: envelope-id", "Original-Envelope-Id:",
			"Final-Log-ID: log-id", "Final-Log-ID:",
		).Replace(complete), want: true},
		{name: "control in original envelope id", status: strings.Replace(complete,
			"Original-Envelope-Id: envelope-id", "Original-Envelope-Id: envelope\x00id", 1)},
		{name: "control in final log id", status: strings.Replace(complete,
			"Final-Log-ID: log-id", "Final-Log-ID: log\x7fid", 1)},
		{name: "multiple extension fields in tail", status: strings.Replace(complete,
			"X-Recipient-Extension: value", "X-Recipient-Extension: value\r\nX-Second: value", 1), want: true},
		{name: "message extension before reporting mta", status: strings.Replace(complete,
			"Reporting-MTA: dns; example.test", "X-Early: value\r\nReporting-MTA: dns; example.test", 1)},
		{name: "message standard after extension", status: strings.Replace(complete,
			"Arrival-Date: "+date+"\r\nX-Message-Extension: value",
			"X-Message-Extension: value\r\nArrival-Date: "+date, 1)},
		{name: "recipient standard after extension", status: strings.Replace(complete,
			"Final-Log-ID: log-id\r\nWill-Retry-Until: "+date+"\r\nX-Recipient-Extension: value",
			"Final-Log-ID: log-id\r\nX-Recipient-Extension: value\r\nWill-Retry-Until: "+date, 1)},
		{name: "duplicate optional message field", status: strings.Replace(complete,
			"Arrival-Date: "+date, "Arrival-Date: "+date+"\r\nArrival-Date: "+date, 1)},
		{name: "duplicate optional recipient field", status: strings.Replace(complete,
			"Remote-MTA: dns; remote.example.test", "Remote-MTA: dns; remote.example.test\r\nRemote-MTA: dns; duplicate.example.test", 1)},
		{name: "out of order message field", status: strings.Replace(complete,
			"DSN-Gateway: dns; gateway.example.test\r\nReceived-From-MTA: dns; source.example.test",
			"Received-From-MTA: dns; source.example.test\r\nDSN-Gateway: dns; gateway.example.test", 1)},
		{name: "out of order recipient field", status: strings.Replace(complete,
			"Remote-MTA: dns; remote.example.test\r\nDiagnostic-Code: smtp; 450 mailbox unavailable",
			"Diagnostic-Code: smtp; 450 mailbox unavailable\r\nRemote-MTA: dns; remote.example.test", 1)},
		{name: "message field in recipient group", status: strings.Replace(complete,
			"Remote-MTA: dns; remote.example.test", "Arrival-Date: "+date+"\r\nRemote-MTA: dns; remote.example.test", 1)},
		{name: "recipient field in message group", status: strings.Replace(complete,
			"X-Message-Extension: value", "Final-Log-ID: log-id\r\nX-Message-Extension: value", 1)},
		{name: "will retry with non-delayed action", status: strings.Replace(complete, "Action: delayed", "Action: failed", 1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := deliveryStatusBodyLinksRecipient([]byte(testCase.status), [][]byte{[]byte("<recipient@example.test>")}, false); got != testCase.want {
				t.Fatalf("deliveryStatusBodyLinksRecipient()=%t, want %t", got, testCase.want)
			}
		})
	}
}

// TestDeliveryStatusRecipientLinkageConfinesPostfixCompatibility proves the
// dedicated mode admits only bounce(8)'s exact legacy field order and its
// wrapped Remote-MTA/Diagnostic-Code output. The generic RFC path stays strict.
func TestDeliveryStatusRecipientLinkageConfinesPostfixCompatibility(t *testing.T) {
	const date = "Tue, 14 Nov 2023 22:13:20 +0000 (UTC)"
	const postfixStatus = "Reporting-MTA: dns; example.test\r\n" +
		"Original-Envelope-Id: synthetic-envid\r\n" +
		"X-Postfix-Queue-ID: synthetic-queue-id\r\n" +
		"X-Postfix-Sender: rfc822; sender@example.test\r\n" +
		"Arrival-Date: " + date + "\r\n\r\n" +
		"Final-Recipient: rfc822; recipient@example.test\r\n" +
		"Original-Recipient: rfc822; recipient@example.test\r\n" +
		"Action: failed\r\n" +
		"Status: 5.1.1\r\n" +
		"Remote-MTA: dns; remote.example.test\r\n" +
		"Diagnostic-Code: smtp; 550 synthetic diagnostic text that is\r\n" +
		" wrapped exactly as Postfix bounce_print_wrap emits it\r\n"
	if deliveryStatusBodyLinksRecipient(
		[]byte(postfixStatus), [][]byte{[]byte("<recipient@example.test>")}, false,
	) {
		t.Fatal("generic RFC path admitted Postfix-specific ordering")
	}
	if !deliveryStatusBodyLinksRecipient(
		[]byte(postfixStatus), [][]byte{[]byte("<recipient@example.test>")}, true,
	) {
		t.Fatal("Postfix compatibility rejected canonical bounce(8) ordering")
	}
	for _, testCase := range []struct {
		name   string
		status string
	}{
		{name: "unknown message extension", status: strings.Replace(postfixStatus,
			"X-Postfix-Queue-ID", "X-Trace", 1)},
		{name: "sender before queue", status: strings.Replace(postfixStatus,
			"X-Postfix-Queue-ID: synthetic-queue-id\r\nX-Postfix-Sender: rfc822; sender@example.test",
			"X-Postfix-Sender: rfc822; sender@example.test\r\nX-Postfix-Queue-ID: synthetic-queue-id", 1)},
		{name: "mismatched mail name", status: strings.Replace(postfixStatus,
			"X-Postfix-Sender", "X-Other-Sender", 1)},
		{name: "duplicate queue id", status: strings.Replace(postfixStatus,
			"X-Postfix-Queue-ID: synthetic-queue-id",
			"X-Postfix-Queue-ID: synthetic-queue-id\r\nX-Postfix-Queue-ID: duplicate", 1)},
		{name: "arrival before queue", status: strings.Replace(postfixStatus,
			"X-Postfix-Queue-ID: synthetic-queue-id\r\nX-Postfix-Sender: rfc822; sender@example.test\r\nArrival-Date: "+date,
			"Arrival-Date: "+date+"\r\nX-Postfix-Queue-ID: synthetic-queue-id\r\nX-Postfix-Sender: rfc822; sender@example.test", 1)},
		{name: "recipient extension", status: strings.Replace(postfixStatus,
			"Action: failed", "X-Trace: opaque\r\nAction: failed", 1)},
		{name: "missing diagnostic", status: strings.Replace(postfixStatus,
			"Diagnostic-Code: smtp; 550 synthetic diagnostic text that is\r\n wrapped exactly as Postfix bounce_print_wrap emits it\r\n", "", 1)},
		{name: "folded queue id", status: strings.Replace(postfixStatus,
			"X-Postfix-Queue-ID: synthetic-queue-id",
			"X-Postfix-Queue-ID: synthetic\r\n queue-id", 1)},
		{name: "empty diagnostic continuation", status: strings.Replace(postfixStatus,
			" wrapped exactly as Postfix bounce_print_wrap emits it",
			" \t", 1)},
		{name: "unfolded diagnostic line limit", status: strings.Replace(postfixStatus,
			"Diagnostic-Code: smtp; 550 synthetic diagnostic text that is\r\n wrapped exactly as Postfix bounce_print_wrap emits it",
			"Diagnostic-Code: smtp; "+strings.Repeat("a", 3000)+"\r\n "+strings.Repeat("b", 2000), 1)},
		{name: "orphan continuation", status: " folded\r\n" + postfixStatus},
		{name: "duplicate original recipient", status: strings.Replace(postfixStatus,
			"Original-Recipient: rfc822; recipient@example.test",
			"Original-Recipient: rfc822; recipient@example.test\r\nOriginal-Recipient: rfc822; duplicate@example.test", 1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if deliveryStatusBodyLinksRecipient(
				[]byte(testCase.status), [][]byte{[]byte("<recipient@example.test>")}, true,
			) {
				t.Fatal("Postfix compatibility admitted non-Postfix field structure")
			}
		})
	}
}

// TestDeliveryStatusDateSyntax enforces the RFC 822 date-time grammar as
// amended by RFC 1123 and RFC 3464's mandatory numeric timezone restriction.
func TestDeliveryStatusDateSyntax(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "weekday seconds and numeric zone", value: "Thu, 7 Jul 1994 17:15:49 -0400", want: true},
		{name: "no weekday or seconds", value: "7 Jul 1994 17:15 +0000", want: true},
		{name: "two digit year", value: "Thu, 7 Jul 94 17:15:49 -0400", want: true},
		{name: "tabs as lexical whitespace", value: "Thu,\t7\tJul\t1994\t17:15:49\t-0400", want: true},
		{name: "trailing comment", value: "Thu, 7 Jul 1994 17:15:49 -0400 (local)", want: true},
		{name: "cfws around delimiters", value: "Thu (weekday) , (date) 7 Jul 1994 17 (hour) : 15 : (seconds) 49 (zone) -0400 (local)", want: true},
		{name: "nested comments", value: "Thu, 7 Jul 1994 17:15:49 -0400 (outer (inner) local)", want: true},
		{name: "quoted closing parenthesis", value: "Thu, 7 Jul 1994 17:15:49 -0400 (local \\) zone)", want: true},
		{name: "named zone", value: "Thu, 7 Jul 1994 17:15:49 GMT"},
		{name: "military zone", value: "Thu, 7 Jul 1994 17:15:49 Z"},
		{name: "missing zone sign", value: "Thu, 7 Jul 1994 17:15:49 0400"},
		{name: "comment splits negative zone", value: "Thu, 7 Jul 1994 17:15:49 -(zone)0400"},
		{name: "cfws splits negative zone", value: "Thu, 7 Jul 1994 17:15:49 - (zone) 0400"},
		{name: "cfws splits positive zone", value: "Thu, 7 Jul 1994 17:15:49 + (zone) 0000"},
		{name: "zone hour range", value: "Thu, 7 Jul 1994 17:15:49 +2400"},
		{name: "zone minute range", value: "Thu, 7 Jul 1994 17:15:49 +0060"},
		{name: "one digit hour", value: "Thu, 7 Jul 1994 7:15:49 -0400"},
		{name: "hour range", value: "Thu, 7 Jul 1994 24:00:00 -0400"},
		{name: "minute range", value: "Thu, 7 Jul 1994 17:60:00 -0400"},
		{name: "second range", value: "Thu, 7 Jul 1994 17:15:60 -0400"},
		{name: "invalid month", value: "Thu, 7 Jly 1994 17:15:49 -0400"},
		{name: "invalid calendar day", value: "Thu, 31 Apr 1994 17:15:49 -0400"},
		{name: "wrong weekday", value: "Fri, 7 Jul 1994 17:15:49 -0400"},
		{name: "one digit year", value: "7 Jul 4 17:15:49 -0400"},
		{name: "five digit year", value: "7 Jul 19940 17:15:49 -0400"},
		{name: "obsolete hyphenated date", value: "Thu, 07-Jul-1994 17:15:49 -0400"},
		{name: "unclosed comment", value: "Thu, 7 Jul 1994 17:15:49 -0400 (local"},
		{name: "unexpected closing parenthesis", value: "Thu, 7 Jul 1994 17:15:49 -0400 local)"},
		{name: "dangling quoted pair", value: "Thu, 7 Jul 1994 17:15:49 -0400 (local \\"},
		{name: "control in comment", value: "Thu, 7 Jul 1994 17:15:49 -0400 (local\x00)"},
		{name: "quoted control in comment", value: "Thu, 7 Jul 1994 17:15:49 -0400 (local \\\x01)"},
		{name: "bare carriage return", value: "Thu, 7 Jul 1994\r 17:15:49 -0400"},
		{name: "folded line", value: "Thu, 7 Jul 1994\r\n 17:15:49 -0400"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := validDeliveryStatusDate([]byte(testCase.value)); got != testCase.want {
				t.Fatalf("validDeliveryStatusDate(%q)=%t, want %t", testCase.value, got, testCase.want)
			}
		})
	}
	for _, testCase := range []struct {
		name  string
		depth int
		want  bool
	}{
		{name: "maximum comment depth", depth: maxDeliveryStatusCommentDepth, want: true},
		{name: "excessive comment depth", depth: maxDeliveryStatusCommentDepth + 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			value := "Thu, 7 Jul 1994 17:15:49 -0400 " + strings.Repeat("(", testCase.depth) +
				"local" + strings.Repeat(")", testCase.depth)
			if got := validDeliveryStatusDate([]byte(value)); got != testCase.want {
				t.Fatalf("validDeliveryStatusDate(depth=%d)=%t, want %t", testCase.depth, got, testCase.want)
			}
		})
	}
}

// TestDeliveryStatusRecipientLinkageLimits proves attacker-controlled status
// structure is rejected at each explicit parser ceiling.
func TestDeliveryStatusRecipientLinkageLimits(t *testing.T) {
	recipientGroup := func(extensionFields int) string {
		return "Final-Recipient: rfc822; recipient@example.test\r\n" +
			"Action: failed\r\nStatus: 5.1.1\r\n" +
			strings.Repeat("X-Extension: value\r\n", extensionFields)
	}
	statusWithGroups := func(groups, extensionFields int) string {
		var builder strings.Builder
		builder.WriteString("Reporting-MTA: dns; example.test\r\n")
		for range groups {
			builder.WriteString("\r\n")
			builder.WriteString(recipientGroup(extensionFields))
		}
		return builder.String()
	}
	for _, testCase := range []struct {
		name   string
		status string
	}{
		{name: "status bytes", status: "Reporting-MTA: dns; example.test\r\n\r\nX-Large: " +
			strings.Repeat("a", maxDeliveryStatusBytes) + "\r\n" + recipientGroup(0)},
		{name: "line bytes", status: "Reporting-MTA: dns; example.test\r\n\r\nX-Long: " +
			strings.Repeat("a", maxDeliveryStatusLineBytes) + "\r\n" + recipientGroup(0)},
		{name: "fields per group", status: statusWithGroups(1, maxDeliveryStatusFieldsPerGroup-2)},
		{name: "total fields", status: statusWithGroups(41, 48)},
		{name: "recipient groups", status: statusWithGroups(maxDeliveryStatusRecipientGroups+1, 0)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if deliveryStatusBodyLinksRecipient([]byte(testCase.status), [][]byte{[]byte("<recipient@example.test>")}, false) {
				t.Fatal("deliveryStatusLinksRecipient() accepted over-limit status data")
			}
		})
	}
}

// evidenceFixture stores a real cryptographic embedded original and its verifier.
type evidenceFixture struct {
	raw      string
	verifier verify.Verifier
}

// newEvidenceFixture constructs either a complete or header-only signed embedded original.
func newEvidenceFixture(t *testing.T, headersOnly bool) evidenceFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error=%v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("canonical.NewCanonicalizer() error=%v", err)
	}
	baseHeaders := "From: sender@example.test\r\nSubject: original\r\n"
	baseRaw := baseHeaders
	if !headersOnly {
		baseRaw += "\r\nbody\r\n"
	}
	baseMessage := mustEvidenceMessage(t, baseRaw)
	headerHash, err := canonicalizer.HeaderHashFromMessage(baseMessage)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error=%v", err)
	}
	headerDigest, ok := headerHash.Digest()
	if !ok {
		t.Fatal("HeaderHashFromMessage() missing digest")
	}
	bodyDigest := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	if !headersOnly {
		bodyHash, hashErr := canonicalizer.BodyHashFromMessage(baseMessage)
		if hashErr != nil {
			t.Fatalf("BodyHashFromMessage() error=%v", hashErr)
		}
		digest, digestOK := bodyHash.Digest()
		if !digestOK {
			t.Fatal("BodyHashFromMessage() missing digest")
		}
		bodyDigest = digest.Base64()
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	unsignedRaw := renderEvidenceOriginal(baseHeaders, headerDigest.Base64(), bodyDigest, placeholder, headersOnly)
	unsigned := mustEvidenceMessage(t, unsignedRaw)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: unsigned.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error=%v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error=%v", err)
	}
	raw := renderEvidenceOriginal(baseHeaders, headerDigest.Base64(), bodyDigest, base64.StdEncoding.EncodeToString(signatureBytes), headersOnly)
	provider, err := verify.NewStaticKeyProvider([]verify.StaticKey{{
		Domain: "example.test", Selector: "selector", Algorithm: verify.AlgorithmRSASHA256, Material: &key.PublicKey,
	}})
	if err != nil {
		t.Fatalf("verify.NewStaticKeyProvider() error=%v", err)
	}
	verifier, err := verify.NewVerifier(provider, verify.WithClock(func() time.Time {
		return time.Unix(int64(evidenceTimestamp), 0).Add(time.Minute)
	}))
	if err != nil {
		t.Fatalf("verify.NewVerifier() error=%v", err)
	}
	return evidenceFixture{raw: raw, verifier: verifier}
}

// renderEvidenceOriginal renders one signed original with RFC 5322 framing chosen by headersOnly.
func renderEvidenceOriginal(baseHeaders string, headerDigest string, bodyDigest string, signatureText string, headersOnly bool) string {
	recipient := base64.StdEncoding.EncodeToString([]byte("<recipient@EXAMPLE.TEST>"))
	raw := baseHeaders +
		"Message-Instance: m=1; h=sha256:" + headerDigest + ":" + bodyDigest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PHNlbmRlckBleGFtcGxlLnRlc3Q+; rt=" + recipient + "; d=example.test; s=selector:rsa-sha256:" + signatureText + ";\r\n"
	if headersOnly {
		return raw
	}
	return raw + "\r\nbody\r\n"
}

// mustEvidenceMessage parses a strict embedded original test fixture.
func mustEvidenceMessage(t *testing.T, raw string) rawmsg.Message {
	t.Helper()
	message, err := rawmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error=%v", err)
	}
	return message
}

// mustEvidenceReport embeds an exact original in a structurally valid RFC 3462 report.
func mustEvidenceReport(t *testing.T, contentType ContentType, original string) Report {
	t.Helper()
	return mustEvidenceReportWithDeliveryStatus(t, contentType, original,
		"Reporting-MTA: dns; example.test\r\n\r\n"+
			"Final-Recipient: rfc822; recipient@example.test\r\n"+
			"Action: failed\r\nStatus: 5.1.1\r\n")
}

func mustEvidenceReportWithDeliveryStatus(t *testing.T, contentType ContentType, original, deliveryStatus string) Report {
	t.Helper()
	separator := ""
	if contentType == ContentTypeRFC822Headers {
		// Preserve the embedded header block's terminating CRLF separately from
		// the MIME delimiter's required leading CRLF.
		separator = "\r\n"
	}
	raw := "From: postmaster@example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\n" + deliveryStatus + "\r\n" +
		"--dsn\r\nContent-Type: " + string(contentType) + "\r\n\r\n" + original + separator +
		"--dsn--\r\n"
	report, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse(report) error=%v", err)
	}
	return report
}
