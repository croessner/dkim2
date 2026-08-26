package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestHeaderHashInputExcludesDraftHeaderClasses verifies Draft-05 Section 4 and Section 6.2 exclusions.
func TestHeaderHashInputExcludesDraftHeaderClasses(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Received: by mx.example\r\n"+
			"RETURN-PATH: <sender@example.test>\r\n"+
			"Delivered-To: <recipient@example.test>\r\n"+
			"Authentication-Results: mx.example; pass\r\n"+
			"X-Trace: trace-secret\r\n"+
			"DKIM-Signature: v=1; secret\r\n"+
			"ARC-Seal: i=1; secret\r\n"+
			"Message-Instance: m=1; h=secret\r\n"+
			"DKIM2-Signature: i=1; s=secret\r\n"+
			"Subject: kept\r\n"+
			"From: sender@example.test\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	want := []byte("from:sender@example.test\r\nsubject:kept\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("HeaderHashInputFromMessage() = %q, want %q", got.Bytes(), want)
	}

	metadata := got.Metadata()
	if metadata.IncludedFields != 2 {
		t.Fatalf("IncludedFields = %d, want 2", metadata.IncludedFields)
	}
	if metadata.ExcludedFields != 9 {
		t.Fatalf("ExcludedFields = %d, want 9", metadata.ExcludedFields)
	}
	counts := metadata.ExcludedHeaderCounts
	if counts.Received != 1 || counts.ReturnPath != 1 || counts.DeliveredTo != 1 || counts.AuthenticationResults != 1 ||
		counts.XHeader != 1 || counts.DKIMSignature != 1 || counts.ARC != 1 ||
		counts.MessageInstance != 1 || counts.DKIM2Signature != 1 {
		t.Fatalf("ExcludedHeaderCounts = %#v, want one per excluded class", counts)
	}
}

// TestHeaderRelevanceDraft05UnsignedSet proves every exact and patterned Draft-05 exclusion and ARC near miss.
func TestHeaderRelevanceDraft05UnsignedSet(t *testing.T) {
	relevance := NewHeaderRelevance()
	tests := []struct {
		name     string
		relevant bool
	}{
		{name: receivedHeaderName},
		{name: "received-spf"},
		{name: "apparently-to"},
		{name: "auto-submitted"},
		{name: "dl-expansion-history"},
		{name: "original-recipient"},
		{name: "sio-label-history"},
		{name: "vbr-info"},
		{name: "x400-received"},
		{name: "x400-trace"},
		{name: "arc-authentication-results"},
		{name: "arc-message-signature"},
		{name: "arc-seal"},
		{name: "arc-future", relevant: true},
		{name: "receivedx", relevant: true},
		{name: "not-received-trace", relevant: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := relevance.IsRelevantHeader(test.name)
			if err != nil || got != test.relevant {
				t.Fatalf("IsRelevantHeader(%q) = %t, %v; want %t", test.name, got, err, test.relevant)
			}
		})
	}
}

// TestHeaderHashInputAppliesDraft05UnsignedSet proves canonical bytes and bounded categories.
func TestHeaderHashInputAppliesDraft05UnsignedSet(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Apparently-To: excluded\r\n"+
			"Auto-Submitted: excluded\r\n"+
			"DL-Expansion-History: excluded\r\n"+
			"Original-Recipient: excluded\r\n"+
			"SIO-Label-History: excluded\r\n"+
			"VBR-Info: excluded\r\n"+
			"X400-Received: excluded\r\n"+
			"X400-Trace: excluded\r\n"+
			"Received-SPF: excluded\r\n"+
			"ARC-Authentication-Results: excluded\r\n"+
			"ARC-Message-Signature: excluded\r\n"+
			"ARC-Seal: excluded\r\n"+
			"ARC-Future: signed\r\n"+
			"ReceivedX: signed\r\n"))
	got, err := mustCanonicalizer(t).HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}
	want := []byte("arc-future:signed\r\nreceivedx:signed\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("canonical bytes = %q, want %q", got.Bytes(), want)
	}
	counts := got.Metadata().ExcludedHeaderCounts
	if counts.ExactUnsigned != 8 || counts.Received != 1 || counts.ARC != 3 || counts.Total() != 12 {
		t.Fatalf("ExcludedHeaderCounts = %#v, want exact=8 received=1 arc=3", counts)
	}
}

// TestDraft04SignatureFailsUnderDraft05HeaderRules proves the legacy-to-current PASS-to-FAIL hash boundary.
func TestDraft04SignatureFailsUnderDraft05HeaderRules(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"From: sender@example.test\r\n"+
			"Auto-Submitted: auto-generated\r\n"+
			"Subject: legacy signer\r\n"))

	draft04Canonical := draft04HeaderHashInputOracle(msg)
	draft05Result, err := mustCanonicalizer(t).HeaderHashFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	draft05Canonical := draft05Result.CanonicalBytes().Bytes()

	wireDigest := mustDecodeHeaderBoundaryDigest(t, "kOot0z6eGAjyHWxwX/baswEx+nIRXJizRLyleAuOzPM=")
	draft04Digest := assertHeaderBoundaryOracle(t, "Draft-04", draft04Canonical,
		"auto-submitted:auto-generated\r\nfrom:sender@example.test\r\nsubject:legacy signer\r\n",
		"kOot0z6eGAjyHWxwX/baswEx+nIRXJizRLyleAuOzPM=")
	draft05Digest := assertHeaderBoundaryOracle(t, "Draft-05", draft05Canonical,
		"from:sender@example.test\r\nsubject:legacy signer\r\n",
		"ggygkH3SuDLLOJs7zNh3xmIv3hREjrhTfkQGUAlh3P4=")
	assertDraft05ResultDigest(t, draft05Result, draft05Digest)

	if sameDraftPass := bytes.Equal(wireDigest, draft04Digest[:]); !sameDraftPass {
		t.Fatal("Draft-04 wire digest did not PASS under Draft-04 header rules")
	}
	if crossDraftPass := bytes.Equal(wireDigest, draft05Digest[:]); crossDraftPass {
		t.Fatal("Draft-04 wire digest did not FAIL under Draft-05 header rules")
	}
}

// TestDraft05SignatureFailsUnderDraft04HeaderRules proves the current-to-legacy PASS-to-FAIL hash boundary.
func TestDraft05SignatureFailsUnderDraft04HeaderRules(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"From: sender@example.test\r\n"+
			"Apparently-To: recipient@example.test\r\n"+
			"Subject: current signer\r\n"))

	draft05Result, err := mustCanonicalizer(t).HeaderHashFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	draft05Canonical := draft05Result.CanonicalBytes().Bytes()
	draft04Canonical := draft04HeaderHashInputOracle(msg)

	wireDigest := mustDecodeHeaderBoundaryDigest(t, "2yds7Wq4hBcmcIL4vWoD6vPB3UBVBJMvkkhAWqpYxD0=")
	draft05Digest := assertHeaderBoundaryOracle(t, "Draft-05", draft05Canonical,
		"from:sender@example.test\r\nsubject:current signer\r\n",
		"2yds7Wq4hBcmcIL4vWoD6vPB3UBVBJMvkkhAWqpYxD0=")
	draft04Digest := assertHeaderBoundaryOracle(t, "Draft-04", draft04Canonical,
		"apparently-to:recipient@example.test\r\nfrom:sender@example.test\r\nsubject:current signer\r\n",
		"lbD4XmQeNiOdO2URVEVkDPnJCgskeYos8iVd+9TX0JU=")
	assertDraft05ResultDigest(t, draft05Result, draft05Digest)

	if sameDraftPass := bytes.Equal(wireDigest, draft05Digest[:]); !sameDraftPass {
		t.Fatal("Draft-05 wire digest did not PASS under Draft-05 header rules")
	}
	if crossDraftPass := bytes.Equal(wireDigest, draft04Digest[:]); crossDraftPass {
		t.Fatal("Draft-05 wire digest did not FAIL under Draft-04 header rules")
	}
}

// draft04HeaderHashInputOracle reproduces only the retired Draft-04 unsigned-header boundary for compatibility tests.
func draft04HeaderHashInputOracle(message rawmsg.Message) []byte {
	records := make([]headerFieldRecord, 0, message.Headers().Len())
	for _, field := range message.Headers().Fields() {
		nameLower := field.NameLower()
		if draft04UnsignedHeaderName(nameLower) {
			continue
		}
		records = append(records, headerFieldRecord{
			nameLower:      nameLower,
			originalIndex:  field.Index(),
			canonicalBytes: canonicalizeHeaderFieldBytes(nameLower, field.UnfoldedValue()),
		})
	}
	sortHeaderFieldRecords(records)

	var canonical []byte
	for _, record := range records {
		canonical = append(canonical, record.canonicalBytes...)
	}
	return canonical
}

// draft04UnsignedHeaderName reports the exact retired Draft-04 exclusion set.
func draft04UnsignedHeaderName(nameLower string) bool {
	return nameLower == receivedHeaderName ||
		nameLower == "return-path" ||
		nameLower == "delivered-to" ||
		nameLower == "authentication-results" ||
		strings.HasPrefix(nameLower, "x-") ||
		nameLower == "dkim-signature" ||
		strings.HasPrefix(nameLower, "arc-") ||
		nameLower == "message-instance" ||
		nameLower == "dkim2-signature"
}

// assertHeaderBoundaryOracle verifies fixed canonical bytes and their fixed SHA-256 digest.
func assertHeaderBoundaryOracle(t *testing.T, draft string, canonical []byte, wantCanonical string, wantDigest string) [sha256.Size]byte {
	t.Helper()
	if !bytes.Equal(canonical, []byte(wantCanonical)) {
		t.Fatalf("%s canonical bytes = %q, want %q", draft, canonical, wantCanonical)
	}
	digest := sha256.Sum256(canonical)
	if got := base64.StdEncoding.EncodeToString(digest[:]); got != wantDigest {
		t.Fatalf("%s digest = %q, want %q", draft, got, wantDigest)
	}
	return digest
}

// assertDraft05ResultDigest verifies that production hashing matches the fixed Draft-05 oracle.
func assertDraft05ResultDigest(t *testing.T, result Result, want [sha256.Size]byte) {
	t.Helper()
	digest, ok := result.Digest()
	if !ok || digest.Algorithm() != HashAlgorithmSHA256 || !bytes.Equal(digest.Bytes(), want[:]) {
		t.Fatalf("Draft-05 result digest present=%t algorithm=%q bytes_match=%t", ok, digest.Algorithm(), bytes.Equal(digest.Bytes(), want[:]))
	}
}

// mustDecodeHeaderBoundaryDigest decodes one fixed SHA-256 wire digest.
func mustDecodeHeaderBoundaryDigest(t *testing.T, encoded string) []byte {
	t.Helper()
	digest, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(digest) != sha256.Size {
		t.Fatalf("fixed wire digest error = %v, length = %d", err, len(digest))
	}
	return digest
}

// TestHeaderHashInputCompressesWSPAndRetainsValueBytes verifies Section 6.2 value rules.
func TestHeaderHashInputCompressesWSPAndRetainsValueBytes(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Subject:\t Alpha\r\n"+
			" \tBeta\t\t Gamma \t\r\n"+
			"Comment: \t=?UTF-8?Q?kept=5Fbytes?=\t value\t\r\n"+
			"Empty:\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	want := []byte(
		"comment:=?UTF-8?Q?kept=5Fbytes?= value\r\n" +
			"empty:\r\n" +
			"subject:Alpha Beta Gamma\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("HeaderHashInputFromMessage() = %q, want %q", got.Bytes(), want)
	}
}

// TestHeaderHashInputSortsDuplicatesByReverseOccurrence verifies deterministic ordering.
func TestHeaderHashInputSortsDuplicatesByReverseOccurrence(t *testing.T) {
	msg := mustParseHeaderMessage(t, []byte(
		"Zed: tail\r\n"+
			"Subject: first\r\n"+
			"Alpha: one\r\n"+
			"subject: second\r\n"+
			"ALPHA: two\r\n"))
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	want := []byte(
		"alpha:two\r\n" +
			"alpha:one\r\n" +
			"subject:second\r\n" +
			"subject:first\r\n" +
			"zed:tail\r\n")
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("HeaderHashInputFromMessage() = %q, want %q", got.Bytes(), want)
	}
}

// TestHeaderHashInputBytesAreImmutable verifies callers cannot mutate canonical output.
func TestHeaderHashInputBytesAreImmutable(t *testing.T) {
	rawHeaders := []byte("Subject: immutable\r\nFrom: sender@example.test\r\n")
	msg := mustParseHeaderMessage(t, rawHeaders)
	canonicalizer := mustCanonicalizer(t)

	got, err := canonicalizer.HeaderHashInputFromMessage(msg)
	if err != nil {
		t.Fatalf("HeaderHashInputFromMessage() error = %v", err)
	}

	rawHeaders[0] = 'X'
	exposed := got.Bytes()
	exposed[0] = 'Y'
	if !bytes.Equal(got.Bytes(), []byte("from:sender@example.test\r\nsubject:immutable\r\n")) {
		t.Fatalf("canonical header bytes were mutated: %q", got.Bytes())
	}
	if !bytes.Equal(msg.Headers().OriginalBytes(), []byte("Subject: immutable\r\nFrom: sender@example.test\r\n")) {
		t.Fatalf("raw header bytes were mutated: %q", msg.Headers().OriginalBytes())
	}
}

// TestHeaderHashInputEnforcesLimitsWithoutLeakingValues verifies fail-closed limits.
func TestHeaderHashInputEnforcesLimitsWithoutLeakingValues(t *testing.T) {
	tests := []struct {
		name       string
		headers    []byte
		mutate     func(*Limits)
		limitName  string
		secretText string
	}{
		{
			name:    "field count",
			headers: []byte("Subject: secret-one\r\nFrom: secret-two\r\n"),
			mutate: func(limits *Limits) {
				limits.MaxFieldCount = 1
			},
			limitName:  "max_field_count",
			secretText: "secret-one",
		},
		{
			name:    "field bytes",
			headers: []byte("Subject: secret-value\r\n"),
			mutate: func(limits *Limits) {
				limits.MaxFieldBytes = len("subject:secret-value\r\n") - 1
			},
			limitName:  "max_field_bytes",
			secretText: "secret-value",
		},
		{
			name:    "header output bytes",
			headers: []byte("Subject: secret-output\r\n"),
			mutate: func(limits *Limits) {
				limits.MaxFieldBytes = 1024
				limits.MaxHeaderInputBytes = len("subject:secret-output\r\n") - 1
			},
			limitName:  "max_header_input_bytes",
			secretText: "secret-output",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limits := DefaultLimits()
			tt.mutate(&limits)
			canonicalizer, err := NewCanonicalizer(WithLimits(limits))
			if err != nil {
				t.Fatalf("NewCanonicalizer() error = %v", err)
			}

			_, err = canonicalizer.HeaderHashInputFromMessage(mustParseHeaderMessage(t, tt.headers))
			if !IsErrorCode(err, ErrorCodeLimitExceeded) {
				t.Fatalf("HeaderHashInputFromMessage() error = %v, want limit exceeded", err)
			}
			var canonicalErr *Error
			if !errors.As(err, &canonicalErr) {
				t.Fatalf("HeaderHashInputFromMessage() error = %T, want *Error", err)
			}
			if canonicalErr.LimitName() != tt.limitName {
				t.Fatalf("LimitName() = %q, want %q", canonicalErr.LimitName(), tt.limitName)
			}
			if strings.Contains(err.Error(), tt.secretText) {
				t.Fatalf("HeaderHashInputFromMessage() error leaked header value: %q", err.Error())
			}
		})
	}
}

// mustCanonicalizer constructs a default canonicalizer for header tests.
func mustCanonicalizer(t *testing.T) Canonicalizer {
	t.Helper()

	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	return canonicalizer
}

// mustParseHeaderMessage parses synthetic strict-CRLF header test messages.
func mustParseHeaderMessage(t *testing.T, headers []byte) rawmsg.Message {
	t.Helper()

	raw := make([]byte, 0, len(headers)+len("\r\nbody"))
	raw = append(raw, headers...)
	raw = append(raw, "\r\nbody"...)
	msg, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}

	return msg
}
