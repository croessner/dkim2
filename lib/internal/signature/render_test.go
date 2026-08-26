package signature

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/rawmsg"
)

const (
	signatureTestDomain         = "example.test"
	signatureTestSelector       = "selector"
	signatureTestEdSelector     = "ed"
	signatureTestEd1Selector    = "ed1"
	signatureTestRSASelector    = "rsa"
	signatureTestRSA1Selector   = "rsa1"
	signatureTestFirstSelector  = "one"
	signatureTestSecondSelector = "two"
	signatureTestThirdSelector  = "three"
)

// TestUnsignedTargetAndCompleteFieldRemainDistinct verifies ordinary deterministic rendering.
func TestUnsignedTargetAndCompleteFieldRemainDistinct(t *testing.T) {
	request := TargetRequest{
		Sequence: 4, InstanceNumber: 3, Timestamp: 1234,
		MailFrom:   []byte("<sender@example.test>"),
		Recipients: [][]byte{[]byte("<one@example.net>"), []byte("<two@example.net>")},
		Domain:     "Example.TEST",
		Sets:       []SetPlan{{Selector: signatureTestEd1Selector, Algorithm: AlgorithmEd25519SHA256}, {Selector: signatureTestRSA1Selector, Algorithm: AlgorithmRSASHA256}},
		Nonce:      []byte{}, NoncePresent: true,
		Flags: []string{FlagExploded, FlagDoNotModify},
	}
	target, err := NewUnsignedTarget(request, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	if _, ok := reflect.TypeFor[UnsignedTarget]().MethodByName("Bytes"); ok {
		t.Fatal("unsigned target exposes complete-field Bytes method")
	}
	unsigned := string(target.UnsignedBytes())
	wantUnsigned := "DKIM2-Signature: i=4;\r\n" +
		"\tm=3;\r\n" +
		"\tt=1234;\r\n" +
		"\tmf=" + base64.StdEncoding.EncodeToString(request.MailFrom) + ";\r\n" +
		"\trt=" + base64.StdEncoding.EncodeToString(request.Recipients[0]) + ",\r\n" +
		"\t" + base64.StdEncoding.EncodeToString(request.Recipients[1]) + ";\r\n" +
		"\td=example.test;\r\n" +
		"\ts=rsa1:rsa-sha256:,\r\n" +
		"\ted1:ed25519-sha256:;\r\n" +
		"\tn=;\r\n" +
		"\tf=donotmodify,exploded;\r\n"
	if unsigned != wantUnsigned {
		t.Fatalf("UnsignedBytes() deterministic equality=false got_length=%d want_length=%d", len(unsigned), len(wantUnsigned))
	}

	rsa := bytes.Repeat([]byte{0x33}, 128)
	ed := bytes.Repeat([]byte{0x44}, 64)
	complete, err := target.Complete([]SetValue{
		{Selector: signatureTestRSA1Selector, Algorithm: AlgorithmRSASHA256, Signature: rsa},
		{Selector: signatureTestEd1Selector, Algorithm: AlgorithmEd25519SHA256, Signature: ed},
	})
	if err != nil {
		t.Fatalf("Complete() code=%s", signatureTestErrorCode(err))
	}
	rsaFolded := foldSignatureBase64ForTest(base64.StdEncoding.EncodeToString(rsa))
	edFolded := foldSignatureBase64ForTest(base64.StdEncoding.EncodeToString(ed))
	if !bytes.Contains(complete.Bytes(), []byte("rsa1:rsa-sha256:"+rsaFolded)) || !bytes.Contains(complete.Bytes(), []byte("ed1:ed25519-sha256:"+edFolded)) {
		t.Fatal("complete field omitted exact folded signature bytes")
	}
	parsedMessage, err := rawmsg.Parse(complete.Bytes())
	if err != nil {
		t.Fatal("rawmsg.Parse(complete) failed")
	}
	parsed, err := Parse(parsedMessage.Headers().FieldsByName(HeaderName)[0])
	if err != nil {
		t.Fatalf("Parse(complete) code=%s", signatureTestErrorCode(err))
	}
	sets := parsed.SignatureSets()
	if !bytes.Equal(sets[0].Signature().Decoded(), rsa) || !bytes.Equal(sets[1].Signature().Decoded(), ed) {
		t.Fatal("folded complete signatures did not decode exactly")
	}
	completeSize := len(complete.Bytes())
	limitedTarget, err := NewUnsignedTarget(request, RenderLimits{MaxFieldBytes: completeSize})
	if err != nil {
		t.Fatalf("exact complete-field preflight target code=%s", signatureTestErrorCode(err))
	}
	if _, err := limitedTarget.Complete([]SetValue{
		{Selector: signatureTestRSA1Selector, Algorithm: AlgorithmRSASHA256, Signature: rsa},
		{Selector: signatureTestEd1Selector, Algorithm: AlgorithmEd25519SHA256, Signature: ed},
	}); err != nil {
		t.Fatalf("exact complete-field preflight code=%s", signatureTestErrorCode(err))
	}
	tightTarget, err := NewUnsignedTarget(request, RenderLimits{MaxFieldBytes: completeSize - 1})
	if err != nil {
		t.Fatalf("one-over complete-field target setup code=%s", signatureTestErrorCode(err))
	}
	if _, err := tightTarget.Complete([]SetValue{
		{Selector: signatureTestRSA1Selector, Algorithm: AlgorithmRSASHA256, Signature: rsa},
		{Selector: signatureTestEd1Selector, Algorithm: AlgorithmEd25519SHA256, Signature: ed},
	}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over complete-field preflight code=%s", signatureTestErrorCode(err))
	}
	unsignedCopy := target.UnsignedBytes()
	unsignedCopy[0] ^= 0xff
	if string(target.UnsignedBytes()) != wantUnsigned {
		t.Fatal("UnsignedBytes() returned mutable storage")
	}
	completeCopy := complete.Bytes()
	completeCopy[0] ^= 0xff
	if bytes.Equal(completeCopy, complete.Bytes()) {
		t.Fatal("CompleteField.Bytes() returned mutable storage")
	}
	request.MailFrom[1], request.Recipients[0][1], request.Sets[0].Selector = 'X', 'X', "changed"
	if string(target.UnsignedBytes()) != wantUnsigned {
		t.Fatal("caller mutation changed unsigned target")
	}
}

// TestNextDomainTargetUsesClosedTagOrder verifies nd= excludes ordinary envelope tags.
func TestNextDomainTargetUsesClosedTagOrder(t *testing.T) {
	target, err := NewUnsignedTarget(TargetRequest{
		Sequence: 2, InstanceNumber: 1, Timestamp: 9, NextDomain: "Next.Example",
		Domain: "Signer.Example", Sets: []SetPlan{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256}},
	}, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	want := "DKIM2-Signature: i=2;\r\n\tm=1;\r\n\tt=9;\r\n\tnd=next.example;\r\n\td=signer.example;\r\n\ts=ed:ed25519-sha256:;\r\n"
	if got := string(target.UnsignedBytes()); got != want {
		t.Fatalf("UnsignedBytes() deterministic equality=false got_length=%d want_length=%d", len(got), len(want))
	}
	if bytes.Contains(target.UnsignedBytes(), []byte("mf=")) || bytes.Contains(target.UnsignedBytes(), []byte("rt=")) {
		t.Fatal("next-domain target contains ordinary envelope tags")
	}
}

// TestPreflightCompleteValidatesPlansWithoutSignatureBytes proves the pre-callback sizing seam.
func TestPreflightCompleteValidatesPlansWithoutSignatureBytes(t *testing.T) {
	request := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: []byte("<>"),
		Recipients: [][]byte{[]byte("<user@example.test>")}, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256}, {Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256}},
	}
	target, err := NewUnsignedTarget(request, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	lengths := []SetLength{
		{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 64},
		{Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Bytes: 128},
	}
	size, err := target.PreflightComplete(lengths)
	if err != nil {
		t.Fatalf("PreflightComplete() code=%s", signatureTestErrorCode(err))
	}
	complete, err := target.Complete([]SetValue{
		{Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Signature: bytes.Repeat([]byte{1}, 128)},
		{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Signature: bytes.Repeat([]byte{2}, 64)},
	})
	if err != nil || size != len(complete.Bytes()) {
		t.Fatalf("preflight/complete size equality=%t code=%s", size == len(complete.Bytes()), signatureTestErrorCode(err))
	}
	exact, err := NewUnsignedTarget(request, RenderLimits{MaxFieldBytes: size})
	if err != nil {
		t.Fatalf("exact target setup code=%s", signatureTestErrorCode(err))
	}
	if got, err := exact.PreflightComplete(lengths); err != nil || got != size {
		t.Fatalf("exact preflight size equality=%t code=%s", got == size, signatureTestErrorCode(err))
	}
	tight, err := NewUnsignedTarget(request, RenderLimits{MaxFieldBytes: size - 1})
	if err != nil {
		t.Fatalf("tight target setup code=%s", signatureTestErrorCode(err))
	}
	if _, err := tight.PreflightComplete(lengths); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over preflight code=%s", signatureTestErrorCode(err))
	}
	badPlans := [][]SetLength{
		{{Selector: "wrong", Algorithm: AlgorithmEd25519SHA256, Bytes: 64}, {Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Bytes: 128}},
		{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 64}},
		{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 64}, {Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 64}},
	}
	for _, bad := range badPlans {
		if _, err := target.PreflightComplete(bad); !IsErrorCode(err, ErrorCodeInvalidConstruction) {
			t.Fatalf("invalid preflight plan code=%s", signatureTestErrorCode(err))
		}
	}
	if _, err := target.PreflightComplete([]SetLength{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 63}, {Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Bytes: 128}}); !IsErrorCode(err, ErrorCodeInvalidSignatureLength) {
		t.Fatalf("invalid Ed25519 length code=%s", signatureTestErrorCode(err))
	}
	if _, err := target.PreflightComplete([]SetLength{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 64}, {Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Bytes: 1025}}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("oversized RSA length code=%s", signatureTestErrorCode(err))
	}
	lengths[0].Selector = "mutated"
	if _, err := target.PreflightComplete([]SetLength{{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Bytes: 64}, {Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Bytes: 128}}); err != nil {
		t.Fatalf("caller mutation affected immutable target code=%s", signatureTestErrorCode(err))
	}
}

// TestRebuildUnsignedFromCompleteDerivesEveryNullSignatureSet verifies reparse-owned reconstruction.
func TestRebuildUnsignedFromCompleteDerivesEveryNullSignatureSet(t *testing.T) {
	target, complete, rsaSignature, edSignature := rebuildUnsignedFixture(t)

	rebuilt, err := target.RebuildUnsignedFromComplete(complete)
	if err != nil {
		t.Fatalf("RebuildUnsignedFromComplete() code=%s", signatureTestErrorCode(err))
	}
	if !bytes.Equal(rebuilt.UnsignedBytes(), target.UnsignedBytes()) {
		t.Fatal("rebuilt unsigned target differs from the pre-sign target")
	}
	if bytes.Contains(rebuilt.UnsignedBytes(), []byte(base64.StdEncoding.EncodeToString(rsaSignature))) ||
		bytes.Contains(rebuilt.UnsignedBytes(), []byte(base64.StdEncoding.EncodeToString(edSignature))) {
		t.Fatal("rebuilt unsigned target retained a completed signature")
	}

	reflowed := bytes.ReplaceAll(complete.Bytes(), []byte("\r\n\t"), []byte(" \t"))
	rebuilt, err = target.RebuildUnsignedFromComplete(CompleteField{field: reflowed})
	if err != nil {
		t.Fatalf("RebuildUnsignedFromComplete(reflowed) code=%s", signatureTestErrorCode(err))
	}
	if !bytes.Equal(rebuilt.UnsignedBytes(), target.UnsignedBytes()) {
		t.Fatal("physical FWS reflow changed the rebuilt logical target")
	}
}

// TestRebuildUnsignedFromCompleteRejectsLogicalTargetMutation verifies exact tag, order, and value binding.
func TestRebuildUnsignedFromCompleteRejectsLogicalTargetMutation(t *testing.T) {
	target, complete, rsaSignature, edSignature := rebuildUnsignedFixture(t)
	compact := string(bytes.ReplaceAll(complete.Bytes(), []byte("\r\n\t"), nil))
	rsaSet := "rsa:rsa-sha256:" + base64.StdEncoding.EncodeToString(rsaSignature)
	edSet := "ed:ed25519-sha256:" + base64.StdEncoding.EncodeToString(edSignature)

	mutations := []struct {
		name  string
		field string
	}{
		{
			name:  "tag reorder",
			field: strings.Replace(compact, "i=7;m=6;t=1234;", "i=7;t=1234;m=6;", 1),
		},
		{
			name:  "extra tag",
			field: strings.Replace(compact, "t=1234;", "t=1234;x-extra=1;", 1),
		},
		{
			name:  "non-signature mutation",
			field: strings.Replace(compact, "d=example.test;", "d=changed.example;", 1),
		},
		{
			name:  "numeric lexical mutation",
			field: strings.Replace(compact, "i=7;", "i=07;", 1),
		},
		{
			name:  "signature-set reorder",
			field: strings.Replace(compact, rsaSet+","+edSet, edSet+","+rsaSet, 1),
		},
		{
			name:  "signature-set selector mutation",
			field: strings.Replace(compact, rsaSet, strings.Replace(rsaSet, "rsa:", "rsa2:", 1), 1),
		},
		{
			name:  "signature-set algorithm mutation",
			field: strings.Replace(compact, rsaSet, strings.Replace(rsaSet, "rsa-sha256", "x-rsa-sha256", 1), 1),
		},
		{
			name:  "second header field",
			field: strings.TrimSuffix(compact, "\r\n") + "\r\nSubject: unrelated\r\n",
		},
		{
			name:  "appended body",
			field: compact + "\r\nunrelated\r\n",
		},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			if test.field == compact {
				t.Fatal("test mutation did not change the complete field")
			}
			_, err := target.RebuildUnsignedFromComplete(CompleteField{field: []byte(test.field)})
			if !IsErrorCode(err, ErrorCodeInvalidConstruction) {
				t.Fatalf("RebuildUnsignedFromComplete() code=%s", signatureTestErrorCode(err))
			}
		})
	}
}

// rebuildUnsignedFixture returns one dual-signature target and its completed field.
func rebuildUnsignedFixture(t *testing.T) (UnsignedTarget, CompleteField, []byte, []byte) {
	t.Helper()
	target, err := NewUnsignedTarget(TargetRequest{
		Sequence: 7, InstanceNumber: 6, Timestamp: 1234,
		MailFrom:   []byte("<sender@example.test>"),
		Recipients: [][]byte{[]byte("<recipient@example.net>")},
		Domain:     signatureTestDomain,
		Sets: []SetPlan{
			{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256},
			{Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256},
		},
		Nonce: []byte("nonce"), NoncePresent: true,
		Flags: []string{FlagDoNotModify, FlagFeedback},
	}, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	rsaSignature := bytes.Repeat([]byte{0x31}, 128)
	edSignature := bytes.Repeat([]byte{0x32}, ed25519SignatureBytes)
	complete, err := target.Complete([]SetValue{
		{Selector: signatureTestRSASelector, Algorithm: AlgorithmRSASHA256, Signature: rsaSignature},
		{Selector: signatureTestEdSelector, Algorithm: AlgorithmEd25519SHA256, Signature: edSignature},
	})
	if err != nil {
		t.Fatalf("Complete() code=%s", signatureTestErrorCode(err))
	}
	return target, complete, rsaSignature, edSignature
}

// TestTargetEnforcesSharedSignatureSetCardinality verifies renderer/parser invariant parity.
func TestTargetEnforcesSharedSignatureSetCardinality(t *testing.T) {
	base := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: []byte("<>"),
		Recipients: [][]byte{[]byte("<user@example.test>")}, Domain: signatureTestDomain,
	}
	accepted := base
	accepted.Sets = []SetPlan{{Selector: signatureTestFirstSelector, Algorithm: AlgorithmRSASHA256}, {Selector: signatureTestSecondSelector, Algorithm: Algorithm("RSA-SHA256")}}
	if _, err := NewUnsignedTarget(accepted, RenderLimits{}); err != nil {
		t.Fatalf("NewUnsignedTarget(two same algorithm) code=%s", signatureTestErrorCode(err))
	}
	extension := base
	extension.Sets = []SetPlan{{Selector: signatureTestFirstSelector, Algorithm: Algorithm("FUTURE-SHA999")}, {Selector: signatureTestSecondSelector, Algorithm: Algorithm(testExtensionAlgorithm)}}
	extensionTarget, err := NewUnsignedTarget(extension, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget(two extension signatures) code=%s", signatureTestErrorCode(err))
	}
	extensionComplete, err := extensionTarget.Complete([]SetValue{
		{Selector: signatureTestFirstSelector, Algorithm: Algorithm(testExtensionAlgorithm), Signature: bytes.Repeat([]byte{0x41}, 48)},
		{Selector: signatureTestSecondSelector, Algorithm: Algorithm("FUTURE-SHA999"), Signature: bytes.Repeat([]byte{0x42}, 48)},
	})
	if err != nil {
		t.Fatalf("Complete(two extension signatures) code=%s", signatureTestErrorCode(err))
	}
	message, err := rawmsg.Parse(extensionComplete.Bytes())
	if err != nil {
		t.Fatalf("rawmsg.Parse(extension complete) error=%v", err)
	}
	parsed, err := Parse(message.Headers().FieldsByName(HeaderName)[0])
	if err != nil || len(parsed.SignatureSets()) != 2 || parsed.SignatureSets()[0].Algorithm() != testExtensionAlgorithm || parsed.SignatureSets()[1].Algorithm() != testExtensionAlgorithm {
		t.Fatalf("Parse(extension complete) code=%s sets=%#v", signatureTestErrorCode(err), parsed.SignatureSets())
	}
	tests := []struct {
		name string
		sets []SetPlan
		code ErrorCode
	}{
		{name: "duplicate selector", sets: []SetPlan{{Selector: "same", Algorithm: AlgorithmRSASHA256}, {Selector: "SAME", Algorithm: AlgorithmEd25519SHA256}}, code: ErrorCodeDuplicateSelector},
		{name: "third extension algorithm", sets: []SetPlan{{Selector: signatureTestFirstSelector, Algorithm: Algorithm("future")}, {Selector: signatureTestSecondSelector, Algorithm: Algorithm("FUTURE")}, {Selector: signatureTestThirdSelector, Algorithm: Algorithm("future")}}, code: ErrorCodeTooManySignatures},
		{name: "total set limit", sets: []SetPlan{{Selector: signatureTestFirstSelector, Algorithm: Algorithm("future-one")}, {Selector: signatureTestSecondSelector, Algorithm: Algorithm("future-two")}, {Selector: signatureTestThirdSelector, Algorithm: Algorithm("future-three")}}, code: ErrorCodeLimitExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.Sets = test.sets
			if _, err := NewUnsignedTarget(request, RenderLimits{}); !IsErrorCode(err, test.code) {
				t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
			}
		})
	}
}

// TestSignatureBase64AndPhysicalLineLimits verifies exact folding and line-bound rejection.
func TestSignatureBase64AndPhysicalLineLimits(t *testing.T) {
	local := strings.Repeat("a", 64)
	domain := strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".example"
	path := []byte("<" + local + "@" + domain + ">")
	target, err := NewUnsignedTarget(TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: path,
		Recipients: [][]byte{path}, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: strings.Repeat("s", 63), Algorithm: AlgorithmRSASHA256}},
	}, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	foldedPath := foldSignatureBase64ForTest(base64.StdEncoding.EncodeToString(path))
	if !bytes.Contains(target.UnsignedBytes(), []byte("mf="+foldedPath)) || !bytes.Contains(target.UnsignedBytes(), []byte("rt="+foldedPath)) {
		t.Fatal("envelope Base64 did not fold in exact 64-character chunks")
	}
	maxLine := longestPhysicalLine(target.UnsignedBytes())
	if _, err := NewUnsignedTarget(TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: path,
		Recipients: [][]byte{path}, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: strings.Repeat("s", 63), Algorithm: AlgorithmRSASHA256}},
	}, RenderLimits{MaxLineBytes: maxLine}); err != nil {
		t.Fatalf("exact physical-line limit code=%s", signatureTestErrorCode(err))
	}
	if _, err := NewUnsignedTarget(TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: path,
		Recipients: [][]byte{path}, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: strings.Repeat("s", 63), Algorithm: AlgorithmRSASHA256}},
	}, RenderLimits{MaxLineBytes: maxLine - 1}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over physical-line code=%s", signatureTestErrorCode(err))
	}
}

// foldSignatureBase64ForTest returns exact 64-character CRLF HTAB chunks.
func foldSignatureBase64ForTest(encoded string) string {
	var builder strings.Builder
	for start := 0; start < len(encoded); start += 64 {
		if start > 0 {
			builder.WriteString("\r\n\t")
		}
		end := min(start+64, len(encoded))
		builder.WriteString(encoded[start:end])
	}
	return builder.String()
}

// longestPhysicalLine returns the longest CRLF-delimited line excluding CRLF.
func longestPhysicalLine(field []byte) int {
	longest := 0
	for line := range bytes.SplitSeq(bytes.TrimSuffix(field, []byte("\r\n")), []byte("\r\n")) {
		longest = max(longest, len(line))
	}
	return longest
}

// TestTargetLimitsAndFormattingFailClosed verifies generation bounds and redaction.
func TestTargetLimitsAndFormattingFailClosed(t *testing.T) {
	request := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1,
		MailFrom: []byte("<secret-sender@example.test>"), Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: "secret-selector", Algorithm: AlgorithmRSASHA256}},
	}
	for range 129 {
		request.Recipients = append(request.Recipients, []byte("<user@example.test>"))
	}
	if _, err := NewUnsignedTarget(request, RenderLimits{}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("129 recipients code=%s", signatureTestErrorCode(err))
	}
	request.Recipients = request.Recipients[:1]
	target, err := NewUnsignedTarget(request, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code = %s", signatureTestErrorCode(err))
	}
	for _, formatted := range []string{fmt.Sprintf("%v", target), fmt.Sprintf("%+v", target), fmt.Sprintf("%#v", target), target.String(), target.GoString()} {
		if strings.Contains(formatted, "secret-") || !strings.Contains(formatted, "redacted") {
			t.Fatal("target formatting was not redacted")
		}
	}
	if _, err := target.Complete([]SetValue{{Selector: "secret-selector", Algorithm: AlgorithmRSASHA256, Signature: bytes.Repeat([]byte{1}, 1025)}}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("oversized signature code=%s", signatureTestErrorCode(err))
	}
}

// TestTargetUsesFrozenFlagOrder verifies the closed order independently of caller order.
func TestTargetUsesFrozenFlagOrder(t *testing.T) {
	target, err := NewUnsignedTarget(TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: []byte("<>"),
		Recipients: [][]byte{[]byte("<user@example.test>")}, Domain: signatureTestDomain,
		Sets:  []SetPlan{{Selector: signatureTestSelector, Algorithm: AlgorithmRSASHA256}},
		Flags: []string{FlagExploded, FlagFeedHere, FlagFeedback, FlagDoNotExplode, FlagDoNotModify},
	}, RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() code=%s", signatureTestErrorCode(err))
	}
	want := []byte("\tf=donotmodify,donotexplode,feedback,feedhere,exploded;\r\n")
	if !bytes.Contains(target.UnsignedBytes(), want) {
		t.Fatal("generated flags did not use the frozen closed order")
	}
}

// TestAggregateEnvelopeAndFieldPreflightLimits verifies exact and one-over rejection before render.
func TestAggregateEnvelopeAndFieldPreflightLimits(t *testing.T) {
	recipients := make([][]byte, 0, 128)
	for index := range 127 {
		recipients = append(recipients, syntheticPath(index, 256))
	}
	recipients = append(recipients, syntheticPath(127, 254))
	request := TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: []byte("<>"),
		Recipients: recipients, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: signatureTestSelector, Algorithm: AlgorithmRSASHA256}},
	}
	target, err := NewUnsignedTarget(request, RenderLimits{})
	if err != nil {
		t.Fatalf("exact aggregate envelope code=%s", signatureTestErrorCode(err))
	}
	fieldBytes := len(target.UnsignedBytes())
	if _, err := NewUnsignedTarget(request, RenderLimits{MaxFieldBytes: fieldBytes}); err != nil {
		t.Fatalf("exact field preflight code=%s", signatureTestErrorCode(err))
	}
	if _, err := NewUnsignedTarget(request, RenderLimits{MaxFieldBytes: fieldBytes - 1}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over field preflight code=%s", signatureTestErrorCode(err))
	}
	request.Recipients[len(request.Recipients)-1] = syntheticPath(127, 255)
	if _, err := NewUnsignedTarget(request, RenderLimits{}); !IsErrorCode(err, ErrorCodeLimitExceeded) {
		t.Fatalf("one-over aggregate envelope code=%s", signatureTestErrorCode(err))
	}
}

// TestTargetRejectsDuplicateRecipients verifies byte-identical paths are not merged.
func TestTargetRejectsDuplicateRecipients(t *testing.T) {
	path := []byte("<duplicate@example.test>")
	_, err := NewUnsignedTarget(TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1, MailFrom: []byte("<>"),
		Recipients: [][]byte{path, bytes.Clone(path)}, Domain: signatureTestDomain,
		Sets: []SetPlan{{Selector: signatureTestSelector, Algorithm: AlgorithmRSASHA256}},
	}, RenderLimits{})
	if !IsErrorCode(err, ErrorCodeInvalidEnvelopePath) {
		t.Fatalf("duplicate recipient code=%s", signatureTestErrorCode(err))
	}
}

// TestSignatureDomainFormattingIsConstantAndSecretSafe covers generated and parsed models.
func TestSignatureDomainFormattingIsConstantAndSecretSafe(t *testing.T) {
	marker := signatureTestSecretMarker
	values := []any{
		TargetRequest{Domain: marker, MailFrom: []byte(marker), Nonce: []byte(marker)},
		SetPlan{Selector: marker, Algorithm: Algorithm(marker)},
		SetValue{Selector: marker, Algorithm: Algorithm(marker), Signature: []byte(marker)},
		SetLength{Selector: marker, Algorithm: Algorithm(marker), Bytes: len(marker)},
		CompleteField{field: []byte(marker)},
		Signature{domain: marker, nextDomain: marker, nonce: []byte(marker)},
		EnvelopePath{value: []byte(marker)}, Set{selector: marker, algorithm: marker},
		Flags{values: []Flag{{name: marker}}}, Flag{name: marker},
	}
	for _, value := range values {
		for _, formatted := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			if strings.Contains(formatted, marker) || !strings.Contains(formatted, "redacted") {
				t.Fatal("content-bearing signature model formatting was not constant and redacted")
			}
		}
		formatter := value.(interface {
			String() string
			GoString() string
		})
		for _, formatted := range []string{formatter.String(), formatter.GoString()} {
			if strings.Contains(formatted, marker) || !strings.Contains(formatted, "redacted") {
				t.Fatal("content-bearing signature model direct formatting was not constant and redacted")
			}
		}
	}
}

// syntheticPath returns one unique valid SMTP path with the requested byte length.
func syntheticPath(index int, length int) []byte {
	local := fmt.Sprintf("%03d", index) + strings.Repeat("a", 61)
	domainLength := length - len(local) - len("<@>")
	labels := make([]string, 0, 4)
	for domainLength > 0 {
		labelLength := min(63, domainLength)
		labels = append(labels, strings.Repeat("b", labelLength))
		domainLength -= labelLength
		if domainLength > 0 {
			domainLength--
		}
	}
	return []byte("<" + local + "@" + strings.Join(labels, ".") + ">")
}

// signatureTestErrorCode returns a safe code without formatting arbitrary errors.
func signatureTestErrorCode(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code()
	}
	return ""
}
