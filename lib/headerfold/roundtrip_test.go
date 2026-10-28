package headerfold

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

// testRSASelector names the RSA set in the rendered long-field fixtures.
const testRSASelector = "rsa"

// projectForTest mirrors the dkim2d REST projection: it drops the field name,
// the colon, the final CRLF, and every CRLF that precedes folding WSP.
func projectForTest(t *testing.T, field []byte) (string, string) {
	t.Helper()
	name, value, ok := bytes.Cut(bytes.TrimSuffix(field, []byte("\r\n")), []byte(":"))
	if !ok {
		t.Fatal("rendered field has no colon")
	}
	return string(name), strings.ReplaceAll(string(value), "\r\n", "")
}

// assertRoundTrip proves Restore rebuilds exactly the library line structure
// with LF line ends and that every physical line fits RFC 5322.
func assertRoundTrip(t *testing.T, field []byte) {
	t.Helper()
	if bytes.Contains(field, []byte("\r\n ")) {
		t.Fatal("renderer folded with CRLF+SP; Restore relies on CRLF+TAB folds only")
	}
	for index := range field {
		if field[index] == '\t' && (index < 2 || field[index-2] != '\r' || field[index-1] != '\n') {
			t.Fatal("renderer emitted a TAB that does not start a continuation line")
		}
	}
	name, value := projectForTest(t, field)
	restored := Restore(value)
	want := strings.TrimSuffix(strings.ReplaceAll(string(field), "\r\n", "\n"), "\n")
	if name+":"+restored != want {
		t.Fatal("Restore did not rebuild the library fold points")
	}
	if !WithinLineLimit(name, restored) {
		t.Fatal("restored library field exceeds the line limit")
	}
}

// TestRestoreRoundTripsLongSignatureField renders a real multi-kilobyte
// DKIM2-Signature (an 8192-bit RSA set plus an Ed25519 set) through the
// library grammar and proves the projection plus Restore round trip, the case
// that previously produced an over-long unfolded line.
func TestRestoreRoundTripsLongSignatureField(t *testing.T) {
	target, err := signature.NewUnsignedTarget(signature.TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1_792_590_164,
		MailFrom:   []byte("<sender@example.test>"),
		Recipients: [][]byte{[]byte("<one@example.net>"), []byte("<two@example.net>")},
		Domain:     "example.test",
		Sets: []signature.SetPlan{
			{Selector: testRSASelector, Algorithm: signature.AlgorithmRSASHA256},
			{Selector: "ed", Algorithm: signature.AlgorithmEd25519SHA256},
		},
	}, signature.RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() error = %v", err)
	}
	complete, err := target.Complete([]signature.SetValue{
		{Selector: testRSASelector, Algorithm: signature.AlgorithmRSASHA256, Signature: bytes.Repeat([]byte{0x33}, 1024)},
		{Selector: "ed", Algorithm: signature.AlgorithmEd25519SHA256, Signature: bytes.Repeat([]byte{0x5a}, 64)},
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	_, projected := projectForTest(t, complete.Bytes())
	if WithinLineLimit("DKIM2-Signature", projected) {
		t.Fatal("fixture is not long enough to reproduce the unfolded-line defect")
	}
	assertRoundTrip(t, complete.Bytes())
}

// TestRestoreRoundTripsMLDSA44SignatureField renders the longest signer
// layout, an 8192-bit RSA set and an Ed25519 set as one sig-all group plus a
// pure ML-DSA-44 alternative after "|", whose 2420-octet value is 3228 base64
// characters (Draft-08 Section 3.4). The renderer folds the value inside the
// base64string, and the REST projection plus Restore must rebuild the exact
// fold points with every physical line inside the RFC 5322 limit.
func TestRestoreRoundTripsMLDSA44SignatureField(t *testing.T) {
	sets := []signature.SetPlan{
		{Selector: testRSASelector, Algorithm: signature.AlgorithmRSASHA256},
		{Selector: "ed", Algorithm: signature.AlgorithmEd25519SHA256},
		{Selector: "pq", Algorithm: signature.AlgorithmMLDSA44},
	}
	target, err := signature.NewUnsignedTarget(signature.TargetRequest{
		Sequence: 1, InstanceNumber: 1, Timestamp: 1_792_590_164,
		MailFrom:   []byte("<sender@example.test>"),
		Recipients: [][]byte{[]byte("<one@example.net>")},
		Domain:     "example.test",
		Sets:       sets,
	}, signature.RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() error = %v", err)
	}
	mldsaValue := bytes.Repeat([]byte{0x6c}, 2420)
	complete, err := target.Complete([]signature.SetValue{
		{Selector: testRSASelector, Algorithm: signature.AlgorithmRSASHA256, Signature: bytes.Repeat([]byte{0x33}, 1024)},
		{Selector: "ed", Algorithm: signature.AlgorithmEd25519SHA256, Signature: bytes.Repeat([]byte{0x5a}, 64)},
		{Selector: "pq", Algorithm: signature.AlgorithmMLDSA44, Signature: mldsaValue},
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	field := complete.Bytes()
	if !bytes.Contains(field, []byte("|\r\n\tpq:mldsa44:")) {
		t.Fatal("mldsa44 set is not a separate sig-any alternative")
	}
	_, projected := projectForTest(t, field)
	if WithinLineLimit("DKIM2-Signature", projected) {
		t.Fatal("fixture is not long enough to reproduce the unfolded-line defect")
	}
	unfolded := strings.NewReplacer("\r\n\t", "", "\r\n", "").Replace(string(field))
	encoded := base64.StdEncoding.EncodeToString(mldsaValue)
	if len(encoded) != 3228 || !strings.Contains(unfolded, "pq:mldsa44:"+encoded+";") {
		t.Fatal("unfolded field does not carry the 3228-character mldsa44 value")
	}
	for line := range strings.SplitSeq(string(field), "\r\n") {
		if len(line) > 998 {
			t.Fatalf("rendered line of %d octets exceeds the RFC 5322 limit", len(line))
		}
	}
	assertRoundTrip(t, field)
	parsed, err := signature.Parse(mustHeaderField(t, field))
	if err != nil || len(parsed.SignatureSets()) != 3 || parsed.SignatureLayout().Groups() != 2 {
		t.Fatalf("Parse(rendered mldsa44 field) error = %v", err)
	}
}

// TestRestoreRoundTripsMessageInstanceField proves the same invariant for the
// second field the adapters add.
func TestRestoreRoundTripsMessageInstanceField(t *testing.T) {
	model, err := instance.NewForSigning(instance.SigningRequest{
		Number: 3, HeaderHash: bytes.Repeat([]byte{0x11}, 32), BodyHash: bytes.Repeat([]byte{0x22}, 32),
		Recipe: []byte(`{"h":{"subject":[{"d":"old"}]}}`), RecipePresent: true,
	})
	if err != nil {
		t.Fatalf("NewForSigning() error = %v", err)
	}
	field, err := model.Render(instance.RenderLimits{})
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	assertRoundTrip(t, field)
}

// mustHeaderField parses one rendered field as the only header of a message.
func mustHeaderField(t *testing.T, field []byte) rawmsg.HeaderField {
	t.Helper()
	message, err := rawmsg.Parse(append(bytes.Clone(field), []byte("\r\nbody\r\n")...))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	fields := message.Headers().FieldsByName(signature.HeaderName)
	if len(fields) != 1 {
		t.Fatalf("parsed %d signature fields", len(fields))
	}
	return fields[0]
}
