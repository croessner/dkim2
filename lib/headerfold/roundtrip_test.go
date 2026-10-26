package headerfold

import (
	"bytes"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/signature"
)

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
			{Selector: "rsa", Algorithm: signature.AlgorithmRSASHA256},
			{Selector: "ed", Algorithm: signature.AlgorithmEd25519SHA256},
		},
	}, signature.RenderLimits{})
	if err != nil {
		t.Fatalf("NewUnsignedTarget() error = %v", err)
	}
	complete, err := target.Complete([]signature.SetValue{
		{Selector: "rsa", Algorithm: signature.AlgorithmRSASHA256, Signature: bytes.Repeat([]byte{0x33}, 1024)},
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
