package replay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// testFirstSeenValue is the first-seen value rendered from testNonceBytes.
const testFirstSeenValue = "v2:0123456789abcdef"

// testNonceBytes is one fixed synthetic nonce source for deterministic grammar tests.
var testNonceBytes = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

// mustTestNonce constructs one deterministic nonce from fixed synthetic bytes.
func mustTestNonce(t testing.TB, source []byte) Nonce {
	t.Helper()
	nonce, err := NewNonce(bytes.NewReader(source))
	if err != nil {
		t.Fatalf("NewNonce error=%v", err)
	}
	return nonce
}

// failingReader returns one constant read failure.
type failingReader struct{}

// Read always fails without producing bytes.
func (failingReader) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

// TestNonceConstructionFailsClosed proves short, failing, and all-zero sources are rejected.
func TestNonceConstructionFailsClosed(t *testing.T) {
	for name, source := range map[string]*bytes.Reader{
		"short": bytes.NewReader([]byte{1, 2, 3}),
		"zero":  bytes.NewReader(make([]byte, nonceByteLength)),
		"empty": bytes.NewReader(nil),
	} {
		if nonce, err := NewNonce(source); nonce.Valid() || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
			t.Fatalf("%s nonce valid=%t code=%q", name, nonce.Valid(), ErrorCodeOf(err))
		}
	}
	if nonce, err := NewNonce(failingReader{}); nonce.Valid() || ErrorCodeOf(err) != ErrorCodeInternalInvariant {
		t.Fatalf("failing reader nonce valid=%t code=%q", nonce.Valid(), ErrorCodeOf(err))
	}
	first, err := NewNonce(nil)
	if err != nil || !first.Valid() {
		t.Fatalf("crypto nonce valid=%t err=%v", first.Valid(), err)
	}
	second, err := NewNonce(nil)
	if err != nil || first == second {
		t.Fatal("crypto nonces repeated or failed")
	}
}

// TestNonceNeverRendersBytes proves formatting and serialization stay content-free.
func TestNonceNeverRendersBytes(t *testing.T) {
	nonce := mustTestNonce(t, testNonceBytes)
	for _, rendered := range []string{
		nonce.String(), nonce.GoString(), fmt.Sprint(nonce), fmt.Sprintf("%v %+v %#v %x %s", nonce, nonce, nonce, nonce, nonce),
	} {
		if strings.Contains(rendered, "0123456789abcdef") || strings.Contains(rendered, "01 23") {
			t.Fatalf("nonce rendered bytes: %q", rendered)
		}
	}
	if _, err := json.Marshal(nonce); err == nil {
		t.Fatal("nonce JSON serialization accepted")
	}
	if _, err := nonce.MarshalText(); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatal("nonce text serialization accepted")
	}
}

// TestFirstSeenValueGrammar proves the nonce-bearing form, legacy acceptance, and the rejection matrix.
func TestFirstSeenValueGrammar(t *testing.T) {
	nonce := mustTestNonce(t, testNonceBytes)
	value, err := FirstSeenValue(nonce)
	if err != nil || value != testFirstSeenValue {
		t.Fatalf("first-seen value=%q err=%v", value, err)
	}
	parsed, legacy, ok := ParseFirstSeenValue(value)
	if !ok || legacy || parsed != nonce {
		t.Fatalf("parsed own value ok=%t legacy=%t equal=%t", ok, legacy, parsed == nonce)
	}
	parsed, legacy, ok = ParseFirstSeenValue(StoredValue)
	if !ok || !legacy || parsed.Valid() {
		t.Fatalf("legacy value ok=%t legacy=%t valid=%t", ok, legacy, parsed.Valid())
	}
	if _, err := FirstSeenValue(Nonce{}); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("zero nonce code=%q", ErrorCodeOf(err))
	}
	for _, invalid := range []string{
		"", "v1 ", "V1", "v2", "v2:", "v2:0123456789abcde", "v2:0123456789abcdef0",
		"v2:0123456789ABCDEF", "v2:0123456789abcdeg", "v3:0123456789abcdef", "v2;0123456789abcdef",
		"v2:0123456789abcde\x00", "committed", "pending:1", " v2:0123456789abcdef",
	} {
		if _, _, ok := ParseFirstSeenValue(invalid); ok {
			t.Fatalf("invalid first-seen value %q accepted", invalid)
		}
	}
}

// TestPropagationPendingValueGrammar proves the nonce-bearing pending form, legacy acceptance, and rejections.
func TestPropagationPendingValueGrammar(t *testing.T) {
	nonce := mustTestNonce(t, testNonceBytes)
	expiry := time.Unix(1_700_000_000, 250_000_000)
	value, err := PropagationPendingValue(expiry, nonce)
	if err != nil || value != "pending:1700000000250:0123456789abcdef" {
		t.Fatalf("pending value=%q err=%v", value, err)
	}
	state, lease, ok := ParsePropagationValue(value)
	if !ok || state != PropagationStatePending || !lease.Equal(expiry) {
		t.Fatalf("parsed nonce pending state=%q ok=%t", state, ok)
	}
	state, lease, ok = ParsePropagationValue("pending:1700000000250")
	if !ok || state != PropagationStatePending || !lease.Equal(expiry) {
		t.Fatalf("parsed legacy pending state=%q ok=%t", state, ok)
	}
	for name, test := range map[string]struct {
		expiry time.Time
		nonce  Nonce
	}{
		"zero nonce":      {expiry: expiry, nonce: Nonce{}},
		"epoch expiry":    {expiry: time.UnixMilli(0), nonce: nonce},
		"negative expiry": {expiry: time.UnixMilli(-1), nonce: nonce},
		"wide expiry":     {expiry: time.UnixMilli(10_000_000_000_000_000), nonce: nonce},
	} {
		if _, err := PropagationPendingValue(test.expiry, test.nonce); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
			t.Fatalf("%s code=%q", name, ErrorCodeOf(err))
		}
	}
	for _, invalid := range []string{
		"pending:1:", "pending::0123456789abcdef", "pending:1:0123456789ABCDEF",
		"pending:1:0123456789abcde", "pending:1:0123456789abcdef0", "pending:1:0123456789abcdef:",
		"pending:0:0123456789abcdef", "pending:-1:0123456789abcdef", "pending:1:" + testFirstSeenValue,
		"pending:99999999999999999:0123456789abcdef", "pending:1 :0123456789abcdef", testFirstSeenValue,
	} {
		if _, _, ok := ParsePropagationValue(invalid); ok {
			t.Fatalf("invalid propagation value %q accepted", invalid)
		}
	}
}

// FuzzReplayValueGrammar proves both parsers never panic, accept only
// canonical forms, and round-trip every value the renderers produce.
func FuzzReplayValueGrammar(f *testing.F) {
	for _, seed := range []string{
		"v1", testFirstSeenValue, "v2:0123456789ABCDEF", "committed",
		"pending:1700000000250", "pending:1700000000250:0123456789abcdef", "pending:1:", "",
	} {
		f.Add(seed, []byte{1, 2, 3, 4, 5, 6, 7, 8}, int64(1_700_000_000_250))
	}
	f.Fuzz(func(t *testing.T, value string, nonceBytes []byte, milliseconds int64) {
		if len(value) > 256 {
			return
		}
		if nonce, legacy, ok := ParseFirstSeenValue(value); ok {
			if legacy && value != StoredValue {
				t.Fatalf("legacy classification of %q", value)
			}
			if !legacy {
				if rendered, err := FirstSeenValue(nonce); nonce.Valid() && (err != nil || rendered != value) {
					t.Fatalf("first-seen value %q is not canonical", value)
				}
			}
		}
		if state, expiry, ok := ParsePropagationValue(value); ok {
			if !state.Known() || state == PropagationStatePending && expiry.UnixMilli() <= 0 {
				t.Fatalf("propagation value %q parsed to an invalid state", value)
			}
		}
		nonce, err := NewNonce(bytes.NewReader(nonceBytes))
		if err != nil {
			return
		}
		firstSeen, err := FirstSeenValue(nonce)
		if err != nil {
			t.Fatal("valid nonce rejected")
		}
		if parsed, legacy, ok := ParseFirstSeenValue(firstSeen); !ok || legacy || parsed != nonce {
			t.Fatal("rendered first-seen value did not round-trip")
		}
		pending, err := PropagationPendingValue(time.UnixMilli(milliseconds), nonce)
		if err != nil {
			return
		}
		state, expiry, ok := ParsePropagationValue(pending)
		if !ok || state != PropagationStatePending || expiry.UnixMilli() != milliseconds {
			t.Fatal("rendered pending value did not round-trip")
		}
	})
}
