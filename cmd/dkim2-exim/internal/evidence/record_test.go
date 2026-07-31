package evidence

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

// panicReader proves dependency panics cannot escape evidence boundaries.
type panicReader struct{}

// Read deliberately panics before yielding protected bytes.
func (panicReader) Read([]byte) (int, error) { panic("synthetic reader failure") }

// TestRecordAuthenticatesExactEnvelopeAndExpiry proves immutable framing,
// locator grammar, MAC verification, creation time, and exact expiry.
func TestRecordAuthenticatesExactEnvelopeAndExpiry(t *testing.T) {
	incoming := testIncoming(t, []byte("<old@example.test>"), [][]byte{
		[]byte("<rcpt@example.test>"),
	}, adapter.SessionSMTP)
	now := time.Unix(1_700_000_000, 987_654_321).UTC()
	record, err := NewRecord(
		now, time.Hour, incoming,
		bytes.NewReader(bytes.Repeat([]byte{7}, LocatorBytes)),
	)
	if err != nil || len(record.Locator()) != LocatorTextBytes ||
		strings.Contains(record.Locator(), "=") ||
		!record.CreatedAt().Equal(time.Unix(now.Unix(), 0).UTC()) {
		t.Fatal("record locator or authenticated creation failed")
	}
	key := bytes.Repeat([]byte{9}, KeyBytes)
	encoded, err := record.Encode(key)
	if err != nil || len(encoded) > MaxRecordBytes {
		t.Fatal("record encoding failed")
	}
	decoded, err := Decode(encoded, key, record.CreatedAt().Add(time.Hour-time.Second))
	if err != nil || decoded.Locator() != record.Locator() ||
		string(decoded.Incoming().MailFrom()) != "<old@example.test>" {
		t.Fatal("record decode lost immutable authority")
	}
	if _, err = Decode(encoded, key, record.CreatedAt().Add(-time.Second)); err == nil {
		t.Fatal("future authenticated creation accepted")
	}
	if _, err = Decode(encoded, key, record.ExpiresAt()); err == nil {
		t.Fatal("expiry boundary accepted")
	}
	forged := bytes.Clone(encoded)
	forged[len(forged)-1] ^= 1
	if _, err = Decode(forged, key, record.CreatedAt()); err == nil {
		t.Fatal("forged MAC accepted")
	}
	incomingCopy := decoded.Incoming()
	mailFrom := incomingCopy.MailFrom()
	mailFrom[0] ^= 1
	if string(decoded.Incoming().MailFrom()) != "<old@example.test>" {
		t.Fatal("decoded record accessor aliases immutable authority")
	}
}

// TestRecordExactIndependentFraming proves every DXE1 field and MAC position.
func TestRecordExactIndependentFraming(t *testing.T) {
	locator := make([]byte, LocatorBytes)
	for index := range locator {
		locator[index] = byte(index)
	}
	now := time.Unix(0x01020304, 0).UTC()
	incoming := testIncoming(t, []byte("m"), [][]byte{
		[]byte("r1"), []byte("r2"),
	}, adapter.SessionBSMTP)
	record, err := NewRecord(now, MinimumRetention, incoming, bytes.NewReader(locator))
	if err != nil {
		t.Fatal("record construction failed")
	}
	key := bytes.Repeat([]byte{0xa5}, KeyBytes)
	got, err := record.Encode(key)
	if err != nil {
		t.Fatal("record encoding failed")
	}
	want := []byte{'D', 'X', 'E', '1', 1, 2}
	want = binary.BigEndian.AppendUint64(want, uint64(now.Unix()))
	want = binary.BigEndian.AppendUint64(want, uint64(now.Add(MinimumRetention).Unix()))
	want = append(want, 1)
	want = append(want, locator...)
	want = binary.BigEndian.AppendUint16(want, 3)
	want = binary.BigEndian.AppendUint16(want, 2)
	want = append(want, '<', 'm', '>')
	want = binary.BigEndian.AppendUint16(want, 4)
	want = append(want, '<', 'r', '1', '>')
	want = binary.BigEndian.AppendUint16(want, 4)
	want = append(want, '<', 'r', '2', '>')
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(want)
	want = append(want, mac.Sum(nil)...)
	if !bytes.Equal(got, want) {
		t.Fatal("DXE1 framing differs from independent construction")
	}
}

// TestRecordHardCapUsesIndependentFixtures proves exact 516339 and one-over.
func TestRecordHardCapUsesIndependentFixtures(t *testing.T) {
	recipients := make([][]byte, maxRecipients)
	for index := range recipients {
		recipients[index] = append([]byte{'<'}, append(bytes.Repeat([]byte{'r'}, maxPathBytes-2), '>')...)
	}
	incoming := testIncoming(
		t, append([]byte{'<'}, append(bytes.Repeat([]byte{'m'}, maxPathBytes-2), '>')...), recipients, adapter.SessionSMTP,
	)
	record, err := NewRecord(
		time.Unix(1_700_000_000, 0).UTC(), MinimumRetention, incoming,
		bytes.NewReader(bytes.Repeat([]byte{1}, LocatorBytes)),
	)
	if err != nil {
		t.Fatal("exact-cap record construction failed")
	}
	key := bytes.Repeat([]byte{2}, KeyBytes)
	exact, err := record.Encode(key)
	if err != nil || len(exact) != MaxRecordBytes {
		t.Fatalf("exact-cap frame length=%d", len(exact))
	}
	if _, err = Decode(exact, key, record.CreatedAt()); err != nil {
		t.Fatal("exact-cap frame rejected")
	}
	oneOverPayload := append(bytes.Clone(exact[:len(exact)-recordMACBytes]), 0)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(oneOverPayload)
	oneOver := append(oneOverPayload, mac.Sum(nil)...)
	if len(oneOver) != MaxRecordBytes+1 {
		t.Fatal("independent one-over fixture has wrong size")
	}
	if _, err = Decode(oneOver, key, record.CreatedAt()); err == nil {
		t.Fatal("one-over authenticated frame accepted")
	}
}

// TestDecodeRejectsAuthenticatedStructuralAmbiguity proves MAC possession does
// not widen the closed version, flags, source, length, or time grammar.
func TestDecodeRejectsAuthenticatedStructuralAmbiguity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	record, err := NewRecord(
		now, MinimumRetention,
		testIncoming(t, nil, [][]byte{[]byte("recipient")}, adapter.SessionLocal),
		bytes.NewReader(bytes.Repeat([]byte{4}, LocatorBytes)),
	)
	if err != nil {
		t.Fatal("fixture construction failed")
	}
	key := bytes.Repeat([]byte{8}, KeyBytes)
	valid, err := record.Encode(key)
	if err != nil {
		t.Fatal("fixture encode failed")
	}
	cases := []struct {
		name   string
		mutate func([]byte)
	}{
		{"version", func(frame []byte) { frame[4] = 2 }},
		{"combined flags", func(frame []byte) { frame[5] = 3 }},
		{"unknown flags", func(frame []byte) { frame[5] = 4 }},
		{"source", func(frame []byte) { frame[22] = 2 }},
		{"equal times", func(frame []byte) { copy(frame[14:22], frame[6:14]) }},
		{"short authenticated retention", func(frame []byte) {
			created := binary.BigEndian.Uint64(frame[6:14])
			binary.BigEndian.PutUint64(frame[14:22], created+uint64(MinimumRetention/time.Second)-1)
		}},
		{"long authenticated retention", func(frame []byte) {
			created := binary.BigEndian.Uint64(frame[6:14])
			binary.BigEndian.PutUint64(frame[14:22], created+uint64(MaximumRetention/time.Second)+1)
		}},
		{"mail length", func(frame []byte) { binary.BigEndian.PutUint16(frame[47:49], 257) }},
		{"recipient count", func(frame []byte) { binary.BigEndian.PutUint16(frame[49:51], 0) }},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			candidate := bytes.Clone(valid[:len(valid)-recordMACBytes])
			current.mutate(candidate)
			candidate = authenticate(candidate, key)
			if _, decodeErr := Decode(candidate, key, now); decodeErr == nil {
				t.Fatal("authenticated structural ambiguity accepted")
			}
		})
	}
}

// TestRecordConstructionBoundsAndPanicsFailClosed proves exact retention,
// second precision, invalid authority, short entropy, and panic containment.
func TestRecordConstructionBoundsAndPanicsFailClosed(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	incoming := testIncoming(t, nil, [][]byte{[]byte("recipient")}, adapter.SessionLocal)
	cases := []struct {
		name      string
		now       time.Time
		retention time.Duration
		random    io.Reader
	}{
		{"zero time", time.Time{}, MinimumRetention, bytes.NewReader(make([]byte, LocatorBytes))},
		{"negative time", time.Unix(-1, 0), MinimumRetention, bytes.NewReader(make([]byte, LocatorBytes))},
		{"short retention", now, MinimumRetention - time.Second, bytes.NewReader(make([]byte, LocatorBytes))},
		{"long retention", now, MaximumRetention + time.Second, bytes.NewReader(make([]byte, LocatorBytes))},
		{"fractional retention", now, MinimumRetention + time.Nanosecond, bytes.NewReader(make([]byte, LocatorBytes))},
		{"short entropy", now, MinimumRetention, bytes.NewReader(make([]byte, LocatorBytes-1))},
		{"panic entropy", now, MinimumRetention, panicReader{}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			if _, err := NewRecord(current.now, current.retention, incoming, current.random); err == nil {
				t.Fatal("invalid construction succeeded")
			}
		})
	}
}

// TestReadKeyRequiresExactOpaqueEOF proves text encodings and suffix bytes
// cannot become the distinct HMAC key.
func TestReadKeyRequiresExactOpaqueEOF(t *testing.T) {
	key := bytes.Repeat([]byte{1}, KeyBytes)
	got, err := ReadKey(bytes.NewReader(key))
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("exact opaque key rejected")
	}
	clear(got)
	cases := []struct {
		name  string
		input io.Reader
	}{
		{"short", bytes.NewReader(key[:KeyBytes-1])},
		{"suffix", bytes.NewReader(append(bytes.Clone(key), 'x'))},
		{"newline", bytes.NewReader(append(bytes.Clone(key), '\n'))},
		{"hex", strings.NewReader(strings.Repeat("00", KeyBytes))},
		{"base64", strings.NewReader(base64.StdEncoding.EncodeToString(key))},
		{"panic", panicReader{}},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			if candidate, readErr := ReadKey(current.input); readErr == nil || candidate != nil {
				clear(candidate)
				t.Fatal("invalid key format accepted")
			}
		})
	}
}

// TestRecordPrivacyBoundary proves protected envelope and locator material
// cannot escape through formatting or generic serialization.
func TestRecordPrivacyBoundary(t *testing.T) {
	const marker = "private-evidence-marker"
	record, err := NewRecord(
		time.Unix(1_700_000_000, 0), MinimumRetention,
		testIncoming(t, []byte(marker), [][]byte{[]byte(marker)}, adapter.SessionSMTP),
		bytes.NewReader(bytes.Repeat([]byte{0xee}, LocatorBytes)),
	)
	if err != nil {
		t.Fatal("privacy fixture construction failed")
	}
	for _, format := range []string{
		protectedDefaultFormat, protectedDetailFormat, protectedGoFormat,
		protectedStringFormat, protectedQuotedFormat,
	} {
		rendered := fmt.Sprintf(format, &record)
		if strings.Contains(rendered, marker) || strings.Contains(rendered, record.Locator()) ||
			len(rendered) > 64 {
			t.Fatal("formatting exposed protected evidence")
		}
	}
	if _, err = json.Marshal(record); err == nil {
		t.Fatal("record JSON serialization succeeded")
	}
	var text encoding.TextMarshaler = record
	if _, err = text.MarshalText(); err == nil {
		t.Fatal("record text serialization succeeded")
	}
	if _, err = record.MarshalJSON(); err == nil {
		t.Fatal("privacy error lost bounded identity")
	}
}

// FuzzDecode rejects malformed authenticated framing without retaining input.
func FuzzDecode(f *testing.F) {
	f.Add([]byte("DXE1"), []byte("short"), int64(1_700_000_000))
	key := bytes.Repeat([]byte{3}, KeyBytes)
	f.Fuzz(func(_ *testing.T, encoded, candidateKey []byte, unixSeconds int64) {
		if len(candidateKey) != KeyBytes {
			candidateKey = key
		}
		_, _ = Decode(encoded, candidateKey, time.Unix(unixSeconds, 0).UTC())
	})
}

// testIncoming creates one exact incoming fixture without repeating diagnostics.
func testIncoming(
	t *testing.T,
	mailFrom []byte,
	recipients [][]byte,
	session adapter.SessionClass,
) adapter.IncomingEvidence {
	t.Helper()
	incoming, err := adapter.NewIncomingEvidence(mailFrom, recipients, session)
	if err != nil {
		t.Fatal("incoming evidence construction failed")
	}
	return incoming
}

// authenticate appends a fresh HMAC to one independently mutated payload.
func authenticate(payload, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return append(payload, mac.Sum(nil)...)
}
