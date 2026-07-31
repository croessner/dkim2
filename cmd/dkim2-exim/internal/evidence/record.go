// Package evidence owns immutable receive-time revision evidence.
package evidence

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const (
	// LocatorBytes is the exact random opaque locator width.
	LocatorBytes = 24
	// LocatorTextBytes is the exact unpadded base64url locator width.
	LocatorTextBytes = 32
	// KeyBytes is the exact HMAC key-file width.
	KeyBytes = 32
	// MaxRecordBytes is the complete DXE1 evidence hard cap.
	MaxRecordBytes = 516_339
	// MinimumRetention is the narrowest supported authenticated retention.
	MinimumRetention = time.Hour
	// MaximumRetention is the widest supported authenticated retention.
	MaximumRetention = 14 * 24 * time.Hour

	recordPrefixBytes = 4 + 1 + 1 + 8 + 8 + 1 + LocatorBytes + 2 + 2
	recordMACBytes    = sha256.Size
	recordVersion     = byte(1)
	recordSource      = byte(1)
	maxPathBytes      = 256
	maxRecipients     = 2_000
)

var (
	// ErrEvidence is the content-free parent error for every evidence failure.
	ErrEvidence = errors.New("exim evidence failure")
	// ErrCapacity identifies exact count or actual-byte admission exhaustion.
	ErrCapacity = fmt.Errorf("%w: capacity", ErrEvidence)
	// ErrNotReady identifies unsafe state that requires operator remediation.
	ErrNotReady = fmt.Errorf("%w: not ready", ErrEvidence)
	// ErrClosed identifies use after store ownership was released.
	ErrClosed = fmt.Errorf("%w: closed", ErrEvidence)
)

// Record owns one immutable authenticated receive-time envelope snapshot.
type Record struct {
	createdAt time.Time
	expiresAt time.Time
	locator   [LocatorBytes]byte
	incoming  adapter.IncomingEvidence
}

// NewRecord creates one authenticated-time-bound record from exact incoming authority.
func NewRecord(now time.Time, retention time.Duration, incoming adapter.IncomingEvidence, random io.Reader) (record Record, err error) {
	defer containPanic(&err)
	if random == nil || retention < MinimumRetention || retention > MaximumRetention {
		return Record{}, ErrEvidence
	}
	createdAt, expiresAt, ok := authenticatedTimes(now, retention)
	if !ok || !validIncoming(incoming) {
		return Record{}, ErrEvidence
	}
	var locator [LocatorBytes]byte
	if _, readErr := io.ReadFull(random, locator[:]); readErr != nil {
		clear(locator[:])
		return Record{}, ErrEvidence
	}
	return Record{
		createdAt: createdAt,
		expiresAt: expiresAt,
		locator:   locator,
		incoming:  incoming,
	}, nil
}

// NewRandomRecord creates one record using the system cryptographic random source.
func NewRandomRecord(now time.Time, retention time.Duration, incoming adapter.IncomingEvidence) (Record, error) {
	return NewRecord(now, retention, incoming, rand.Reader)
}

// Locator returns the opaque canonical base64url locator.
func (r Record) Locator() string {
	return base64.RawURLEncoding.EncodeToString(r.locator[:])
}

// Incoming returns an immutable copy of receive-time SMTP authority.
func (r Record) Incoming() adapter.IncomingEvidence { return r.incoming }

// CreatedAt returns the authenticated UTC creation second.
func (r Record) CreatedAt() time.Time { return r.createdAt }

// ExpiresAt returns the authenticated UTC expiry boundary.
func (r Record) ExpiresAt() time.Time { return r.expiresAt }

// Expired reports the exact authenticated expiry boundary.
func (r Record) Expired(now time.Time) bool {
	return now.IsZero() || !now.Before(r.expiresAt)
}

// AuthenticAt reports whether authenticated creation and expiry contain now.
func (r Record) AuthenticAt(now time.Time) bool {
	return !now.IsZero() && !now.Before(r.createdAt) && now.Before(r.expiresAt)
}

// String returns a content-free evidence-record diagnostic.
func (Record) String() string { return "exim_evidence_record{redacted}" }

// GoString returns a content-free Go representation.
func (r Record) GoString() string { return r.String() }

// Format prevents formatting from traversing authenticated mail evidence.
func (r Record) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, r.String())
}

// MarshalJSON rejects serialization of authenticated mail evidence.
func (Record) MarshalJSON() ([]byte, error) { return nil, ErrEvidence }

// MarshalText rejects textual serialization of authenticated mail evidence.
func (Record) MarshalText() ([]byte, error) { return nil, ErrEvidence }

// Encode frames and authenticates a record with the exact opaque 32-byte key.
func (r Record) Encode(key []byte) (output []byte, err error) {
	defer containPanic(&err)
	if len(key) != KeyBytes || !validRecord(r) {
		return nil, ErrEvidence
	}
	mailFrom := r.incoming.MailFrom()
	recipients := r.incoming.Recipients()
	defer clearEnvelope(mailFrom, recipients)
	length, ok := encodedLength(mailFrom, recipients)
	if !ok {
		return nil, ErrEvidence
	}
	output = make([]byte, 0, length)
	output = append(output, 'D', 'X', 'E', '1', recordVersion, sessionFlags(r.incoming.Session()))
	output = binary.BigEndian.AppendUint64(output, uint64(r.createdAt.Unix()))
	output = binary.BigEndian.AppendUint64(output, uint64(r.expiresAt.Unix()))
	output = append(output, recordSource)
	output = append(output, r.locator[:]...)
	output = binary.BigEndian.AppendUint16(output, uint16(len(mailFrom)))
	output = binary.BigEndian.AppendUint16(output, uint16(len(recipients)))
	output = append(output, mailFrom...)
	for _, recipient := range recipients {
		output = binary.BigEndian.AppendUint16(output, uint16(len(recipient)))
		output = append(output, recipient...)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(output)
	digest := mac.Sum(nil)
	output = append(output, digest...)
	clear(digest)
	return output, nil
}

// Decode verifies, parses, and expiry-checks one exact EOF-delimited record.
func Decode(encoded, key []byte, now time.Time) (record Record, err error) {
	defer containPanic(&err)
	record, err = decodeAuthenticated(encoded, key)
	if err != nil || !record.AuthenticAt(now) {
		return Record{}, ErrEvidence
	}
	return record, nil
}

// decodeAuthenticated verifies and parses a record without applying wall time.
func decodeAuthenticated(encoded, key []byte) (Record, error) {
	if len(key) != KeyBytes || len(encoded) < recordPrefixBytes+recordMACBytes ||
		len(encoded) > MaxRecordBytes {
		return Record{}, ErrEvidence
	}
	payloadLength := len(encoded) - recordMACBytes
	payload := encoded[:payloadLength]
	createdAt, expiresAt, locator, mailFromLength, recipientCount, flags, structureErr :=
		validateFrameStructure(payload)
	if structureErr != nil {
		return Record{}, ErrEvidence
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)
	authenticated := hmac.Equal(encoded[payloadLength:], expected)
	clear(expected)
	if !authenticated {
		return Record{}, ErrEvidence
	}
	cursor := 23 + LocatorBytes
	cursor += 2
	cursor += 2
	mailFrom := slices.Clone(payload[cursor : cursor+mailFromLength])
	cursor += mailFromLength
	recipients := make([][]byte, recipientCount)
	for index := range recipients {
		if len(payload)-cursor < 2 {
			clearEnvelope(mailFrom, recipients)
			return Record{}, ErrEvidence
		}
		length := int(binary.BigEndian.Uint16(payload[cursor : cursor+2]))
		cursor += 2
		if length > maxPathBytes || length > len(payload)-cursor {
			clearEnvelope(mailFrom, recipients)
			return Record{}, ErrEvidence
		}
		recipients[index] = slices.Clone(payload[cursor : cursor+length])
		cursor += length
	}
	if cursor != len(payload) {
		clearEnvelope(mailFrom, recipients)
		return Record{}, ErrEvidence
	}
	incoming, incomingErr := adapter.NewIncomingEvidence(
		mailFrom, recipients, flagsSession(flags),
	)
	clearEnvelope(mailFrom, recipients)
	if incomingErr != nil {
		return Record{}, ErrEvidence
	}
	record := Record{
		createdAt: createdAt,
		expiresAt: expiresAt,
		locator:   locator,
		incoming:  incoming,
	}
	if !validRecord(record) {
		return Record{}, ErrEvidence
	}
	return record, nil
}

// validateFrameStructure locates the terminal MAC only after overflow-safe framing.
func validateFrameStructure(payload []byte) (
	time.Time,
	time.Time,
	[LocatorBytes]byte,
	int,
	int,
	byte,
	error,
) {
	if len(payload) < recordPrefixBytes ||
		string(payload[:4]) != "DXE1" || payload[4] != recordVersion ||
		(payload[5] != 0 && payload[5] != 1 && payload[5] != 2) ||
		payload[22] != recordSource {
		return time.Time{}, time.Time{}, [LocatorBytes]byte{}, 0, 0, 0, ErrEvidence
	}
	createdSeconds := binary.BigEndian.Uint64(payload[6:14])
	expiresSeconds := binary.BigEndian.Uint64(payload[14:22])
	if createdSeconds > math.MaxInt64 || expiresSeconds > math.MaxInt64 ||
		createdSeconds >= expiresSeconds ||
		expiresSeconds-createdSeconds < uint64(MinimumRetention/time.Second) ||
		expiresSeconds-createdSeconds > uint64(MaximumRetention/time.Second) {
		return time.Time{}, time.Time{}, [LocatorBytes]byte{}, 0, 0, 0, ErrEvidence
	}
	createdAt := time.Unix(int64(createdSeconds), 0).UTC()
	expiresAt := time.Unix(int64(expiresSeconds), 0).UTC()
	var locator [LocatorBytes]byte
	copy(locator[:], payload[23:23+LocatorBytes])
	cursor := 23 + LocatorBytes
	mailFromLength := int(binary.BigEndian.Uint16(payload[cursor : cursor+2]))
	cursor += 2
	recipientCount := int(binary.BigEndian.Uint16(payload[cursor : cursor+2]))
	cursor += 2
	if recipientCount == 0 || recipientCount > maxRecipients ||
		mailFromLength > maxPathBytes || mailFromLength > len(payload)-cursor {
		return time.Time{}, time.Time{}, [LocatorBytes]byte{}, 0, 0, 0, ErrEvidence
	}
	cursor += mailFromLength
	for range recipientCount {
		if len(payload)-cursor < 2 {
			return time.Time{}, time.Time{}, [LocatorBytes]byte{}, 0, 0, 0, ErrEvidence
		}
		length := int(binary.BigEndian.Uint16(payload[cursor : cursor+2]))
		cursor += 2
		if length > maxPathBytes || length > len(payload)-cursor {
			return time.Time{}, time.Time{}, [LocatorBytes]byte{}, 0, 0, 0, ErrEvidence
		}
		cursor += length
	}
	if cursor != len(payload) {
		return time.Time{}, time.Time{}, [LocatorBytes]byte{}, 0, 0, 0, ErrEvidence
	}
	return createdAt, expiresAt, locator, mailFromLength, recipientCount, payload[5], nil
}

// ReadKey accepts exactly one opaque key-file value followed by EOF.
func ReadKey(input io.Reader) (key []byte, err error) {
	defer func() {
		if recover() != nil {
			clear(key)
			key = nil
			err = ErrEvidence
		}
	}()
	if input == nil {
		return nil, ErrEvidence
	}
	key = make([]byte, KeyBytes)
	if _, readErr := io.ReadFull(input, key); readErr != nil {
		clear(key)
		return nil, ErrEvidence
	}
	var extra [1]byte
	count, readErr := input.Read(extra[:])
	clear(extra[:])
	if count != 0 || readErr != io.EOF {
		clear(key)
		return nil, ErrEvidence
	}
	return key, nil
}

// authenticatedTimes normalizes construction to exact nonnegative Unix seconds.
func authenticatedTimes(now time.Time, retention time.Duration) (time.Time, time.Time, bool) {
	if now.IsZero() || retention%time.Second != 0 {
		return time.Time{}, time.Time{}, false
	}
	createdAt := time.Unix(now.Unix(), 0).UTC()
	if createdAt.Unix() < 0 {
		return time.Time{}, time.Time{}, false
	}
	retentionSeconds := int64(retention / time.Second)
	if retentionSeconds <= 0 || createdAt.Unix() > math.MaxInt64-retentionSeconds {
		return time.Time{}, time.Time{}, false
	}
	expiresAt := time.Unix(createdAt.Unix()+retentionSeconds, 0).UTC()
	return createdAt, expiresAt, expiresAt.After(createdAt)
}

// encodedLength computes the complete frame size without integer overflow.
func encodedLength(mailFrom []byte, recipients [][]byte) (int, bool) {
	if len(mailFrom) > maxPathBytes || len(recipients) == 0 ||
		len(recipients) > maxRecipients {
		return 0, false
	}
	length := recordPrefixBytes + recordMACBytes + len(mailFrom)
	for _, recipient := range recipients {
		if len(recipient) > maxPathBytes ||
			length > MaxRecordBytes-2-len(recipient) {
			return 0, false
		}
		length += 2 + len(recipient)
	}
	return length, length <= MaxRecordBytes
}

// sessionFlags maps the closed adapter session state to exact DXE1 flags.
func sessionFlags(session adapter.SessionClass) byte {
	switch session {
	case adapter.SessionLocal:
		return 0
	case adapter.SessionSMTP:
		return 1
	case adapter.SessionBSMTP:
		return 2
	default:
		return 0xff
	}
}

// flagsSession maps exact DXE1 flags to one closed adapter session state.
func flagsSession(flags byte) adapter.SessionClass {
	switch flags {
	case 0:
		return adapter.SessionLocal
	case 1:
		return adapter.SessionSMTP
	case 2:
		return adapter.SessionBSMTP
	default:
		return adapter.SessionClass(math.MaxUint8)
	}
}

// validIncoming verifies immutable constructor-owned receive-time state.
func validIncoming(incoming adapter.IncomingEvidence) bool {
	mailFrom := incoming.MailFrom()
	recipients := incoming.Recipients()
	defer clearEnvelope(mailFrom, recipients)
	if incoming.Session() > adapter.SessionBSMTP {
		return false
	}
	_, ok := encodedLength(mailFrom, recipients)
	return ok
}

// validRecord verifies complete authenticated record state before framing.
func validRecord(record Record) bool {
	return !record.createdAt.IsZero() &&
		record.createdAt.Equal(time.Unix(record.createdAt.Unix(), 0).UTC()) &&
		record.createdAt.Unix() >= 0 &&
		record.expiresAt.Equal(time.Unix(record.expiresAt.Unix(), 0).UTC()) &&
		record.expiresAt.After(record.createdAt) &&
		validLocator(record.Locator()) &&
		validIncoming(record.incoming)
}

// validLocator proves the exact external 24-byte unpadded base64url form.
func validLocator(locator string) bool {
	if len(locator) != LocatorTextBytes {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(locator)
	if err != nil || len(decoded) != LocatorBytes {
		clear(decoded)
		return false
	}
	canonical := base64.RawURLEncoding.EncodeToString(decoded)
	clear(decoded)
	return canonical == locator
}

// clearEnvelope erases temporary envelope copies from immutable accessors.
func clearEnvelope(mailFrom []byte, recipients [][]byte) {
	clear(mailFrom)
	for index := range recipients {
		clear(recipients[index])
	}
	clear(recipients)
}

// containPanic maps dependency panics to the content-free evidence error.
func containPanic(err *error) {
	if recover() != nil {
		*err = ErrEvidence
	}
}

var (
	_ fmt.Formatter          = Record{}
	_ json.Marshaler         = Record{}
	_ encoding.TextMarshaler = Record{}
)
