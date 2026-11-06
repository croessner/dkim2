package replay

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	// FirstSeenValuePrefix starts the nonce-bearing stored value of a first-seen record.
	FirstSeenValuePrefix = "v2:"
	// NonceHexLength is the exact lowercase hexadecimal length of one stored nonce.
	NonceHexLength = 2 * nonceByteLength

	nonceByteLength   = 8
	nonceRedactedText = "replay_nonce"
)

// Nonce is one random 64-bit write identity that a networked provider embeds
// in the value of one logical write. Because the value is fixed for every
// client-level attempt of that write, a retried attempt that observes its own
// value proves its own earlier commit instead of reporting a foreign record.
// The zero value is invalid and never rendered.
type Nonce struct {
	bytes [nonceByteLength]byte
}

// NewNonce reads exactly one nonce from random, or from crypto/rand when
// random is nil. A short read, a read error, or an all-zero nonce fails
// closed as an internal invariant without exposing source detail.
func NewNonce(random io.Reader) (Nonce, error) {
	if random == nil {
		random = rand.Reader
	}
	var nonce Nonce
	if _, err := io.ReadFull(random, nonce.bytes[:]); err != nil || !nonce.Valid() {
		return Nonce{}, NewError(ErrorCodeInternalInvariant)
	}
	return nonce, nil
}

// Valid reports whether the nonce is non-zero and therefore renderable.
func (n Nonce) Valid() bool {
	return n.bytes != [nonceByteLength]byte{}
}

// String returns one constant content-free representation.
func (Nonce) String() string { return nonceRedactedText }

// GoString returns one constant content-free representation.
func (Nonce) GoString() string { return nonceRedactedText }

// Format prevents formatting verbs from exposing nonce bytes.
func (Nonce) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, nonceRedactedText) }

// MarshalText rejects serialization of nonce bytes.
func (Nonce) MarshalText() ([]byte, error) { return nil, NewError(ErrorCodeInvalidRequest) }

// MarshalJSON rejects serialization of nonce bytes.
func (Nonce) MarshalJSON() ([]byte, error) { return nil, NewError(ErrorCodeInvalidRequest) }

// encode renders the exact lowercase hexadecimal nonce form of the value grammar.
func (n Nonce) encode() string {
	return hex.EncodeToString(n.bytes[:])
}

// parseNonce decodes exactly NonceHexLength lowercase hexadecimal characters.
// Uppercase digits are rejected so every nonce has one canonical spelling and
// own-value recognition by exact string equality stays sound.
func parseNonce(text string) (Nonce, bool) {
	if len(text) != NonceHexLength {
		return Nonce{}, false
	}
	for index := range len(text) {
		character := text[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return Nonce{}, false
		}
	}
	var nonce Nonce
	if _, err := hex.Decode(nonce.bytes[:], []byte(text)); err != nil {
		return Nonce{}, false
	}
	return nonce, true
}

// FirstSeenValue renders the nonce-bearing first-seen value "v2:<nonce>".
// An invalid nonce is rejected so no provider can write an unidentifiable
// record.
func FirstSeenValue(nonce Nonce) (string, error) {
	if !nonce.Valid() {
		return "", NewError(ErrorCodeInvalidRequest)
	}
	return FirstSeenValuePrefix + nonce.encode(), nil
}

// ParseFirstSeenValue decodes one stored first-seen value. It accepts the
// nonce-bearing form "v2:<16 lowercase hex>" and the legacy nonce-free
// StoredValue "v1" written by earlier providers; legacy reports true for the
// latter and a zero nonce. Every other string reports ok false.
func ParseFirstSeenValue(value string) (nonce Nonce, legacy bool, ok bool) {
	if value == StoredValue {
		return Nonce{}, true, true
	}
	if len(value) != len(FirstSeenValuePrefix)+NonceHexLength ||
		value[:len(FirstSeenValuePrefix)] != FirstSeenValuePrefix {
		return Nonce{}, false, false
	}
	nonce, ok = parseNonce(value[len(FirstSeenValuePrefix):])
	if !ok {
		return Nonce{}, false, false
	}
	return nonce, false, true
}
