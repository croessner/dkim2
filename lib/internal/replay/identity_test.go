package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type syntheticIdentitySource struct {
	valid            bool
	draft            string
	message          [32]byte
	messagePresent   bool
	signature        [32]byte
	signaturePresent bool
	recipients       [][32]byte
	exploded         bool
}

// Valid reports whether the synthetic projection is sealed.
func (s syntheticIdentitySource) Valid() bool { return s.valid }

// Draft returns the synthetic draft identifier.
func (s syntheticIdentitySource) Draft() string { return s.draft }

// MessageDigest returns the synthetic selected Message-Instance digest.
func (s syntheticIdentitySource) MessageDigest() ([32]byte, bool) {
	return s.message, s.messagePresent
}

// SignatureInputDigest returns the synthetic canonical signature-input digest.
func (s syntheticIdentitySource) SignatureInputDigest() ([32]byte, bool) {
	return s.signature, s.signaturePresent
}

// RecipientCount returns the number of synthetic recipient scopes.
func (s syntheticIdentitySource) RecipientCount() int { return len(s.recipients) }

// RecipientDigest returns one synthetic recipient scope by value.
func (s syntheticIdentitySource) RecipientDigest(index int) ([32]byte, bool) {
	if index < 0 || index >= len(s.recipients) {
		return [32]byte{}, false
	}
	return s.recipients[index], true
}

// Exploded returns the synthetic authenticated exploded fact.
func (s syntheticIdentitySource) Exploded() bool { return s.exploded }

// TestIdentitySetRequiresCompleteOrderedProjection verifies all-or-nothing provenance and immutable ordering.
func TestIdentitySetRequiresCompleteOrderedProjection(t *testing.T) {
	message := sha256.Sum256([]byte("message"))
	signature := sha256.Sum256([]byte("signature"))
	first := sha256.Sum256([]byte("recipient-a"))
	second := sha256.Sum256([]byte("recipient-b"))
	if bytes.Compare(first[:], second[:]) > 0 {
		first, second = second, first
	}
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: message, messagePresent: true,
		signature: signature, signaturePresent: true,
		recipients: [][32]byte{first, second}, exploded: true,
	}
	set, err := NewIdentitySet(source)
	if err != nil || !set.Valid() || set.Len() != 2 || !set.Exploded() {
		t.Fatalf("NewIdentitySet() = %v, %v", set, err)
	}
	identity, err := set.Identity(0)
	if err != nil || !identity.Valid() {
		t.Fatalf("Identity(0) = %v, %v", identity, err)
	}
	if _, err := set.Identity(-1); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("Identity(-1) error = %v", err)
	}
	if _, err := set.Identity(2); ErrorCodeOf(err) != ErrorCodeInvalidRequest {
		t.Fatalf("Identity(2) error = %v", err)
	}

	source.recipients[0] = [32]byte{}
	source.message = [32]byte{}
	if !set.Valid() {
		t.Fatal("caller mutation changed identity set")
	}

	for name, mutate := range map[string]func(*syntheticIdentitySource){
		"unsealed":          func(s *syntheticIdentitySource) { s.valid = false },
		"draft":             func(s *syntheticIdentitySource) { s.draft = "future" },
		"message absent":    func(s *syntheticIdentitySource) { s.messagePresent = false },
		"signature absent":  func(s *syntheticIdentitySource) { s.signaturePresent = false },
		"recipients absent": func(s *syntheticIdentitySource) { s.recipients = nil },
		"duplicate":         func(s *syntheticIdentitySource) { s.recipients[1] = s.recipients[0] },
		"unsorted":          func(s *syntheticIdentitySource) { s.recipients[0], s.recipients[1] = s.recipients[1], s.recipients[0] },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := source
			candidate.message = message
			candidate.recipients = [][32]byte{first, second}
			mutate(&candidate)
			if got, candidateErr := NewIdentitySet(candidate); got.Valid() || ErrorCodeOf(candidateErr) != ErrorCodeInvalidRequest {
				t.Fatalf("NewIdentitySet(%s) = %v, %v", name, got, candidateErr)
			}
		})
	}
}

// TestIdentitySetAcceptsPresentAllZeroDigests verifies presence is distinct from bytes.
func TestIdentitySetAcceptsPresentAllZeroDigests(t *testing.T) {
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		messagePresent: true, signaturePresent: true,
		recipients: [][32]byte{sha256.Sum256([]byte("recipient"))},
	}
	set, err := NewIdentitySet(source)
	if err != nil || !set.Valid() || set.Len() != 1 {
		t.Fatalf("all-zero present facts rejected: %v, %v", set, err)
	}
}

// TestIdentityFormattingNeverExposesDigestMaterial verifies nested diagnostic privacy.
func TestIdentityFormattingNeverExposesDigestMaterial(t *testing.T) {
	var marker [32]byte
	copy(marker[:], []byte("TOXIC-IDENTITY-DIGEST-MARKER"))
	source := syntheticIdentitySource{
		valid: true, draft: DraftIdentifier,
		message: marker, messagePresent: true,
		signature: marker, signaturePresent: true,
		recipients: [][32]byte{marker},
	}
	set, err := NewIdentitySet(source)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := set.Identity(0)
	if err != nil {
		t.Fatal(err)
	}
	values := []any{identity, &identity, set, &set, []Identity{identity}, map[Identity]struct{}{identity: {}}}
	for _, value := range values {
		formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", value, value, value, value, value, value)
		if strings.Contains(formatted, "TOXIC") || strings.Contains(formatted, "544f584943") || strings.Contains(formatted, "84 79 88 73 67") {
			t.Fatalf("%T formatting exposed digest material: %q", value, formatted)
		}
		encoded, err := json.Marshal(value)
		if strings.Contains(string(encoded), "TOXIC") || strings.Contains(string(encoded), "VE9YSUM") ||
			err != nil && strings.Contains(err.Error(), "TOXIC") {
			t.Fatalf("json.Marshal(%T) = %s, %v", value, encoded, err)
		}
	}
	if _, ok := any(identity).(encoding.TextMarshaler); ok {
		t.Fatal("Identity unexpectedly exposes text serialization")
	}
	if _, ok := any(identity).(json.Marshaler); ok {
		t.Fatal("Identity unexpectedly exposes JSON serialization")
	}
}
