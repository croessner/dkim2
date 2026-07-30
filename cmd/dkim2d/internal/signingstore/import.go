package signingstore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/croessner/dkim2"
)

// publicSPKI derives canonical public material from one validated private key.
func publicSPKI(key crypto.PrivateKey) ([]byte, error) {
	var public any
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		public = &typed.PublicKey
	case ed25519.PrivateKey:
		public = typed.Public()
	default:
		return nil, &Error{}
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, &Error{}
	}
	return encoded, nil
}

// ImportedPrivateKey is one short-lived validated legacy private-key value.
type ImportedPrivateKey struct {
	encoded   []byte
	publicDER []byte
	algorithm dkim2.Algorithm
	closed    bool
}

// InspectImportedPrivateKey validates one bounded exact PKCS#8 PEM key.
func InspectImportedPrivateKey(
	encoded []byte,
	algorithm string,
) (*ImportedPrivateKey, error) {
	if len(encoded) == 0 || len(encoded) > maxPrivateBytes {
		return nil, &Error{}
	}
	var selected dkim2.Algorithm
	switch algorithm {
	case "rsa":
		selected = dkim2.AlgorithmRSASHA256
	case "ed25519":
		selected = dkim2.AlgorithmEd25519SHA256
	default:
		return nil, &Error{}
	}
	key, _, err := parsePrivateKey(encoded, selected)
	if err != nil {
		return nil, &Error{}
	}
	publicDER, err := publicSPKI(key)
	clearPrivateKey(key)
	if err != nil {
		return nil, &Error{}
	}
	return &ImportedPrivateKey{
		encoded: append([]byte(nil), encoded...), publicDER: publicDER,
		algorithm: selected,
	}, nil
}

// PublicSPKIDER returns detached canonical public key bytes.
func (k *ImportedPrivateKey) PublicSPKIDER() []byte {
	if k == nil || k.closed {
		return nil
	}
	return append([]byte(nil), k.publicDER...)
}

// Encoded returns a detached validated private PEM for protected staging.
func (k *ImportedPrivateKey) Encoded() []byte {
	if k == nil || k.closed {
		return nil
	}
	return append([]byte(nil), k.encoded...)
}

// Algorithm returns the validated signing algorithm.
func (k *ImportedPrivateKey) Algorithm() dkim2.Algorithm {
	if k == nil || k.closed {
		return dkim2.AlgorithmUnknown
	}
	return k.algorithm
}

// Close clears retained private and public bytes.
func (k *ImportedPrivateKey) Close() error {
	if k == nil || k.closed {
		return nil
	}
	clear(k.encoded)
	clear(k.publicDER)
	k.encoded = nil
	k.publicDER = nil
	k.algorithm = dkim2.AlgorithmUnknown
	k.closed = true
	return nil
}

// String returns a constant protected imported-key summary.
func (*ImportedPrivateKey) String() string { return storeRedacted }

// GoString returns a constant protected imported-key representation.
func (*ImportedPrivateKey) GoString() string { return storeRedacted }

// Format prevents formatting verbs from exposing imported key material.
func (*ImportedPrivateKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, storeRedacted)
}

// MarshalJSON emits an empty object without key material.
func (*ImportedPrivateKey) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
