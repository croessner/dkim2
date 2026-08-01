package signingstore

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"sync"

	"github.com/croessner/dkim2"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

const nativeMaterialRedacted = "dkim2d_native_key_material{redacted}"

// NativeKeyMaterial is one owned immutable datasource key and its exact
// storage-neutral signing binding.
type NativeKeyMaterial struct {
	mu           sync.Mutex
	generation   uint64
	tenantID     string
	domain       string
	use          provider.ProfileUse
	handleID     string
	algorithm    provider.Algorithm
	publicSPKI   []byte
	privatePKCS8 []byte
	closed       bool
}

// NewNativeKeyMaterial copies one bounded native datasource record without
// retaining caller-owned private or public byte slices.
func NewNativeKeyMaterial(
	generation uint64,
	tenantID string,
	domain string,
	use provider.ProfileUse,
	handleID string,
	algorithm provider.Algorithm,
	publicSPKI []byte,
	privatePKCS8 []byte,
) (*NativeKeyMaterial, error) {
	limits := provider.HardLimits()
	if generation == 0 || tenantID == "" || domain == "" || handleID == "" ||
		len(tenantID) > limits.MaxIdentifierBytes ||
		len(handleID) > limits.MaxIdentifierBytes ||
		!use.Known() || !nativeAlgorithmKnown(algorithm) ||
		len(publicSPKI) == 0 || len(publicSPKI) > 2048 ||
		len(privatePKCS8) == 0 || len(privatePKCS8) > maxPrivateBytes {
		return nil, &Error{}
	}
	return &NativeKeyMaterial{
		generation: generation, tenantID: tenantID, domain: domain, use: use,
		handleID: handleID, algorithm: algorithm,
		publicSPKI:   append([]byte(nil), publicSPKI...),
		privatePKCS8: append([]byte(nil), privatePKCS8...),
	}, nil
}

// Close destroys retained encoded key material and invalidates the record.
func (m *NativeKeyMaterial) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	clear(m.publicSPKI)
	clear(m.privatePKCS8)
	m.publicSPKI = nil
	m.privatePKCS8 = nil
	m.generation = 0
	m.tenantID = ""
	m.domain = ""
	m.use = provider.ProfileUse(0)
	m.handleID = ""
	m.algorithm = ""
	m.closed = true
	return nil
}

// String returns a constant protected native-material summary.
func (*NativeKeyMaterial) String() string { return nativeMaterialRedacted }

// GoString returns a constant protected native-material representation.
func (*NativeKeyMaterial) GoString() string { return nativeMaterialRedacted }

// Format prevents formatting verbs from traversing native key state.
func (*NativeKeyMaterial) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, nativeMaterialRedacted)
}

// MarshalJSON emits an empty object without binding or key material.
func (*NativeKeyMaterial) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// OpenNativeRegistry validates and takes detached ownership of one complete
// native datasource key generation.
func OpenNativeRegistry(
	generation uint64,
	materials []*NativeKeyMaterial,
) (datasourceruntime.Registry, error) {
	if generation == 0 || len(materials) == 0 ||
		len(materials) > provider.HardLimits().MaxHandles {
		return nil, &Error{}
	}
	keys := make(map[dkim2.PrivateKeyHandle]privateCredential, len(materials))
	bindings := make([]provider.Binding, 0, len(materials))
	handles := make(map[string]struct{}, len(materials))
	identities := make(map[[sha256.Size]byte]struct{}, len(materials))
	selections := make(map[string]struct{}, len(materials))
	success := false
	defer func() {
		if !success {
			clearCredentials(keys)
		}
	}()
	for _, material := range materials {
		if material == nil {
			return nil, &Error{}
		}
		material.mu.Lock()
		if material.closed || material.generation != generation {
			material.mu.Unlock()
			return nil, &Error{}
		}
		key, digest, err := parseNativePrivateKey(
			material.privatePKCS8, material.publicSPKI, material.algorithm,
		)
		if err != nil {
			material.mu.Unlock()
			return nil, &Error{}
		}
		handleID := material.handleID
		selection := material.tenantID + "\x00" + material.domain + "\x00" +
			material.use.String() + "\x00" + string(material.algorithm)
		if _, duplicate := handles[handleID]; duplicate {
			clearPrivateKey(key)
			material.mu.Unlock()
			return nil, &Error{}
		}
		if _, duplicate := identities[digest]; duplicate {
			clearPrivateKey(key)
			material.mu.Unlock()
			return nil, &Error{}
		}
		if _, duplicate := selections[selection]; duplicate {
			clearPrivateKey(key)
			material.mu.Unlock()
			return nil, &Error{}
		}
		handle, handleErr := dkim2.NewPrivateKeyHandle([]byte(handleID))
		binding, bindingErr := provider.NewBinding(
			material.tenantID, material.domain, material.use, handleID,
			handle, material.algorithm, digest,
		)
		if handleErr != nil || bindingErr != nil {
			clearPrivateKey(key)
			material.mu.Unlock()
			return nil, &Error{}
		}
		keys[handle] = privateCredential{
			publicHandle: handle, use: PolicyUse(material.use.String()),
			algorithm: dkim2.Algorithm(material.algorithm), key: key,
			publicDigest: digest,
		}
		bindings = append(bindings, binding)
		handles[handleID] = struct{}{}
		identities[digest] = struct{}{}
		selections[selection] = struct{}{}
		material.mu.Unlock()
	}
	success = true
	return &Registry{generation: generation, keys: keys, bindings: bindings}, nil
}

// parseNativePrivateKey accepts only canonical unencrypted PKCS#8 DER and
// proves its exact algorithm and public SPKI relationship.
func parseNativePrivateKey(
	encoded []byte,
	publicSPKI []byte,
	algorithm provider.Algorithm,
) (crypto.PrivateKey, [sha256.Size]byte, error) {
	if len(encoded) == 0 || len(encoded) > maxPrivateBytes ||
		len(publicSPKI) == 0 || len(publicSPKI) > 2048 ||
		!nativeAlgorithmKnown(algorithm) {
		return nil, [sha256.Size]byte{}, &Error{}
	}
	key, err := x509.ParsePKCS8PrivateKey(encoded)
	if err != nil {
		return nil, [sha256.Size]byte{}, &Error{}
	}
	canonical, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil || !bytes.Equal(canonical, encoded) {
		clear(canonical)
		clearPrivateKey(key)
		return nil, [sha256.Size]byte{}, &Error{}
	}
	clear(canonical)
	var public any
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		if algorithm != provider.AlgorithmRSASHA256 || typed.Validate() != nil ||
			typed.N.BitLen() < 1024 || len(typed.Primes) != 2 {
			clearPrivateKey(key)
			return nil, [sha256.Size]byte{}, &Error{}
		}
		public = &typed.PublicKey
	case ed25519.PrivateKey:
		if algorithm != provider.AlgorithmEd25519SHA256 ||
			len(typed) != ed25519.PrivateKeySize {
			clearPrivateKey(key)
			return nil, [sha256.Size]byte{}, &Error{}
		}
		public = typed.Public()
	default:
		clearPrivateKey(key)
		return nil, [sha256.Size]byte{}, &Error{}
	}
	derived, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(derived, publicSPKI) {
		clear(derived)
		clearPrivateKey(key)
		return nil, [sha256.Size]byte{}, &Error{}
	}
	digest := sha256.Sum256(derived)
	clear(derived)
	return key, digest, nil
}

// nativeAlgorithmKnown reports whether native custody supports the exact
// closed signing algorithm.
func nativeAlgorithmKnown(algorithm provider.Algorithm) bool {
	return algorithm == provider.AlgorithmRSASHA256 ||
		algorithm == provider.AlgorithmEd25519SHA256
}
