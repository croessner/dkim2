package canonical

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"testing"
)

// TestDigestSHA256HashesCanonicalInput verifies SHA-256 over Message-Instance bytes.
func TestDigestSHA256HashesCanonicalInput(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := NewCanonicalBytes(KindBodyHashInput, []byte("alpha\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}

	digest, err := canonicalizer.Digest(input)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}

	want := sha256.Sum256([]byte("alpha\r\n"))
	if !bytes.Equal(digest.Bytes(), want[:]) {
		t.Fatalf("Digest().Bytes() = %x, want %x", digest.Bytes(), want[:])
	}
	wantBase64 := base64.StdEncoding.EncodeToString(want[:])
	if digest.Base64() != wantBase64 {
		t.Fatalf("Digest().Base64() = %q, want %q", digest.Base64(), wantBase64)
	}
	if digest.Algorithm() != HashAlgorithmSHA256 {
		t.Fatalf("Digest().Algorithm() = %q, want sha256", digest.Algorithm())
	}
}

// TestSHA512DigestHashesCanonicalInput verifies the algorithm-owned SHA-512 path.
func TestSHA512DigestHashesCanonicalInput(t *testing.T) {
	canonicalizer, err := NewCanonicalizer(WithHashAlgorithm(HashAlgorithmSHA512))
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := NewCanonicalBytes(KindBodyHashInput, []byte("alpha\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}
	digest, err := canonicalizer.Digest(input)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	want := sha512.Sum512([]byte("alpha\r\n"))
	if !bytes.Equal(digest.Bytes(), want[:]) || digest.Algorithm() != HashAlgorithmSHA512 || digest.Len() != sha512.Size {
		t.Fatalf("Digest() algorithm=%q length=%d bytes_match=%t", digest.Algorithm(), digest.Len(), bytes.Equal(digest.Bytes(), want[:]))
	}
	if digest.Base64() != base64.StdEncoding.EncodeToString(want[:]) {
		t.Fatal("Digest().Base64() differs from the standard-library vector")
	}
}

// TestSHA256DigestRemainsFixedForSignatureInput verifies SHA-512 message options do not alter signature hashing.
func TestSHA256DigestRemainsFixedForSignatureInput(t *testing.T) {
	canonicalizer, err := NewCanonicalizer(WithHashAlgorithm(HashAlgorithmSHA512))
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := NewCanonicalBytes(KindSignatureInput, []byte("signature\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}
	digest, err := canonicalizer.SHA256Digest(input)
	if err != nil || digest.Algorithm() != HashAlgorithmSHA256 || digest.Len() != sha256.Size {
		t.Fatalf("SHA256Digest() error=%v algorithm=%q length=%d", err, digest.Algorithm(), digest.Len())
	}
}

// TestDigestRejectsSignatureInput proves Message-Instance algorithms cannot hash Section 9.6 input.
func TestDigestRejectsSignatureInput(t *testing.T) {
	input, err := NewCanonicalBytes(KindSignatureInput, []byte("signature\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}
	for _, algorithm := range []HashAlgorithm{HashAlgorithmSHA256, HashAlgorithmSHA512} {
		canonicalizer, canonicalizerErr := NewCanonicalizer(WithHashAlgorithm(algorithm))
		if canonicalizerErr != nil {
			t.Fatalf("NewCanonicalizer(%s) error = %v", algorithm, canonicalizerErr)
		}
		_, digestErr := canonicalizer.Digest(input)
		var typed *Error
		if !errors.As(digestErr, &typed) || typed.Code() != ErrorCodeInternalMisuse || typed.Class() != ErrorClassInternal || typed.Location().Kind != KindSignatureInput {
			t.Fatalf("Digest(%s, signature input) error = %#v, want typed internal misuse", algorithm, typed)
		}
	}
}

// TestSHA256DigestRejectsZeroCanonicalizer proves the fixed digest path validates receiver options.
func TestSHA256DigestRejectsZeroCanonicalizer(t *testing.T) {
	input, err := NewCanonicalBytes(KindSignatureInput, []byte("signature\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}
	_, err = (Canonicalizer{}).SHA256Digest(input)
	var typed *Error
	if !errors.As(err, &typed) || typed.Code() != ErrorCodeInvalidOptions || typed.Class() != ErrorClassInvariant {
		t.Fatalf("zero SHA256Digest() error = %#v, want typed invalid options", typed)
	}
}

// TestSHA256DigestRejectsMessageHashKinds proves fixed Section 9.6 hashing cannot replace h= hashing.
func TestSHA256DigestRejectsMessageHashKinds(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	for _, kind := range []Kind{KindBodyHashInput, KindHeaderHashInput} {
		input, inputErr := NewCanonicalBytes(kind, []byte("canonical\r\n"), Metadata{})
		if inputErr != nil {
			t.Fatalf("NewCanonicalBytes(%s) error = %v", kind, inputErr)
		}
		_, digestErr := canonicalizer.SHA256Digest(input)
		var typed *Error
		if !errors.As(digestErr, &typed) || typed.Code() != ErrorCodeInternalMisuse || typed.Class() != ErrorClassInternal || typed.Location().Kind != kind {
			t.Fatalf("SHA256Digest(%s) error = %#v, want typed internal misuse", kind, typed)
		}
	}
}

// TestSHA256DigestBytesAreImmutable verifies digest accessors return copies.
func TestSHA256DigestBytesAreImmutable(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := NewCanonicalBytes(KindSignatureInput, []byte("immutable\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}

	digest, err := canonicalizer.SHA256Digest(input)
	if err != nil {
		t.Fatalf("SHA256Digest() error = %v", err)
	}
	exposed := digest.Bytes()
	exposed[0] ^= 0xff

	want := sha256.Sum256([]byte("immutable\r\n"))
	if !bytes.Equal(digest.Bytes(), want[:]) {
		t.Fatalf("digest bytes were mutated: %x", digest.Bytes())
	}
}

// TestBodyHashComputesCanonicalInputAndDigest verifies the combined body hash path.
func TestBodyHashComputesCanonicalInputAndDigest(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	result, err := canonicalizer.BodyHash(mustParseBodyMessage(t, []byte("alpha\r\n\r\n")).Body())
	if err != nil {
		t.Fatalf("BodyHash() error = %v", err)
	}
	if !bytes.Equal(result.CanonicalBytes().Bytes(), []byte("alpha\r\n")) {
		t.Fatalf("BodyHash() canonical bytes = %q, want collapsed body", result.CanonicalBytes().Bytes())
	}
	digest, ok := result.Digest()
	if !ok {
		t.Fatal("BodyHash() result did not include digest")
	}

	want := sha256.Sum256([]byte("alpha\r\n"))
	if !bytes.Equal(digest.Bytes(), want[:]) {
		t.Fatalf("BodyHash() digest = %x, want %x", digest.Bytes(), want[:])
	}
}

// TestHeaderHashComputesCanonicalInputAndDigest verifies the combined header hash path.
func TestHeaderHashComputesCanonicalInputAndDigest(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	result, err := canonicalizer.HeaderHashFromMessage(mustParseHeaderMessage(t, []byte(
		"Subject: beta\r\n"+
			"Received: excluded\r\n"+
			"From: alpha\r\n")))
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}

	wantCanonical := []byte("from:alpha\r\nsubject:beta\r\n")
	if !bytes.Equal(result.CanonicalBytes().Bytes(), wantCanonical) {
		t.Fatalf("HeaderHashFromMessage() canonical bytes = %q, want %q", result.CanonicalBytes().Bytes(), wantCanonical)
	}
	digest, ok := result.Digest()
	if !ok {
		t.Fatal("HeaderHashFromMessage() result did not include digest")
	}

	wantDigest := sha256.Sum256(wantCanonical)
	if !bytes.Equal(digest.Bytes(), wantDigest[:]) {
		t.Fatalf("HeaderHashFromMessage() digest = %x, want %x", digest.Bytes(), wantDigest[:])
	}
}
