package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// TestSHA256DigestHashesCanonicalInput verifies SHA-256 over canonical bytes.
func TestSHA256DigestHashesCanonicalInput(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := NewCanonicalBytes(KindBodyHashInput, []byte("alpha\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}

	digest, err := canonicalizer.SHA256Digest(input)
	if err != nil {
		t.Fatalf("SHA256Digest() error = %v", err)
	}

	want := sha256.Sum256([]byte("alpha\r\n"))
	if !bytes.Equal(digest.Bytes(), want[:]) {
		t.Fatalf("SHA256Digest().Bytes() = %x, want %x", digest.Bytes(), want[:])
	}
	wantBase64 := base64.StdEncoding.EncodeToString(want[:])
	if digest.Base64() != wantBase64 {
		t.Fatalf("SHA256Digest().Base64() = %q, want %q", digest.Base64(), wantBase64)
	}
	if digest.Algorithm() != HashAlgorithmSHA256 {
		t.Fatalf("SHA256Digest().Algorithm() = %q, want sha256", digest.Algorithm())
	}
}

// TestSHA256DigestBytesAreImmutable verifies digest accessors return copies.
func TestSHA256DigestBytesAreImmutable(t *testing.T) {
	canonicalizer, err := NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	input, err := NewCanonicalBytes(KindBodyHashInput, []byte("immutable\r\n"), Metadata{})
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
