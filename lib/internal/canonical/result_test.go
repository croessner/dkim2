package canonical

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestCanonicalBytesAccessorsAreImmutable(t *testing.T) {
	input := []byte("synthetic canonical bytes\r\n")
	result, err := NewCanonicalBytes(KindHeaderHashInput, input, Metadata{
		InputBytes:         -10,
		IncludedFields:     -1,
		ExcludedFields:     2,
		Algorithm:          HashAlgorithmSHA256,
		BodyTerminalAction: BodyTerminalAction("secret-action"),
		ExcludedHeaderCounts: ExcludedHeaderCounts{
			Received:        1,
			DKIM2Signature:  -5,
			MessageInstance: 2,
		},
	})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}

	input[0] = 'X'
	got := result.Bytes()
	got[0] = 'Y'
	if bytes.Equal(result.Bytes(), input) {
		t.Fatal("CanonicalBytes stored caller-owned input slice")
	}
	if result.Bytes()[0] != 's' {
		t.Fatalf("stored canonical bytes were mutated: %q", result.Bytes())
	}
	if result.Kind() != KindHeaderHashInput {
		t.Fatalf("Kind() = %q, want header hash input", result.Kind())
	}
	if result.Len() != len("synthetic canonical bytes\r\n") {
		t.Fatalf("Len() = %d, want original length", result.Len())
	}

	metadata := result.Metadata()
	if metadata.Draft != DraftBaseline {
		t.Fatalf("Metadata().Draft = %q, want baseline", metadata.Draft)
	}
	if metadata.OutputBytes != result.Len() {
		t.Fatalf("Metadata().OutputBytes = %d, want %d", metadata.OutputBytes, result.Len())
	}
	if metadata.InputBytes != 0 || metadata.IncludedFields != 0 {
		t.Fatalf("negative metadata was not clamped: %#v", metadata)
	}
	if metadata.BodyTerminalAction != BodyTerminalActionUnspecified {
		t.Fatalf("BodyTerminalAction = %q, want unspecified", metadata.BodyTerminalAction)
	}
	if metadata.ExcludedHeaderCounts.Total() != 3 {
		t.Fatalf("ExcludedHeaderCounts.Total() = %d, want 3", metadata.ExcludedHeaderCounts.Total())
	}
}

func TestSHA256DigestAccessorsAreImmutable(t *testing.T) {
	input := bytes.Repeat([]byte{0x42}, sha256DigestBytes)
	digest, err := NewSHA256Digest(input)
	if err != nil {
		t.Fatalf("NewSHA256Digest() error = %v", err)
	}

	input[0] = 0x99
	got := digest.Bytes()
	got[0] = 0x11
	if digest.Bytes()[0] != 0x42 {
		t.Fatalf("digest bytes were mutated: %#v", digest.Bytes())
	}
	if digest.Len() != sha256DigestBytes {
		t.Fatalf("Len() = %d, want %d", digest.Len(), sha256DigestBytes)
	}
	if digest.Algorithm() != HashAlgorithmSHA256 {
		t.Fatalf("Algorithm() = %q, want sha256", digest.Algorithm())
	}
	wantBase64 := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, sha256DigestBytes))
	if digest.Base64() != wantBase64 {
		t.Fatalf("Base64() = %q, want %q", digest.Base64(), wantBase64)
	}
}

func TestSHA256DigestRejectsWrongLength(t *testing.T) {
	if _, err := NewSHA256Digest([]byte("short")); !IsErrorCode(err, ErrorCodeMalformedState) {
		t.Fatalf("NewSHA256Digest() error = %v, want malformed state", err)
	}
}

func TestResultContainersExposeDigestPresence(t *testing.T) {
	canonicalBytes, err := NewCanonicalBytes(KindBodyHashInput, []byte("\r\n"), Metadata{})
	if err != nil {
		t.Fatalf("NewCanonicalBytes() error = %v", err)
	}
	digest, err := NewSHA256Digest(bytes.Repeat([]byte{0x01}, sha256DigestBytes))
	if err != nil {
		t.Fatalf("NewSHA256Digest() error = %v", err)
	}

	withDigest := NewResult(canonicalBytes, digest)
	if _, ok := withDigest.Digest(); !ok {
		t.Fatal("Digest() reported absent digest")
	}
	if !bytes.Equal(withDigest.CanonicalBytes().Bytes(), []byte("\r\n")) {
		t.Fatalf("CanonicalBytes() = %q, want CRLF", withDigest.CanonicalBytes().Bytes())
	}

	withoutDigest := NewResultWithoutDigest(canonicalBytes)
	if _, ok := withoutDigest.Digest(); ok {
		t.Fatal("Digest() reported digest for no-digest result")
	}
}

func TestCanonicalBytesRejectUnknownKind(t *testing.T) {
	if _, err := NewCanonicalBytes(Kind("unknown"), []byte("x"), Metadata{}); !IsErrorCode(err, ErrorCodeInternalMisuse) {
		t.Fatalf("NewCanonicalBytes() error = %v, want internal misuse", err)
	}
}
