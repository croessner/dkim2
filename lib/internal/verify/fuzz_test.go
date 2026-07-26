package verify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// FuzzVerifyStaticKeyRequest smoke-tests static verifier request handling.
func FuzzVerifyStaticKeyRequest(f *testing.F) {
	f.Add([]byte("From: fuzz@example.test\r\n\r\nbody\r\n"))
	f.Add([]byte(rawWithSignatureSetEnvelopeAt(
		base64.StdEncoding.EncodeToString(bytesOf(0x11, 32)),
		base64.StdEncoding.EncodeToString(bytesOf(0x22, 32)),
		string(AlgorithmRSASHA256),
		base64.StdEncoding.EncodeToString(bytesOf(0x33, 128)),
		testTimestampSeconds,
		[]byte("<>"),
		[][]byte{[]byte("<rcpt@example.test>")},
	)))
	f.Add([]byte(secretMarkerFuzzSeed()))
	signedSeed, provider := currentVerificationFuzzSeed(f)
	f.Add(signedSeed)

	verifier, err := NewVerifier(provider, WithClock(func() time.Time {
		return time.Unix(int64(testTimestampSeconds), 0)
	}))
	if err != nil {
		f.Fatalf("NewVerifier() error = %v", err)
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		original := bytes.Clone(input)
		message, parseErr := rawmsg.Parse(input)
		if !bytes.Equal(input, original) {
			t.Fatal("raw message parse mutated caller input")
		}
		if parseErr != nil {
			assertNoSyntheticSecretMarkers(t, parseErr.Error())

			return
		}

		current, currentErr := verifier.VerifyCurrent(context.Background(), Request{Message: message, Envelope: matchingEnvelope()})
		full, fullErr := verifier.Verify(context.Background(), Request{Message: message, Envelope: matchingEnvelope()})
		if !bytes.Equal(input, original) {
			t.Fatal("verification mutated caller input")
		}
		if currentVerificationErrorCode(currentErr) != currentVerificationErrorCode(fullErr) {
			t.Fatal("current-only and history-capable error classes differ")
		}
		if currentErr != nil {
			assertNoSyntheticSecretMarkers(t, currentErr.Error())
		}
		if fullErr != nil {
			assertNoSyntheticSecretMarkers(t, fullErr.Error())
		}
		if currentErr == nil && fullErr == nil {
			assertCurrentVerificationParity(t, current, full)
		}
		if _, ok := current.historyWalk(); ok {
			t.Fatal("current-only fuzz verification retained history")
		}
		assertNoSyntheticSecretMarkers(t, fmt.Sprintf("%#v|%#v", current, full))
	})
}

// currentVerificationFuzzSeed returns a reproducible passing Ed25519 request and provider.
func currentVerificationFuzzSeed(f *testing.F) ([]byte, StaticKeyProvider) {
	f.Helper()
	seed := sha256.Sum256([]byte("current-verification-fuzz-seed"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		f.Fatalf("NewCanonicalizer() error = %v", err)
	}
	base, err := rawmsg.Parse([]byte(baseVerificationHeaders() + "\r\n" + verificationBody()))
	if err != nil {
		f.Fatalf("rawmsg.Parse(base) error = %v", err)
	}
	headerHash, err := canonicalizer.HeaderHashFromMessage(base)
	if err != nil {
		f.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	bodyHash, err := canonicalizer.BodyHashFromMessage(base)
	if err != nil {
		f.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	headerDigest, headerOK := headerHash.Digest()
	bodyDigest, bodyOK := bodyHash.Digest()
	if !headerOK || !bodyOK {
		f.Fatal("fuzz seed canonicalization omitted a digest")
	}
	placeholder := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, ed25519.SignatureSize))
	unsignedRaw := rawWithSignatureSetEnvelopeAt(
		headerDigest.Base64(), bodyDigest.Base64(), string(AlgorithmEd25519SHA256),
		placeholder, testTimestampSeconds, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")},
	)
	unsigned, err := rawmsg.Parse([]byte(unsignedRaw))
	if err != nil {
		f.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	signatureInput, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        unsigned.Headers(),
		TargetSequence: 1,
	})
	if err != nil {
		f.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(signatureInput.Bytes())
	signedRaw := rawWithSignatureSetEnvelopeAt(
		headerDigest.Base64(), bodyDigest.Base64(), string(AlgorithmEd25519SHA256),
		base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:])),
		testTimestampSeconds, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")},
	)
	provider, err := NewStaticKeyProvider([]StaticKey{{
		Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmEd25519SHA256, Material: publicKey,
	}})
	if err != nil {
		f.Fatalf("NewStaticKeyProvider() error = %v", err)
	}
	return []byte(signedRaw), provider
}

// currentVerificationErrorCode returns a bounded verifier or Go error class.
func currentVerificationErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var typed *Error
	if errors.As(err, &typed) {
		return string(typed.Code())
	}
	return fmt.Sprintf("%T", err)
}

// secretMarkerFuzzSeed returns a parser-shaped synthetic marker message.
func secretMarkerFuzzSeed() string {
	return "From: HEADER-SECRET-MARKER@example.test\r\n" +
		"Subject: fuzz diagnostics\r\n" +
		"Message-Instance: m=1; h=sha256:" + base64.StdEncoding.EncodeToString(bytesOf(0x44, 32)) + ":" + base64.StdEncoding.EncodeToString(bytesOf(0x55, 32)) + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=" + base64.StdEncoding.EncodeToString([]byte("<PATH-SECRET-MARKER@example.test>")) + "; rt=" + base64.StdEncoding.EncodeToString([]byte("<BODY-SECRET-MARKER@example.test>")) + "; d=example.test; s=selector.test:rsa-sha256:" + base64.StdEncoding.EncodeToString(bytesOf(0x66, 128)) + "; n=NONCE-SECRET-MARKER;\r\n" +
		"\r\n" +
		"BODY-SECRET-MARKER\r\n"
}
