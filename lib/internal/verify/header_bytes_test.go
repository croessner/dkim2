package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
)

// TestVerifierPassesMessageWithNonUTF8HeaderBytes reproduces the Draft-07
// Sections 5 and 18 byte model: header hashing treats the message as bytes,
// so a legacy unencoded Latin-1 Subject must verify instead of being rejected
// as a malformed message.
func TestVerifierPassesMessageWithNonUTF8HeaderBytes(t *testing.T) {
	headers := "From: sender@example.test\r\nSubject: caf\xe9 cr\xe8me\r\n"
	message := mustParseVerificationMessage(t, headers+"\r\n"+verificationBody())
	canonicalizer := mustCanonicalizer(t)
	headerHash, err := canonicalizer.HeaderHashFromMessage(message)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	bodyHash, err := canonicalizer.BodyHashFromMessage(message)
	if err != nil {
		t.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	build := func(signatureText string) string {
		return headers + "Message-Instance: m=1; h=sha256:" + mustDigest(t, headerHash).Base64() + ":" + mustDigest(t, bodyHash).Base64() + ";\r\n" +
			"DKIM2-Signature: " + signatureField(1, testSelector+":"+string(AlgorithmRSASHA256)+":"+signatureText) + "\r\n\r\n" + verificationBody()
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	digest := signatureDigestForTarget(t, mustParseVerificationMessage(t, build(placeholder)), 1)
	signed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15() error = %v", err)
	}
	raw := build(base64.StdEncoding.EncodeToString(signed))
	if !strings.Contains(raw, "\xe9") {
		t.Fatal("fixture lost its non-UTF-8 header byte")
	}
	verifier := mustVerifierWithKeys(t, []StaticKey{{Domain: testDomain, Selector: testSelector, Algorithm: AlgorithmRSASHA256, Material: &key.PublicKey}})
	result, err := verifier.Verify(context.Background(), Request{Message: mustParseVerificationMessage(t, raw), Envelope: matchingEnvelope()})
	if err != nil || result.Status() != TargetStatusPass {
		t.Fatalf("Verify() status=%q error=%v", result.Status(), err)
	}
}
