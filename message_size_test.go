package dkim2

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// TestSMTPMessageSizeConfiguration proves a 100 MiB deployment can construct
// matching signing and verification limits while retaining a finite ceiling.
func TestSMTPMessageSizeConfiguration(t *testing.T) {
	limits := DefaultSigningLimits()
	limits.MaxMessageBytes = 100 << 20
	limits.MaxCanonicalWorkBytes = 200 << 20
	if err := limits.Validate(); err != nil {
		t.Fatal("100 MiB signing configuration rejected")
	}
	config := verifierConfig{limits: DefaultVerificationLimits()}
	if err := WithMaxRawMessageBytes(100 << 20)(&config); err != nil {
		t.Fatal("100 MiB verification configuration rejected")
	}
}

// TestSMTPSizeMessageSignsAndVerifies exercises real signing, MIME-style
// short body lines, and signature verification above the former 32 MiB cap.
func TestSMTPSizeMessageSignsAndVerifies(t *testing.T) {
	const size = 100 << 20
	header := []byte("From: alice@example.test\r\nSubject: large attachment\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	line := append(bytes.Repeat([]byte("A"), 76), '\r', '\n')
	raw := make([]byte, 0, size)
	raw = append(raw, header...)
	for len(raw)+len(line) <= size {
		raw = append(raw, line...)
	}
	remaining := size - len(raw)
	if remaining >= 2 {
		raw = append(raw, bytes.Repeat([]byte("A"), remaining-2)...)
		raw = append(raw, '\r', '\n')
	}
	fixture := newPublicSigningFixture(t)
	handle, err := NewPrivateKeyHandle([]byte("fixture-dual"))
	if err != nil {
		t.Fatal(err)
	}
	rsaCredential, err := NewRSASigningCredential(testRSASelector, &fixture.provider.rsaKey.PublicKey, handle)
	if err != nil {
		t.Fatal(err)
	}
	edCredential, err := NewEd25519SigningCredential("ed", fixture.provider.edKey.Public().(ed25519.PublicKey), handle)
	if err != nil {
		t.Fatal(err)
	}
	fixture.profile, err = NewDualSigningProfile("example.test", rsaCredential, edCredential)
	if err != nil {
		t.Fatal(err)
	}
	fixture.existingProfile, err = NewDualSigningProfile("example.net", rsaCredential, edCredential)
	if err != nil {
		t.Fatal(err)
	}
	signed := fixture.signOrigin(t, raw, RouteDisclosureSingle)
	if len(signed) <= len(raw) || !bytes.HasSuffix(signed, raw[len(header):]) {
		t.Fatal("large signing changed the body or omitted generated headers")
	}
	fixture.assertPublicChainPass(t, signed, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")}, 1)
	proof, capability, err := fixture.facade.VerifyForRevision(t.Context(), NewVerifyRequest(
		signed, []byte("<alice@example.test>"), [][]byte{[]byte("<bob@example.net>")},
	))
	if err != nil || proof.Status() != RevisionVerificationVerified || !capability.Valid() {
		t.Fatal("large revision input did not verify")
	}
	revised := bytes.Replace(signed, []byte("Subject: large attachment"), []byte("Subject: revised attachment"), 1)
	request := NewExistingSigningRequest(
		capability, revised, []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")},
		fixture.existingTicket(t, capability, revised, RouteDisclosureSingle),
		fixture.existingProfile, SigningMetadata{}, SigningTransportFinalNetworkPreDotStuffing,
		RejectUnavailableBody, RecipeAllowLiterals,
	)
	result, recovery, err := fixture.facade.SignExisting(t.Context(), request)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf("large header-only revision failed: %v", err)
	}
	output, ok := result.Unrestricted()
	if !ok {
		t.Fatal("large revision returned no unrestricted output")
	}
	fixture.assertPublicChainPass(t, output.Bytes(), []byte("<relay@example.net>"), [][]byte{[]byte("<carol@next.test>")}, 2)
}
