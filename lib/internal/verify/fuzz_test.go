package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

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

	provider, err := NewStaticKeyProvider(nil)
	if err != nil {
		f.Fatalf("NewStaticKeyProvider(nil) error = %v", err)
	}
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

		result, verifyErr := verifier.Verify(context.Background(), Request{Message: message, Envelope: matchingEnvelope()})
		if !bytes.Equal(input, original) {
			t.Fatal("verification mutated caller input")
		}
		if verifyErr != nil {
			assertNoSyntheticSecretMarkers(t, verifyErr.Error())
		}
		assertNoSyntheticSecretMarkers(t, fmt.Sprintf("%#v", result))
	})
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
