package app

// This fixture is duplicated in the app and httpjson test packages on purpose:
// it needs the library canonicalizer, which only _test.go files under cmd/ may
// import (the command-module internal-import boundary), and Go test files
// cannot be shared across packages.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// forwardedReplayRelayPath is the SMTP reverse-path of the forwarding hop that
// carries the i=2 signature of signedForwardedReplayMessage.
const forwardedReplayRelayPath = "<relay@example.test>"

// signedForwardedReplayMessage creates one passing two-hop synthetic message:
// the originator's i=1 signature to the relay and the relay's i=2 signature to
// the exact final recipients, both over one m=1 instance and one RSA key.
// Draft-07 Section 15.1 counts only such intermediary re-sends as replays, so
// this is the minimal replay-eligible fixture. flags is appended verbatim to
// the i=2 tag list (for example "; f=exploded").
func signedForwardedReplayMessage(t testing.TB, timestamp int64, recipients [][]byte, flags string) ([]byte, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal("forwarded replay RSA fixture construction failed")
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatal("forwarded replay canonicalizer construction failed")
	}
	const headers = "From: sender@example.test\r\nSubject: replay forward\r\n"
	const body = "body line\r\n"
	base, err := rawmsg.Parse([]byte(headers + "\r\n" + body))
	if err != nil {
		t.Fatal("forwarded replay base message construction failed")
	}
	headerHash, _ := canonicalizer.HeaderHashFromMessage(base)
	bodyHash, _ := canonicalizer.BodyHashFromMessage(base)
	headerDigest, _ := headerHash.Digest()
	bodyDigest, _ := bodyHash.Digest()
	encodedRecipients := make([]string, len(recipients))
	for index, recipient := range recipients {
		encodedRecipients[index] = base64.StdEncoding.EncodeToString(recipient)
	}
	stamp := strconv.FormatInt(timestamp, 10)
	relay := base64.StdEncoding.EncodeToString([]byte(forwardedReplayRelayPath))
	fields := headers + "Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n"
	values := []string{
		"i=1; m=1; t=" + stamp + "; mf=" + base64.StdEncoding.EncodeToString([]byte("<sender@example.test>")) +
			"; rt=" + relay + "; d=example.test; s=selector.test:rsa-sha256:",
		"i=2; m=1; t=" + stamp + "; mf=" + relay + "; rt=" + strings.Join(encodedRecipients, ",") + flags +
			"; d=example.test; s=selector.test:rsa-sha256:",
	}
	placeholder := base64.StdEncoding.EncodeToString(make([]byte, 128))
	for index, value := range values {
		unsigned, err := rawmsg.Parse([]byte(fields + "DKIM2-Signature: " + value + placeholder + ";\r\n\r\n" + body))
		if err != nil {
			t.Fatal("forwarded replay unsigned fixture construction failed")
		}
		input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
			Headers: unsigned.Headers(), TargetSequence: uint64(index + 1),
		})
		if err != nil {
			t.Fatal("forwarded replay signature-input construction failed")
		}
		digest := sha256.Sum256(input.Bytes())
		sealed, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal("forwarded replay signature construction failed")
		}
		fields += "DKIM2-Signature: " + value + base64.StdEncoding.EncodeToString(sealed) + ";\r\n"
	}
	return []byte(fields + "\r\n" + body), &key.PublicKey
}
