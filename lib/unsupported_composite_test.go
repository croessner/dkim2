package dkim2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const (
	// compositeTestToken is the Draft-08 Section 3.4 post-quantum composite
	// algorithm and DNS-02 key type this implementation deliberately does
	// not support while its construction is unsettled.
	compositeTestToken = "mldsa44-ed25519-sha512"
	// compositeTestSignatureBytes is the size of a real composite value, so
	// the regression covers a multi-kilobyte unknown set.
	compositeTestSignatureBytes = 2484
	compositeTestFoldWidth      = 76
	compositeTestEdSelector     = "ed.test"
	compositeTestPQSelector     = "pq.test"
)

// foldTestBase64 folds a long base64 tag value with CRLF HTAB so every
// RFC 5322 header line stays below the 998-octet limit.
func foldTestBase64(value string) string {
	var builder strings.Builder
	for start := 0; start < len(value); start += compositeTestFoldWidth {
		if start > 0 {
			builder.WriteString("\r\n\t")
		}
		builder.WriteString(value[start:min(start+compositeTestFoldWidth, len(value))])
	}
	return builder.String()
}

// mixedCompositeFixture builds a current DKIM2 message whose one signature
// carries a real Ed25519 set plus a composite set with a 2484-byte value. The
// composite value is opaque here: the Section 12.8 input blanks every set
// signature, so only the Ed25519 set is cryptographically meaningful.
func mixedCompositeFixture(t *testing.T, includeEd25519 bool, separator string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("dkim2-unsupported-composite-ed25519"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	base := []byte("From: sender@example.test\r\nSubject: provider facade\r\n\r\nbody\r\n")
	message, err := rawmsg.Parse(base)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}
	header, _ := canonicalizer.HeaderHashFromMessage(message)
	body, _ := canonicalizer.BodyHashFromMessage(message)
	headerDigest, _ := header.Digest()
	bodyDigest, _ := body.Digest()
	placeholder := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, ed25519.SignatureSize))
	compositeSet := compositeTestPQSelector + ":" + compositeTestToken + ":" +
		foldTestBase64(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, compositeTestSignatureBytes)))
	sets := compositeSet
	if includeEd25519 {
		sets = compositeTestEdSelector + ":ed25519-sha256:" + placeholder + separator + "\r\n\t" + compositeSet
	}
	unsigned := []byte("From: sender@example.test\r\nSubject: provider facade\r\n" +
		"Message-Instance: m=1; h=sha256:" + headerDigest.Base64() + ":" + bodyDigest.Base64() + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=1700000000; mf=PD4=; rt=PHJjcHRAZXhhbXBsZS50ZXN0Pg==; d=example.test;\r\n\ts=" +
		sets + ";\r\n\r\nbody\r\n")
	if !includeEd25519 {
		return unsigned, privateKey.Public().(ed25519.PublicKey)
	}
	parsed, err := rawmsg.Parse(unsigned)
	if err != nil {
		t.Fatalf("rawmsg.Parse(unsigned) error = %v", err)
	}
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{Headers: parsed.Headers(), TargetSequence: 1})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, digest[:]))
	return bytes.Replace(unsigned, []byte(placeholder), []byte(signature), 1), privateKey.Public().(ed25519.PublicKey)
}

// compositeDNSTransport serves the Ed25519 key and a DNS-02
// k=mldsa44-ed25519-sha512 record, and records every queried owner name.
type compositeDNSTransport struct {
	mu      sync.Mutex
	t       *testing.T
	edKey   ed25519.PublicKey
	queried []string
}

// LookupTXT returns the fixture record for one owner name.
func (c *compositeDNSTransport) LookupTXT(_ context.Context, owner string) (TXTLookupResult, error) {
	c.mu.Lock()
	c.queried = append(c.queried, owner)
	c.mu.Unlock()
	switch owner {
	case compositeTestEdSelector + "._domainkey.example.test.":
		return mustPublicFoundLookup(c.t, []byte("v=DKIM1; k=ed25519; p="+base64.StdEncoding.EncodeToString(c.edKey))), nil
	case compositeTestPQSelector + "._domainkey.example.test.":
		return mustPublicFoundLookup(c.t, []byte("v=DKIM1; k="+compositeTestToken+"; p="+
			base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 1344)))), nil
	default:
		return mustPublicAbsentLookup(c.t), nil
	}
}

// verifyWithCompositeDNS verifies raw through the DNS provider at the fixture clock.
func verifyWithCompositeDNS(t *testing.T, transport *compositeDNSTransport, raw []byte) VerifyResult {
	t.Helper()
	provider, err := NewDNSPublicKeyProvider(transport)
	if err != nil {
		t.Fatalf("NewDNSPublicKeyProvider() error = %v", err)
	}
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(1700000000, 0) }))
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}
	result, err := verifier.Verify(context.Background(), NewVerifyRequest(raw, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	return result
}

// TestVerifierCompositeBesideEd25519DependsOnSeparator re-derives the
// Draft-07 "composite plus ed25519 set passes" case under Draft-08. The
// composite mldsa44-ed25519-sha512 token is an unimplemented algorithm, a
// PERMERROR intermediate decided without fetching its key (Section 14.6 step
// 4). Joined by "|" the Ed25519 group passes on its own (step 7); joined by
// "," the sig-all group holding the composite is PERMERROR (step 6), so the
// message no longer verifies.
func TestVerifierCompositeBesideEd25519DependsOnSeparator(t *testing.T) {
	for _, test := range []struct {
		separator string
		state     ResultState
		reason    ReasonCode
	}{
		{"|", ResultStatePASS, ReasonNone},
		{",", ResultStatePERMERROR, ReasonUnsupportedAlgorithm},
	} {
		raw, edKey := mixedCompositeFixture(t, true, test.separator)
		transport := &compositeDNSTransport{t: t, edKey: edKey}
		result := verifyWithCompositeDNS(t, transport, raw)
		if result.State() != test.state || result.PrimaryReason() != test.reason {
			t.Fatalf("%q: Verify() = %q/%q", test.separator, result.State(), result.PrimaryReason())
		}
		sets := result.SignatureSets()
		if len(sets) != 2 ||
			sets[0].Algorithm() != AlgorithmEd25519SHA256 || sets[0].Status() != SignatureStatusPASS || sets[0].Reason() != ReasonNone ||
			sets[1].Algorithm() != AlgorithmUnknown || sets[1].Status() != SignatureStatusIgnored || sets[1].Reason() != ReasonUnsupportedAlgorithm {
			t.Fatalf("%q: signature sets = %#v", test.separator, sets)
		}
		for _, owner := range transport.queried {
			if strings.HasPrefix(owner, compositeTestPQSelector+".") {
				t.Fatalf("composite selector key was fetched: %q", owner)
			}
		}
	}
	if Algorithm(compositeTestToken).Known() {
		t.Fatal("composite algorithm is part of the public vocabulary")
	}
}

// TestVerifierRejectsCompositeOnlySignature proves a signature whose only set
// uses the composite algorithm has no checkable supported algorithm and ends
// in PERMERROR unsupported_algorithm, as for any unknown-only signature.
func TestVerifierRejectsCompositeOnlySignature(t *testing.T) {
	raw, edKey := mixedCompositeFixture(t, false, "")
	result := verifyWithCompositeDNS(t, &compositeDNSTransport{t: t, edKey: edKey}, raw)
	if result.State() != ResultStatePERMERROR || result.PrimaryReason() != ReasonUnsupportedAlgorithm {
		t.Fatalf("Verify() = %q/%q", result.State(), result.PrimaryReason())
	}
	sets := result.SignatureSets()
	if len(sets) != 1 || sets[0].Algorithm() != AlgorithmUnknown || sets[0].Status() != SignatureStatusIgnored ||
		sets[0].Reason() != ReasonUnsupportedAlgorithm {
		t.Fatalf("signature sets = %#v", sets)
	}
}
