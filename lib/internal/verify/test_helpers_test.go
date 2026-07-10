package verify

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

type verificationFixture struct {
	raw                string
	message            rawmsg.Message
	instances          []instance.MessageInstance
	signatures         []signature.Signature
	algorithm          Algorithm
	signatureBase64    string
	signatureBytes     []byte
	bodyDigestBase64   string
	headerDigestBase64 string
	rsaPublicKey       *rsa.PublicKey
	ed25519PublicKey   ed25519.PublicKey
}

const testTimestampSeconds = uint64(1700000000)

// newRSAVerificationFixture creates a synthetic RSA-SHA256 signed message.
func newRSAVerificationFixture(t *testing.T) verificationFixture {
	t.Helper()

	return newRSAVerificationFixtureAt(t, testTimestampSeconds)
}

// newRSAVerificationFixtureAt creates a synthetic RSA-SHA256 message with a fixed timestamp.
func newRSAVerificationFixtureAt(t *testing.T, timestamp uint64) verificationFixture {
	t.Helper()

	return newRSAVerificationFixtureWithEnvelopeAt(t, timestamp, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")})
}

// newRSAVerificationFixtureWithEnvelopeAt creates a synthetic RSA message with fixed envelope tags.
func newRSAVerificationFixtureWithEnvelopeAt(t *testing.T, timestamp uint64, reversePath []byte, forwardPaths [][]byte) verificationFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	fixture := buildVerificationFixtureWithEnvelopeAt(t, AlgorithmRSASHA256, timestamp, reversePath, forwardPaths, func(digest []byte, _ []byte) []byte {
		signatureBytes, signErr := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
		if signErr != nil {
			t.Fatalf("rsa.SignPKCS1v15() error = %v", signErr)
		}

		return signatureBytes
	})
	fixture.rsaPublicKey = &key.PublicKey

	return fixture
}

// newEd25519VerificationFixture creates a synthetic Ed25519-SHA256 signed message.
func newEd25519VerificationFixture(t *testing.T) verificationFixture {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fixture := buildVerificationFixture(t, AlgorithmEd25519SHA256, func(digest []byte, _ []byte) []byte {
		return ed25519.Sign(privateKey, digest)
	})
	fixture.ed25519PublicKey = publicKey

	return fixture
}

// newEd25519RawInputSignatureFixture signs raw Section 9.6 bytes as a negative control.
func newEd25519RawInputSignatureFixture(t *testing.T) verificationFixture {
	t.Helper()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}

	fixture := buildVerificationFixture(t, AlgorithmEd25519SHA256, func(_ []byte, input []byte) []byte {
		return ed25519.Sign(privateKey, input)
	})
	fixture.ed25519PublicKey = publicKey

	return fixture
}

// buildVerificationFixture creates one signed synthetic DKIM2 message.
func buildVerificationFixture(t *testing.T, algorithm Algorithm, signer func([]byte, []byte) []byte) verificationFixture {
	t.Helper()

	return buildVerificationFixtureAt(t, algorithm, testTimestampSeconds, signer)
}

// buildVerificationFixtureAt creates one signed synthetic DKIM2 message with a fixed t= value.
func buildVerificationFixtureAt(t *testing.T, algorithm Algorithm, timestamp uint64, signer func([]byte, []byte) []byte) verificationFixture {
	t.Helper()

	return buildVerificationFixtureWithEnvelopeAt(t, algorithm, timestamp, []byte("<>"), [][]byte{[]byte("<rcpt@example.test>")}, signer)
}

// buildVerificationFixtureWithEnvelopeAt creates a signed message with fixed envelope tags.
func buildVerificationFixtureWithEnvelopeAt(t *testing.T, algorithm Algorithm, timestamp uint64, reversePath []byte, forwardPaths [][]byte, signer func([]byte, []byte) []byte) verificationFixture {
	t.Helper()

	canonicalizer := mustCanonicalizer(t)
	baseRaw := baseVerificationHeaders() + "\r\n" + verificationBody()
	baseMessage := mustParseVerificationMessage(t, baseRaw)
	bodyHash, err := canonicalizer.BodyHashFromMessage(baseMessage)
	if err != nil {
		t.Fatalf("BodyHashFromMessage() error = %v", err)
	}
	headerHash, err := canonicalizer.HeaderHashFromMessage(baseMessage)
	if err != nil {
		t.Fatalf("HeaderHashFromMessage() error = %v", err)
	}
	bodyDigest := mustDigest(t, bodyHash)
	headerDigest := mustDigest(t, headerHash)
	placeholder := base64.StdEncoding.EncodeToString(bytesOf(0xa5, placeholderSignatureLength(algorithm)))
	unsignedRaw := rawWithSignatureSetEnvelopeAt(headerDigest.Base64(), bodyDigest.Base64(), string(algorithm), placeholder, timestamp, reversePath, forwardPaths)
	unsigned := mustParseVerificationMessage(t, unsignedRaw)
	input, err := canonicalizer.SignatureInput(canonical.SignatureInputSelection{
		Headers:        unsigned.Headers(),
		TargetSequence: 1,
	})
	if err != nil {
		t.Fatalf("SignatureInput() error = %v", err)
	}
	digest := sha256.Sum256(input.Bytes())
	signatureBytes := signer(digest[:], input.Bytes())
	signatureText := base64.StdEncoding.EncodeToString(signatureBytes)
	signedRaw := rawWithSignatureSetEnvelopeAt(headerDigest.Base64(), bodyDigest.Base64(), string(algorithm), signatureText, timestamp, reversePath, forwardPaths)
	fixture, err := parseVerificationFixture(signedRaw)
	if err != nil {
		t.Fatalf("parseVerificationFixture() error = %v", err)
	}
	fixture.algorithm = algorithm
	fixture.signatureBase64 = signatureText
	fixture.signatureBytes = signatureBytes
	fixture.bodyDigestBase64 = bodyDigest.Base64()
	fixture.headerDigestBase64 = headerDigest.Base64()

	return fixture
}

// parseVerificationFixture parses one signed synthetic DKIM2 message.
func parseVerificationFixture(raw string) (verificationFixture, error) {
	message, err := rawmsg.Parse([]byte(raw))
	if err != nil {
		return verificationFixture{}, err
	}
	instances, err := instance.Extract(message)
	if err != nil {
		return verificationFixture{}, err
	}
	signatures, err := signature.Extract(message)
	if err != nil {
		return verificationFixture{}, err
	}

	return verificationFixture{
		raw:        raw,
		message:    message,
		instances:  instances,
		signatures: signatures,
	}, nil
}

// withRaw reparses a mutated fixture while preserving key metadata.
func (f verificationFixture) withRaw(raw string) verificationFixture {
	parsed, err := f.withRawResult(raw)
	if err != nil {
		panic(err)
	}

	return parsed
}

// withRawResult reparses a mutated fixture without converting parser errors into panics.
func (f verificationFixture) withRawResult(raw string) (verificationFixture, error) {
	parsed, err := parseVerificationFixture(raw)
	if err != nil {
		return verificationFixture{}, err
	}
	parsed.algorithm = f.algorithm
	parsed.signatureBase64 = f.signatureBase64
	parsed.signatureBytes = f.signatureBytes
	parsed.bodyDigestBase64 = f.bodyDigestBase64
	parsed.headerDigestBase64 = f.headerDigestBase64
	parsed.rsaPublicKey = f.rsaPublicKey
	parsed.ed25519PublicKey = f.ed25519PublicKey

	return parsed, nil
}

// withSignatureBytes returns a fixture carrying replacement decoded signature bytes.
func (f verificationFixture) withSignatureBytes(signatureBytes []byte) verificationFixture {
	return f.withSignatureSet(testSelector + ":" + string(f.algorithm) + ":" + base64.StdEncoding.EncodeToString(signatureBytes))
}

// withSignatureSet returns a fixture carrying a replacement s= value.
func (f verificationFixture) withSignatureSet(signatureSet string) verificationFixture {
	parsed, err := f.withSignatureSetResult(signatureSet)
	if err != nil {
		panic(err)
	}

	return parsed
}

// withSignatureSetResult returns a reparsed signature-set fixture and preserves parser errors.
func (f verificationFixture) withSignatureSetResult(signatureSet string) (verificationFixture, error) {
	old := "s=" + testSelector + ":" + string(f.algorithm) + ":" + f.signatureBase64
	raw := strings.Replace(f.raw, old, "s="+signatureSet, 1)

	return f.withRawResult(raw)
}

// mustVerifierForFixture builds a verifier with the fixture public key.
func mustVerifierForFixture(t *testing.T, fixture verificationFixture) Verifier {
	t.Helper()

	switch fixture.algorithm {
	case AlgorithmRSASHA256:
		return mustVerifierWithKeys(t, []StaticKey{{
			Domain:    testDomain,
			Selector:  testSelector,
			Algorithm: AlgorithmRSASHA256,
			Material:  fixture.rsaPublicKey,
		}})
	case AlgorithmEd25519SHA256:
		return mustVerifierWithKeys(t, []StaticKey{{
			Domain:    testDomain,
			Selector:  testSelector,
			Algorithm: AlgorithmEd25519SHA256,
			Material:  fixture.ed25519PublicKey,
		}})
	default:
		t.Fatalf("unsupported fixture algorithm %q", fixture.algorithm)
		return Verifier{}
	}
}

// mustVerifierWithKeys constructs a verifier from static keys.
func mustVerifierWithKeys(t *testing.T, keys []StaticKey) Verifier {
	t.Helper()

	provider, err := NewStaticKeyProvider(keys)
	if err != nil {
		t.Fatalf("NewStaticKeyProvider() error = %v", err)
	}
	verifier, err := NewVerifier(provider, testClockOption())
	if err != nil {
		t.Fatalf("NewVerifier() error = %v", err)
	}

	return verifier
}

// testClockOption keeps static verification fixtures inside the default age window.
func testClockOption() Option {
	return WithClock(func() time.Time {
		return time.Unix(int64(testTimestampSeconds), 0).Add(time.Hour)
	})
}

// mustCanonicalizer constructs the default canonicalizer for verification tests.
func mustCanonicalizer(t *testing.T) canonical.Canonicalizer {
	t.Helper()

	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		t.Fatalf("NewCanonicalizer() error = %v", err)
	}

	return canonicalizer
}

// mustDigest extracts the digest from a canonicalization result.
func mustDigest(t *testing.T, result canonical.Result) canonical.Digest {
	t.Helper()

	digest, ok := result.Digest()
	if !ok {
		t.Fatal("canonical result missing digest")
	}

	return digest
}

// mustParseVerificationMessage parses a synthetic test message.
func mustParseVerificationMessage(t *testing.T, raw string) rawmsg.Message {
	t.Helper()

	message, err := rawmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("rawmsg.Parse() error = %v", err)
	}

	return message
}

// baseVerificationHeaders returns non-protocol headers covered by the header hash.
func baseVerificationHeaders() string {
	return "From: sender@example.test\r\nSubject: Static verification\r\n"
}

// verificationBody returns the synthetic body covered by the body hash.
func verificationBody() string {
	return "body line\r\n"
}

// rawWithSignatureSetEnvelopeAt returns a synthetic message with explicit envelope tags.
func rawWithSignatureSetEnvelopeAt(headerDigest string, bodyDigest string, algorithm string, signatureText string, timestamp uint64, reversePath []byte, forwardPaths [][]byte) string {
	return baseVerificationHeaders() +
		"Message-Instance: m=1; h=sha256:" + headerDigest + ":" + bodyDigest + ";\r\n" +
		"DKIM2-Signature: i=1; m=1; t=" + strconv.FormatUint(timestamp, 10) + "; mf=" + encodeEnvelopePath(reversePath) + "; rt=" + encodeEnvelopePaths(forwardPaths) + "; d=" + testDomain + "; s=" + testSelector + ":" + algorithm + ":" + signatureText + ";\r\n" +
		"\r\n" +
		verificationBody()
}

// matchingEnvelope returns current SMTP envelope bytes matching the base signature fixture.
func matchingEnvelope() Envelope {
	return NewEnvelope([]byte("<>"), [][]byte{[]byte("<rcpt@example.test>")})
}

// encodeEnvelopePath encodes one parser-compatible SMTP path container.
func encodeEnvelopePath(path []byte) string {
	return base64.StdEncoding.EncodeToString(path)
}

// encodeEnvelopePaths encodes ordered forward-path containers for rt=.
func encodeEnvelopePaths(paths [][]byte) string {
	encoded := make([]string, len(paths))
	for i, path := range paths {
		encoded[i] = encodeEnvelopePath(path)
	}

	return strings.Join(encoded, ",")
}

// placeholderSignatureLength returns parser-compatible synthetic signature sizes.
func placeholderSignatureLength(algorithm Algorithm) int {
	if algorithm == AlgorithmEd25519SHA256 {
		return ed25519.SignatureSize
	}

	return 128
}

// bytesOf returns repeated bytes for synthetic base64 fields.
func bytesOf(value byte, count int) []byte {
	output := make([]byte, count)
	for i := range output {
		output[i] = value
	}

	return output
}

// bytesWithFirstBitFlipped returns a detached byte slice with the first bit changed.
func bytesWithFirstBitFlipped(input []byte) []byte {
	output := append([]byte(nil), input...)
	if len(output) > 0 {
		output[0] ^= 0x01
	}

	return output
}

// LookupKey verifies providerFunc satisfies KeyProvider at compile time.
var _ KeyProvider = providerFunc(nil)

// ensureContextImport keeps context anchored in this helper file for provider assertions.
var _ = context.Background
