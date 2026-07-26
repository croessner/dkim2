package config

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TestValidatePasswordPreservesExactOpaqueGrammar freezes the password length
// bounds and rejects only the three forbidden delimiter octets.
func TestValidatePasswordPreservesExactOpaqueGrammar(t *testing.T) {
	for _, value := range [][]byte{
		{'x'},
		{0xff},
		bytes.Repeat([]byte{'x'}, maxPasswordBytes),
	} {
		if err := validatePassword(value); err != nil {
			t.Fatalf("validatePassword() rejected an allowed opaque value with code %s", CodeOf(err))
		}
	}
	for _, value := range [][]byte{
		nil,
		{},
		bytes.Repeat([]byte{'x'}, maxPasswordBytes+1),
		{'a', 0, 'b'},
		{'a', '\r', 'b'},
		{'a', '\n', 'b'},
	} {
		if CodeOf(validatePassword(value)) != CodeProtectedContent {
			t.Fatal("validatePassword() accepted a forbidden password grammar")
		}
	}
}

// TestValidateExactKeyPreservesRawBytesAndRejectsZero freezes the capability
// and HMAC grammar without treating newline bytes as delimiters.
func TestValidateExactKeyPreservesRawBytesAndRejectsZero(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa5}, exactKeyBytes)
	raw[0] = '\n'
	if err := validateExactKey(raw); err != nil {
		t.Fatalf("validateExactKey() rejected an exact raw key with code %s", CodeOf(err))
	}
	for _, value := range [][]byte{
		nil,
		bytes.Repeat([]byte{1}, exactKeyBytes-1),
		bytes.Repeat([]byte{1}, exactKeyBytes+1),
		make([]byte, exactKeyBytes),
	} {
		if CodeOf(validateExactKey(value)) != CodeProtectedContent {
			t.Fatal("validateExactKey() accepted invalid key material")
		}
	}
}

// TestValidateProtectedSeparationRejectsCrossRoleEquality freezes exact
// capability, HMAC, and password role separation without value formatting.
func TestValidateProtectedSeparationRejectsCrossRoleEquality(t *testing.T) {
	if CodeOf(validateProtectedSeparation(nil)) != CodeInternal {
		t.Fatal("validateProtectedSeparation() accepted a nil owner")
	}
	if err := validateProtectedSeparation(testSeparatedProtectedState()); err != nil {
		t.Fatalf("validateProtectedSeparation() rejected distinct roles with code %s", CodeOf(err))
	}

	tests := []func(*protectedState){
		func(state *protectedState) { state.auditorPassword = append([]byte(nil), state.applicationPassword...) },
		func(state *protectedState) { state.hmac = state.capability },
		func(state *protectedState) { state.applicationPassword = append([]byte(nil), state.capability[:]...) },
		func(state *protectedState) { state.auditorPassword = append([]byte(nil), state.capability[:]...) },
		func(state *protectedState) { state.applicationPassword = append([]byte(nil), state.hmac[:]...) },
		func(state *protectedState) { state.auditorPassword = append([]byte(nil), state.hmac[:]...) },
	}
	for _, mutate := range tests {
		state := testSeparatedProtectedState()
		mutate(state)
		if CodeOf(validateProtectedSeparation(state)) != CodeProtectedContent {
			t.Fatal("validateProtectedSeparation() accepted equal cross-role material")
		}
	}
}

// TestValidateProtectedSeparationIgnoresAbsentReplayRoles proves the common
// capability-only backend does not invent equality against absent values.
func TestValidateProtectedSeparationIgnoresAbsentReplayRoles(t *testing.T) {
	state := testSeparatedProtectedState()
	state.hasHMAC = false
	state.hmac = state.capability
	state.applicationPassword = nil
	state.auditorPassword = nil
	if err := validateProtectedSeparation(state); err != nil {
		t.Fatalf("validateProtectedSeparation() rejected absent replay roles with code %s", CodeOf(err))
	}
}

// TestParseCertificateRootsAcceptsOnlyStrictCABundles freezes the accepted PEM
// separators, CA property, key usage, uniqueness, and owned DER output.
func TestParseCertificateRootsAcceptsOnlyStrictCABundles(t *testing.T) {
	first := testProtectedCertificateDER(t, 1, true, x509.KeyUsageCertSign)
	second := testProtectedCertificateDER(t, 2, true, 0)
	document := append([]byte(" \t\r\n"), pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: first})...)
	document = append(document, []byte("\n\t")...)
	document = append(document, pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: second})...)
	document = append(document, []byte(" \r\n")...)

	roots, err := parseCertificateRoots(document)
	if err != nil {
		t.Fatalf("parseCertificateRoots() rejected a strict CA bundle with code %s", CodeOf(err))
	}
	if len(roots) != 2 || !bytes.Equal(roots[0], first) || !bytes.Equal(roots[1], second) {
		t.Fatal("parseCertificateRoots() changed the ordered DER roots")
	}
	firstBeforeMutation := append([]byte(nil), first...)
	first[0] ^= 0xff
	if !bytes.Equal(roots[0], firstBeforeMutation) {
		t.Fatal("parseCertificateRoots() retained an alias into caller-owned DER")
	}
}

// TestParseCertificateRootsRejectsPEMAmbiguity freezes closed failure for
// non-CA, wrong-usage, malformed, duplicate, encrypted, and trailing inputs.
func TestParseCertificateRootsRejectsPEMAmbiguity(t *testing.T) {
	valid := testProtectedCertificateDER(t, 10, true, x509.KeyUsageCertSign)
	notCA := testProtectedCertificateDER(t, 11, false, x509.KeyUsageDigitalSignature)
	wrongUsage := testProtectedCertificateDER(t, 12, true, x509.KeyUsageDigitalSignature)
	presentZeroUsage := testProtectedCertificateWithExtensions(
		t,
		13,
		[]pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
			Critical: true,
			Value:    []byte{0x03, 0x01, 0x00},
		}},
	)
	parsedPresentZero, err := x509.ParseCertificate(presentZeroUsage)
	if err != nil || !hasCertificateKeyUsage(parsedPresentZero) || parsedPresentZero.KeyUsage != 0 {
		t.Fatal("present-zero KeyUsage fixture did not preserve the intended parsed state")
	}
	validPEM := pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: valid})
	duplicate := append(append([]byte(nil), validPEM...), validPEM...)
	tests := [][]byte{
		nil,
		[]byte(" \t\r\n"),
		append(append([]byte(nil), validPEM...), 'x'),
		append(append([]byte(nil), validPEM...), '\v'),
		append(append([]byte(nil), validPEM...), '\f'),
		append(append([]byte(nil), validPEM...), 0),
		append(append([]byte(nil), validPEM...), []byte("\u00a0")...),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: valid}),
		pem.EncodeToMemory(&pem.Block{
			Type:    certificatePEMType,
			Headers: map[string]string{"Comment": "forbidden"},
			Bytes:   valid,
		}),
		pem.EncodeToMemory(&pem.Block{
			Type: certificatePEMType,
			Headers: map[string]string{
				"Proc-Type": "4,ENCRYPTED",
				"DEK-Info":  "AES-256-CBC,00000000000000000000000000000000",
			},
			Bytes: valid,
		}),
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: []byte{1, 2, 3}}),
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: notCA}),
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: wrongUsage}),
		pem.EncodeToMemory(&pem.Block{Type: certificatePEMType, Bytes: presentZeroUsage}),
		duplicate,
		bytes.Repeat([]byte{'x'}, maxCAPEMBytes+1),
		pem.EncodeToMemory(&pem.Block{
			Type:  certificatePEMType,
			Bytes: bytes.Repeat([]byte{1}, maxCertificateDERBytes+1),
		}),
	}
	for _, document := range tests {
		roots, err := parseCertificateRoots(document)
		if roots != nil || CodeOf(err) != CodeProtectedContent {
			t.Fatal("parseCertificateRoots() accepted an ambiguous CA bundle")
		}
	}
}

// testProtectedCertificateWithExtensions creates a CA with exact supplied DER extensions.
func testProtectedCertificateWithExtensions(
	t *testing.T,
	serial int64,
	extensions []pkix.Extension,
) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ed25519.GenerateKey() failed")
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "protected-parser-extension-test"},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtraExtensions:       extensions,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal("x509.CreateCertificate() failed")
	}
	return der
}

// TestIsPEMWhitespaceUsesTheClosedASCIISet prevents Unicode or alternate ASCII
// whitespace from widening the trust-bundle grammar.
func TestIsPEMWhitespaceUsesTheClosedASCIISet(t *testing.T) {
	if !isPEMWhitespace([]byte{' ', '\t', '\r', '\n'}) {
		t.Fatal("isPEMWhitespace() rejected the exact allowed separator set")
	}
	for _, value := range [][]byte{{'\v'}, {'\f'}, {0}, []byte("\u00a0")} {
		if isPEMWhitespace(value) {
			t.Fatal("isPEMWhitespace() accepted a forbidden separator")
		}
	}
}

// TestParseCertificateRootsCountBoundary accepts 128 unique roots and rejects 129.
func TestParseCertificateRootsCountBoundary(t *testing.T) {
	document := make([]byte, 0, 128*512)
	for serial := int64(1); serial <= maxCertificateCount; serial++ {
		der := testProtectedCertificateDER(t, 1_000+serial, true, 0)
		document = append(document, pem.EncodeToMemory(&pem.Block{
			Type:  certificatePEMType,
			Bytes: der,
		})...)
	}
	roots, err := parseCertificateRoots(document)
	if err != nil || len(roots) != maxCertificateCount {
		t.Fatalf("exact root count rejected with code %s", CodeOf(err))
	}
	extra := testProtectedCertificateDER(t, 2_000, true, 0)
	document = append(document, pem.EncodeToMemory(&pem.Block{
		Type:  certificatePEMType,
		Bytes: extra,
	})...)
	if roots, err := parseCertificateRoots(document); roots != nil || CodeOf(err) != CodeProtectedContent {
		t.Fatalf("over root count returned code %s", CodeOf(err))
	}
}

// TestValidateCertificateBoundsFreezesPerRootCountAndAggregateEdges.
func TestValidateCertificateBoundsFreezesPerRootCountAndAggregateEdges(t *testing.T) {
	if total, err := validateCertificateBounds(
		maxCertificateCount-1,
		maxCertificateAggregate-maxCertificateDERBytes,
		maxCertificateDERBytes,
	); err != nil || total != maxCertificateAggregate {
		t.Fatalf("exact certificate bounds rejected with code %s", CodeOf(err))
	}
	tests := [][3]int{
		{0, 0, 0},
		{0, 0, maxCertificateDERBytes + 1},
		{maxCertificateCount, 0, 1},
		{0, maxCertificateAggregate, 1},
		{-1, 0, 1},
		{0, -1, 1},
	}
	for _, values := range tests {
		if _, err := validateCertificateBounds(values[0], values[1], values[2]); CodeOf(err) != CodeProtectedContent {
			t.Fatalf("invalid certificate bounds returned code %s", CodeOf(err))
		}
	}
}

// testProtectedCertificateDER creates one small synthetic certificate for
// protected trust-bundle parser tests.
func testProtectedCertificateDER(
	t *testing.T,
	serial int64,
	isCA bool,
	usage x509.KeyUsage,
) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ed25519.GenerateKey() failed")
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "protected-parser-test"},
		NotBefore:             time.Unix(1, 0),
		NotAfter:              time.Unix(2, 0),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal("x509.CreateCertificate() failed")
	}
	return der
}

// FuzzProtectedContentParsers exercises bounded password, exact-key, and PEM rejection.
func FuzzProtectedContentParsers(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xa5}, exactKeyBytes))
	f.Add([]byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"))
	f.Fuzz(func(t *testing.T, value []byte) {
		passwordErr := validatePassword(value)
		if passwordErr != nil && CodeOf(passwordErr) != CodeProtectedContent {
			t.Fatalf("validatePassword() returned code %s", CodeOf(passwordErr))
		}
		keyErr := validateExactKey(value)
		if keyErr != nil && CodeOf(keyErr) != CodeProtectedContent {
			t.Fatalf("validateExactKey() returned code %s", CodeOf(keyErr))
		}
		roots, rootErr := parseCertificateRoots(value)
		if rootErr != nil {
			if roots != nil || CodeOf(rootErr) != CodeProtectedContent {
				t.Fatalf("parseCertificateRoots() returned code %s", CodeOf(rootErr))
			}
			return
		}
		if len(roots) == 0 || len(roots) > maxCertificateCount {
			t.Fatal("parseCertificateRoots() produced an invalid root count")
		}
	})
}

// testSeparatedProtectedState constructs one owner whose protected roles are
// each valid and byte-distinct.
func testSeparatedProtectedState() *protectedState {
	state := &protectedState{
		hasHMAC:             true,
		applicationPassword: bytes.Repeat([]byte{0x33}, exactKeyBytes),
		auditorPassword:     bytes.Repeat([]byte{0x44}, exactKeyBytes),
	}
	copy(state.capability[:], bytes.Repeat([]byte{0x11}, exactKeyBytes))
	copy(state.hmac[:], bytes.Repeat([]byte{0x22}, exactKeyBytes))
	return state
}
