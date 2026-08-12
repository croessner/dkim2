package dkim2

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
	"reflect"
	"testing"
)

// TestPublicProviderVocabulariesAreClosed verifies exact public provider tokens.
func TestPublicProviderVocabulariesAreClosed(t *testing.T) {
	algorithms := []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256, AlgorithmUnknown}
	if got := tokensFromAlgorithms(algorithms); !reflect.DeepEqual(got, []string{"rsa-sha256", "ed25519-sha256", "unknown"}) {
		t.Fatalf("algorithms = %v", got)
	}
	for _, algorithm := range algorithms {
		if !algorithm.Known() {
			t.Fatalf("Algorithm(%q).Known() = false", algorithm)
		}
	}
	if Algorithm("").Known() || Algorithm("future-secret-token").Known() {
		t.Fatal("zero or unknown algorithm reported known")
	}

	statuses := []PublicKeyStatus{PublicKeyStatusFound, PublicKeyStatusMissing, PublicKeyStatusInvalid, PublicKeyStatusAmbiguous, PublicKeyStatusRevoked, PublicKeyStatusUnsupportedKeyType, PublicKeyStatusAlgorithmMismatch}
	if got := tokensFromPublicKeyStatuses(statuses); !reflect.DeepEqual(got, []string{string(PublicKeyStatusFound), string(PublicKeyStatusMissing), string(PublicKeyStatusInvalid), string(PublicKeyStatusAmbiguous), string(PublicKeyStatusRevoked), string(PublicKeyStatusUnsupportedKeyType), string(PublicKeyStatusAlgorithmMismatch)}) {
		t.Fatalf("statuses = %v", got)
	}
	for _, status := range statuses {
		if !status.Known() {
			t.Fatalf("PublicKeyStatus(%q).Known() = false", status)
		}
	}
	if PublicKeyStatus("").Known() || PublicKeyStatus("future-secret-token").Known() {
		t.Fatal("zero or unknown public-key status reported known")
	}
}

// TestPublicKeyQueryUsesBoundedImmutableValues verifies the closed query shape.
func TestPublicKeyQueryUsesBoundedImmutableValues(t *testing.T) {
	query := newPublicKeyQuery(testSigningDomain, testSelector, AlgorithmRSASHA256)
	if query.SigningDomain() != testSigningDomain || query.Selector() != testSelector || query.Algorithm() != AlgorithmRSASHA256 {
		t.Fatalf("query accessors returned unexpected values")
	}
}

// TestPublicKeyResultsCloneExplicitKeyMaterial verifies provider ownership boundaries.
func TestPublicKeyResultsCloneExplicitKeyMaterial(t *testing.T) {
	rsaKey := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 1023), E: 65537}
	rsaResult := FoundRSAPublicKey(rsaKey)
	rsaKey.N.SetInt64(17)
	firstRSA, ok := rsaResult.RSAPublicKey()
	if !ok || firstRSA == nil || firstRSA.N.BitLen() != 1024 || firstRSA.E != 65537 {
		t.Fatal("RSA result did not retain an independent public-key clone")
	}
	firstRSA.N.SetInt64(19)
	secondRSA, ok := rsaResult.RSAPublicKey()
	if !ok || secondRSA.N.BitLen() != 1024 {
		t.Fatal("RSA accessor exposed mutable result storage")
	}
	if _, ok := rsaResult.Ed25519PublicKey(); ok {
		t.Fatal("RSA result also exposed Ed25519 material")
	}

	edKey := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range edKey {
		edKey[index] = byte(index)
	}
	edResult := FoundEd25519PublicKey(edKey)
	edKey[0] ^= 0xff
	firstEd, ok := edResult.Ed25519PublicKey()
	if !ok || len(firstEd) != ed25519.PublicKeySize || firstEd[0] == edKey[0] {
		t.Fatal("Ed25519 result did not retain an independent public-key clone")
	}
	firstEd[0] ^= 0xff
	secondEd, ok := edResult.Ed25519PublicKey()
	if !ok || firstEd[0] == secondEd[0] {
		t.Fatal("Ed25519 accessor exposed mutable result storage")
	}
	if _, ok := edResult.RSAPublicKey(); ok {
		t.Fatal("Ed25519 result also exposed RSA material")
	}
}

// TestNonFoundPublicKeyResultsCarryNoMaterial verifies closed non-success variants.
func TestNonFoundPublicKeyResultsCarryNoMaterial(t *testing.T) {
	tests := []struct {
		name   string
		result PublicKeyResult
		status PublicKeyStatus
	}{
		{name: "missing", result: MissingPublicKey(AlgorithmRSASHA256), status: PublicKeyStatusMissing},
		{name: testNameInvalid, result: InvalidPublicKey(AlgorithmRSASHA256), status: PublicKeyStatusInvalid},
		{name: testNameAmbiguous, result: AmbiguousPublicKey(AlgorithmRSASHA256), status: PublicKeyStatusAmbiguous},
		{name: testNameRevoked, result: RevokedPublicKey(AlgorithmRSASHA256), status: PublicKeyStatusRevoked},
		{name: testNameUnsupported, result: UnsupportedKeyTypePublicKey(AlgorithmRSASHA256), status: PublicKeyStatusUnsupportedKeyType},
		{name: testNameMismatch, result: AlgorithmMismatchPublicKey(AlgorithmRSASHA256), status: PublicKeyStatusAlgorithmMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.Status() != tt.status || tt.result.Algorithm() != AlgorithmRSASHA256 {
				t.Fatalf("result status/algorithm = %q/%q", tt.result.Status(), tt.result.Algorithm())
			}
			if _, ok := tt.result.RSAPublicKey(); ok {
				t.Fatal("non-found result exposed RSA material")
			}
			if _, ok := tt.result.Ed25519PublicKey(); ok {
				t.Fatal("non-found result exposed Ed25519 material")
			}
		})
	}
}

// TestPublicKeyResultCarriesImmutablePolicyMetadata verifies bounded DNS declarations.
func TestPublicKeyResultCarriesImmutablePolicyMetadata(t *testing.T) {
	metadata := newKeyPolicyMetadata(true, true)
	result := withKeyPolicyMetadata(RevokedPublicKey(AlgorithmRSASHA256), metadata)
	got := result.KeyPolicyMetadata()
	if !got.TestingDeclared() || !got.StrictIdentityDeclared() || got.StrictIdentityApplicable() {
		t.Fatalf("metadata = testing %v strict %v applicable %v", got.TestingDeclared(), got.StrictIdentityDeclared(), got.StrictIdentityApplicable())
	}
	if MissingPublicKey(AlgorithmRSASHA256).KeyPolicyMetadata().TestingDeclared() {
		t.Fatal("static missing result carried DNS policy metadata")
	}
}

// TestZeroPublicKeyResultIsNotSuccess verifies fail-closed zero-value behavior.
func TestZeroPublicKeyResultIsNotSuccess(t *testing.T) {
	var result PublicKeyResult
	if result.Status().Known() || result.Algorithm().Known() {
		t.Fatal("zero public-key result reported known success state")
	}
	if _, ok := result.RSAPublicKey(); ok {
		t.Fatal("zero public-key result exposed RSA material")
	}
	if _, ok := result.Ed25519PublicKey(); ok {
		t.Fatal("zero public-key result exposed Ed25519 material")
	}
}

// TestPublicProviderTypesContainNoOpenEndedMaterial verifies the result model has no interface slot.
func TestPublicProviderTypesContainNoOpenEndedMaterial(t *testing.T) {
	typeOfResult := reflect.TypeFor[PublicKeyResult]()
	for field := range typeOfResult.Fields() {
		if field.Type.Kind() == reflect.Interface {
			t.Fatalf("PublicKeyResult field %q is open-ended interface material", field.Name)
		}
	}

	providerType := reflect.TypeFor[PublicKeyProvider]()
	method, ok := providerType.MethodByName("LookupPublicKey")
	if !ok || method.Type.NumIn() != 2 || method.Type.In(0) != reflect.TypeFor[context.Context]() || method.Type.In(1) != reflect.TypeFor[PublicKeyQuery]() {
		t.Fatal("PublicKeyProvider has unexpected lookup signature")
	}
}

// tokensFromAlgorithms returns algorithm string values for exact-vocabulary assertions.
func tokensFromAlgorithms(values []Algorithm) []string {
	tokens := make([]string, len(values))
	for index, value := range values {
		tokens[index] = string(value)
	}

	return tokens
}

// tokensFromPublicKeyStatuses returns status string values for exact-vocabulary assertions.
func tokensFromPublicKeyStatuses(values []PublicKeyStatus) []string {
	tokens := make([]string, len(values))
	for index, value := range values {
		tokens[index] = string(value)
	}

	return tokens
}
