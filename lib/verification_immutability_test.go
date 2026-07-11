package dkim2

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
	"sync"
	"testing"
	"time"
)

// TestPublicProviderKeysAreClonedBeforeUse proves post-handoff RSA and Ed25519 mutation isolation.
func TestPublicProviderKeysAreClonedBeforeUse(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	tests := []struct {
		name   string
		vector string
		build  func(chan<- struct{}, <-chan struct{}) (PublicKeyProvider, func())
	}{
		{
			name: "rsa", vector: goldenVectorRSAPass,
			build: func(handoff chan<- struct{}, mutated <-chan struct{}) (PublicKeyProvider, func()) {
				key := corpus.rsaKey(t)
				provider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
					result := FoundRSAPublicKey(key)
					close(handoff)
					<-mutated
					return result, nil
				})
				return provider, func() { key.N.SetInt64(3) }
			},
		},
		{
			name: "ed25519", vector: goldenVectorEd25519Pass,
			build: func(handoff chan<- struct{}, mutated <-chan struct{}) (PublicKeyProvider, func()) {
				key := corpus.edKey(t)
				provider := publicProviderFunc(func(context.Context, PublicKeyQuery) (PublicKeyResult, error) {
					result := FoundEd25519PublicKey(key)
					close(handoff)
					<-mutated
					return result, nil
				})
				return provider, func() { key[0] ^= 0xff }
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			handoff := make(chan struct{})
			mutated := make(chan struct{})
			provider, mutate := testCase.build(handoff, mutated)
			verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
			if err != nil {
				t.Fatal("immutability verifier construction failed")
			}
			vector := corpus.Vectors[testCase.vector]
			request := NewVerifyRequest(decodeGoldenBytes(t, vector.Raw), decodeGoldenBytes(t, vector.Reverse), decodeGoldenPaths(t, vector.Forward))
			go func() {
				<-handoff
				mutate()
				close(mutated)
			}()
			result, verifyErr := verifier.Verify(context.Background(), request)
			if verifyErr != nil || result.State() != ResultStatePASS {
				t.Fatal("provider-owned key mutation changed verification")
			}
		})
	}
}

// TestPublicVerifierConcurrentReuseWithFrozenKeys proves race-safe shared facade use.
func TestPublicVerifierConcurrentReuseWithFrozenKeys(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	provider := publicGoldenProvider{mode: goldenProviderKeys, rsa: cloneTestRSA(corpus.rsaKey(t)), ed: ed25519.PublicKey(append([]byte(nil), corpus.edKey(t)...))}
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("concurrent verifier construction failed")
	}
	vector := corpus.Vectors[goldenVectorRSAPass]
	request := NewVerifyRequest(decodeGoldenBytes(t, vector.Raw), decodeGoldenBytes(t, vector.Reverse), decodeGoldenPaths(t, vector.Forward))
	var group sync.WaitGroup
	for range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, verifyErr := verifier.Verify(context.Background(), request)
			if verifyErr != nil || result.State() != ResultStatePASS {
				t.Errorf("concurrent verification failed")
			}
		}()
	}
	group.Wait()
}

// TestPublicRequestConcurrentCallerMutation proves constructor-owned bytes are isolated under reuse.
func TestPublicRequestConcurrentCallerMutation(t *testing.T) {
	corpus := loadPublicGoldenCorpus(t)
	vector := corpus.Vectors[goldenVectorRSAPass]
	raw := decodeGoldenBytes(t, vector.Raw)
	reverse := decodeGoldenBytes(t, vector.Reverse)
	forward := decodeGoldenPaths(t, vector.Forward)
	request := NewVerifyRequest(raw, reverse, forward)
	provider := publicGoldenProvider{mode: goldenProviderKeys, rsa: corpus.rsaKey(t), ed: corpus.edKey(t)}
	verifier, err := NewVerifier(provider, WithVerificationClock(func() time.Time { return time.Unix(publicVectorClock, 0) }))
	if err != nil {
		t.Fatal("request immutability verifier construction failed")
	}
	start := make(chan struct{})
	mutated := make(chan struct{})
	go func() {
		<-start
		for index := range raw {
			raw[index] ^= 0xff
		}
		for index := range reverse {
			reverse[index] ^= 0xff
		}
		for _, path := range forward {
			for index := range path {
				path[index] ^= 0xff
			}
		}
		close(mutated)
	}()
	close(start)
	for range 16 {
		result, verifyErr := verifier.Verify(context.Background(), request)
		if verifyErr != nil || result.State() != ResultStatePASS {
			t.Fatal("caller-owned mutation changed immutable request")
		}
	}
	<-mutated
}

// cloneTestRSA clones synthetic RSA public material for isolated concurrent use.
func cloneTestRSA(key *rsa.PublicKey) *rsa.PublicKey {
	if key == nil || key.N == nil {
		return nil
	}
	return &rsa.PublicKey{N: new(big.Int).Set(key.N), E: key.E}
}
