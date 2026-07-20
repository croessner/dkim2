package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/provider"
	"github.com/croessner/dkim2/internal/verify"
)

type publicationProviderFunc func(context.Context, verify.KeyQuery) (verify.PublicKey, error)

// LookupKey delegates one publication test lookup.
func (f publicationProviderFunc) LookupKey(ctx context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
	return f(ctx, query)
}

// TestProfileCanonicalizesCredentialOrderAndRejectsDuplicates proves immutable profile ownership.
func TestProfileCanonicalizesCredentialOrderAndRejectsDuplicates(t *testing.T) {
	edCredential, _ := testEd25519Credential(t, "profile-ed")
	// A second Ed25519 credential proves duplicate algorithm rejection.
	other, _ := testEd25519Credential(t, "profile-other")
	if _, err := NewProfile("example.test", []Credential{edCredential, other}); err == nil {
		t.Fatal("duplicate profile algorithm accepted")
	}
	profile, err := NewProfile("EXAMPLE.TEST", []Credential{edCredential})
	if err != nil || !profile.Valid() || profile.Domain() != "example.test" {
		t.Fatalf("NewProfile() domain=%q valid=%t error=%v", profile.Domain(), profile.Valid(), err)
	}
	got := profile.Credentials()
	got[0].publicKey.(ed25519.PublicKey)[0] ^= 1
	if !profile.Valid() {
		t.Fatal("profile accessor retained public-key alias")
	}
	if handle, err := NewPrivateKeyHandle(make([]byte, maxPrivateKeyHandleIdentityBytes+1)); !IsErrorCode(err, ErrorCodeInvalidRequest) || handle.Valid() {
		t.Fatalf("one-over private handle valid=%t error=%v", handle.Valid(), err)
	}
}

// TestPublicationCapabilityIsFreshSingleUseAndDetectsDrift proves exact revalidation.
func TestPublicationCapabilityIsFreshSingleUseAndDetectsDrift(t *testing.T) {
	credential, public := testEd25519Credential(t, "publication")
	now := time.Unix(1_700_000_000, 0)
	current := append(ed25519.PublicKey(nil), public...)
	var calls atomic.Int32
	providerFunc := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		calls.Add(1)
		return verify.PublicKey{
			Algorithm: query.Algorithm, Material: append(ed25519.PublicKey(nil), current...),
			Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound, Source: "test"},
		}, nil
	})
	var seal [sha256.Size]byte
	seal[0] = 1
	authority, err := newPublicationAuthority(providerFunc, func() time.Time { return now }, time.Minute, seal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("NewPublicationAuthority() error = %v", err)
	}
	capability, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil || !capability.Valid() || calls.Load() != 1 {
		t.Fatalf("IssueNextDomain() valid=%t calls=%d error=%v", capability.Valid(), calls.Load(), err)
	}
	if err := authority.ConsumeAndRevalidate(context.Background(), capability); err != nil || calls.Load() != 2 {
		t.Fatalf("ConsumeAndRevalidate() calls=%d error=%v", calls.Load(), err)
	}
	if err := authority.ConsumeAndRevalidate(context.Background(), capability); !IsErrorCode(err, ErrorCodeCapabilityMismatch) || calls.Load() != 2 {
		t.Fatalf("reused capability calls=%d error=%v", calls.Load(), err)
	}

	fresh, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil {
		t.Fatalf("fresh issuance error = %v", err)
	}
	current[0] ^= 1
	if err := authority.ConsumeAndRevalidate(context.Background(), fresh); !IsErrorCode(err, ErrorCodeKeyMismatch) {
		t.Fatalf("publication drift error = %v", err)
	}
}

// TestPublicationRejectsExpiryMissingAndTypedProviderFailures proves fail-closed states.
func TestPublicationRejectsExpiryMissingAndTypedProviderFailures(t *testing.T) {
	credential, public := testEd25519Credential(t, "publication-errors")
	now := time.Unix(1_700_000_000, 0)
	mode := "found"
	providerFunc := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		switch mode {
		case "temporary":
			return verify.PublicKey{}, provider.NewFailure(provider.FailureTemporary)
		case "missing":
			return verify.PublicKey{Algorithm: query.Algorithm, Metadata: verify.KeyMetadata{Status: verify.KeyStatusMissing}}, nil
		case "revoked":
			return verify.PublicKey{Algorithm: query.Algorithm, Metadata: verify.KeyMetadata{Status: verify.KeyStatusRevoked}}, nil
		case "ambiguous":
			return verify.PublicKey{Algorithm: query.Algorithm, Metadata: verify.KeyMetadata{Status: verify.KeyStatusAmbiguous}}, nil
		default:
			return verify.PublicKey{Algorithm: query.Algorithm, Material: public, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
		}
	})
	var seal [sha256.Size]byte
	seal[0] = 2
	authority, err := newPublicationAuthority(providerFunc, func() time.Time { return now }, time.Minute, seal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("NewPublicationAuthority() error = %v", err)
	}
	capability, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil {
		t.Fatalf("IssueNextDomain() error = %v", err)
	}
	now = now.Add(time.Minute)
	if err := authority.ConsumeAndRevalidate(context.Background(), capability); !IsErrorCode(err, ErrorCodeCapabilityMismatch) {
		t.Fatalf("expired capability error = %v", err)
	}
	mode = "missing"
	if _, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential); !IsErrorCode(err, ErrorCodeKeyMismatch) {
		t.Fatalf("missing publication error = %v", err)
	}
	mode = "temporary"
	if _, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential); !IsErrorCode(err, ErrorCodeCallbackTemporary) {
		t.Fatalf("temporary publication error = %v", err)
	}
	for _, rejected := range []string{"revoked", "ambiguous"} {
		mode = rejected
		if _, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential); !IsErrorCode(err, ErrorCodeKeyMismatch) {
			t.Fatalf("%s publication error = %v", rejected, err)
		}
	}
}

// TestPublicationProviderMatrixRejectsResultErrorAndTypedNilPairs proves exact callback contracts.
func TestPublicationProviderMatrixRejectsResultErrorAndTypedNilPairs(t *testing.T) {
	credential, public := testEd25519Credential(t, "publication-matrix")
	var seal [sha256.Size]byte
	seal[0] = 4
	tests := []struct {
		name string
		fn   publicationProviderFunc
		code ErrorCode
	}{
		{name: "result plus typed error", fn: func(_ context.Context, q verify.KeyQuery) (verify.PublicKey, error) {
			return verify.PublicKey{Algorithm: q.Algorithm, Material: public, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}},
				provider.NewFailure(provider.FailureTemporary)
		}, code: ErrorCodeInternalInvariant},
		{name: "nonzero missing plus raw error", fn: func(_ context.Context, q verify.KeyQuery) (verify.PublicKey, error) {
			return verify.PublicKey{Algorithm: q.Algorithm, Metadata: verify.KeyMetadata{Status: verify.KeyStatusMissing}},
				fmt.Errorf("SECRET raw provider")
		}, code: ErrorCodeInternalInvariant},
		{name: "typed nil error", fn: func(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
			var typedNil *publicationTestError
			return verify.PublicKey{}, typedNil
		}, code: ErrorCodeInternalInvariant},
		{name: "missing with disallowed policy", fn: func(_ context.Context, q verify.KeyQuery) (verify.PublicKey, error) {
			return verify.PublicKey{Algorithm: q.Algorithm, Metadata: verify.KeyMetadata{
				Status: verify.KeyStatusMissing, Policy: verify.KeyPolicyMetadata{TestingDeclared: true},
			}}, nil
		}, code: ErrorCodeInternalInvariant},
		{name: "oversized provider source", fn: func(_ context.Context, q verify.KeyQuery) (verify.PublicKey, error) {
			return verify.PublicKey{Algorithm: q.Algorithm, Material: public, Metadata: verify.KeyMetadata{
				Status: verify.KeyStatusFound, Source: strings.Repeat("a", 65),
			}}, nil
		}, code: ErrorCodeInternalInvariant},
		{name: "unsafe provider source", fn: func(_ context.Context, q verify.KeyQuery) (verify.PublicKey, error) {
			return verify.PublicKey{Algorithm: q.Algorithm, Material: public, Metadata: verify.KeyMetadata{
				Status: verify.KeyStatusFound, Source: "unsafe/source",
			}}, nil
		}, code: ErrorCodeInternalInvariant},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authority, err := newPublicationAuthority(test.fn, func() time.Time {
				return time.Unix(1_700_000_000, 0)
			}, time.Minute, seal, maxConsumedPublicationCapabilities)
			if err != nil {
				t.Fatalf("newPublicationAuthority() error = %v", err)
			}
			if _, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential); !IsErrorCode(err, test.code) {
				t.Fatalf("IssueNextDomain() error = %v, want %q", err, test.code)
			}
		})
	}
	var nilProvider *publicationNilProvider
	if _, err := NewPublicationAuthority(nilProvider, time.Now, time.Minute); !IsErrorCode(err, ErrorCodeInvalidOptions) {
		t.Fatalf("typed-nil provider constructor error = %v", err)
	}
}

// TestPublicationPreCanceledConsumePreservesCapability proves local cancellation cannot spend evidence.
func TestPublicationPreCanceledConsumePreservesCapability(t *testing.T) {
	credential, public := testEd25519Credential(t, "publication-pre-cancel")
	var calls atomic.Int32
	providerFunc := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		calls.Add(1)
		return verify.PublicKey{Algorithm: query.Algorithm, Material: public, Metadata: verify.KeyMetadata{
			Status: verify.KeyStatusFound, Source: strings.Repeat("a", 64),
		}}, nil
	})
	var seal [sha256.Size]byte
	seal[0] = 10
	authority, err := newPublicationAuthority(providerFunc, func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}, time.Minute, seal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("newPublicationAuthority() error = %v", err)
	}
	capability, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil || calls.Load() != 1 {
		t.Fatalf("IssueNextDomain() calls=%d error=%v", calls.Load(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := authority.ConsumeAndRevalidate(ctx, capability); !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("pre-canceled consume calls=%d error=%v", calls.Load(), err)
	}
	if err := authority.ConsumeAndRevalidate(context.Background(), capability); err != nil || calls.Load() != 2 {
		t.Fatalf("retry consume calls=%d error=%v", calls.Load(), err)
	}
}

// TestPublicationCancellationCannotMaskMalformedProviderPairs proves context follows matrix validation.
func TestPublicationCancellationCannotMaskMalformedProviderPairs(t *testing.T) {
	credential, _ := testEd25519Credential(t, "publication-cancel-matrix")
	var seal [sha256.Size]byte
	seal[0] = 6
	ctx, cancel := context.WithCancel(context.Background())
	providerFunc := publicationProviderFunc(func(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
		cancel()
		return verify.PublicKey{}, nil
	})
	authority, err := newPublicationAuthority(providerFunc, func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}, time.Minute, seal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("newPublicationAuthority() error = %v", err)
	}
	if _, err := authority.IssueNextDomain(ctx, "next.example.test", credential); !IsErrorCode(err, ErrorCodeInternalInvariant) {
		t.Fatalf("malformed provider pair hidden by cancellation: %v", err)
	}
}

// TestPublicationEntropyPreflightsAndSealsRejectForgery proves local failure ordering and issuer binding.
func TestPublicationEntropyPreflightsAndSealsRejectForgery(t *testing.T) {
	credential, public := testEd25519Credential(t, "publication-seal")
	var calls atomic.Int32
	providerFunc := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		calls.Add(1)
		return verify.PublicKey{Algorithm: query.Algorithm, Material: public, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
	})
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	var firstSeal, secondSeal [sha256.Size]byte
	firstSeal[0], secondSeal[0] = 7, 8
	noEntropy, err := newPublicationAuthorityWithEntropy(providerFunc, now, strings.NewReader(""), time.Minute, firstSeal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("entropy authority constructor error = %v", err)
	}
	if capability, err := noEntropy.IssueNextDomain(context.Background(), "next.example.test", credential); !IsErrorCode(err, ErrorCodeInternalInvariant) || capability.Valid() || calls.Load() != 0 {
		t.Fatalf("entropy failure valid=%t calls=%d error=%v", capability.Valid(), calls.Load(), err)
	}
	first, _ := newPublicationAuthority(providerFunc, now, time.Minute, firstSeal, maxConsumedPublicationCapabilities)
	second, _ := newPublicationAuthority(providerFunc, now, time.Minute, secondSeal, maxConsumedPublicationCapabilities)
	capability, err := first.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil {
		t.Fatalf("IssueNextDomain() error = %v", err)
	}
	before := calls.Load()
	if err := second.ConsumeAndRevalidate(context.Background(), capability); !IsErrorCode(err, ErrorCodeCapabilityMismatch) || calls.Load() != before {
		t.Fatalf("cross-issuer consume calls=%d/%d error=%v", calls.Load(), before, err)
	}
	forged := capability
	forged.seal[0] ^= 1
	if err := first.ConsumeAndRevalidate(context.Background(), forged); !IsErrorCode(err, ErrorCodeCapabilityMismatch) || calls.Load() != before {
		t.Fatalf("bit-flipped consume calls=%d/%d error=%v", calls.Load(), before, err)
	}
}

type publicationTestError struct{}

// Error implements one typed-nil test error.
func (*publicationTestError) Error() string { return "SECRET typed nil" }

type publicationNilProvider struct{}

// LookupKey exists only to construct a typed-nil provider.
func (*publicationNilProvider) LookupKey(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
	return verify.PublicKey{}, nil
}

// TestPublicationFailureConsumesCapabilityAndClockOverflowPreflights proves single-use rejection semantics.
func TestPublicationFailureConsumesCapabilityAndClockOverflowPreflights(t *testing.T) {
	credential, public := testEd25519Credential(t, "publication-consume")
	now := time.Unix(1_700_000_000, 0)
	current := append(ed25519.PublicKey(nil), public...)
	var calls atomic.Int32
	providerFunc := publicationProviderFunc(func(_ context.Context, q verify.KeyQuery) (verify.PublicKey, error) {
		calls.Add(1)
		return verify.PublicKey{Algorithm: q.Algorithm, Material: append(ed25519.PublicKey(nil), current...),
			Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
	})
	var seal [sha256.Size]byte
	seal[0] = 5
	authority, err := newPublicationAuthority(providerFunc, func() time.Time { return now }, time.Minute, seal, 2)
	if err != nil {
		t.Fatalf("newPublicationAuthority() error = %v", err)
	}
	capability, err := authority.IssueNextDomain(context.Background(), "next.example.test", credential)
	if err != nil {
		t.Fatalf("IssueNextDomain() error = %v", err)
	}
	current[0] ^= 1
	if err := authority.ConsumeAndRevalidate(context.Background(), capability); !IsErrorCode(err, ErrorCodeKeyMismatch) {
		t.Fatalf("drift error = %v", err)
	}
	current[0] ^= 1
	before := calls.Load()
	if err := authority.ConsumeAndRevalidate(context.Background(), capability); !IsErrorCode(err, ErrorCodeCapabilityMismatch) || calls.Load() != before {
		t.Fatalf("retry after failed consume calls=%d/%d error=%v", calls.Load(), before, err)
	}

	overflowCalls := atomic.Int32{}
	overflowProvider := publicationProviderFunc(func(context.Context, verify.KeyQuery) (verify.PublicKey, error) {
		overflowCalls.Add(1)
		return verify.PublicKey{}, nil
	})
	overflow, err := newPublicationAuthority(overflowProvider, func() time.Time {
		return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	}, time.Minute, seal, 2)
	if err != nil {
		t.Fatalf("overflow authority constructor error = %v", err)
	}
	if _, err := overflow.IssueNextDomain(context.Background(), "next.example.test", credential); !IsErrorCode(err, ErrorCodeInternalInvariant) || overflowCalls.Load() != 0 {
		t.Fatalf("overflow issuance calls=%d error=%v", overflowCalls.Load(), err)
	}
}

// TestPublicationFormattingAndProviderAliasesRemainSecretSafe proves privacy and cloning.
func TestPublicationFormattingAndProviderAliasesRemainSecretSafe(t *testing.T) {
	credential, public := testEd25519Credential(t, "SECRET-publication")
	providerFunc := publicationProviderFunc(func(_ context.Context, query verify.KeyQuery) (verify.PublicKey, error) {
		return verify.PublicKey{Algorithm: query.Algorithm, Material: public, Metadata: verify.KeyMetadata{Status: verify.KeyStatusFound}}, nil
	})
	var seal [sha256.Size]byte
	seal[0] = 3
	authority, err := newPublicationAuthority(providerFunc, func() time.Time { return time.Unix(1_700_000_000, 0) }, time.Minute, seal, maxConsumedPublicationCapabilities)
	if err != nil {
		t.Fatalf("NewPublicationAuthority() error = %v", err)
	}
	capability, err := authority.IssueNextDomain(context.Background(), "secret.example.test", credential)
	if err != nil {
		t.Fatalf("IssueNextDomain() error = %v", err)
	}
	public[0] ^= 1
	formatted := fmt.Sprintf("%v %+v %#v %v %+v %#v", capability, capability, capability, authority, authority, authority)
	if strings.Contains(formatted, "secret") || !strings.Contains(formatted, "redacted") {
		t.Fatalf("unsafe capability formatting %q", formatted)
	}
}
