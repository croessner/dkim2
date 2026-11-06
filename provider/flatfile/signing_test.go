package flatfile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/provider"
)

type privacyContract interface {
	fmt.Stringer
	fmt.GoStringer
	fmt.Formatter
	json.Marshaler
}

// requirePrivacyContract makes protected formatting and JSON behavior a
// compile-time obligation.
func requirePrivacyContract[T privacyContract]() {}

// TestProviderBoundaryFormattingIsContentFree proves zero and populated
// provider wrappers cannot be traversed by formatting or JSON encoding.
func TestProviderBoundaryFormattingIsContentFree(t *testing.T) {
	requirePrivacyContract[Binding]()
	requirePrivacyContract[*Resolver]()
	for name, value := range map[string]any{
		"binding":  Binding{},
		"resolver": &Resolver{},
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
				if got := fmt.Sprintf(format, value); got != providerRedacted {
					t.Fatalf("format %q produced %q", format, got)
				}
			}
			encoded, err := json.Marshal(value)
			if err != nil || !bytes.Equal(encoded, []byte("{}")) {
				t.Fatalf("json.Marshal() = %q, %v", encoded, err)
			}
		})
	}
}

// TestResolvePolicyPreservesPublicAndGranularFailureClasses proves the public
// compatibility projection and daemon datasource taxonomy coexist exactly.
func TestResolvePolicyPreservesPublicAndGranularFailureClasses(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	resolver := newClassificationResolver(t, at, at.Add(time.Hour))
	t.Cleanup(func() { _ = resolver.Close(context.Background()) })

	_, notFoundErr := resolver.ResolvePolicy(
		context.Background(), "other-tenant", "example.test", PolicyOriginator, at,
	)
	_, inactiveErr := resolver.ResolvePolicy(
		context.Background(), "tenant", "example.test", PolicyOriginator, at.Add(2*time.Hour),
	)
	malformedErr := classifyResolutionError(
		datasource.NewError(datasource.ErrorCodeMalformedData),
	)
	temporaryResolver := newClassificationResolver(t, at, at.Add(time.Hour))
	if err := temporaryResolver.Close(context.Background()); err != nil {
		t.Fatal("close temporary resolver")
	}
	_, temporaryErr := temporaryResolver.ResolvePolicy(
		context.Background(), "tenant", "example.test", PolicyOriginator, at,
	)

	for _, testCase := range []struct {
		name        string
		err         error
		wantCode    provider.ErrorCode
		wantClass   dkim2.ProviderErrorClass
		wantMessage string
	}{
		{
			name: "not found", err: notFoundErr,
			wantCode: provider.ErrorCodeNotFound, wantClass: dkim2.ProviderErrorClassPermanent,
			wantMessage: dkim2.NewPermanentProviderError().Error(),
		},
		{
			name: "inactive", err: inactiveErr,
			wantCode: provider.ErrorCodeInactive, wantClass: dkim2.ProviderErrorClassPermanent,
			wantMessage: dkim2.NewPermanentProviderError().Error(),
		},
		{
			name: "malformed", err: malformedErr,
			wantCode: provider.ErrorCodeMalformedData, wantClass: dkim2.ProviderErrorClassPermanent,
			wantMessage: dkim2.NewPermanentProviderError().Error(),
		},
		{
			name: "temporary", err: temporaryErr,
			wantCode: provider.ErrorCodeUnavailable, wantClass: dkim2.ProviderErrorClassTemporary,
			wantMessage: dkim2.NewTemporaryProviderError().Error(),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.err == nil || provider.ErrorCodeOf(testCase.err) != testCase.wantCode ||
				dkim2.ProviderErrorClassOf(testCase.err) != testCase.wantClass ||
				testCase.err.Error() != testCase.wantMessage {
				t.Fatalf(
					"classification code=%q public=%q error=%v",
					provider.ErrorCodeOf(testCase.err),
					dkim2.ProviderErrorClassOf(testCase.err),
					testCase.err,
				)
			}
		})
	}
}

// newClassificationResolver constructs one exact valid resolver whose profile
// becomes inactive at the supplied upper bound.
func newClassificationResolver(t *testing.T, at, notAfter time.Time) *Resolver {
	t.Helper()
	publicKey := ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
	publicKey[0] = 1
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal("marshal public key")
	}
	handle, err := dkim2.NewPrivateKeyHandle([]byte("handle"))
	if err != nil {
		t.Fatal("construct private-key handle")
	}
	digest := sha256.Sum256(spki)
	binding, err := NewBinding(
		"tenant", "example.test", PolicyOriginator, "handle", handle,
		dkim2.AlgorithmEd25519SHA256, digest,
	)
	if err != nil {
		t.Fatal("construct flat-file binding")
	}
	profile := map[string]any{
		"id": "profile", "domain": "example.test", "status": "active",
		"not_before": at.Add(-time.Hour).Format(time.RFC3339),
		"not_after":  notAfter.Format(time.RFC3339),
		"credentials": []any{map[string]any{
			"algorithm": "ed25519-sha256", "selector": "selector",
			"public_key_spki": base64.StdEncoding.EncodeToString(spki),
			"handle_id":       "handle",
		}},
	}
	document, err := json.Marshal(map[string]any{
		"version":  "dkim2-datasource-v1",
		"handles":  []any{map[string]any{"id": "handle"}},
		"profiles": []any{profile},
		"policies": []any{map[string]any{
			"tenant_id": "tenant", "domain": "example.test", "use": "originator",
			"profile_id": "profile", "status": "active", "rollout": "enforce",
			"compatibility": "strict",
		}},
	})
	if err != nil {
		t.Fatal("serialize flat-file document")
	}
	resolver, err := Open(document, []Binding{binding}, at)
	if err != nil {
		t.Fatal("open flat-file resolver")
	}
	return resolver
}
