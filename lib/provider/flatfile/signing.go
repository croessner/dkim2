// Package flatfile exposes the explicit flat-file signing provider adapter.
package flatfile

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/internal/datasource"
	datasourceflatfile "github.com/croessner/dkim2/internal/datasource/flatfile"
	"github.com/croessner/dkim2/internal/datasource/signingprofile"
)

const providerRedacted = "dkim2_flatfile_signing_provider{redacted}"

// PolicyUse identifies one closed flat-file signing-policy selection.
type PolicyUse string

const (
	// PolicyOriginator selects an originator signing policy.
	PolicyOriginator PolicyUse = "originator"
	// PolicyOrdinaryTransit selects an ordinary-transit signing policy.
	PolicyOrdinaryTransit PolicyUse = "ordinary_transit"
)

// Known reports whether the use is supported by the provider adapter.
func (u PolicyUse) Known() bool {
	return u == PolicyOriginator || u == PolicyOrdinaryTransit
}

// Binding is one opaque manifest-to-public-profile declaration.
type Binding struct {
	value signingprofile.Binding
}

// String returns a constant protected binding summary.
func (Binding) String() string { return providerRedacted }

// GoString returns a constant protected binding representation.
func (Binding) GoString() string { return providerRedacted }

// Format prevents formatting verbs from traversing binding state.
func (Binding) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, providerRedacted)
}

// MarshalJSON emits an empty object without selection or key facts.
func (Binding) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// NewBinding validates one exact key declaration against closed vocabularies.
func NewBinding(
	tenant string,
	domain string,
	use PolicyUse,
	handleID string,
	handle dkim2.PrivateKeyHandle,
	algorithm dkim2.Algorithm,
	publicDigest [sha256.Size]byte,
) (Binding, error) {
	projectedHandle, err := dkim2.ProjectedPrivateKeyHandle(handle)
	if err != nil || !use.Known() {
		return Binding{}, &Error{}
	}
	value, err := signingprofile.NewBinding(
		tenant, domain, string(use), handleID, projectedHandle,
		string(algorithm), publicDigest,
	)
	if err != nil {
		return Binding{}, &Error{}
	}
	return Binding{value: value}, nil
}

// Resolver is one opaque immutable flat-file profile projection.
type Resolver struct {
	resolver *signingprofile.Resolver
}

// Open decodes one descriptor-proven document and validates every key binding.
func Open(document []byte, bindings []Binding, at time.Time) (*Resolver, error) {
	snapshot, err := datasourceflatfile.Decode(
		1, document, datasource.DefaultLimits(),
	)
	if err != nil {
		return nil, &Error{}
	}
	internal := make([]signingprofile.Binding, len(bindings))
	for index := range bindings {
		internal[index] = bindings[index].value
	}
	resolver, err := signingprofile.NewResolver(snapshot, internal, at)
	if err != nil {
		return nil, &Error{}
	}
	return &Resolver{resolver: resolver}, nil
}

// ResolvePolicy resolves one exact administrative selection.
func (r *Resolver) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use PolicyUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	if r == nil || r.resolver == nil || ctx == nil || !use.Known() {
		return dkim2.SigningProfile{}, &Error{}
	}
	projected, err := r.resolver.ResolvePolicy(
		ctx, tenant, domain, string(use), at,
	)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return dkim2.SigningProfile{}, contextError
		}
		return dkim2.SigningProfile{}, classifyResolutionError(err)
	}
	return dkim2.NewProjectedSigningProfile(projected)
}

// classifyResolutionError projects the internal datasource taxonomy onto the
// public temporary-or-permanent provider boundary.
func classifyResolutionError(err error) error {
	switch datasource.ErrorCodeOf(err) {
	case datasource.ErrorCodeInvalidRequest,
		datasource.ErrorCodeNotFound,
		datasource.ErrorCodeAmbiguous,
		datasource.ErrorCodeInactive,
		datasource.ErrorCodeMalformedData,
		datasource.ErrorCodeLimitExceeded,
		datasource.ErrorCodeUnsupportedPlatform:
		return dkim2.NewPermanentProviderError()
	case datasource.ErrorCodeUnavailable,
		datasource.ErrorCodeCancelled,
		datasource.ErrorCodeDeadlineExceeded,
		datasource.ErrorCodeInternalInvariant:
		return dkim2.NewTemporaryProviderError()
	default:
		return dkim2.NewTemporaryProviderError()
	}
}

// Close releases the immutable provider projection.
func (r *Resolver) Close(ctx context.Context) error {
	if r == nil || r.resolver == nil {
		return nil
	}
	if err := r.resolver.Close(ctx); err != nil {
		return &Error{}
	}
	return nil
}

// String returns a constant protected resolver summary.
func (*Resolver) String() string { return providerRedacted }

// GoString returns a constant protected resolver representation.
func (*Resolver) GoString() string { return providerRedacted }

// Format prevents formatting verbs from traversing provider state.
func (*Resolver) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, providerRedacted)
}

// MarshalJSON emits an empty object without provider or binding facts.
func (*Resolver) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Error is the sole content-free provider failure.
type Error struct{}

// Error returns a constant secret-safe diagnostic.
func (*Error) Error() string { return "flat-file signing provider failure" }

// Is recognizes the closed provider failure class.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}
