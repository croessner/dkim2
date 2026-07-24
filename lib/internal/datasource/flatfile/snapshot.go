package flatfile

import (
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/memory"
	"github.com/croessner/dkim2/internal/niliface"
)

var _ datasource.Provider = (*Snapshot)(nil)

// Snapshot owns one immutable decoded provider and its parser accounting.
type Snapshot struct {
	provider      *memory.Provider
	providerOwner *memory.Provider
	usage         datasource.Usage
	providerUsage datasource.Usage
	parserBytes   int
	generation    uint64
	limits        datasource.Limits
	complete      bool
}

// newSnapshot binds one validated provider to exact parser accounting.
func newSnapshot(
	provider *memory.Provider,
	generation uint64,
	decodedStringBytes int,
	limits datasource.Limits,
) (*Snapshot, error) {
	if provider == nil || generation == 0 ||
		limits.Validate() != nil || decodedStringBytes < 0 {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	providerUsage, err := provider.Usage()
	if err != nil {
		return nil, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	usage, err := datasource.NewUsage(
		providerUsage.Profiles(),
		providerUsage.Credentials(),
		providerUsage.Handles(),
		providerUsage.Policies(),
		decodedStringBytes,
		limits,
	)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		provider: provider, providerOwner: provider,
		usage: usage, providerUsage: providerUsage,
		parserBytes: decodedStringBytes, generation: generation,
		limits: limits, complete: true,
	}, nil
}

// Valid reports whether the decoded snapshot and accounting remain consistent.
func (s *Snapshot) Valid() bool {
	if !s.operational() || !s.provider.Valid() {
		return false
	}
	providerUsage, err := s.provider.Usage()
	return err == nil && providerUsage == s.providerUsage
}

// Usage returns bounded counts and aggregate decoded JSON string bytes.
func (s *Snapshot) Usage() (datasource.Usage, error) {
	if !s.Valid() {
		return datasource.Usage{}, datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return s.usage, nil
}

// ResolveProfile delegates one exact lookup to the immutable decoded provider.
func (s *Snapshot) ResolveProfile(
	ctx context.Context,
	request datasource.ProfileRequest,
) (datasource.ResolvedProfile, error) {
	if err := s.preflight(ctx); err != nil {
		return datasource.ResolvedProfile{}, err
	}
	return s.provider.ResolveProfile(ctx, request)
}

// ResolvePolicy delegates one exact lookup to the immutable decoded provider.
func (s *Snapshot) ResolvePolicy(
	ctx context.Context,
	request datasource.PolicyRequest,
) (datasource.ResolvedPolicy, error) {
	if err := s.preflight(ctx); err != nil {
		return datasource.ResolvedPolicy{}, err
	}
	return s.provider.ResolvePolicy(ctx, request)
}

// String returns a constant protected snapshot summary.
func (s *Snapshot) String() string { return "flatfile.Snapshot{redacted}" }

// GoString returns a constant protected snapshot representation.
func (s *Snapshot) GoString() string { return s.String() }

// Format prevents formatting verbs from exposing decoded provider facts.
func (s *Snapshot) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, s.String())
}

// MarshalJSON emits an empty object so decoded facts cannot be serialized.
func (s *Snapshot) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// operational performs constant-time wrapper integrity checks.
func (s *Snapshot) operational() bool {
	return s != nil && s.complete && s.provider != nil &&
		s.provider == s.providerOwner &&
		s.limits.Validate() == nil && s.usage.ValidForLimits(s.limits) &&
		s.providerUsage.ValidForLimits(s.limits) &&
		s.providerUsage.Bytes() == 0 &&
		s.generation != 0 &&
		s.parserBytes >= 0 && s.usage.Bytes() == s.parserBytes &&
		s.usage.Profiles() == s.providerUsage.Profiles() &&
		s.usage.Credentials() == s.providerUsage.Credentials() &&
		s.usage.Handles() == s.providerUsage.Handles() &&
		s.usage.Policies() == s.providerUsage.Policies() &&
		s.usage.Records() == s.providerUsage.Records()
}

// preflight preserves context-first failure and constant-time snapshot checks.
func (s *Snapshot) preflight(ctx context.Context) error {
	if niliface.IsNil(ctx) {
		return datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	if err := datasource.ErrorFromContext(ctx); err != nil {
		return err
	}
	if !s.operational() {
		return datasource.NewError(datasource.ErrorCodeInternalInvariant)
	}
	return nil
}
