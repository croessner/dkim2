package verify

import (
	"slices"
	"time"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/cryptodkim2"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/recipe"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	// DraftBaseline identifies the active DKIM2 verification draft.
	DraftBaseline = "draft-ietf-dkim-dkim2-spec-04"
	// AlgorithmRSASHA256 identifies RSA with SHA-256 and PKCS#1 v1.5 verification.
	AlgorithmRSASHA256 = signature.AlgorithmRSASHA256
	// AlgorithmEd25519SHA256 identifies Ed25519 verification over SHA-256 digest bytes.
	AlgorithmEd25519SHA256 = signature.AlgorithmEd25519SHA256
	// AlgorithmUnknown is the bounded result token for algorithms outside the active contract.
	AlgorithmUnknown Algorithm = "unknown"
)

const (
	defaultMaxSignatureSets      = 16
	defaultMaxEnvelopeRecipients = 2000
	defaultRSAMinBits            = 1024
	defaultFutureTolerance       = 5 * time.Minute
	defaultMaxSignatureAge       = 14 * 24 * time.Hour
)

// Algorithm aliases the signature owner's closed algorithm vocabulary.
type Algorithm = signature.Algorithm

// Clock returns the verification time used by timestamp policy.
type Clock func() time.Time

// Options contains validated verifier dependencies and local policies.
type Options struct {
	// AlgorithmPolicy controls known signature algorithms and RSA key size.
	AlgorithmPolicy AlgorithmPolicy
	// TimestampPolicy controls local timestamp acceptance windows.
	TimestampPolicy TimestampPolicy
	// Limits bounds verification result and request dimensions.
	Limits Limits
	// RevisionLimits bounds cumulative all-hop revision proof work.
	RevisionLimits RevisionLimits
	// Clock supplies deterministic current time for timestamp checks.
	Clock Clock
}

// Option mutates verifier options before validation.
type Option func(*Options)

// Verifier owns validated verification dependencies and policies.
type Verifier struct {
	keyProvider     KeyProvider
	options         Options
	history         HistoryCoordinator
	revisionHistory HistoryCoordinator
	revisionOwner   *revisionInstantOwner
}

// revisionInstantOwner gives copied Verifier values one stable opaque clock identity.
type revisionInstantOwner struct{ marker byte }

// AlgorithmPolicy contains fail-closed signature algorithm settings.
type AlgorithmPolicy struct {
	// AllowedAlgorithms lists enabled DKIM2 signature algorithms.
	AllowedAlgorithms []Algorithm
	// MinRSABits is the minimum accepted RSA public key size for verification.
	MinRSABits int
	// MaxRSABits is the narrowable maximum accepted RSA public key size.
	MaxRSABits int
}

// TimestampPolicy contains local timestamp validation settings.
type TimestampPolicy struct {
	// FutureTolerance permits small clock skew for future t= values.
	FutureTolerance time.Duration
	// MaxAge bounds stale t= values when positive; zero disables the age cap.
	MaxAge time.Duration
}

// Limits contains fail-closed verification resource settings.
type Limits struct {
	// MaxInstanceHashSets bounds h= sets parsed from one Message-Instance.
	MaxInstanceHashSets int
	// MaxSignatureSets bounds signature sets evaluated for one DKIM2-Signature.
	MaxSignatureSets int
	// MaxEnvelopeRecipients bounds current forward-path values in one request.
	MaxEnvelopeRecipients int
}

// RevisionLimits contains cumulative all-hop proof ceilings.
type RevisionLimits struct {
	// MaxProtocolFields bounds inherited Message-Instance and DKIM2-Signature fields.
	MaxProtocolFields int
	// MaxTotalSignatureSets bounds sets across all inherited signature fields.
	MaxTotalSignatureSets int
	// MaxPublicKeyLookups bounds supported inherited sets and provider calls.
	MaxPublicKeyLookups int
	// MaxCanonicalWorkBytes bounds aggregate Section 9.6 canonical input bytes.
	MaxCanonicalWorkBytes int
	// MaxSignatureInputBytes bounds one Section 9.6 canonical input.
	MaxSignatureInputBytes int
	// MaxDecodedRecipeBytes bounds each inherited decoded recipe.
	MaxDecodedRecipeBytes int
}

// DefaultOptions returns restrictive verifier defaults except for the injected key provider.
func DefaultOptions() Options {
	return Options{
		AlgorithmPolicy: DefaultAlgorithmPolicy(),
		TimestampPolicy: DefaultTimestampPolicy(),
		Limits:          DefaultLimits(),
		RevisionLimits:  DefaultRevisionLimits(),
		Clock:           systemClock,
	}
}

// DefaultRevisionLimits returns the signing-contract all-hop hard ceilings.
func DefaultRevisionLimits() RevisionLimits {
	return RevisionLimits{
		MaxProtocolFields: 256, MaxTotalSignatureSets: 256,
		MaxPublicKeyLookups: 256, MaxCanonicalWorkBytes: 64 * 1024 * 1024,
		MaxSignatureInputBytes: canonical.DefaultLimits().MaxSignatureInputBytes,
		MaxDecodedRecipeBytes:  recipe.DefaultLimits().MaxDecodedRecipeBytes,
	}
}

// DefaultAlgorithmPolicy returns the active signature algorithm allowlist.
func DefaultAlgorithmPolicy() AlgorithmPolicy {
	return AlgorithmPolicy{
		AllowedAlgorithms: []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256},
		MinRSABits:        defaultRSAMinBits,
		MaxRSABits:        cryptodkim2.DefaultLimits().MaxRSABits,
	}
}

// DefaultTimestampPolicy returns deterministic local timestamp defaults.
func DefaultTimestampPolicy() TimestampPolicy {
	return TimestampPolicy{
		FutureTolerance: defaultFutureTolerance,
		MaxAge:          defaultMaxSignatureAge,
	}
}

// DefaultLimits returns restrictive verification resource defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxInstanceHashSets:   defaultMaxSignatureSets,
		MaxSignatureSets:      defaultMaxSignatureSets,
		MaxEnvelopeRecipients: defaultMaxEnvelopeRecipients,
	}
}

// WithAlgorithmPolicy replaces verifier algorithm policy.
func WithAlgorithmPolicy(policy AlgorithmPolicy) Option {
	return func(options *Options) {
		options.AlgorithmPolicy = policy
	}
}

// WithTimestampPolicy replaces verifier timestamp policy.
func WithTimestampPolicy(policy TimestampPolicy) Option {
	return func(options *Options) {
		options.TimestampPolicy = policy
	}
}

// WithLimits replaces verifier resource limits.
func WithLimits(limits Limits) Option {
	return func(options *Options) {
		options.Limits = limits
	}
}

// WithRevisionLimits replaces cumulative all-hop proof ceilings.
func WithRevisionLimits(limits RevisionLimits) Option {
	return func(options *Options) {
		options.RevisionLimits = limits
	}
}

// WithClock replaces the verifier clock.
func WithClock(clock Clock) Option {
	return func(options *Options) {
		options.Clock = clock
	}
}

// NewVerifier constructs a verifier with validated dependencies and policies.
func NewVerifier(provider KeyProvider, options ...Option) (Verifier, error) {
	if nilKeyProvider(provider) {
		return Verifier{}, invalidOptionError("key_provider", 0)
	}

	resolved := DefaultOptions()
	for _, option := range options {
		if option != nil {
			option(&resolved)
		}
	}
	if err := resolved.Validate(); err != nil {
		return Verifier{}, err
	}
	recipeLimits := recipe.DefaultLimits()
	recipeLimits.MaxDecodedRecipeBytes = resolved.RevisionLimits.MaxDecodedRecipeBytes
	recipeLimits.MaxTotalLiteralBytes = min(
		recipeLimits.MaxTotalLiteralBytes, recipeLimits.MaxDecodedRecipeBytes,
	)
	recipeLimits.MaxDataStringBytes = min(
		recipeLimits.MaxDataStringBytes, recipeLimits.MaxTotalLiteralBytes,
	)
	revisionParser, err := recipe.NewParser(recipeLimits)
	if err != nil {
		return Verifier{}, invalidOptionError("history_parser", 0)
	}
	applier, err := recipe.NewApplier(recipe.Limits{})
	if err != nil {
		return Verifier{}, invalidOptionError("history_applier", 0)
	}
	canonicalizer, err := canonical.NewCanonicalizer()
	if err != nil {
		return Verifier{}, invalidOptionError("history_canonicalizer", 0)
	}
	parser, err := recipe.NewParser(recipe.Limits{})
	if err != nil {
		return Verifier{}, invalidOptionError("history_parser", 0)
	}
	history, err := NewHistoryCoordinator(parser, applier, canonicalizer, HistoryLimits{})
	if err != nil {
		return Verifier{}, invalidOptionError("history_coordinator", 0)
	}
	revisionHistory, err := NewHistoryCoordinator(revisionParser, applier, canonicalizer, HistoryLimits{})
	if err != nil {
		return Verifier{}, invalidOptionError("revision_history_coordinator", 0)
	}

	return Verifier{
		keyProvider:     provider,
		options:         resolved.clone(),
		history:         history,
		revisionHistory: revisionHistory,
		revisionOwner:   &revisionInstantOwner{marker: 1},
	}, nil
}

// nilKeyProvider reports nil and typed-nil key-provider dependencies without invoking them.
func nilKeyProvider(provider KeyProvider) bool {
	return niliface.IsNil(provider)
}

// Validate rejects unsafe verifier options before verification begins.
func (o Options) Validate() error {
	if o.Clock == nil {
		return invalidOptionError("clock", 0)
	}
	if err := o.AlgorithmPolicy.Validate(); err != nil {
		return err
	}
	if err := o.TimestampPolicy.Validate(); err != nil {
		return err
	}
	if err := o.Limits.Validate(); err != nil {
		return err
	}
	if err := o.RevisionLimits.Validate(); err != nil {
		return err
	}

	return nil
}

// Validate rejects nonpositive or widened all-hop proof ceilings.
func (l RevisionLimits) Validate() error {
	hard := DefaultRevisionLimits()
	values := []struct {
		name string
		got  int
		max  int
	}{
		{"max_protocol_fields", l.MaxProtocolFields, hard.MaxProtocolFields},
		{"max_total_signature_sets", l.MaxTotalSignatureSets, hard.MaxTotalSignatureSets},
		{"max_public_key_lookups", l.MaxPublicKeyLookups, hard.MaxPublicKeyLookups},
		{"max_canonical_work_bytes", l.MaxCanonicalWorkBytes, hard.MaxCanonicalWorkBytes},
		{"max_signature_input_bytes", l.MaxSignatureInputBytes, hard.MaxSignatureInputBytes},
		{"max_decoded_recipe_bytes", l.MaxDecodedRecipeBytes, hard.MaxDecodedRecipeBytes},
	}
	for _, value := range values {
		if value.got <= 0 || value.got > value.max {
			return invalidOptionError(value.name, value.got)
		}
	}
	if l.MaxPublicKeyLookups > l.MaxTotalSignatureSets {
		return invalidOptionError("max_public_key_lookups", l.MaxPublicKeyLookups)
	}
	return nil
}

// Validate rejects unsafe signature algorithm policy settings.
func (p AlgorithmPolicy) Validate() error {
	if p.MinRSABits < defaultRSAMinBits || p.MaxRSABits > cryptodkim2.DefaultLimits().MaxRSABits ||
		p.MaxRSABits < p.MinRSABits {
		return invalidOptionError("rsa_min_bits", p.MinRSABits)
	}
	if len(p.AllowedAlgorithms) == 0 {
		return invalidOptionError("allowed_algorithms", 0)
	}

	seen := make(map[Algorithm]struct{}, len(p.AllowedAlgorithms))
	for _, algorithm := range p.AllowedAlgorithms {
		if !knownAlgorithm(algorithm) {
			return unsupportedAlgorithmError(algorithm)
		}
		if _, exists := seen[algorithm]; exists {
			return invalidOptionError("allowed_algorithms", len(p.AllowedAlgorithms))
		}
		seen[algorithm] = struct{}{}
	}

	return nil
}

// Allows reports whether algorithm is enabled by the policy.
func (p AlgorithmPolicy) Allows(algorithm Algorithm) bool {
	return slices.Contains(p.AllowedAlgorithms, algorithm)
}

// Algorithms returns the enabled signature algorithms as an immutable copy.
func (p AlgorithmPolicy) Algorithms() []Algorithm {
	return slices.Clone(p.AllowedAlgorithms)
}

// Validate rejects unsafe timestamp policy settings.
func (p TimestampPolicy) Validate() error {
	if p.FutureTolerance < 0 {
		return invalidOptionError("future_tolerance", int(p.FutureTolerance))
	}
	if p.MaxAge < 0 {
		return invalidOptionError("max_age", int(p.MaxAge))
	}

	return nil
}

// Validate rejects unsafe verification limit settings.
func (l Limits) Validate() error {
	switch {
	case l.MaxInstanceHashSets <= 0:
		return invalidOptionError("max_instance_hash_sets", l.MaxInstanceHashSets)
	case l.MaxSignatureSets <= 0:
		return invalidOptionError("max_signature_sets", l.MaxSignatureSets)
	case l.MaxEnvelopeRecipients <= 0:
		return invalidOptionError("max_envelope_recipients", l.MaxEnvelopeRecipients)
	default:
		return nil
	}
}

// Options returns a copy of the verifier policies.
func (v Verifier) Options() Options {
	return v.options.clone()
}

// KeyProvider returns the injected static key provider boundary.
func (v Verifier) KeyProvider() KeyProvider {
	return v.keyProvider
}

// Now returns the clock's current time.
func (c Clock) Now() time.Time {
	return c()
}

// clone returns a deep copy of option slices.
func (o Options) clone() Options {
	o.AlgorithmPolicy.AllowedAlgorithms = slices.Clone(o.AlgorithmPolicy.AllowedAlgorithms)

	return o
}

// knownAlgorithm reports whether algorithm is defined by the active verification contract.
func knownAlgorithm(algorithm Algorithm) bool {
	return algorithm.Known()
}

// systemClock returns wall-clock time for default timestamp policy.
func systemClock() time.Time {
	return time.Now()
}
