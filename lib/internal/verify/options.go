package verify

import (
	"slices"
	"time"
)

const (
	// DraftBaseline identifies the active DKIM2 verification draft.
	DraftBaseline = "draft-ietf-dkim-dkim2-spec-04"
	// AlgorithmRSASHA256 identifies RSA with SHA-256 and PKCS#1 v1.5 verification.
	AlgorithmRSASHA256 Algorithm = "rsa-sha256"
	// AlgorithmEd25519SHA256 identifies Ed25519 verification over SHA-256 digest bytes.
	AlgorithmEd25519SHA256 Algorithm = "ed25519-sha256"
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

// Algorithm identifies a safe DKIM2 signature algorithm token.
type Algorithm string

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
	// Clock supplies deterministic current time for timestamp checks.
	Clock Clock
}

// Option mutates verifier options before validation.
type Option func(*Options)

// Verifier owns validated verification dependencies and policies.
type Verifier struct {
	keyProvider KeyProvider
	options     Options
}

// AlgorithmPolicy contains fail-closed signature algorithm settings.
type AlgorithmPolicy struct {
	// AllowedAlgorithms lists enabled DKIM2 signature algorithms.
	AllowedAlgorithms []Algorithm
	// MinRSABits is the minimum accepted RSA public key size for verification.
	MinRSABits int
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
	// MaxSignatureSets bounds signature sets evaluated for one DKIM2-Signature.
	MaxSignatureSets int
	// MaxEnvelopeRecipients bounds current forward-path values in one request.
	MaxEnvelopeRecipients int
}

// DefaultOptions returns restrictive verifier defaults except for the injected key provider.
func DefaultOptions() Options {
	return Options{
		AlgorithmPolicy: DefaultAlgorithmPolicy(),
		TimestampPolicy: DefaultTimestampPolicy(),
		Limits:          DefaultLimits(),
		Clock:           systemClock,
	}
}

// DefaultAlgorithmPolicy returns the active M4 signature algorithm allowlist.
func DefaultAlgorithmPolicy() AlgorithmPolicy {
	return AlgorithmPolicy{
		AllowedAlgorithms: []Algorithm{AlgorithmRSASHA256, AlgorithmEd25519SHA256},
		MinRSABits:        defaultRSAMinBits,
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

// WithClock replaces the verifier clock.
func WithClock(clock Clock) Option {
	return func(options *Options) {
		options.Clock = clock
	}
}

// NewVerifier constructs a verifier with validated dependencies and policies.
func NewVerifier(provider KeyProvider, options ...Option) (Verifier, error) {
	if provider == nil {
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

	return Verifier{
		keyProvider: provider,
		options:     resolved.clone(),
	}, nil
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

	return nil
}

// Validate rejects unsafe signature algorithm policy settings.
func (p AlgorithmPolicy) Validate() error {
	if p.MinRSABits < defaultRSAMinBits {
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
	for _, allowed := range p.AllowedAlgorithms {
		if allowed == algorithm {
			return true
		}
	}

	return false
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

// knownAlgorithm reports whether algorithm is defined by the active M4 contract.
func knownAlgorithm(algorithm Algorithm) bool {
	switch algorithm {
	case AlgorithmRSASHA256, AlgorithmEd25519SHA256:
		return true
	default:
		return false
	}
}

// systemClock returns wall-clock time for default timestamp policy.
func systemClock() time.Time {
	return time.Now()
}
