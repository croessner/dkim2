package canonical

const (
	// DraftBaseline identifies the active DKIM2 canonicalization draft.
	DraftBaseline = "draft-ietf-dkim-dkim2-spec-04"
	// HashAlgorithmSHA256 identifies the mandatory baseline message hash.
	HashAlgorithmSHA256 HashAlgorithm = "sha256"
)

// Kind identifies one DKIM2 canonicalization byte stream.
type Kind string

const (
	// KindBodyHashInput identifies Section 6.1 body hash input.
	KindBodyHashInput Kind = "body_hash_input"
	// KindHeaderHashInput identifies Section 6.2 header hash input.
	KindHeaderHashInput Kind = "header_hash_input"
	// KindSignatureInput identifies Section 9.6 signature input.
	KindSignatureInput Kind = "signature_input"
)

// HashAlgorithm identifies a safe canonicalization hash algorithm name.
type HashAlgorithm string

// Options contains domain-named canonicalization settings.
type Options struct {
	// Limits bounds canonical byte builders and debug metadata.
	Limits Limits
	// HashAlgorithm selects the supported canonicalization digest algorithm.
	HashAlgorithm HashAlgorithm
}

// Option mutates canonicalization options before validation.
type Option func(*Options)

// Canonicalizer carries validated options for canonical byte builders.
type Canonicalizer struct {
	options Options
}

// DefaultOptions returns fail-closed canonicalization defaults.
func DefaultOptions() Options {
	return Options{
		Limits:        DefaultLimits(),
		HashAlgorithm: HashAlgorithmSHA256,
	}
}

// WithLimits replaces canonicalization resource limits.
func WithLimits(limits Limits) Option {
	return func(options *Options) {
		options.Limits = limits
	}
}

// WithHashAlgorithm replaces the canonicalization digest algorithm.
func WithHashAlgorithm(algorithm HashAlgorithm) Option {
	return func(options *Options) {
		options.HashAlgorithm = algorithm
	}
}

// NewCanonicalizer constructs a canonicalizer with validated options.
func NewCanonicalizer(options ...Option) (Canonicalizer, error) {
	resolved := DefaultOptions()
	for _, option := range options {
		if option != nil {
			option(&resolved)
		}
	}
	if err := resolved.Validate(); err != nil {
		return Canonicalizer{}, err
	}

	return Canonicalizer{options: resolved}, nil
}

// Validate rejects unsafe canonicalization options before builders run.
func (o Options) Validate() error {
	if err := o.Limits.Validate(); err != nil {
		return err
	}
	if o.HashAlgorithm != HashAlgorithmSHA256 {
		return newError(ErrorCodeUnsupportedAlgorithm, ErrorLocation{}, ErrorDetails{
			Class:     ErrorClassAlgorithm,
			Algorithm: o.HashAlgorithm,
		}, nil)
	}

	return nil
}

// Options returns a copy of the canonicalizer configuration.
func (c Canonicalizer) Options() Options {
	return c.options
}

// validKind reports whether kind names a supported canonical byte stream.
func validKind(kind Kind) bool {
	switch kind {
	case KindBodyHashInput, KindHeaderHashInput, KindSignatureInput:
		return true
	default:
		return false
	}
}
