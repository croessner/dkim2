package dkim2

import (
	"time"

	"github.com/croessner/dkim2/internal/dsn"
	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/service"
)

const (
	// HardMaxRawMessageBytes is the public verification maximum raw RFC 5322 message size.
	HardMaxRawMessageBytes = 32 << 20
	// HardMaxRecipients is the public verification maximum current SMTP recipient count.
	HardMaxRecipients = 2_000
	// HardMaxInstanceHashSets is the public verification maximum hash-set count per Message-Instance.
	HardMaxInstanceHashSets = 16
	// HardMaxSignatureSets is the public verification maximum signature-set count per DKIM2-Signature.
	HardMaxSignatureSets = 16
	// HardMaxCheckFacts is the public verification maximum retained check-fact count.
	HardMaxCheckFacts = 128
	// HardMaxSignatureFacts is the public verification maximum retained signature-set-fact count.
	HardMaxSignatureFacts = 16
)

// VerificationLimits is an immutable closed configuration whose values may only narrow hard maxima.
type VerificationLimits struct {
	maxRawMessageBytes  int
	maxRecipients       int
	maxInstanceHashSets int
	maxSignatureSets    int
	maxCheckFacts       int
	maxSignatureFacts   int
}

// DefaultVerificationLimits returns the closed defaults, which equal the hard maxima.
func DefaultVerificationLimits() VerificationLimits {
	return VerificationLimits{
		maxRawMessageBytes:  HardMaxRawMessageBytes,
		maxRecipients:       HardMaxRecipients,
		maxInstanceHashSets: HardMaxInstanceHashSets,
		maxSignatureSets:    HardMaxSignatureSets,
		maxCheckFacts:       HardMaxCheckFacts,
		maxSignatureFacts:   HardMaxSignatureFacts,
	}
}

// MaxRawMessageBytes returns the configured raw-message byte limit.
func (l VerificationLimits) MaxRawMessageBytes() int {
	return l.maxRawMessageBytes
}

// MaxRecipients returns the configured current-recipient count limit.
func (l VerificationLimits) MaxRecipients() int {
	return l.maxRecipients
}

// MaxInstanceHashSets returns the configured Message-Instance hash-set limit.
func (l VerificationLimits) MaxInstanceHashSets() int {
	return l.maxInstanceHashSets
}

// MaxSignatureSets returns the configured DKIM2-Signature set limit per field.
func (l VerificationLimits) MaxSignatureSets() int {
	return l.maxSignatureSets
}

// MaxCheckFacts returns the configured retained check-fact limit.
func (l VerificationLimits) MaxCheckFacts() int {
	return l.maxCheckFacts
}

// MaxSignatureFacts returns the configured retained signature-set-fact limit.
func (l VerificationLimits) MaxSignatureFacts() int {
	return l.maxSignatureFacts
}

type verifierConfig struct {
	limits VerificationLimits
	clock  *verificationClock
	sink   ObservationSink
}

type verificationClock struct{ now func() time.Time }

// Verifier is the public current-verification facade.
type Verifier struct {
	state *verifierState
}

type verifierState struct {
	service     service.Verifier
	receivedDSN dsn.ReceivedEvaluator
	limits      VerificationLimits
	initialized bool
	sink        ObservationSink
}

// WithObservationSink injects one bounded nonnormative observation receiver.
func WithObservationSink(sink ObservationSink) VerifierOption {
	return func(config *verifierConfig) error {
		if config == nil || nilObservationSink(sink) {
			return newAPIError(APIErrorCodeInvalidOption)
		}
		config.sink = sink
		return nil
	}
}

// VerifierOption narrows one validated verifier setting during construction.
type VerifierOption func(*verifierConfig) error

// WithVerificationClock injects the deterministic time source used by timestamp policy.
func WithVerificationClock(clock func() time.Time) VerifierOption {
	return func(config *verifierConfig) error {
		if config == nil || clock == nil {
			return newAPIError(APIErrorCodeInvalidOption)
		}
		config.clock = &verificationClock{now: clock}
		return nil
	}
}

// WithMaxRawMessageBytes narrows the raw RFC 5322 message-size limit.
func WithMaxRawMessageBytes(limit int) VerifierOption {
	return newLimitOption(limit, HardMaxRawMessageBytes, func(config *verifierConfig, value int) {
		config.limits.maxRawMessageBytes = value
	})
}

// WithMaxRecipients narrows the current SMTP recipient-count limit.
func WithMaxRecipients(limit int) VerifierOption {
	return newLimitOption(limit, HardMaxRecipients, func(config *verifierConfig, value int) {
		config.limits.maxRecipients = value
	})
}

// WithMaxInstanceHashSets narrows the hash-set limit per Message-Instance field.
func WithMaxInstanceHashSets(limit int) VerifierOption {
	return newLimitOption(limit, HardMaxInstanceHashSets, func(config *verifierConfig, value int) {
		config.limits.maxInstanceHashSets = value
	})
}

// WithMaxSignatureSets narrows the signature-set limit per DKIM2-Signature field.
func WithMaxSignatureSets(limit int) VerifierOption {
	return newLimitOption(limit, HardMaxSignatureSets, func(config *verifierConfig, value int) {
		config.limits.maxSignatureSets = value
	})
}

// WithMaxCheckFacts narrows the retained public check-fact limit.
func WithMaxCheckFacts(limit int) VerifierOption {
	return newLimitOption(limit, HardMaxCheckFacts, func(config *verifierConfig, value int) {
		config.limits.maxCheckFacts = value
	})
}

// WithMaxSignatureFacts narrows the retained public signature-set-fact limit.
func WithMaxSignatureFacts(limit int) VerifierOption {
	return newLimitOption(limit, HardMaxSignatureFacts, func(config *verifierConfig, value int) {
		config.limits.maxSignatureFacts = value
	})
}

// newLimitOption constructs a validated narrowing option without retaining invalid state.
func newLimitOption(limit, hardMaximum int, apply func(*verifierConfig, int)) VerifierOption {
	return func(config *verifierConfig) error {
		if config == nil || limit <= 0 || limit > hardMaximum || apply == nil {
			return newAPIError(APIErrorCodeInvalidOption)
		}
		apply(config, limit)
		return nil
	}
}

// applyVerifierOptions validates all options atomically and returns zero configuration on failure.
func applyVerifierOptions(options ...VerifierOption) (verifierConfig, error) {
	config := verifierConfig{
		limits: DefaultVerificationLimits(),
		sink:   NoopObservationSink{},
	}
	for _, option := range options {
		if option == nil {
			return verifierConfig{}, newAPIError(APIErrorCodeInvalidOption)
		}
		if err := option(&config); err != nil {
			return verifierConfig{}, newAPIError(APIErrorCodeInvalidOption)
		}
	}
	return config, nil
}

// nilObservationSink reports nil and typed-nil observation dependencies.
func nilObservationSink(sink ObservationSink) bool {
	return niliface.IsNil(sink)
}
