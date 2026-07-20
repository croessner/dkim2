package dkim2

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
)

// DNSPublicKeyProvider resolves public verification keys through DNS TXT records.
type DNSPublicKeyProvider struct{ resolver keyresolver.Resolver }

// DNSResolverLimits bounds public DNS resolution, caching, and concurrency resources.
type DNSResolverLimits struct {
	MaxSelectorBytes, MaxSelectorLabels             int
	MaxSigningDomainBytes, MaxSigningDomainLabels   int
	MaxOwnerBytes, MaxTXTRecords, MaxTXTRecordBytes int
	MaxTags, MaxTagNameBytes, MaxTagValueBytes      int
	MaxDecodedKeyBytes, MaxCacheEntries             int
	MaxPositiveTTL, MaxNegativeTTL                  time.Duration
	MaxStableErrorTTL                               time.Duration
	MaxConcurrentLookups, MaxCoalescedWaiters       int
	LookupTimeout                                   time.Duration
}

// DNSProviderConfig configures one instance-owned DNS public-key provider.
type DNSProviderConfig struct {
	Limits DNSResolverLimits
	Clock  func() time.Time
	Parent context.Context
}

// DefaultDNSProviderConfig returns restrictive cache, concurrency, and lookup defaults.
func DefaultDNSProviderConfig() DNSProviderConfig {
	limits := keyresolver.DefaultLimits()
	return DNSProviderConfig{Limits: publicDNSResolverLimits(limits), Clock: time.Now, Parent: context.Background()}
}

// NewDNSPublicKeyProvider constructs a DNS-backed provider with restrictive defaults.
func NewDNSPublicKeyProvider(transport TXTTransport) (*DNSPublicKeyProvider, error) {
	return NewDNSPublicKeyProviderWithConfig(transport, DefaultDNSProviderConfig())
}

// NewDNSPublicKeyProviderWithConfig constructs a configured bounded DNS-backed provider.
func NewDNSPublicKeyProviderWithConfig(transport TXTTransport, config DNSProviderConfig) (*DNSPublicKeyProvider, error) {
	if nilPublicTXTTransport(transport) {
		return nil, newAPIError(APIErrorCodeInvalidProvider)
	}
	limits := internalDNSResolverLimits(config.Limits)
	resolver, err := keyresolver.NewResolver(publicTXTTransportAdapter{transport: transport}, limits,
		keyresolver.WithResolverClock(config.Clock), keyresolver.WithResolverParentContext(config.Parent))
	if err != nil {
		return nil, newAPIError(APIErrorCodeInvalidProvider)
	}
	return &DNSPublicKeyProvider{resolver: resolver}, nil
}

// publicDNSResolverLimits maps internal defaults into the public configuration shape.
func publicDNSResolverLimits(limits keyresolver.Limits) DNSResolverLimits {
	return DNSResolverLimits{
		MaxSelectorBytes: limits.MaxSelectorBytes, MaxSelectorLabels: limits.MaxSelectorLabels,
		MaxSigningDomainBytes: limits.MaxSigningDomainBytes, MaxSigningDomainLabels: limits.MaxSigningDomainLabels,
		MaxOwnerBytes: limits.MaxOwnerBytes, MaxTXTRecords: limits.MaxTXTRecords, MaxTXTRecordBytes: limits.MaxTXTRecordBytes,
		MaxTags: limits.MaxTags, MaxTagNameBytes: limits.MaxTagNameBytes, MaxTagValueBytes: limits.MaxTagValueBytes,
		MaxDecodedKeyBytes: limits.MaxDecodedKeyBytes, MaxCacheEntries: limits.MaxCacheEntries,
		MaxPositiveTTL: limits.MaxPositiveTTL, MaxNegativeTTL: limits.MaxNegativeTTL, MaxStableErrorTTL: limits.MaxStableErrorTTL,
		MaxConcurrentLookups: limits.MaxConcurrentLookups, MaxCoalescedWaiters: limits.MaxCoalescedWaiters,
		LookupTimeout: limits.LookupTimeout,
	}
}

// internalDNSResolverLimits maps public configuration into resolver ownership for validation.
func internalDNSResolverLimits(limits DNSResolverLimits) keyresolver.Limits {
	return keyresolver.Limits{
		MaxSelectorBytes: limits.MaxSelectorBytes, MaxSelectorLabels: limits.MaxSelectorLabels,
		MaxSigningDomainBytes: limits.MaxSigningDomainBytes, MaxSigningDomainLabels: limits.MaxSigningDomainLabels,
		MaxOwnerBytes: limits.MaxOwnerBytes, MaxTXTRecords: limits.MaxTXTRecords, MaxTXTRecordBytes: limits.MaxTXTRecordBytes,
		MaxTags: limits.MaxTags, MaxTagNameBytes: limits.MaxTagNameBytes, MaxTagValueBytes: limits.MaxTagValueBytes,
		MaxDecodedKeyBytes: limits.MaxDecodedKeyBytes, MaxCacheEntries: limits.MaxCacheEntries,
		MaxPositiveTTL: limits.MaxPositiveTTL, MaxNegativeTTL: limits.MaxNegativeTTL, MaxStableErrorTTL: limits.MaxStableErrorTTL,
		MaxConcurrentLookups: limits.MaxConcurrentLookups, MaxCoalescedWaiters: limits.MaxCoalescedWaiters,
		LookupTimeout: limits.LookupTimeout,
	}
}

// nilPublicTXTTransport reports nil and typed-nil public transport dependencies.
func nilPublicTXTTransport(transport TXTTransport) bool {
	return niliface.IsNil(transport)
}

// LookupPublicKey resolves one canonical public query without applying verifier key policy.
func (p *DNSPublicKeyProvider) LookupPublicKey(ctx context.Context, query PublicKeyQuery) (PublicKeyResult, error) {
	if p == nil || ctx == nil {
		return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	algorithm, ok := resolverAlgorithm(query.Algorithm())
	if !ok {
		return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	outcome, err := p.resolver.Resolve(ctx, query.SigningDomain(), query.Selector(), algorithm)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && errors.Is(err, ctxErr) {
			return PublicKeyResult{}, ctxErr
		}
		return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
	metadata := newKeyPolicyMetadata(outcome.Metadata().TestingDeclared(), outcome.Metadata().StrictIdentityDeclared())
	baseAlgorithm := query.Algorithm()
	switch outcome.Status() {
	case keyresolver.KeyOutcomeFound:
		switch key := outcome.Material().(type) {
		case *rsa.PublicKey:
			return withKeyPolicyMetadata(FoundRSAPublicKey(key), metadata), nil
		case ed25519.PublicKey:
			return withKeyPolicyMetadata(FoundEd25519PublicKey(key), metadata), nil
		default:
			return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
		}
	case keyresolver.KeyOutcomeMissing:
		return MissingPublicKey(baseAlgorithm), nil
	case keyresolver.KeyOutcomeInvalid:
		return withKeyPolicyMetadata(InvalidPublicKey(baseAlgorithm), metadata), nil
	case keyresolver.KeyOutcomeAmbiguous:
		return AmbiguousPublicKey(baseAlgorithm), nil
	case keyresolver.KeyOutcomeRevoked:
		return withKeyPolicyMetadata(RevokedPublicKey(baseAlgorithm), metadata), nil
	case keyresolver.KeyOutcomeUnsupportedKeyType:
		return withKeyPolicyMetadata(UnsupportedKeyTypePublicKey(baseAlgorithm), metadata), nil
	case keyresolver.KeyOutcomeAlgorithmMismatch:
		return withKeyPolicyMetadata(AlgorithmMismatchPublicKey(baseAlgorithm), metadata), nil
	case keyresolver.KeyOutcomeTemporary:
		return PublicKeyResult{}, NewTemporaryProviderError()
	case keyresolver.KeyOutcomePermanent:
		return PublicKeyResult{}, NewPermanentProviderError()
	case keyresolver.KeyOutcomeProviderContract:
		return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
	default:
		return PublicKeyResult{}, newAPIError(APIErrorCodeInvalidProvider)
	}
}

// resolverAlgorithm maps a supported public query into resolver ownership.
func resolverAlgorithm(algorithm Algorithm) (keyresolver.Algorithm, bool) {
	switch algorithm {
	case AlgorithmRSASHA256:
		return keyresolver.AlgorithmRSASHA256, true
	case AlgorithmEd25519SHA256:
		return keyresolver.AlgorithmEd25519SHA256, true
	default:
		return "", false
	}
}

type publicTXTTransportAdapter struct{ transport TXTTransport }

// LookupTXT maps the closed public transport contract into resolver-owned transport facts.
func (a publicTXTTransportAdapter) LookupTXT(ctx context.Context, owner string) (keyresolver.LookupResult, error) {
	result, err := a.transport.LookupTXT(ctx, owner)
	if err != nil {
		if !result.IsZero() {
			return keyresolver.LookupResult{}, publicTXTContractError{}
		}
		if ctx != nil && ctx.Err() != nil {
			return keyresolver.LookupResult{}, err
		}
		switch ProviderErrorClassOf(err) {
		case ProviderErrorClassTemporary:
			return keyresolver.LookupResult{}, keyresolver.NewTransportError(keyresolver.TransportErrorTemporary)
		case ProviderErrorClassPermanent:
			return keyresolver.LookupResult{}, keyresolver.NewTransportError(keyresolver.TransportErrorPermanent)
		default:
			return keyresolver.LookupResult{}, publicTXTContractError{}
		}
	}
	if result.IsZero() || !result.Status().Known() || !result.DNSSECStatus().Known() {
		return keyresolver.LookupResult{}, publicTXTContractError{}
	}
	dnssec, ok := resolverDNSSECStatus(result.DNSSECStatus())
	if !ok {
		return keyresolver.LookupResult{}, publicTXTContractError{}
	}
	if !publicTXTLookupShapeValid(result) {
		return keyresolver.LookupResult{}, publicTXTContractError{}
	}
	switch result.Status() {
	case TXTLookupStatusFound:
		if result.RecordCount() > 1 {
			return keyresolver.NewAmbiguousResult(result.RecordCount(), result.PositiveTTL(), dnssec)
		}
		records := result.Records()
		if result.RecordCount() != 1 || len(records) != 1 {
			return keyresolver.LookupResult{}, publicTXTContractError{}
		}
		return keyresolver.NewFoundResult([][]byte{records[0].Payload()}, result.PositiveTTL(), dnssec)
	case TXTLookupStatusAbsent:
		absence, ok := resolverAbsenceClass(result.Absence())
		if !ok {
			return keyresolver.LookupResult{}, publicTXTContractError{}
		}
		return keyresolver.NewAbsentResult(absence, result.NegativeTTL(), dnssec)
	default:
		return keyresolver.LookupResult{}, publicTXTContractError{}
	}
}

// publicTXTLookupShapeValid validates mutually exclusive public transport fields in constant time.
func publicTXTLookupShapeValid(result TXTLookupResult) bool {
	switch result.Status() {
	case TXTLookupStatusFound:
		if result.Absence() != "" || result.NegativeTTL() != 0 || result.RecordCount() <= 0 {
			return false
		}
		return result.RecordCount() > 1 && len(result.records) == 0 || result.RecordCount() == 1 && len(result.records) == 1
	case TXTLookupStatusAbsent:
		return result.Absence().Known() && result.RecordCount() == 0 && len(result.records) == 0 && result.PositiveTTL() == 0
	default:
		return false
	}
}

type publicTXTContractError struct{}

// Error returns a bounded cause-free public transport contract diagnostic.
func (publicTXTContractError) Error() string { return "dns txt transport contract failure" }

// resolverAbsenceClass maps public authoritative absence into resolver ownership.
func resolverAbsenceClass(absence TXTAbsenceClass) (keyresolver.AbsenceClass, bool) {
	switch absence {
	case TXTAbsenceNXDOMAIN:
		return keyresolver.AbsenceNXDOMAIN, true
	case TXTAbsenceNODATA:
		return keyresolver.AbsenceNODATA, true
	default:
		return "", false
	}
}

// resolverDNSSECStatus maps verdict-neutral public DNSSEC diagnostics.
func resolverDNSSECStatus(status DNSSECStatus) (keyresolver.DNSSECStatus, bool) {
	if !status.Known() {
		return "", false
	}
	return keyresolver.DNSSECStatus(status), true
}
