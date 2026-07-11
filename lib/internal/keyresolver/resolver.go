package keyresolver

import (
	"context"
	"math"
	"reflect"
	"time"
)

// Resolver owns bounded cached DNS TXT lookup, parsing, decoding, and miss coordination.
type Resolver struct {
	transport   TXTTransport
	limits      Limits
	cache       *outcomeCache
	flights     *flightGroup
	initialized bool
}

type resolverConfig struct {
	clock  func() time.Time
	parent context.Context
}

// ResolverOption configures instance-owned resolver runtime dependencies.
type ResolverOption func(*resolverConfig)

// WithResolverClock injects deterministic cache time.
func WithResolverClock(clock func() time.Time) ResolverOption {
	return func(config *resolverConfig) { config.clock = clock }
}

// WithResolverParentContext injects instance lifetime ownership for transport flights.
func WithResolverParentContext(parent context.Context) ResolverOption {
	return func(config *resolverConfig) { config.parent = parent }
}

// NewResolver constructs a resolver from validated immutable dependencies.
func NewResolver(transport TXTTransport, limits Limits, options ...ResolverOption) (Resolver, error) {
	config := resolverConfig{clock: time.Now, parent: context.Background()}
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}
	if nilTXTTransport(transport) || limits.Validate() != nil {
		return Resolver{}, newResolverError(ErrorClassContract)
	}
	if config.clock == nil || config.parent == nil {
		return Resolver{}, newResolverError(ErrorClassContract)
	}
	cache := newOutcomeCache(limits.MaxCacheEntries, config.clock)
	flights := newFlightGroup(config.parent, limits.MaxConcurrentLookups, limits.MaxCoalescedWaiters, limits.LookupTimeout,
		flightPublication{cache: cache})
	return Resolver{
		transport: transport, limits: limits, cache: cache, flights: flights,
		initialized: true,
	}, nil
}

// nilTXTTransport reports nil and typed-nil injected transport dependencies.
func nilTXTTransport(transport TXTTransport) bool {
	if transport == nil {
		return true
	}
	value := reflect.ValueOf(transport)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Resolve returns one cached or coalesced TXT key outcome for a validated query.
func (r Resolver) Resolve(ctx context.Context, signingDomain, selector string, algorithm Algorithm) (KeyOutcome, error) {
	if !r.initialized || r.transport == nil || ctx == nil || !algorithm.Known() {
		return KeyOutcome{}, newResolverError(ErrorClassContract)
	}
	if err := ctx.Err(); err != nil {
		return KeyOutcome{}, err
	}
	query, err := NewQuery(signingDomain, selector, algorithm, r.limits)
	if err != nil {
		if IsErrorClass(err, ErrorClassPermanent) {
			return newStatusOutcome(KeyOutcomePermanent, algorithm, newMetadata(false, false)), nil
		}
		return newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false)), nil
	}
	key := cacheKey{owner: query.AbsoluteOwner(), algorithm: algorithm}
	if cached, hit, corrupt := r.cache.get(key); corrupt {
		if err := ctx.Err(); err != nil {
			return KeyOutcome{}, err
		}
		return newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false)), nil
	} else if hit {
		if err := ctx.Err(); err != nil {
			return KeyOutcome{}, err
		}
		return cached, nil
	}
	resolved, saturated, flightErr := r.flights.do(ctx, key, func(lookupCtx context.Context) flightResult {
		return r.resolveLookup(lookupCtx, query)
	})
	if err := ctx.Err(); err != nil {
		return KeyOutcome{}, err
	}
	if flightErr != nil {
		return KeyOutcome{}, flightErr
	}
	if saturated {
		return newStatusOutcome(KeyOutcomeTemporary, algorithm, newMetadata(false, false)), nil
	}
	if !resolved.outcome.Valid() {
		return newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false)), nil
	}
	return cloneKeyOutcome(resolved.outcome), nil
}

// resolveLookup performs one transport call and retains bounded TTL provenance.
func (r Resolver) resolveLookup(ctx context.Context, query Query) flightResult {
	algorithm := query.Algorithm()
	lookup, lookupErr := r.transport.LookupTXT(ctx, query.AbsoluteOwner())
	observedAt := r.cache.clock()
	if ctx.Err() != nil {
		return flightResult{outcome: newStatusOutcome(KeyOutcomeTemporary, algorithm, newMetadata(false, false))}
	}
	if lookupErr != nil {
		return flightResult{outcome: r.transportFailure(algorithm, lookup, lookupErr)}
	}
	if !lookup.IsZero() && !lookupResultValid(lookup) {
		return flightResult{outcome: newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false))}
	}
	if lookup.IsZero() {
		return flightResult{outcome: newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false))}
	}
	if lookup.Status() == LookupStatusAbsent {
		outcome := newStatusOutcome(KeyOutcomeMissing, algorithm, newMetadata(false, false))
		return flightResult{outcome: outcome, expiry: boundedCacheExpiry(observedAt, lookup.NegativeTTL(), r.limits.MaxNegativeTTL)}
	}
	if lookup.RecordCount() > r.limits.MaxTXTRecords {
		outcome := newStatusOutcome(KeyOutcomeAmbiguous, algorithm, newMetadata(false, false))
		return flightResult{outcome: outcome, expiry: boundedCacheExpiry(observedAt, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)}
	}
	records := lookup.Records()
	if len(records) != 1 {
		return flightResult{outcome: newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false))}
	}
	payload := records[0].Payload()
	if len(payload) > r.limits.MaxTXTRecordBytes {
		outcome := newStatusOutcome(KeyOutcomeInvalid, algorithm, newMetadata(false, false))
		return flightResult{outcome: outcome, expiry: boundedCacheExpiry(observedAt, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)}
	}
	record, parseErr := ParseRecord(payload, r.limits)
	if parseErr != nil {
		if IsRecordErrorCode(parseErr, RecordErrorContract) {
			return flightResult{outcome: newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false))}
		}
		outcome := newStatusOutcome(KeyOutcomeInvalid, algorithm, newMetadata(false, false))
		return flightResult{outcome: outcome, expiry: boundedCacheExpiry(observedAt, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)}
	}
	outcome, decodeErr := DecodeKey(record, algorithm)
	if decodeErr != nil {
		return flightResult{outcome: newStatusOutcome(KeyOutcomeProviderContract, algorithm, record.Metadata())}
	}
	ttlCap := r.limits.MaxStableErrorTTL
	if outcome.Status() == KeyOutcomeFound {
		ttlCap = r.limits.MaxPositiveTTL
	}
	return flightResult{outcome: outcome, expiry: boundedCacheExpiry(observedAt, lookup.PositiveTTL(), ttlCap)}
}

// transportFailure maps disjoint caller and typed transport failures without raw causes.
func (r Resolver) transportFailure(algorithm Algorithm, lookup LookupResult, err error) KeyOutcome {
	if !lookup.IsZero() {
		return newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false))
	}
	switch TransportErrorClassOf(err) {
	case TransportErrorTemporary:
		return newStatusOutcome(KeyOutcomeTemporary, algorithm, newMetadata(false, false))
	case TransportErrorPermanent:
		return newStatusOutcome(KeyOutcomePermanent, algorithm, newMetadata(false, false))
	default:
		return newStatusOutcome(KeyOutcomeProviderContract, algorithm, newMetadata(false, false))
	}
}

// boundedCacheTTL clamps positive DNS provenance without inventing lifetime.
func boundedCacheTTL(ttl, maximum time.Duration) time.Duration {
	const maximumDNSTTL = time.Duration(math.MaxUint32) * time.Second
	if ttl <= 0 || ttl > maximumDNSTTL || maximum <= 0 {
		return 0
	}
	if ttl > maximum {
		return maximum
	}
	return ttl
}

// boundedCacheExpiry anchors a clamped DNS lifetime to answer observation time.
func boundedCacheExpiry(observedAt time.Time, ttl, maximum time.Duration) time.Time {
	ttl = boundedCacheTTL(ttl, maximum)
	if ttl <= 0 {
		return time.Time{}
	}
	expiry := observedAt.Add(ttl)
	if !expiry.After(observedAt) || expiry.Year() > 9999 {
		return time.Time{}
	}
	return expiry
}

// lookupResultValid exhaustively validates mutually exclusive transport state.
func lookupResultValid(result LookupResult) bool {
	if !result.Status().Known() || !result.DNSSECStatus().Known() {
		return false
	}
	switch result.Status() {
	case LookupStatusFound:
		if result.Absence() != "" || result.NegativeTTL() != 0 || result.RecordCount() <= 0 {
			return false
		}
		return result.RecordCount() > 1 && len(result.records) == 0 || result.RecordCount() == 1 && len(result.records) == 1
	case LookupStatusAbsent:
		return result.Absence().Known() && result.RecordCount() == 0 && len(result.records) == 0 && result.PositiveTTL() == 0
	default:
		return false
	}
}
