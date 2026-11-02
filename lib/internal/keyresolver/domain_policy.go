package keyresolver

import (
	"context"
	"strings"
	"time"

	"github.com/croessner/dkim2/internal/tagvalue"
)

// domainPolicyTags lists the Draft-09 Section 3.8 Domain Policy Record tags.
// Every other tag, including a p= tag of a co-located DKIM1 key-shaped
// record, is ignored after generic tag-list validation.
var domainPolicyTags = tagvalue.MustKnownTags("v", "f")

// domainPolicyStrictFlag is the case-sensitive Section 3.8 flag that removes
// the upward Authentic From match for the record's domain.
const domainPolicyStrictFlag = "strict"

// DomainPolicyStatus identifies one closed Domain Policy Record outcome
// (Draft-09 Sections 3.8 and 7.1 item 3).
type DomainPolicyStatus string

const (
	// DomainPolicyAuthorized reports that subdomains may make From header
	// fields of the domain Authentic: no record, NXDOMAIN, NODATA, no
	// record beginning with v=DKIM1, no f= tag, or no strict flag.
	DomainPolicyAuthorized DomainPolicyStatus = "authorized"
	// DomainPolicyStrict reports exactly one record whose f= tag carries the
	// strict flag.
	DomainPolicyStrict DomainPolicyStatus = "strict"
	// DomainPolicyTemporary reports a temporary DNS failure or a bounded
	// timeout; the relevant match result is TEMPERROR.
	DomainPolicyTemporary DomainPolicyStatus = "temporary"
	// DomainPolicyAmbiguous reports more than one record beginning with
	// v=DKIM1, or a count-only answer that cannot be filtered; PERMERROR.
	DomainPolicyAmbiguous DomainPolicyStatus = "ambiguous"
	// DomainPolicyInvalid reports a record that begins with v=DKIM1 but is
	// not a valid tag-list, an over-bound record, a permanent transport
	// failure, or contradictory transport state; PERMERROR (local fail-closed
	// interpretation D1, the draft is silent).
	DomainPolicyInvalid DomainPolicyStatus = "invalid"
)

// Known reports whether the status belongs to the closed policy vocabulary.
func (s DomainPolicyStatus) Known() bool {
	switch s {
	case DomainPolicyAuthorized, DomainPolicyStrict, DomainPolicyTemporary, DomainPolicyAmbiguous, DomainPolicyInvalid:
		return true
	default:
		return false
	}
}

// DomainPolicyOutcome stores one immutable Domain Policy Record resolution.
type DomainPolicyOutcome struct {
	status      DomainPolicyStatus
	initialized bool
}

// newDomainPolicyOutcome constructs one initialized policy outcome.
func newDomainPolicyOutcome(status DomainPolicyStatus) DomainPolicyOutcome {
	return DomainPolicyOutcome{status: status, initialized: true}
}

// Status returns the closed policy outcome.
func (o DomainPolicyOutcome) Status() DomainPolicyStatus { return o.status }

// Valid reports whether the outcome is initialized and in the closed vocabulary.
func (o DomainPolicyOutcome) Valid() bool { return o.initialized && o.status.Known() }

// cacheable reports whether the outcome is a stable DNS-backed answer. A
// temporary outcome is never cached.
func (o DomainPolicyOutcome) cacheable() bool {
	return o.Valid() && o.status != DomainPolicyTemporary
}

// DomainPolicyQuery owns one validated Domain Policy Record owner.
type DomainPolicyQuery struct {
	domain       string
	absoluteName string
}

// NewDomainPolicyQuery validates one canonical A-label domain and constructs
// the absolute owner _domainkey.<domain>. (Draft-09 Section 3.8). The lookup
// uses the domain exactly: there is no walk up or down the DNS tree.
func NewDomainPolicyQuery(domain string, limits Limits) (DomainPolicyQuery, error) {
	if err := limits.Validate(); err != nil {
		return DomainPolicyQuery{}, newResolverError(ErrorClassContract)
	}
	canonicalDomain, err := CanonicalSigningDomain(domain, limits.MaxSigningDomainBytes, limits.MaxSigningDomainLabels)
	if err != nil {
		return DomainPolicyQuery{}, newResolverError(ErrorClassContract)
	}
	presentation := "_domainkey." + canonicalDomain
	if len(presentation) > limits.MaxOwnerBytes || len(presentation) > hardMaxNameBytes {
		return DomainPolicyQuery{}, newResolverError(ErrorClassPermanent)
	}
	absolute := presentation + "."
	if !OwnerKindDomainPolicy.ValidAbsoluteOwner(absolute) {
		return DomainPolicyQuery{}, newResolverError(ErrorClassContract)
	}
	return DomainPolicyQuery{domain: canonicalDomain, absoluteName: absolute}, nil
}

// Domain returns the canonical ASCII domain that holds the record.
func (q DomainPolicyQuery) Domain() string { return q.domain }

// AbsoluteOwner returns the canonical transport owner with a terminal root dot.
func (q DomainPolicyQuery) AbsoluteOwner() string { return q.absoluteName }

// DomainPolicyRecord is one parsed Draft-09 Section 3.8 Domain Policy Record.
type DomainPolicyRecord struct {
	strict      bool
	initialized bool
}

// Strict reports whether the record carries the case-sensitive strict flag.
func (r DomainPolicyRecord) Strict() bool { return r.initialized && r.strict }

// Valid reports whether the record was produced by the parser.
func (r DomainPolicyRecord) Valid() bool { return r.initialized }

// ParseDomainPolicyRecord parses one already-concatenated TXT payload that
// begins with v=DKIM1 as a Draft-09 Section 3.8 Domain Policy Record. The
// tag-list follows Section 8 through the shared scanner; v= must be the first
// tag with the exact value DKIM1. The optional f= value is split on ':' with
// surrounding WSP trimmed from every flag (local interpretation D1, the draft
// gives no ABNF); flags are case-sensitive and unknown flags are ignored.
func ParseDomainPolicyRecord(input []byte, limits Limits) (DomainPolicyRecord, error) {
	if err := limits.Validate(); err != nil {
		return DomainPolicyRecord{}, newRecordError(RecordErrorContract)
	}
	field, err := tagvalue.Scan(input, domainPolicyTags, tagvalue.Limits{
		MaxFieldValueBytes: limits.MaxTXTRecordBytes,
		MaxTags:            limits.MaxTags, MaxTagNameBytes: limits.MaxTagNameBytes,
		MaxTagValueBytes:      limits.MaxTagValueBytes,
		MaxBase64DecodedBytes: limits.MaxDecodedKeyBytes,
	})
	if err != nil {
		return DomainPolicyRecord{}, mappedScannerError(err)
	}
	tags := field.Tags()
	version, ok := field.Get("v")
	if !ok || len(tags) == 0 || tags[0].Name() != "v" || version.Value() != dkim1Version {
		return DomainPolicyRecord{}, newRecordError(RecordErrorInvalidVersion)
	}
	record := DomainPolicyRecord{initialized: true}
	if flags, ok := field.Get("f"); ok {
		for flag := range strings.SplitSeq(flags.Value(), ":") {
			if strings.Trim(flag, " \t") == domainPolicyStrictFlag {
				record.strict = true
			}
		}
	}
	return record, nil
}

// domainPolicyRecordCandidate reports whether a TXT payload is a purported
// Domain Policy Record: its first tag-spec is v=DKIM1. Unlike the key-record
// filter, a payload without a leading v= tag is ignored here (Section 3.8).
func domainPolicyRecordCandidate(payload []byte) bool {
	version, ok := leadingVersion(payload)
	return ok && version == dkim1Version
}

// ResolveDomainPolicy returns one cached or coalesced Domain Policy Record
// outcome for the canonical A-label domain. It shares the transport, cache,
// single-flight coordination, and limits of key resolution; the policy owner
// grammar keeps a distinct cache key space. A context error is returned only
// when the caller context ended.
func (r Resolver) ResolveDomainPolicy(ctx context.Context, domain string) (DomainPolicyOutcome, error) {
	if !r.initialized || r.transport == nil || ctx == nil {
		return DomainPolicyOutcome{}, newResolverError(ErrorClassContract)
	}
	if err := ctx.Err(); err != nil {
		return DomainPolicyOutcome{}, err
	}
	query, err := NewDomainPolicyQuery(domain, r.limits)
	if err != nil {
		return newDomainPolicyOutcome(DomainPolicyInvalid), nil
	}
	key := cacheKey{owner: query.AbsoluteOwner()}
	if cached, hit, corrupt := r.cache.getPolicy(key); corrupt {
		if err := ctx.Err(); err != nil {
			return DomainPolicyOutcome{}, err
		}
		return newDomainPolicyOutcome(DomainPolicyInvalid), nil
	} else if hit {
		if err := ctx.Err(); err != nil {
			return DomainPolicyOutcome{}, err
		}
		return cached, nil
	}
	resolved, saturated, flightErr := r.flights.do(ctx, key, func(lookupCtx context.Context) flightResult {
		return r.resolveDomainPolicyLookup(lookupCtx, query)
	})
	if err := ctx.Err(); err != nil {
		return DomainPolicyOutcome{}, err
	}
	if flightErr != nil {
		return DomainPolicyOutcome{}, flightErr
	}
	if saturated {
		return newDomainPolicyOutcome(DomainPolicyTemporary), nil
	}
	if !resolved.policy.Valid() {
		return newDomainPolicyOutcome(DomainPolicyInvalid), nil
	}
	return resolved.policy, nil
}

// resolveDomainPolicyLookup performs one transport call and classifies the
// answer under Section 3.8 with bounded TTL provenance: absence uses the
// negative cap, a policy record the positive cap, an answer whose records
// were all ignored the negative cap, and ambiguity or invalidity the stable
// error cap. Contract and permanent transport failures are never cached.
func (r Resolver) resolveDomainPolicyLookup(ctx context.Context, query DomainPolicyQuery) flightResult {
	lookup, lookupErr := r.transport.LookupTXT(ctx, query.AbsoluteOwner())
	observedAt := r.cache.clock()
	uncached := func(status DomainPolicyStatus) flightResult {
		return flightResult{policy: newDomainPolicyOutcome(status)}
	}
	cached := func(status DomainPolicyStatus, ttl, maximum time.Duration) flightResult {
		return flightResult{policy: newDomainPolicyOutcome(status), expiry: boundedCacheExpiry(observedAt, ttl, maximum)}
	}
	if ctx.Err() != nil {
		return uncached(DomainPolicyTemporary)
	}
	if lookupErr != nil {
		if lookup.IsZero() && TransportErrorClassOf(lookupErr) == TransportErrorTemporary {
			return uncached(DomainPolicyTemporary)
		}
		return uncached(DomainPolicyInvalid)
	}
	if lookup.IsZero() || !lookupResultValid(lookup) {
		return uncached(DomainPolicyInvalid)
	}
	if lookup.Status() == LookupStatusAbsent {
		return cached(DomainPolicyAuthorized, lookup.NegativeTTL(), r.limits.MaxNegativeTTL)
	}
	records := lookup.Records()
	if lookup.RecordCount() > r.limits.MaxTXTRecords || len(records) == 0 {
		// Count-only answers cannot be filtered, so they stay ambiguous.
		return cached(DomainPolicyAmbiguous, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)
	}
	var candidate []byte
	candidates := 0
	for _, txt := range records {
		// Section 3.8 ignores every record that does not begin with v=DKIM1
		// before any other rule, so the per-record byte bound applies to
		// candidates only; an unrelated long record at the owner is ignored.
		payload := txt.Payload()
		if !domainPolicyRecordCandidate(payload) {
			continue
		}
		if len(payload) > r.limits.MaxTXTRecordBytes {
			return cached(DomainPolicyInvalid, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)
		}
		candidate = payload
		candidates++
	}
	switch candidates {
	case 0:
		return cached(DomainPolicyAuthorized, lookup.PositiveTTL(), r.limits.MaxNegativeTTL)
	case 1:
	default:
		return cached(DomainPolicyAmbiguous, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)
	}
	record, err := ParseDomainPolicyRecord(candidate, r.limits)
	if err != nil {
		if IsRecordErrorCode(err, RecordErrorContract) {
			return uncached(DomainPolicyInvalid)
		}
		return cached(DomainPolicyInvalid, lookup.PositiveTTL(), r.limits.MaxStableErrorTTL)
	}
	if record.Strict() {
		return cached(DomainPolicyStrict, lookup.PositiveTTL(), r.limits.MaxPositiveTTL)
	}
	return cached(DomainPolicyAuthorized, lookup.PositiveTTL(), r.limits.MaxPositiveTTL)
}
