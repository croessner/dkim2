package verify

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/internal/niliface"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	localHopRunRedactedText = "verify.LocalHopRun{redacted}"
	// DefaultMaxLocalAuthorityLookups bounds distinct datasource authority lookups per run detection.
	DefaultMaxLocalAuthorityLookups = 256
)

// LocalAuthorityStatus is the closed answer of one local-authority lookup.
type LocalAuthorityStatus string

const (
	// LocalAuthorityLocal reports that the caller's tenant holds an active signing profile for the domain.
	LocalAuthorityLocal LocalAuthorityStatus = "local"
	// LocalAuthorityNotLocal reports that the domain is not a local authority domain for the tenant.
	LocalAuthorityNotLocal LocalAuthorityStatus = "not_local"
)

// Known reports whether the status belongs to the closed vocabulary.
func (s LocalAuthorityStatus) Known() bool {
	return s == LocalAuthorityLocal || s == LocalAuthorityNotLocal
}

// LocalAuthority answers whether a canonical DNS domain is a local authority
// domain for the tenant the implementation was bound to. Any returned error
// is a temporary failure; a status outside the closed vocabulary is a contract
// violation and is also treated as temporary. Implementations never receive a
// malformed domain.
type LocalAuthority interface {
	LookupLocalAuthority(ctx context.Context, domain string) (LocalAuthorityStatus, error)
}

// LocalHopRunOutcome is the closed result of one run detection.
type LocalHopRunOutcome string

const (
	// LocalHopRunDetected reports a complete run with bounded previous-hop facts.
	LocalHopRunDetected LocalHopRunOutcome = "detected"
	// LocalHopRunTemporary reports an authority lookup that failed temporarily or violated its contract.
	LocalHopRunTemporary LocalHopRunOutcome = "temporary"
	// LocalHopRunLimitExceeded reports that the run needed more authority lookups than permitted.
	LocalHopRunLimitExceeded LocalHopRunOutcome = "limit_exceeded"
	// LocalHopRunMalformed reports a signature chain whose custody structure is not coherent.
	LocalHopRunMalformed LocalHopRunOutcome = "malformed"
)

// Known reports whether the outcome belongs to the closed vocabulary.
func (o LocalHopRunOutcome) Known() bool {
	switch o {
	case LocalHopRunDetected, LocalHopRunTemporary, LocalHopRunLimitExceeded, LocalHopRunMalformed:
		return true
	default:
		return false
	}
}

// LocalHopRunLimits bounds one run detection.
type LocalHopRunLimits struct {
	// MaxAuthorityLookups bounds distinct domain lookups; zero selects the default.
	MaxAuthorityLookups int
}

// normalized fills zero limits with the restrictive default and rejects widening.
func (l LocalHopRunLimits) normalized() (LocalHopRunLimits, bool) {
	if l.MaxAuthorityLookups == 0 {
		l.MaxAuthorityLookups = DefaultMaxLocalAuthorityLookups
	}
	if l.MaxAuthorityLookups < 0 || l.MaxAuthorityLookups > DefaultMaxLocalAuthorityLookups {
		return LocalHopRunLimits{}, false
	}
	return l, true
}

// previousHopFacts stores bounded facts about the signature directly below the run.
type previousHopFacts struct {
	sequence   uint64
	instance   uint64
	timestamp  uint64
	domain     string
	nextDomain bool
	nullSender bool
	mailFrom   []byte
	recipients [][]byte
}

// LocalHopRun is the immutable maximal contiguous suffix of a verified
// embedded signature chain created by the local system, plus bounded facts
// about the signature directly below it.
type LocalHopRun struct {
	completion  uint64
	lowest      uint64
	previous    previousHopFacts
	hasPrevious bool
	initialized bool
}

// Valid reports whether the run was produced by DetectLocalHopRun.
func (r LocalHopRun) Valid() bool {
	return r.initialized && r.completion > 0 && r.lowest > 0 && r.lowest <= r.completion &&
		(r.hasPrevious == (r.lowest > 1)) && (!r.hasPrevious || r.previous.sequence == r.lowest-1)
}

// CompletionSequence returns the i= of the completion signature.
func (r LocalHopRun) CompletionSequence() uint64 { return r.completion }

// LowestSequence returns the i= of the lowest run member.
func (r LocalHopRun) LowestSequence() uint64 { return r.lowest }

// Members returns the run member sequences in ascending order.
func (r LocalHopRun) Members() []uint64 {
	if !r.Valid() {
		return nil
	}
	members := make([]uint64, 0, r.completion-r.lowest+1)
	for sequence := r.lowest; sequence <= r.completion; sequence++ {
		members = append(members, sequence)
	}
	return members
}

// HasPreviousHop reports whether a signature exists directly below the run.
func (r LocalHopRun) HasPreviousHop() bool { return r.Valid() && r.hasPrevious }

// PreviousHopSequence returns the i= of the previous hop or zero.
func (r LocalHopRun) PreviousHopSequence() uint64 {
	if !r.HasPreviousHop() {
		return 0
	}
	return r.previous.sequence
}

// PreviousHopInstance returns the m= referenced by the previous hop or zero.
func (r LocalHopRun) PreviousHopInstance() uint64 {
	if !r.HasPreviousHop() {
		return 0
	}
	return r.previous.instance
}

// PreviousHopTimestamp returns the previous hop's t= value or zero.
func (r LocalHopRun) PreviousHopTimestamp() uint64 {
	if !r.HasPreviousHop() {
		return 0
	}
	return r.previous.timestamp
}

// PreviousHopDomain returns the previous hop's canonical d= or an empty string.
func (r LocalHopRun) PreviousHopDomain() string {
	if !r.HasPreviousHop() {
		return ""
	}
	return r.previous.domain
}

// PreviousHopIsNextDomain reports whether the previous hop uses the nd= custody scheme.
func (r LocalHopRun) PreviousHopIsNextDomain() bool {
	return r.HasPreviousHop() && r.previous.nextDomain
}

// PreviousHopNullSender reports whether the previous hop carries mf=<>.
func (r LocalHopRun) PreviousHopNullSender() bool { return r.HasPreviousHop() && r.previous.nullSender }

// PreviousHopMailFrom returns a detached copy of the previous hop's exact mf= path.
func (r LocalHopRun) PreviousHopMailFrom() []byte {
	if !r.HasPreviousHop() {
		return nil
	}
	return bytes.Clone(r.previous.mailFrom)
}

// PreviousHopRecipients returns detached copies of the previous hop's exact rt= paths.
func (r LocalHopRun) PreviousHopRecipients() [][]byte {
	if !r.HasPreviousHop() {
		return nil
	}
	return cloneByteSlices(r.previous.recipients)
}

// String returns a constant secret-safe run summary.
func (LocalHopRun) String() string { return localHopRunRedactedText }

// GoString returns the constant secret-safe run Go representation.
func (r LocalHopRun) GoString() string { return r.String() }

// Format routes every run formatting form through the redacted summary.
func (r LocalHopRun) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

// localAuthorityCache bounds and deduplicates authority lookups during one detection.
type localAuthorityCache struct {
	authority LocalAuthority
	answers   map[string]LocalAuthorityStatus
	remaining int
}

// lookup resolves one canonical domain at most once per detection.
func (c *localAuthorityCache) lookup(ctx context.Context, domain string) (LocalAuthorityStatus, LocalHopRunOutcome, error) {
	if status, ok := c.answers[domain]; ok {
		return status, "", nil
	}
	if c.remaining <= 0 {
		return "", LocalHopRunLimitExceeded, nil
	}
	c.remaining--
	status, err := c.authority.LookupLocalAuthority(ctx, domain)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", "", ctxErr
	}
	if err != nil || !status.Known() {
		return "", LocalHopRunTemporary, nil
	}
	c.answers[domain] = status
	return status, "", nil
}

// DetectLocalHopRun extends the local hop run backwards from the completion
// signature over Section 9.3 nd= members and same-tenant imaginary-hop
// members. The caller must already have proven that the completion signature
// verified and that its d= is a local authority domain; this function checks
// only the extension rules and the custody structure. It never verifies
// cryptography; use VerifyEmbeddedSignatures for run members.
func DetectLocalHopRun(ctx context.Context, signatures []signature.Signature, completion uint64, authority LocalAuthority, limits LocalHopRunLimits) (LocalHopRun, LocalHopRunOutcome, error) {
	if ctx == nil || niliface.IsNil(authority) || completion == 0 || completion > uint64(len(signatures)) {
		return LocalHopRun{}, "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	resolved, ok := limits.normalized()
	if !ok {
		return LocalHopRun{}, "", newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{Class: ErrorClassRequest}, nil)
	}
	if err := ctx.Err(); err != nil {
		return LocalHopRun{}, "", err
	}
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil {
		return LocalHopRun{}, LocalHopRunMalformed, nil
	}
	custody, err := signature.ValidateCustody(ordered, signature.CustodyLimits{})
	if err != nil || !custody.Valid() || ordered[completion-1].HasNextDomain() {
		return LocalHopRun{}, LocalHopRunMalformed, nil
	}
	cache := &localAuthorityCache{authority: authority, answers: make(map[string]LocalAuthorityStatus), remaining: resolved.MaxAuthorityLookups}
	lowest := completion
	for candidate := completion - 1; candidate >= 1; candidate-- {
		member, outcome, memberErr := runMember(ctx, cache, custody, ordered[candidate-1], ordered[candidate])
		if memberErr != nil {
			return LocalHopRun{}, "", memberErr
		}
		if outcome != "" {
			return LocalHopRun{}, outcome, nil
		}
		if !member {
			break
		}
		lowest = candidate
	}
	run := LocalHopRun{completion: completion, lowest: lowest, initialized: true}
	if lowest > 1 {
		run.hasPrevious = true
		run.previous = newPreviousHopFacts(ordered[lowest-2])
	}
	if !run.Valid() {
		return LocalHopRun{}, "", newError(ErrorCodeInternalMisuse, ErrorLocation{}, ErrorDetails{Class: ErrorClassInternal}, nil)
	}
	return run, LocalHopRunDetected, nil
}

// runMember applies rule (a) for nd= candidates and rule (b) for imaginary-hop
// candidates against the already validated custody chain.
func runMember(ctx context.Context, cache *localAuthorityCache, custody signature.CustodyResult, candidate signature.Signature, above signature.Signature) (bool, LocalHopRunOutcome, error) {
	if next, present := candidate.NextDomain(); present {
		if next != above.Domain() {
			return false, "", nil
		}
		return cache.allLocal(ctx, []string{candidate.Domain()})
	}
	if above.HasNextDomain() || custody.DirectAlignment(candidate.Sequence()) != signature.CustodyDirectAlignmentPass {
		return false, "", nil
	}
	mailDomain, ok := signature.CanonicalEnvelopeDomain(candidate.MailFrom().Value(), false)
	if !ok {
		return false, "", nil
	}
	domains := []string{candidate.Domain(), mailDomain}
	for _, recipient := range candidate.Recipients() {
		recipientDomain, recipientOK := signature.CanonicalEnvelopeDomain(recipient.Value(), false)
		if !recipientOK {
			return false, "", nil
		}
		domains = append(domains, recipientDomain)
	}
	return cache.allLocal(ctx, domains)
}

// allLocal reports whether every domain is local, stopping at the first foreign answer.
func (c *localAuthorityCache) allLocal(ctx context.Context, domains []string) (bool, LocalHopRunOutcome, error) {
	for _, domain := range domains {
		status, outcome, err := c.lookup(ctx, domain)
		if err != nil || outcome != "" {
			return false, outcome, err
		}
		if status != LocalAuthorityLocal {
			return false, "", nil
		}
	}
	return true, "", nil
}

// newPreviousHopFacts snapshots bounded facts of the signature below the run.
func newPreviousHopFacts(parsed signature.Signature) previousHopFacts {
	facts := previousHopFacts{
		sequence: parsed.Sequence(), instance: parsed.InstanceNumber(), timestamp: parsed.TimestampSeconds(),
		domain: parsed.Domain(), nextDomain: parsed.HasNextDomain(),
	}
	if facts.nextDomain {
		return facts
	}
	facts.mailFrom = parsed.MailFrom().Value()
	facts.nullSender = bytes.Equal(facts.mailFrom, []byte("<>"))
	recipients := parsed.Recipients()
	facts.recipients = make([][]byte, len(recipients))
	for index, recipient := range recipients {
		facts.recipients[index] = recipient.Value()
	}
	return facts
}
