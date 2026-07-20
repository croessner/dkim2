package signature

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/croessner/dkim2/internal/rawmsg"
)

// CustodyLimits bounds one complete signature custody evaluation.
type CustodyLimits struct {
	// MaxSignatures bounds the complete custody chain.
	MaxSignatures int
	// MaxRecipientsPerSignature bounds each ordinary signature recipient set.
	MaxRecipientsPerSignature int
}

// DefaultCustodyLimits returns parser-aligned hard custody limits.
func DefaultCustodyLimits() CustodyLimits {
	parserLimits := DefaultLimits()
	return CustodyLimits{
		MaxSignatures:             parserLimits.MaxSignatures,
		MaxRecipientsPerSignature: parserLimits.MaxRecipients,
	}
}

// Validate rejects widened, nonpositive, or incoherent custody limits.
func (l CustodyLimits) Validate() error {
	hard := DefaultCustodyLimits()
	if l.MaxSignatures <= 0 || l.MaxSignatures > hard.MaxSignatures ||
		l.MaxRecipientsPerSignature <= 0 || l.MaxRecipientsPerSignature > hard.MaxRecipientsPerSignature {
		return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{}, nil)
	}
	return nil
}

// normalized fills zero custody limits with restrictive defaults.
func (l CustodyLimits) normalized() (CustodyLimits, error) {
	defaults := DefaultCustodyLimits()
	if l.MaxSignatures == 0 {
		l.MaxSignatures = defaults.MaxSignatures
	}
	if l.MaxRecipientsPerSignature == 0 {
		l.MaxRecipientsPerSignature = defaults.MaxRecipientsPerSignature
	}
	if err := l.Validate(); err != nil {
		return CustodyLimits{}, err
	}
	return l, nil
}

// CustodyStatus identifies the bounded terminal form of a valid chain.
type CustodyStatus string

const (
	// CustodyStatusOrdinaryComplete reports a chain ending in an ordinary signature.
	CustodyStatusOrdinaryComplete CustodyStatus = "ordinary_complete"
	// CustodyStatusTerminalNextDomain reports a chain ending in nd= and requiring OOB acceptance.
	CustodyStatusTerminalNextDomain CustodyStatus = "terminal_next_domain"
)

// Known reports whether status belongs to the closed custody vocabulary.
func (s CustodyStatus) Known() bool {
	return s == CustodyStatusOrdinaryComplete || s == CustodyStatusTerminalNextDomain
}

// CustodyDirectAlignmentStatus identifies one signature's shared d=/mf= result.
type CustodyDirectAlignmentStatus string

const (
	// CustodyDirectAlignmentPass reports relaxed d=/mf= alignment.
	CustodyDirectAlignmentPass CustodyDirectAlignmentStatus = "pass"
	// CustodyDirectAlignmentNotApplicableNull reports a null reverse-path signature.
	CustodyDirectAlignmentNotApplicableNull CustodyDirectAlignmentStatus = "not_applicable_null"
	// CustodyDirectAlignmentNotApplicableNextDomain reports an nd= signature.
	CustodyDirectAlignmentNotApplicableNextDomain CustodyDirectAlignmentStatus = "not_applicable_next_domain"
	// CustodyDirectAlignmentMismatch reports a valid reverse path outside d=.
	CustodyDirectAlignmentMismatch CustodyDirectAlignmentStatus = "mismatch"
	// CustodyDirectAlignmentInvalid reports a non-DNS reverse-path domain.
	CustodyDirectAlignmentInvalid CustodyDirectAlignmentStatus = "invalid"
)

// Known reports whether status belongs to the closed direct-alignment vocabulary.
func (s CustodyDirectAlignmentStatus) Known() bool {
	return s == CustodyDirectAlignmentPass || s == CustodyDirectAlignmentNotApplicableNull ||
		s == CustodyDirectAlignmentNotApplicableNextDomain ||
		s == CustodyDirectAlignmentMismatch || s == CustodyDirectAlignmentInvalid
}

// CustodyResult stores only bounded chain facts and no domains or paths.
type CustodyResult struct {
	status        CustodyStatus
	count         int
	hadNextDomain bool
	direct        []CustodyDirectAlignmentStatus
	initialized   bool
}

// Status returns the terminal form of the evaluated chain.
func (r CustodyResult) Status() CustodyStatus { return r.status }

// Count returns the number of evaluated signatures.
func (r CustodyResult) Count() int { return r.count }

// HadNextDomain reports whether the validated chain contained any nd= hop.
func (r CustodyResult) HadNextDomain() bool { return r.hadNextDomain }

// DirectAlignment returns one bounded d=/mf= fact by semantic sequence.
func (r CustodyResult) DirectAlignment(sequence uint64) CustodyDirectAlignmentStatus {
	if !r.Evaluated() || sequence == 0 || sequence > uint64(len(r.direct)) {
		return ""
	}
	return r.direct[sequence-1]
}

// Evaluated reports whether the result contains one coherent complete state-machine run.
func (r CustodyResult) Evaluated() bool {
	if !r.initialized || !r.status.Known() || r.count <= 0 || r.count > DefaultCustodyLimits().MaxSignatures || len(r.direct) != r.count {
		return false
	}
	derivedHadNextDomain := false
	for _, status := range r.direct {
		if !status.Known() {
			return false
		}
		derivedHadNextDomain = derivedHadNextDomain || status == CustodyDirectAlignmentNotApplicableNextDomain
	}
	terminalNextDomain := r.direct[len(r.direct)-1] == CustodyDirectAlignmentNotApplicableNextDomain
	return r.hadNextDomain == derivedHadNextDomain &&
		(r.status == CustodyStatusTerminalNextDomain) == terminalNextDomain
}

// AllDirectAligned reports whether every direct d=/mf= fact passed or was not applicable.
func (r CustodyResult) AllDirectAligned() bool {
	if !r.Evaluated() {
		return false
	}
	for _, status := range r.direct {
		if status == CustodyDirectAlignmentMismatch || status == CustodyDirectAlignmentInvalid {
			return false
		}
	}
	return true
}

// AllDirectAlignedExcept reports whether only the named sequence may be non-aligned.
func (r CustodyResult) AllDirectAlignedExcept(sequence uint64) bool {
	if !r.Evaluated() || sequence == 0 || sequence > uint64(len(r.direct)) {
		return false
	}
	for index, status := range r.direct {
		if uint64(index+1) == sequence {
			continue
		}
		if status == CustodyDirectAlignmentMismatch || status == CustodyDirectAlignmentInvalid {
			return false
		}
	}
	return true
}

// FirstDirectMismatch returns the first non-aligned semantic sequence.
func (r CustodyResult) FirstDirectMismatch() (uint64, CustodyDirectAlignmentStatus, bool) {
	if !r.Evaluated() {
		return 0, "", false
	}
	for index, status := range r.direct {
		if status == CustodyDirectAlignmentMismatch || status == CustodyDirectAlignmentInvalid {
			return uint64(index + 1), status, true
		}
	}
	return 0, "", false
}

// Valid reports whether result is coherently evaluated and every direct check is acceptable.
func (r CustodyResult) Valid() bool {
	return r.Evaluated() && r.AllDirectAligned()
}

// String returns a constant secret-safe custody-result summary.
func (r CustodyResult) String() string { return "signature.CustodyResult{redacted}" }

// GoString returns the constant secret-safe custody-result Go representation.
func (r CustodyResult) GoString() string { return r.String() }

// Format routes every custody-result fmt form through the secret-safe summary.
func (r CustodyResult) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, r.String()) }

type custodyEntry struct {
	domain        string
	mailDomain    string
	nullReverse   bool
	recipients    map[string]struct{}
	nextDomain    string
	hasNextDomain bool
	direct        CustodyDirectAlignmentStatus
}

// ValidateCustody returns an evaluated partial result with a typed error for direct authentication failures.
func ValidateCustody(signatures []Signature, limits CustodyLimits) (CustodyResult, error) {
	result, err := evaluateCustody(signatures, limits)
	if err != nil {
		return CustodyResult{}, err
	}
	if sequence, _, mismatch := result.FirstDirectMismatch(); mismatch {
		return result, custodyError(ErrorCodeCustodyMismatch, signatures[sequenceIndex(signatures, sequence)], ErrorDetails{TagName: TagNameMailFrom})
	}
	return result, nil
}

// ValidateCompletedExtension evaluates inherited fields plus one detached generated field.
func ValidateCompletedExtension(headers rawmsg.HeaderBlock, complete CompleteField, limits CustodyLimits) (CustodyResult, error) {
	if !complete.Valid() {
		return CustodyResult{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	signatures, err := inheritedCustodySignatures(headers)
	if err != nil {
		return CustodyResult{}, err
	}
	raw := append(complete.Bytes(), '\r', '\n')
	message, err := rawmsg.Parse(raw)
	if err != nil {
		return CustodyResult{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	generated := message.Headers().FieldsByName(HeaderName)
	if len(generated) != 1 || len(message.Headers().Fields()) != 1 {
		return CustodyResult{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	parsed, err := Parse(generated[0])
	if err != nil {
		return CustodyResult{}, err
	}
	signatures = append(signatures, parsed)
	return ValidateCustody(signatures, limits)
}

// ValidateUnsignedExtension proves custody for a structured target before private signing.
func ValidateUnsignedExtension(headers rawmsg.HeaderBlock, target UnsignedTarget, limits CustodyLimits) (CustodyResult, error) {
	if !target.Valid() {
		return CustodyResult{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	signatures, err := inheritedCustodySignatures(headers)
	if err != nil {
		return CustodyResult{}, err
	}
	recipients := make([]EnvelopePath, len(target.request.Recipients))
	for index := range target.request.Recipients {
		recipients[index] = EnvelopePath{value: bytes.Clone(target.request.Recipients[index])}
	}
	synthetic := Signature{
		sequence: target.request.Sequence, instanceNumber: target.request.InstanceNumber,
		timestamp: target.request.Timestamp, mailFrom: EnvelopePath{value: bytes.Clone(target.request.MailFrom)},
		recipients: recipients, nextDomain: target.request.NextDomain,
		hasNextDomain: target.request.NextDomain != "", domain: target.request.Domain, headerIndex: -1,
	}
	signatures = append(signatures, synthetic)
	return ValidateCustody(signatures, limits)
}

// inheritedCustodySignatures parses the sole shared inherited custody source.
func inheritedCustodySignatures(headers rawmsg.HeaderBlock) ([]Signature, error) {
	fields := headers.FieldsByName(HeaderName)
	signatures := make([]Signature, 0, len(fields)+1)
	for _, field := range fields {
		parsed, err := Parse(field)
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, parsed)
	}
	return signatures, nil
}

// sequenceIndex returns the caller-slice index for one validated semantic sequence.
func sequenceIndex(signatures []Signature, sequence uint64) int {
	for index, parsed := range signatures {
		if parsed.Sequence() == sequence {
			return index
		}
	}
	return 0
}

// evaluateCustody runs the complete bounded custody state machine and retains direct facts.
func evaluateCustody(signatures []Signature, limits CustodyLimits) (CustodyResult, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return CustodyResult{}, err
	}
	if len(signatures) == 0 {
		return CustodyResult{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	if len(signatures) > resolved.MaxSignatures {
		return CustodyResult{}, newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
			LimitName: LimitNameMaxSignatures, Limit: resolved.MaxSignatures, Count: len(signatures),
		}, nil)
	}
	if err := ValidateSequence(signatures); err != nil {
		return CustodyResult{}, err
	}
	ordered, err := OrderBySequence(signatures)
	if err != nil {
		return CustodyResult{}, err
	}
	var previous custodyEntry
	direct := make([]CustodyDirectAlignmentStatus, len(ordered))
	for index, parsed := range ordered {
		entry, entryErr := newCustodyEntry(parsed, resolved)
		if entryErr != nil {
			var typed *Error
			if errors.As(entryErr, &typed) {
				tagName := TagNameMailFrom
				if parsed.HasNextDomain() {
					tagName = TagNameNextDomain
				}
				return CustodyResult{}, custodyError(typed.Code(), parsed, ErrorDetails{
					TagName:   tagName,
					LimitName: LimitName(typed.LimitName()), Limit: typed.Limit(), Count: typed.Count(),
				})
			}
			return CustodyResult{}, custodyError(ErrorCodeCustodyMismatch, parsed, ErrorDetails{})
		}
		if index > 0 && !custodyTransitionAllowed(previous, entry) {
			tagName := TagNameMailFrom
			offending := parsed
			if previous.hasNextDomain || entry.hasNextDomain {
				tagName = TagNameNextDomain
			}
			if previous.hasNextDomain {
				offending = ordered[index-1]
			}
			return CustodyResult{}, custodyError(ErrorCodeCustodyMismatch, offending, ErrorDetails{TagName: tagName})
		}
		direct[index] = entry.direct
		previous = entry
	}
	status := CustodyStatusOrdinaryComplete
	if previous.hasNextDomain {
		status = CustodyStatusTerminalNextDomain
	}
	return CustodyResult{
		status: status, count: len(signatures), hadNextDomain: custodyContainsNextDomain(ordered), direct: direct, initialized: true,
	}, nil
}

// custodyContainsNextDomain reports whether the already validated chain contains nd=.
func custodyContainsNextDomain(signatures []Signature) bool {
	for _, parsed := range signatures {
		if parsed.HasNextDomain() {
			return true
		}
	}
	return false
}

// newCustodyEntry derives one bounded canonical state-machine input.
func newCustodyEntry(parsed Signature, limits CustodyLimits) (custodyEntry, error) {
	domain, ok := canonicalDNSName([]byte(parsed.Domain()))
	if !ok {
		return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	entry := custodyEntry{domain: domain}
	if nextDomain, present := parsed.NextDomain(); present {
		if len(parsed.mailFrom.value) != 0 || len(parsed.recipients) != 0 {
			return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
		}
		canonicalNext, nextOK := canonicalDNSName([]byte(nextDomain))
		if !nextOK {
			return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
		}
		entry.nextDomain, entry.hasNextDomain = canonicalNext, true
		entry.direct = CustodyDirectAlignmentNotApplicableNextDomain
		return entry, nil
	}
	if parsed.nextDomain != "" || parsed.hasNextDomain {
		return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	reversePath := parsed.MailFrom().Value()
	if !validEnvelopePath(reversePath, true) {
		return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	if bytes.Equal(reversePath, []byte("<>")) {
		entry.nullReverse = true
		entry.direct = CustodyDirectAlignmentNotApplicableNull
	} else {
		mailDomain, mailOK := custodyPathDomain(reversePath)
		if !mailOK {
			entry.direct = CustodyDirectAlignmentInvalid
		} else {
			entry.mailDomain = mailDomain
			entry.direct = CustodyDirectAlignmentPass
			if !relaxedCustodyDomainMatch(domain, mailDomain) {
				entry.direct = CustodyDirectAlignmentMismatch
			}
		}
	}
	recipients := parsed.Recipients()
	if len(recipients) == 0 {
		return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
	}
	if len(recipients) > limits.MaxRecipientsPerSignature {
		return custodyEntry{}, newError(ErrorCodeLimitExceeded, ErrorLocation{}, ErrorDetails{
			LimitName: LimitNameMaxRecipients, Limit: limits.MaxRecipientsPerSignature, Count: len(recipients),
		}, nil)
	}
	entry.recipients = make(map[string]struct{}, len(recipients))
	for _, recipient := range recipients {
		path := recipient.Value()
		if !validEnvelopePath(path, false) {
			return custodyEntry{}, newError(ErrorCodeCustodyMismatch, ErrorLocation{}, ErrorDetails{}, nil)
		}
		recipientDomain, recipientOK := custodyPathDomain(path)
		if !recipientOK {
			continue
		}
		entry.recipients[recipientDomain] = struct{}{}
	}
	return entry, nil
}

// custodyError constructs one sequence-aware secret-safe custody failure.
func custodyError(code ErrorCode, parsed Signature, details ErrorDetails) *Error {
	details.ObservedNumber = parsed.Sequence()
	return newError(code, ErrorLocation{FieldIndex: parsed.HeaderIndex()}, details, nil)
}

// custodyTransitionAllowed applies the exact directional adjacent-hop rules.
func custodyTransitionAllowed(previous, current custodyEntry) bool {
	if previous.hasNextDomain {
		return current.domain == previous.nextDomain
	}
	if current.hasNextDomain {
		_, ok := previous.recipients[current.domain]
		return ok
	}
	if current.nullReverse || current.mailDomain == "" {
		return false
	}
	for recipientDomain := range previous.recipients {
		if relaxedCustodyDomainMatch(recipientDomain, current.mailDomain) {
			return true
		}
	}
	return false
}

// custodyPathDomain extracts one canonical DNS domain from a bracketed SMTP path.
func custodyPathDomain(path []byte) (string, bool) {
	if len(path) < 4 || path[0] != '<' || path[len(path)-1] != '>' {
		return "", false
	}
	mailbox := path[1 : len(path)-1]
	separator := bytes.LastIndexByte(mailbox, '@')
	if separator < 1 || separator == len(mailbox)-1 {
		return "", false
	}
	return canonicalDNSName(mailbox[separator+1:])
}

// relaxedCustodyDomainMatch removes labels only from the candidate side.
func relaxedCustodyDomainMatch(base, candidate string) bool {
	return candidate == base || strings.HasSuffix(candidate, "."+base)
}
