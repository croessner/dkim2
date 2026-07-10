package signature

import (
	"strconv"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

var knownSignatureTags = tagvalue.MustKnownTags("i", "m", "t", "mf", "rt", "nd", "d", "s", "n", "f")

// Parser parses DKIM2-Signature fields with immutable output.
type Parser struct {
	limits Limits
}

// NewParser constructs a DKIM2-Signature parser with restrictive defaults.
func NewParser(limits Limits) (Parser, error) {
	limits = limits.normalize()
	if err := limits.Validate(); err != nil {
		return Parser{}, err
	}

	return Parser{limits: limits}, nil
}

// Parse parses one DKIM2-Signature field with default limits.
func Parse(field rawmsg.HeaderField) (Signature, error) {
	parser, err := NewParser(Limits{})
	if err != nil {
		return Signature{}, err
	}

	return parser.ParseField(field)
}

// ParseField parses one rawmsg header field as a DKIM2-Signature.
func (p Parser) ParseField(field rawmsg.HeaderField) (Signature, error) {
	if field.NameLower() != HeaderName {
		return Signature{}, newError(ErrorCodeWrongHeaderField, ErrorLocation{FieldIndex: field.Index()}, ErrorDetails{}, nil)
	}

	tagField, err := tagvalue.ScanTerminated(field.UnfoldedValue(), knownSignatureTags, p.limits.TagLimits)
	if err != nil {
		return Signature{}, err
	}

	sequenceTag, err := requiredTag(tagField, field.Index(), "i")
	if err != nil {
		return Signature{}, err
	}
	instanceTag, err := requiredTag(tagField, field.Index(), "m")
	if err != nil {
		return Signature{}, err
	}
	timestampTag, err := requiredTag(tagField, field.Index(), "t")
	if err != nil {
		return Signature{}, err
	}
	domainTag, err := requiredTag(tagField, field.Index(), "d")
	if err != nil {
		return Signature{}, err
	}
	signaturesTag, err := requiredTag(tagField, field.Index(), "s")
	if err != nil {
		return Signature{}, err
	}

	sequence, err := parsePositiveDecimal(sequenceTag.Value(), field.Index(), "i")
	if err != nil {
		return Signature{}, err
	}
	instanceNumber, err := parsePositiveDecimal(instanceTag.Value(), field.Index(), "m")
	if err != nil {
		return Signature{}, err
	}
	timestamp, err := parseTimestamp(timestampTag.Value(), field.Index())
	if err != nil {
		return Signature{}, err
	}
	domain, err := parseDomain(domainTag.Value(), field.Index(), "d")
	if err != nil {
		return Signature{}, err
	}
	signatures, err := parseSignatureSets(signaturesTag.Value(), p.limits, field.Index())
	if err != nil {
		return Signature{}, err
	}

	signature := Signature{
		sequence:       sequence,
		instanceNumber: instanceNumber,
		timestamp:      timestamp,
		domain:         domain,
		signatures:     signatures,
		headerIndex:    field.Index(),
	}
	if err := p.parseEnvelopeForm(tagField, field.Index(), &signature); err != nil {
		return Signature{}, err
	}
	if nonceTag, ok := tagField.Get("n"); ok {
		nonce, nonceErr := parseNonce(nonceTag.Value(), p.limits, field.Index())
		if nonceErr != nil {
			return Signature{}, nonceErr
		}
		signature.nonce = nonce
		signature.hasNonce = true
	}
	if flagsTag, ok := tagField.Get("f"); ok {
		flags, flagErr := parseFlags(flagsTag.Value(), p.limits, field.Index())
		if flagErr != nil {
			return Signature{}, flagErr
		}
		signature.flags = flags
	}

	return signature, nil
}

// parseEnvelopeForm parses exactly one of nd= or the mf=/rt= pair into signature.
func (p Parser) parseEnvelopeForm(field tagvalue.Field, fieldIndex int, parsed *Signature) error {
	nextDomainTag, hasNextDomain := field.Get("nd")
	mailFromTag, hasMailFrom := field.Get("mf")
	recipientsTag, hasRecipients := field.Get("rt")

	if hasNextDomain {
		if hasMailFrom || hasRecipients {
			return invalidEnvelopeFormError(fieldIndex)
		}
		nextDomain, err := parseDomain(nextDomainTag.Value(), fieldIndex, "nd")
		if err != nil {
			return err
		}
		parsed.nextDomain = nextDomain
		parsed.hasNextDomain = true

		return nil
	}
	if !hasMailFrom || !hasRecipients {
		return invalidEnvelopeFormError(fieldIndex)
	}

	mailFrom, err := parseEnvelopePath(mailFromTag.Value(), p.limits.TagLimits, fieldIndex, -1, "mf")
	if err != nil {
		return err
	}
	recipients, err := parseRecipientPaths(recipientsTag.Value(), p.limits, fieldIndex)
	if err != nil {
		return err
	}
	parsed.mailFrom = mailFrom
	parsed.recipients = recipients

	return nil
}

// invalidEnvelopeFormError constructs a bounded nd=/mf=/rt= exclusivity failure.
func invalidEnvelopeFormError(fieldIndex int) *Error {
	return newError(ErrorCodeInvalidEnvelopeForm, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{}, nil)
}

// normalize fills zero-valued limits with restrictive defaults.
func (l Limits) normalize() Limits {
	defaults := DefaultLimits()
	if l.TagLimits == (tagvalue.Limits{}) {
		l.TagLimits = defaults.TagLimits
	}
	if l.MaxRecipients == 0 {
		l.MaxRecipients = defaults.MaxRecipients
	}
	if l.MaxSignatureSets == 0 {
		l.MaxSignatureSets = defaults.MaxSignatureSets
	}
	if l.MaxFlags == 0 {
		l.MaxFlags = defaults.MaxFlags
	}
	if l.MaxNonceBytes == 0 {
		l.MaxNonceBytes = defaults.MaxNonceBytes
	}

	return l
}

// requiredTag returns a required tag or a bounded missing-tag error.
func requiredTag(field tagvalue.Field, fieldIndex int, tagName string) (tagvalue.Tag, error) {
	tag, ok := field.Get(tagName)
	if ok {
		return tag, nil
	}

	return tagvalue.Tag{}, missingTagError(fieldIndex, tagName)
}

// missingTagError constructs a bounded required-tag failure.
func missingTagError(fieldIndex int, tagName string) *Error {
	return newError(ErrorCodeMissingRequiredTag, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
		Class:   ErrorClassMissing,
		TagName: tagName,
	}, nil)
}

// parsePositiveDecimal parses i= and m= as positive unsigned decimal values.
func parsePositiveDecimal(value string, fieldIndex int, tagName string) (uint64, error) {
	if value == "" {
		return 0, invalidNumberError(fieldIndex, tagName)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, invalidNumberError(fieldIndex, tagName)
		}
	}

	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number == 0 {
		return 0, invalidNumberError(fieldIndex, tagName)
	}

	return number, nil
}

// parseTimestamp parses t= as unsigned decimal seconds without age policy.
func parseTimestamp(value string, fieldIndex int) (uint64, error) {
	if value == "" {
		return 0, invalidTimestampError(fieldIndex)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, invalidTimestampError(fieldIndex)
		}
	}

	timestamp, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, invalidTimestampError(fieldIndex)
	}

	return timestamp, nil
}

// invalidNumberError constructs a bounded i= or m= syntax failure.
func invalidNumberError(fieldIndex int, tagName string) *Error {
	return newError(ErrorCodeInvalidNumber, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
		TagName: tagName,
	}, nil)
}

// invalidTimestampError constructs a bounded t= syntax failure.
func invalidTimestampError(fieldIndex int) *Error {
	return newError(ErrorCodeInvalidTimestamp, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
		TagName: "t",
	}, nil)
}

// invalidLimitError constructs a bounded parser option failure.
func invalidLimitError(limitName string, limit int) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
		Class:     ErrorClassInvariant,
		LimitName: limitName,
		Limit:     limit,
	}, nil)
}
