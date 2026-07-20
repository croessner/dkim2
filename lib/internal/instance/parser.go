package instance

import (
	"strconv"

	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/tagvalue"
)

var knownMessageInstanceTags = tagvalue.MustKnownTags("m", "h", "r")

// Parser parses Message-Instance fields with immutable output.
type Parser struct {
	limits Limits
}

// NewParser constructs a Message-Instance parser with restrictive defaults.
func NewParser(limits Limits) (Parser, error) {
	limits = limits.normalize()
	if err := limits.Validate(); err != nil {
		return Parser{}, err
	}

	return Parser{limits: limits}, nil
}

// Parse parses one Message-Instance field with default limits.
func Parse(field rawmsg.HeaderField) (MessageInstance, error) {
	parser, err := NewParser(Limits{})
	if err != nil {
		return MessageInstance{}, err
	}

	return parser.ParseField(field)
}

// ParseField parses one rawmsg header field as a Message-Instance.
func (p Parser) ParseField(field rawmsg.HeaderField) (MessageInstance, error) {
	if field.NameLower() != HeaderName {
		return MessageInstance{}, newError(ErrorCodeWrongHeaderField, ErrorLocation{FieldIndex: field.Index()}, ErrorDetails{}, nil)
	}

	tagField, err := tagvalue.ScanTerminated(field.UnfoldedValue(), knownMessageInstanceTags, p.limits.TagLimits)
	if err != nil {
		return MessageInstance{}, err
	}

	numberTag, ok := tagField.Get("m")
	if !ok {
		return MessageInstance{}, missingTagError(field.Index(), "m")
	}
	hashTag, ok := tagField.Get("h")
	if !ok {
		return MessageInstance{}, missingTagError(field.Index(), "h")
	}

	number, err := parseInstanceNumber(numberTag.Value(), field.Index())
	if err != nil {
		return MessageInstance{}, err
	}
	hashes, err := parseHashSets(hashTag.Value(), p.limits, field.Index())
	if err != nil {
		return MessageInstance{}, err
	}

	instance := MessageInstance{
		number:      number,
		hashes:      hashes,
		headerIndex: field.Index(),
	}
	if recipeTag, ok := tagField.Get("r"); ok {
		recipe, recipeErr := tagvalue.ParseBase64String([]byte(recipeTag.Value()), p.limits.TagLimits)
		if recipeErr != nil {
			return MessageInstance{}, newError(ErrorCodeInvalidRecipeBase64, ErrorLocation{FieldIndex: field.Index()}, ErrorDetails{
				TagName: "r",
			}, recipeErr)
		}
		instance.recipe = recipe
		instance.hasRecipe = true
	}

	return instance, nil
}

// normalize fills zero-valued limits with restrictive defaults.
func (l Limits) normalize() Limits {
	defaults := DefaultLimits()
	if l.MaxHashSets == 0 {
		l.MaxHashSets = defaults.MaxHashSets
	}
	if l.MaxInstances == 0 {
		l.MaxInstances = defaults.MaxInstances
	}

	return l
}

// missingTagError constructs a bounded required-tag failure.
func missingTagError(fieldIndex int, tagName string) *Error {
	return newError(ErrorCodeMissingRequiredTag, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
		Class:   ErrorClassMissing,
		TagName: TagName(tagName),
	}, nil)
}

// parseInstanceNumber parses m= as a positive unsigned decimal value.
func parseInstanceNumber(value string, fieldIndex int) (uint64, error) {
	if value == "" {
		return 0, invalidNumberError(fieldIndex)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, invalidNumberError(fieldIndex)
		}
	}

	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil || number == 0 {
		return 0, invalidNumberError(fieldIndex)
	}

	return number, nil
}

// invalidNumberError constructs a bounded m= syntax failure.
func invalidNumberError(fieldIndex int) *Error {
	return newError(ErrorCodeInvalidNumber, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
		TagName: TagNameNumber,
	}, nil)
}
