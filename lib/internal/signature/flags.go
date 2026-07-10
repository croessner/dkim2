package signature

import "slices"

const (
	// FlagDoNotModify is the parser-known donotmodify policy flag.
	FlagDoNotModify = "donotmodify"
	// FlagDoNotExplode is the parser-known donotexplode policy flag.
	FlagDoNotExplode = "donotexplode"
	// FlagFeedback is the parser-known feedback policy flag.
	FlagFeedback = "feedback"
	// FlagFeedHere is the parser-known privacy-preserving feedback destination flag.
	FlagFeedHere = "feedhere"
	// FlagExploded is the parser-known exploded state flag.
	FlagExploded = "exploded"
)

// Flags stores immutable f= flag data in field order.
type Flags struct {
	values []Flag
}

// Values returns immutable copies of parsed f= flags in field order.
func (f Flags) Values() []Flag {
	return slices.Clone(f.values)
}

// HasKnown reports whether a known canonical flag is present.
func (f Flags) HasKnown(name string) bool {
	canonical, ok := canonicalTokenName([]byte(name))
	if !ok || !knownFlag(canonical) {
		return false
	}
	for _, flag := range f.values {
		if flag.known && flag.name == canonical {
			return true
		}
	}

	return false
}

// clone returns immutable flag data.
func (f Flags) clone() Flags {
	return Flags{values: slices.Clone(f.values)}
}

// Flag stores one parsed f= flag.
type Flag struct {
	name  string
	known bool
}

// Name returns the canonical flag name.
func (f Flag) Name() string {
	return f.name
}

// Known reports whether this flag is parser-known.
func (f Flag) Known() bool {
	return f.known
}

// parseFlags parses comma-separated f= flags.
func parseFlags(value string, limits Limits, fieldIndex int) (Flags, error) {
	parts := splitCommaList([]byte(value))
	if len(parts) == 0 {
		return Flags{}, malformedFlagError(fieldIndex, 0)
	}
	if len(parts) > limits.MaxFlags {
		return Flags{}, newError(ErrorCodeLimitExceeded, ErrorLocation{FieldIndex: fieldIndex}, ErrorDetails{
			Class:     ErrorClassLimit,
			TagName:   "f",
			LimitName: "max_flags",
			Limit:     limits.MaxFlags,
			Count:     len(parts),
		}, nil)
	}

	seenKnown := make(map[string]struct{}, len(parts))
	flags := make([]Flag, 0, len(parts))
	for i, part := range parts {
		trimmed, _ := trimWSP(part)
		name, ok := canonicalTokenName(trimmed)
		if !ok {
			return Flags{}, malformedFlagError(fieldIndex, i)
		}

		known := knownFlag(name)
		if known {
			if _, exists := seenKnown[name]; exists {
				return Flags{}, newError(ErrorCodeDuplicateKnownFlag, ErrorLocation{FieldIndex: fieldIndex, FlagIndex: i}, ErrorDetails{
					Class:   ErrorClassDuplicate,
					TagName: "f",
				}, nil)
			}
			seenKnown[name] = struct{}{}
		}
		flags = append(flags, Flag{name: name, known: known})
	}

	return Flags{values: flags}, nil
}

// knownFlag reports whether name is one of the parser-known f= flags.
func knownFlag(name string) bool {
	switch name {
	case FlagDoNotModify, FlagDoNotExplode, FlagFeedback, FlagFeedHere, FlagExploded:
		return true
	default:
		return false
	}
}

// malformedFlagError constructs a bounded f= syntax failure.
func malformedFlagError(fieldIndex int, flagIndex int) *Error {
	return newError(ErrorCodeMalformedFlag, ErrorLocation{FieldIndex: fieldIndex, FlagIndex: flagIndex}, ErrorDetails{
		TagName: "f",
	}, nil)
}
