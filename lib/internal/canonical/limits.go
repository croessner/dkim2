package canonical

const (
	defaultMaxBodyInputBytes      = 32 * 1024 * 1024
	defaultMaxHeaderInputBytes    = 2 * 1024 * 1024
	defaultMaxSignatureInputBytes = 2 * 1024 * 1024
	defaultMaxFieldBytes          = 128 * 1024
	defaultMaxFieldCount          = 4000
	defaultExcludedCounterCount   = 10
)

// Limits contains fail-closed canonicalization resource settings.
type Limits struct {
	// MaxBodyInputBytes bounds Section 6.1 canonical body input bytes.
	MaxBodyInputBytes int
	// MaxHeaderInputBytes bounds Section 6.2 canonical header input bytes.
	MaxHeaderInputBytes int
	// MaxSignatureInputBytes bounds Section 9.6 canonical signature input bytes.
	MaxSignatureInputBytes int
	// MaxFieldBytes bounds one canonicalized header or protocol field.
	MaxFieldBytes int
	// MaxFieldCount bounds fields considered by header or signature builders.
	MaxFieldCount int
	// MaxExcludedHeaderCounters bounds allowlisted debug exclusion counters.
	MaxExcludedHeaderCounters int
}

// DefaultLimits returns restrictive canonicalization defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxBodyInputBytes:         defaultMaxBodyInputBytes,
		MaxHeaderInputBytes:       defaultMaxHeaderInputBytes,
		MaxSignatureInputBytes:    defaultMaxSignatureInputBytes,
		MaxFieldBytes:             defaultMaxFieldBytes,
		MaxFieldCount:             defaultMaxFieldCount,
		MaxExcludedHeaderCounters: defaultExcludedCounterCount,
	}
}

// Validate rejects unsafe canonicalization limit values.
func (l Limits) Validate() error {
	switch {
	case l.MaxBodyInputBytes <= 0:
		return invalidLimitOptionError("max_body_input_bytes", l.MaxBodyInputBytes)
	case l.MaxHeaderInputBytes <= 0:
		return invalidLimitOptionError("max_header_input_bytes", l.MaxHeaderInputBytes)
	case l.MaxSignatureInputBytes <= 0:
		return invalidLimitOptionError("max_signature_input_bytes", l.MaxSignatureInputBytes)
	case l.MaxFieldBytes <= 0:
		return invalidLimitOptionError("max_field_bytes", l.MaxFieldBytes)
	case l.MaxFieldCount <= 0:
		return invalidLimitOptionError("max_field_count", l.MaxFieldCount)
	case l.MaxExcludedHeaderCounters <= 0 || l.MaxExcludedHeaderCounters > defaultExcludedCounterCount:
		return invalidLimitOptionError("max_excluded_header_counters", l.MaxExcludedHeaderCounters)
	default:
		return nil
	}
}

// invalidLimitOptionError reports an unsafe limit value without raw input.
func invalidLimitOptionError(limitName string, limit int) *Error {
	return newError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
		Class:     ErrorClassInvariant,
		LimitName: limitName,
		Limit:     limit,
	}, nil)
}
