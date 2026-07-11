package tagvalue

const (
	defaultMaxFieldValueBytes    = 64 * 1024
	defaultMaxTags               = 64
	defaultMaxTagNameBytes       = 64
	defaultMaxTagValueBytes      = 64 * 1024
	defaultMaxBase64DecodedBytes = 1024 * 1024
)

// Limits contains fail-closed DKIM2 tag-value scanner resource settings.
type Limits struct {
	// MaxFieldValueBytes bounds one unfolded DKIM2 header field value.
	MaxFieldValueBytes int
	// MaxTags bounds the number of tag specifications in one field.
	MaxTags int
	// MaxTagNameBytes bounds one tag identifier before canonicalization.
	MaxTagNameBytes int
	// MaxTagValueBytes bounds one tag value before tag-specific decoding.
	MaxTagValueBytes int
	// MaxBase64DecodedBytes bounds decoded parser-owned base64 containers.
	MaxBase64DecodedBytes int
}

// DefaultLimits returns the restrictive tag scanner defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxFieldValueBytes:    defaultMaxFieldValueBytes,
		MaxTags:               defaultMaxTags,
		MaxTagNameBytes:       defaultMaxTagNameBytes,
		MaxTagValueBytes:      defaultMaxTagValueBytes,
		MaxBase64DecodedBytes: defaultMaxBase64DecodedBytes,
	}
}

// Validate rejects unsafe scanner limit values before scanning begins.
func (l Limits) Validate() error {
	if l.MaxFieldValueBytes <= 0 {
		return limitOptionError("max_field_value_bytes", l.MaxFieldValueBytes)
	}
	if l.MaxTags <= 0 {
		return limitOptionError("max_tags", l.MaxTags)
	}
	if l.MaxTagNameBytes <= 0 {
		return limitOptionError("max_tag_name_bytes", l.MaxTagNameBytes)
	}
	if l.MaxTagValueBytes <= 0 {
		return limitOptionError("max_tag_value_bytes", l.MaxTagValueBytes)
	}
	if l.MaxBase64DecodedBytes <= 0 {
		return limitOptionError("max_base64_decoded_bytes", l.MaxBase64DecodedBytes)
	}

	return nil
}

// normalize fills zero-valued limits with restrictive defaults.
func (l Limits) normalize() Limits {
	defaults := DefaultLimits()
	if l.MaxFieldValueBytes == 0 {
		l.MaxFieldValueBytes = defaults.MaxFieldValueBytes
	}
	if l.MaxTags == 0 {
		l.MaxTags = defaults.MaxTags
	}
	if l.MaxTagNameBytes == 0 {
		l.MaxTagNameBytes = defaults.MaxTagNameBytes
	}
	if l.MaxTagValueBytes == 0 {
		l.MaxTagValueBytes = defaults.MaxTagValueBytes
	}
	if l.MaxBase64DecodedBytes == 0 {
		l.MaxBase64DecodedBytes = defaults.MaxBase64DecodedBytes
	}

	return l
}

// limitOptionError reports a scanner option resource-limit failure.
func limitOptionError(limitName string, limit int) *Error {
	return NewError(ErrorCodeInvalidOptions, ErrorLocation{}, ErrorDetails{
		Class:     ErrorClassInvariant,
		LimitName: limitName,
		Limit:     limit,
	})
}

// limitExceededError reports input rejected by a configured resource limit.
func limitExceededError(limitName string, limit int, count int, location ErrorLocation) *Error {
	return NewError(ErrorCodeLimitExceeded, location, ErrorDetails{
		Class:     ErrorClassLimit,
		LimitName: limitName,
		Limit:     limit,
		Count:     count,
	})
}
