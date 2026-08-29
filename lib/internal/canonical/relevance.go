package canonical

import "github.com/croessner/dkim2/internal/rawmsg"

// HeaderRelevance is the immutable Draft-06 signed-header relevance classifier.
type HeaderRelevance struct {
	initialized bool
}

// NewHeaderRelevance constructs the canonical-owned production classifier.
func NewHeaderRelevance() HeaderRelevance {
	return HeaderRelevance{initialized: true}
}

// Validate rejects a zero classifier before it crosses a consumer boundary.
func (r HeaderRelevance) Validate() error {
	if !r.initialized {
		return newError(ErrorCodeMalformedState, ErrorLocation{Kind: KindHeaderHashInput}, ErrorDetails{Class: ErrorClassMalformed}, nil)
	}
	return nil
}

// IsRelevantHeader classifies one validated canonical lowercase ASCII field name.
func (r HeaderRelevance) IsRelevantHeader(nameLower string) (bool, error) {
	canonicalName, ok := rawmsg.CanonicalHeaderName(nameLower)
	if err := r.Validate(); err != nil || !ok || canonicalName != nameLower {
		return false, newError(ErrorCodeMalformedState, ErrorLocation{Kind: KindHeaderHashInput}, ErrorDetails{Class: ErrorClassMalformed}, nil)
	}
	return excludedHeaderKindForName(nameLower) == excludedHeaderNone, nil
}
