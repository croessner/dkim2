package signing

// Resource identifies one bounded signing usage dimension.
type Resource string

// Signing resources form the closed cumulative-usage vocabulary.
const (
	ResourceMessageBytes                 Resource = "message_bytes"
	ResourceHeaderBytes                  Resource = "header_bytes"
	ResourceHeaderFields                 Resource = "header_fields"
	ResourceProtocolFields               Resource = "protocol_fields"
	ResourceSignatureSets                Resource = "signature_sets"
	ResourcePublicKeyLookups             Resource = "public_key_lookups"
	ResourceSignatureInputBytes          Resource = "signature_input_bytes"
	ResourceCanonicalWorkBytes           Resource = "canonical_work_bytes"
	ResourceGeneratedRecipients          Resource = "generated_recipients"
	ResourceParentOutputCopiesAndTickets Resource = "parent_output_copies_and_tickets"
	ResourceEnvelopePathBytes            Resource = "envelope_path_bytes"
	ResourceDecodedRecipeBytes           Resource = "decoded_recipe_bytes"
	ResourceGeneratedSignatureSets       Resource = "generated_signature_sets"
	ResourceAuthorizationCalls           Resource = "authorization_calls"
	ResourcePrivateSigningCalls          Resource = "private_signing_calls"
	ResourceNonceBytes                   Resource = "nonce_bytes"
	ResourceNewInstances                 Resource = "new_instances"
	ResourceNewSignatures                Resource = "new_signatures"
)

var resources = [...]Resource{
	ResourceMessageBytes, ResourceHeaderBytes, ResourceHeaderFields, ResourceProtocolFields,
	ResourceSignatureSets, ResourcePublicKeyLookups, ResourceSignatureInputBytes,
	ResourceCanonicalWorkBytes, ResourceGeneratedRecipients,
	ResourceParentOutputCopiesAndTickets, ResourceEnvelopePathBytes, ResourceDecodedRecipeBytes,
	ResourceGeneratedSignatureSets, ResourceAuthorizationCalls, ResourcePrivateSigningCalls,
	ResourceNonceBytes, ResourceNewInstances, ResourceNewSignatures,
}

// Known reports whether resource belongs to the closed usage vocabulary.
func (r Resource) Known() bool {
	_, ok := resourceIndex(r)
	return ok
}

// Usage stores one immutable snapshot of bounded signing work.
type Usage struct {
	counts      [len(resources)]int
	initialized bool
}

// Valid reports whether usage was initialized with nonnegative counters.
func (u Usage) Valid() bool {
	if !u.initialized {
		return false
	}
	for _, count := range u.counts {
		if count < 0 {
			return false
		}
	}
	return true
}

// Count returns the charged count for a closed resource.
func (u Usage) Count(resource Resource) int {
	index, ok := resourceIndex(resource)
	if !ok || !u.Valid() {
		return 0
	}
	return u.counts[index]
}

// UsageCounter transactionally owns one operation's usage counters.
type UsageCounter struct {
	limits Limits
	counts [len(resources)]int
}

// NewUsageCounter constructs a counter under resolved restrictive limits.
func NewUsageCounter(limits Limits) (*UsageCounter, error) {
	resolved, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	return &UsageCounter{limits: resolved}, nil
}

// Charge transactionally accounts for one nonnegative resource increment.
func (c *UsageCounter) Charge(resource Resource, count int) error {
	index, ok := resourceIndex(resource)
	if c == nil || !ok || count < 0 {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhasePreflight}, ErrorDetails{})
	}
	updated, addOK := checkedAdd(c.counts[index], count)
	limit := c.limit(resource)
	if !addOK || updated > limit {
		if !addOK {
			updated = int(^uint(0) >> 1)
		}
		return newError(ErrorCodeLimitExceeded, ErrorLocation{Phase: PhasePreflight, Resource: resource}, ErrorDetails{
			LimitName: resourceLimitName(resource), Limit: limit, Actual: updated,
		})
	}
	c.counts[index] = updated
	return nil
}

// Finalize validates exact signing-operation completion invariants.
func (c *UsageCounter) Finalize() error {
	if c == nil {
		return newError(ErrorCodeInvalidRequest, ErrorLocation{Phase: PhaseComplete}, ErrorDetails{})
	}
	count := c.counts[mustResourceIndex(ResourceNewSignatures)]
	if count != c.limits.RequiredNewSignatures {
		return newError(ErrorCodeInternalInvariant, ErrorLocation{Phase: PhaseComplete, Resource: ResourceNewSignatures}, ErrorDetails{
			LimitName: LimitNameRequiredNewSignatures, Limit: c.limits.RequiredNewSignatures, Actual: count,
		})
	}
	return nil
}

// Usage returns an immutable initialized accounting snapshot.
func (c *UsageCounter) Usage() Usage {
	if c == nil {
		return Usage{}
	}
	return Usage{counts: c.counts, initialized: true}
}

// limit returns the configured ceiling for resource.
func (c *UsageCounter) limit(resource Resource) int {
	switch resource {
	case ResourceMessageBytes:
		return c.limits.MaxMessageBytes
	case ResourceHeaderBytes:
		return c.limits.MaxHeaderBytes
	case ResourceHeaderFields:
		return c.limits.MaxHeaderFields
	case ResourceProtocolFields:
		return c.limits.MaxProtocolFields
	case ResourceSignatureSets:
		return c.limits.MaxTotalSignatureSets
	case ResourcePublicKeyLookups:
		return c.limits.MaxPublicKeyLookups
	case ResourceSignatureInputBytes:
		return c.limits.MaxSignatureInputBytes
	case ResourceCanonicalWorkBytes:
		return c.limits.MaxCanonicalWorkBytes
	case ResourceGeneratedRecipients:
		return c.limits.MaxGeneratedRecipients
	case ResourceParentOutputCopiesAndTickets:
		return c.limits.MaxParentOutputCopiesAndTickets
	case ResourceEnvelopePathBytes:
		return c.limits.MaxEnvelopePathBytes
	case ResourceDecodedRecipeBytes:
		return c.limits.MaxDecodedRecipeBytes
	case ResourceGeneratedSignatureSets:
		return c.limits.MaxGeneratedSignatureSets
	case ResourceAuthorizationCalls:
		return c.limits.MaxAuthorizationCalls
	case ResourcePrivateSigningCalls:
		return c.limits.MaxPrivateSigningCalls
	case ResourceNonceBytes:
		return c.limits.MaxNonceBytes
	case ResourceNewInstances:
		return c.limits.MaxNewInstances
	case ResourceNewSignatures:
		return c.limits.RequiredNewSignatures
	default:
		return 0
	}
}

// resourceLimitName maps each operation-wide resource to its closed limit name.
func resourceLimitName(resource Resource) LimitName {
	switch resource {
	case ResourceMessageBytes:
		return LimitNameMaxMessageBytes
	case ResourceHeaderBytes:
		return LimitNameMaxHeaderBytes
	case ResourceHeaderFields:
		return LimitNameMaxHeaderFields
	case ResourceProtocolFields:
		return LimitNameMaxProtocolFields
	case ResourceSignatureSets:
		return LimitNameMaxTotalSignatureSets
	case ResourcePublicKeyLookups:
		return LimitNameMaxPublicKeyLookups
	case ResourceSignatureInputBytes:
		return LimitNameMaxSignatureInputBytes
	case ResourceCanonicalWorkBytes:
		return LimitNameMaxCanonicalWorkBytes
	case ResourceGeneratedRecipients:
		return LimitNameMaxGeneratedRecipients
	case ResourceParentOutputCopiesAndTickets:
		return LimitNameMaxParentOutputCopiesAndTickets
	case ResourceEnvelopePathBytes:
		return LimitNameMaxEnvelopePathBytes
	case ResourceDecodedRecipeBytes:
		return LimitNameMaxDecodedRecipeBytes
	case ResourceGeneratedSignatureSets:
		return LimitNameMaxGeneratedSignatureSets
	case ResourceAuthorizationCalls:
		return LimitNameMaxAuthorizationCalls
	case ResourcePrivateSigningCalls:
		return LimitNameMaxPrivateSigningCalls
	case ResourceNonceBytes:
		return LimitNameMaxNonceBytes
	case ResourceNewInstances:
		return LimitNameMaxNewInstances
	case ResourceNewSignatures:
		return LimitNameRequiredNewSignatures
	default:
		return ""
	}
}

// mustResourceIndex returns the index of one compile-time known resource.
func mustResourceIndex(resource Resource) int {
	index, _ := resourceIndex(resource)
	return index
}

// resourceIndex returns the stable array index for resource.
func resourceIndex(resource Resource) (int, bool) {
	for index, candidate := range resources {
		if candidate == resource {
			return index, true
		}
	}
	return 0, false
}
