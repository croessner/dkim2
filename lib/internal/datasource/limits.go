package datasource

// Limits bounds every datasource construction and parsing resource.
type Limits struct {
	MaxIdentifierBytes       int
	MaxDomainBytes           int
	MaxDomainLabels          int
	MaxSelectorBytes         int
	MaxSelectorLabels        int
	MaxProfiles              int
	MaxCredentialsPerProfile int
	MaxHandles               int
	MaxPolicies              int
	MaxJSONFileBytes         int
	MaxJSONDepth             int
	MaxJSONStringBytes       int
	MaxDecodedStringBytes    int
	MaxDecodedPublicKeyBytes int
	MaxRecords               int
}

// HardLimits returns every non-widenable datasource maximum.
func HardLimits() Limits {
	return Limits{
		MaxIdentifierBytes: 128, MaxDomainBytes: 253, MaxDomainLabels: 127,
		MaxSelectorBytes: 253, MaxSelectorLabels: 127, MaxProfiles: 131072,
		MaxCredentialsPerProfile: 2, MaxHandles: 262144, MaxPolicies: 262144,
		MaxJSONFileBytes: 512 << 20, MaxJSONDepth: 16, MaxJSONStringBytes: 16 << 10,
		MaxDecodedStringBytes: 512 << 20, MaxDecodedPublicKeyBytes: 2048, MaxRecords: 1 << 20,
	}
}

// DefaultLimits returns the restrictive default datasource limits.
func DefaultLimits() Limits {
	limits := HardLimits()
	limits.MaxProfiles = 1024
	limits.MaxHandles = 2048
	limits.MaxPolicies = 4096
	limits.MaxJSONFileBytes = 1 << 20
	limits.MaxDecodedStringBytes = 1 << 20
	limits.MaxRecords = 9216
	return limits
}

// ProductionLimits returns the finite large-installation profile.
func ProductionLimits() Limits {
	limits := HardLimits()
	limits.MaxProfiles = 32768
	limits.MaxHandles = 65536
	limits.MaxPolicies = 65536
	limits.MaxJSONFileBytes = 128 << 20
	limits.MaxDecodedStringBytes = 128 << 20
	limits.MaxRecords = 229376
	return limits
}

// Validate rejects zero, negative, or widened limits.
func (l Limits) Validate() error {
	hard := HardLimits()
	values := []struct{ value, maximum int }{
		{l.MaxIdentifierBytes, hard.MaxIdentifierBytes}, {l.MaxDomainBytes, hard.MaxDomainBytes},
		{l.MaxDomainLabels, hard.MaxDomainLabels}, {l.MaxSelectorBytes, hard.MaxSelectorBytes},
		{l.MaxSelectorLabels, hard.MaxSelectorLabels}, {l.MaxProfiles, hard.MaxProfiles},
		{l.MaxCredentialsPerProfile, hard.MaxCredentialsPerProfile}, {l.MaxHandles, hard.MaxHandles},
		{l.MaxPolicies, hard.MaxPolicies}, {l.MaxJSONFileBytes, hard.MaxJSONFileBytes},
		{l.MaxJSONDepth, hard.MaxJSONDepth}, {l.MaxJSONStringBytes, hard.MaxJSONStringBytes},
		{l.MaxDecodedStringBytes, hard.MaxDecodedStringBytes},
		{l.MaxDecodedPublicKeyBytes, hard.MaxDecodedPublicKeyBytes}, {l.MaxRecords, hard.MaxRecords},
	}
	for _, candidate := range values {
		if candidate.value <= 0 || candidate.value > candidate.maximum {
			return NewError(ErrorCodeInvalidRequest)
		}
	}
	return nil
}

// Usage contains bounded datasource work counters.
type Usage struct {
	profiles    int
	credentials int
	handles     int
	policies    int
	records     int
	bytes       int
}

// NewUsage constructs one internally consistent bounded usage value.
func NewUsage(profiles, credentials, handles, policies, bytes int, limits Limits) (Usage, error) {
	if err := limits.Validate(); err != nil {
		return Usage{}, err
	}
	if profiles < 0 || credentials < 0 || handles < 0 || policies < 0 || bytes < 0 {
		return Usage{}, NewError(ErrorCodeInvalidRequest)
	}
	records, ok := checkedAdd(profiles, credentials, limits.MaxRecords)
	if ok {
		records, ok = checkedAdd(records, handles, limits.MaxRecords)
	}
	if ok {
		records, ok = checkedAdd(records, policies, limits.MaxRecords)
	}
	if !ok || profiles > limits.MaxProfiles ||
		credentials > limits.MaxProfiles*limits.MaxCredentialsPerProfile ||
		handles > limits.MaxHandles || policies > limits.MaxPolicies ||
		bytes > limits.MaxDecodedStringBytes {
		return Usage{}, NewError(ErrorCodeLimitExceeded)
	}
	return Usage{
		profiles: profiles, credentials: credentials, handles: handles,
		policies: policies, records: records, bytes: bytes,
	}, nil
}

// Add returns checked aggregate usage under the supplied limits.
func (u Usage) Add(other Usage, limits Limits) (Usage, error) {
	if err := limits.Validate(); err != nil {
		return Usage{}, err
	}
	if !u.valid(limits) || !other.valid(limits) {
		return Usage{}, NewError(ErrorCodeInvalidRequest)
	}
	profiles, ok := checkedAdd(u.profiles, other.profiles, limits.MaxProfiles)
	if !ok {
		return Usage{}, NewError(ErrorCodeLimitExceeded)
	}
	credentials, ok := checkedAdd(
		u.credentials,
		other.credentials,
		limits.MaxProfiles*limits.MaxCredentialsPerProfile,
	)
	if !ok {
		return Usage{}, NewError(ErrorCodeLimitExceeded)
	}
	handles, ok := checkedAdd(u.handles, other.handles, limits.MaxHandles)
	if !ok {
		return Usage{}, NewError(ErrorCodeLimitExceeded)
	}
	policies, ok := checkedAdd(u.policies, other.policies, limits.MaxPolicies)
	if !ok {
		return Usage{}, NewError(ErrorCodeLimitExceeded)
	}
	bytes, ok := checkedAdd(u.bytes, other.bytes, limits.MaxDecodedStringBytes)
	if !ok {
		return Usage{}, NewError(ErrorCodeLimitExceeded)
	}
	return NewUsage(profiles, credentials, handles, policies, bytes, limits)
}

// ValidForLimits reports whether every usage counter satisfies one datasource contract.
func (u Usage) ValidForLimits(limits Limits) bool { return u.valid(limits) }

// valid reports whether usage counters and their derived record total agree.
func (u Usage) valid(limits Limits) bool {
	rebuilt, err := NewUsage(u.profiles, u.credentials, u.handles, u.policies, u.bytes, limits)
	return err == nil && rebuilt == u
}

// Profiles returns the bounded profile count.
func (u Usage) Profiles() int { return u.profiles }

// Credentials returns the bounded credential count.
func (u Usage) Credentials() int { return u.credentials }

// Handles returns the bounded handle count.
func (u Usage) Handles() int { return u.handles }

// Policies returns the bounded policy count.
func (u Usage) Policies() int { return u.policies }

// Records returns the derived provider-record work count.
func (u Usage) Records() int { return u.records }

// Bytes returns the bounded decoded-string byte count.
func (u Usage) Bytes() int { return u.bytes }

// checkedAdd adds nonnegative counters without overflow or limit widening.
func checkedAdd(left, right, maximum int) (int, bool) {
	if left < 0 || right < 0 || left > maximum || right > maximum-left {
		return 0, false
	}
	return left + right, true
}
