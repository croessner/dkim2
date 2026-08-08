// Package provider exposes storage-neutral datasource construction and lookup.
//
// Concrete LDAP and SQL implementations remain service-owned. This package is
// deliberately a narrow bridge to the library's authoritative datasource
// validators and immutable in-memory snapshot.
package provider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/internal/datasource"
	"github.com/croessner/dkim2/internal/datasource/memory"
	"github.com/croessner/dkim2/internal/datasource/signingprofile"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/niliface"
)

const redacted = "dkim2.provider{redacted}"

// ErrorCode is one stable storage-neutral datasource failure class.
type ErrorCode = datasource.ErrorCode

const (
	// ErrorCodeInvalidRequest classifies invalid or incomplete input.
	ErrorCodeInvalidRequest = datasource.ErrorCodeInvalidRequest
	// ErrorCodeNotFound classifies an absent exact record.
	ErrorCodeNotFound = datasource.ErrorCodeNotFound
	// ErrorCodeAmbiguous classifies duplicate exact records.
	ErrorCodeAmbiguous = datasource.ErrorCodeAmbiguous
	// ErrorCodeInactive classifies an administratively inactive record.
	ErrorCodeInactive = datasource.ErrorCodeInactive
	// ErrorCodeMalformedData classifies invalid persisted data.
	ErrorCodeMalformedData = datasource.ErrorCodeMalformedData
	// ErrorCodeLimitExceeded classifies an exceeded resource bound.
	ErrorCodeLimitExceeded = datasource.ErrorCodeLimitExceeded
	// ErrorCodeUnavailable classifies an unavailable safe snapshot.
	ErrorCodeUnavailable = datasource.ErrorCodeUnavailable
	// ErrorCodeUnsupportedPlatform classifies a missing required platform primitive.
	ErrorCodeUnsupportedPlatform = datasource.ErrorCodeUnsupportedPlatform
	// ErrorCodeCancelled classifies caller cancellation.
	ErrorCodeCancelled = datasource.ErrorCodeCancelled
	// ErrorCodeDeadlineExceeded classifies an elapsed caller deadline.
	ErrorCodeDeadlineExceeded = datasource.ErrorCodeDeadlineExceeded
	// ErrorCodeInternalInvariant classifies an impossible provider outcome.
	ErrorCodeInternalInvariant = datasource.ErrorCodeInternalInvariant
)

// ErrorCodeOf returns the stable direct class for one storage-neutral provider error.
func ErrorCodeOf(err error) (code ErrorCode) {
	code = datasource.ErrorCodeInternalInvariant
	coded, ok := err.(interface{ Code() ErrorCode })
	if !ok || niliface.IsNil(coded) {
		return code
	}
	defer func() {
		if recover() != nil {
			code = datasource.ErrorCodeInternalInvariant
		}
	}()
	if candidate := coded.Code(); candidate.Known() {
		return candidate
	}
	return code
}

// NewError constructs one content-free storage-neutral provider failure.
func NewError(code ErrorCode) error { return datasource.NewError(code) }

// Limits bounds datasource construction and loading work.
type Limits = datasource.Limits

// HardLimits returns every non-widenable datasource maximum.
func HardLimits() Limits { return datasource.HardLimits() }

// DefaultLimits returns the restrictive default datasource limits.
func DefaultLimits() Limits { return datasource.DefaultLimits() }

// ProductionLimits returns the finite large-installation datasource profile.
func ProductionLimits() Limits { return datasource.ProductionLimits() }

// ValidateDomainSelector validates one canonical DNS signing identity.
func ValidateDomainSelector(domain, selector string, algorithm Algorithm) error {
	limits := keyresolver.DefaultLimits()
	query, err := keyresolver.NewQuery(domain, selector, algorithm, limits)
	if err != nil || query.SigningDomain() != domain || query.Selector() != selector {
		return datasource.NewError(datasource.ErrorCodeMalformedData)
	}
	return nil
}

// Algorithm identifies one supported signing credential algorithm.
type Algorithm = datasource.Algorithm

const (
	// AlgorithmRSASHA256 identifies RSA-SHA256 credentials.
	AlgorithmRSASHA256 = datasource.AlgorithmRSASHA256
	// AlgorithmEd25519SHA256 identifies Ed25519-SHA256 credentials.
	AlgorithmEd25519SHA256 = datasource.AlgorithmEd25519SHA256
)

// ProfileUse identifies one administrative profile-selection purpose.
type ProfileUse = datasource.ProfileUse

const (
	// ProfileUseOriginator selects an originator profile.
	ProfileUseOriginator = datasource.ProfileUseOriginator
	// ProfileUseOrdinaryTransit selects an ordinary-transit profile.
	ProfileUseOrdinaryTransit = datasource.ProfileUseOrdinaryTransit
	// ProfileUseNextDomainTransit selects a next-domain profile.
	ProfileUseNextDomainTransit = datasource.ProfileUseNextDomainTransit
	// ProfileUseDeliveryStatus selects a delivery-status profile.
	ProfileUseDeliveryStatus = datasource.ProfileUseDeliveryStatus
)

// ParseProfileUse parses one exact closed profile-use value.
func ParseProfileUse(value string) (ProfileUse, error) {
	return datasource.ParseProfileUse(value)
}

// RecordStatus identifies one administrative record state.
type RecordStatus = datasource.RecordStatus

const (
	// RecordStatusActive permits an otherwise authorized record.
	RecordStatusActive = datasource.RecordStatusActive
	// RecordStatusDisabled closes an administrative record.
	RecordStatusDisabled = datasource.RecordStatusDisabled
)

// ParseRecordStatus parses one exact closed record status.
func ParseRecordStatus(value string) (RecordStatus, error) {
	return datasource.ParseRecordStatus(value)
}

// Rollout identifies one closed administrative rollout state.
type Rollout = datasource.Rollout

const (
	// RolloutEnforce permits signing after all other checks.
	RolloutEnforce = datasource.RolloutEnforce
	// RolloutObserve resolves without permitting signing.
	RolloutObserve = datasource.RolloutObserve
	// RolloutOff disables the administrative binding.
	RolloutOff = datasource.RolloutOff
)

// ParseRollout parses one exact closed rollout value.
func ParseRollout(value string) (Rollout, error) { return datasource.ParseRollout(value) }

// Compatibility identifies one closed compatibility policy.
type Compatibility = datasource.Compatibility

const (
	// CompatibilityStrict requires the exact provider contract.
	CompatibilityStrict = datasource.CompatibilityStrict
)

// ParseCompatibility parses one exact closed compatibility value.
func ParseCompatibility(value string) (Compatibility, error) {
	return datasource.ParseCompatibility(value)
}

// Credential contains one immutable public signing credential and opaque handle.
type Credential struct {
	value datasource.Credential
}

// NewCredential validates and detaches one storage-neutral credential.
func NewCredential(
	selector string,
	algorithm Algorithm,
	publicKeySPKI []byte,
	handleID string,
	limits Limits,
) (Credential, error) {
	handle, err := datasource.NewKeyHandleID(handleID)
	if err != nil {
		return Credential{}, err
	}
	value, err := datasource.NewCredential(selector, algorithm, publicKeySPKI, handle, limits)
	if err != nil {
		return Credential{}, err
	}
	return Credential{value: value}, nil
}

// Valid reports whether the credential remains complete.
func (c Credential) Valid() bool { return c.value.Valid() }

// Selector returns the canonical selector.
func (c Credential) Selector() string { return c.value.Selector() }

// Algorithm returns the credential algorithm.
func (c Credential) Algorithm() Algorithm { return c.value.Algorithm() }

// PublicKeySPKIDER returns detached canonical public SPKI DER.
func (c Credential) PublicKeySPKIDER() []byte { return c.value.PublicKeySPKIDER() }

// KeyHandleIDEqual reports whether the credential owns the exact opaque ID.
func (c Credential) KeyHandleIDEqual(value string) bool {
	handle, err := datasource.NewKeyHandleID(value)
	return err == nil && c.value.KeyHandleID() == handle
}

// String returns a constant protected credential summary.
func (Credential) String() string { return redacted }

// GoString returns a constant protected credential representation.
func (Credential) GoString() string { return redacted }

// Format prevents formatting verbs from exposing credential facts.
func (Credential) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without credential facts.
func (Credential) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Profile contains one immutable complete datasource signing profile.
type Profile struct {
	value datasource.Profile
}

// NewProfile validates and detaches one complete storage-neutral profile.
func NewProfile(
	id string,
	domain string,
	status RecordStatus,
	credentials []Credential,
	notBefore time.Time,
	notAfter time.Time,
	limits Limits,
) (Profile, error) {
	profileID, err := datasource.NewProfileID(id)
	if err != nil {
		return Profile{}, err
	}
	internal := make([]datasource.Credential, len(credentials))
	for index := range credentials {
		internal[index] = credentials[index].value
	}
	value, err := datasource.NewProfile(
		profileID, domain, status, internal, notBefore, notAfter, limits,
	)
	if err != nil {
		return Profile{}, err
	}
	return Profile{value: value}, nil
}

// Valid reports whether the profile remains complete.
func (p Profile) Valid() bool { return p.value.Valid() }

// SigningDomain returns the canonical signing domain.
func (p Profile) SigningDomain() string { return p.value.SigningDomain() }

// Status returns the closed administrative profile state.
func (p Profile) Status() RecordStatus { return p.value.Status() }

// Credentials returns detached profile credentials.
func (p Profile) Credentials() []Credential {
	values := p.value.Credentials()
	output := make([]Credential, len(values))
	for index := range values {
		output[index] = Credential{value: values[index]}
	}
	return output
}

// ValidityWindow returns the optional half-open UTC validity window.
func (p Profile) ValidityWindow() (time.Time, time.Time, bool) {
	return p.value.ValidityWindow()
}

// IDMatches reports whether the profile has the exact opaque profile ID.
func (p Profile) IDMatches(value string) bool {
	id, err := datasource.NewProfileID(value)
	return err == nil && p.value.ID() == id
}

// String returns a constant protected profile summary.
func (Profile) String() string { return redacted }

// GoString returns a constant protected profile representation.
func (Profile) GoString() string { return redacted }

// Format prevents formatting verbs from exposing profile facts.
func (Profile) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without profile facts.
func (Profile) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Policy contains one immutable exact administrative profile binding.
type Policy struct {
	value datasource.Policy
}

// NewPolicy validates one exact storage-neutral policy binding.
func NewPolicy(
	tenant string,
	domain string,
	use ProfileUse,
	profileID string,
	status RecordStatus,
	rollout Rollout,
	compatibility Compatibility,
	feedbackRouteID string,
	limits Limits,
) (Policy, error) {
	tenantID, err := datasource.NewTenantID(tenant)
	if err != nil {
		return Policy{}, err
	}
	id, err := datasource.NewProfileID(profileID)
	if err != nil {
		return Policy{}, err
	}
	var feedback datasource.FeedbackRouteID
	if feedbackRouteID != "" {
		feedback, err = datasource.NewFeedbackRouteID(feedbackRouteID)
		if err != nil {
			return Policy{}, err
		}
	}
	value, err := datasource.NewPolicy(
		tenantID, domain, use, id, status, rollout, compatibility, feedback, limits,
	)
	if err != nil {
		return Policy{}, err
	}
	return Policy{value: value}, nil
}

// Valid reports whether the policy remains complete.
func (p Policy) Valid() bool { return p.value.Valid() }

// SigningDomain returns the canonical policy signing domain.
func (p Policy) SigningDomain() string { return p.value.SigningDomain() }

// Use returns the exact administrative use.
func (p Policy) Use() ProfileUse { return p.value.Use() }

// String returns a constant protected policy summary.
func (Policy) String() string { return redacted }

// GoString returns a constant protected policy representation.
func (Policy) GoString() string { return redacted }

// Format prevents formatting verbs from exposing policy facts.
func (Policy) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without policy facts.
func (Policy) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Dataset is one complete immutable storage-neutral datasource generation.
type Dataset struct {
	generation uint64
	provider   *memory.Provider
}

// Binding is one opaque datasource-credential to private-signer declaration.
type Binding struct {
	value signingprofile.Binding
}

// Equivalent reports whether two valid bindings contain the exact same
// protected projection facts without exposing them.
func (b Binding) Equivalent(other Binding) bool {
	return b.value.Valid() && other.value.Valid() && b.value == other.value
}

// NewBinding validates one exact storage-neutral signing projection binding.
func NewBinding(
	tenant string,
	domain string,
	use ProfileUse,
	handleID string,
	handle dkim2.PrivateKeyHandle,
	algorithm Algorithm,
	publicDigest [sha256.Size]byte,
) (Binding, error) {
	projected, err := dkim2.ProjectedPrivateKeyHandle(handle)
	if err != nil {
		return Binding{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	value, err := signingprofile.NewBinding(
		tenant, domain, use.String(), handleID, projected,
		string(algorithm), publicDigest,
	)
	if err != nil {
		return Binding{}, err
	}
	return Binding{value: value}, nil
}

// String returns a constant protected binding summary.
func (Binding) String() string { return redacted }

// GoString returns a constant protected binding representation.
func (Binding) GoString() string { return redacted }

// Format prevents formatting verbs from exposing binding facts.
func (Binding) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without binding facts.
func (Binding) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// SigningResolver owns one immutable dataset and its exact signer projection.
type SigningResolver struct {
	value *signingprofile.Resolver
}

// NewSigningResolver validates all private registry bindings against this dataset.
func (d *Dataset) NewSigningResolver(
	bindings []Binding,
	at time.Time,
) (*SigningResolver, error) {
	if !d.Valid() || len(bindings) == 0 || at.IsZero() {
		return nil, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	internal := make([]signingprofile.Binding, len(bindings))
	for index := range bindings {
		internal[index] = bindings[index].value
	}
	value, err := signingprofile.NewResolver(d.provider, internal, at)
	if err != nil {
		return nil, err
	}
	return &SigningResolver{value: value}, nil
}

// ResolvePolicy resolves one exact policy into the public signing profile.
func (r *SigningResolver) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use ProfileUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	if r == nil || r.value == nil || ctx == nil || at.IsZero() {
		return dkim2.SigningProfile{}, datasource.NewError(datasource.ErrorCodeInvalidRequest)
	}
	projected, err := r.value.ResolvePolicy(ctx, tenant, domain, use.String(), at)
	if err != nil {
		return dkim2.SigningProfile{}, err
	}
	return dkim2.NewProjectedSigningProfile(projected)
}

// Close releases the immutable signing projection.
func (r *SigningResolver) Close(ctx context.Context) error {
	if r == nil || r.value == nil {
		return nil
	}
	return r.value.Close(ctx)
}

// String returns a constant protected signing-resolver summary.
func (*SigningResolver) String() string { return redacted }

// GoString returns a constant protected signing-resolver representation.
func (*SigningResolver) GoString() string { return redacted }

// Format prevents formatting verbs from exposing resolver facts.
func (*SigningResolver) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redacted)
}

// MarshalJSON emits an empty object without resolver facts.
func (*SigningResolver) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// NewDataset validates and owns one complete immutable generation.
func NewDataset(
	generation uint64,
	handleIDs []string,
	profiles []Profile,
	policies []Policy,
	limits Limits,
) (*Dataset, error) {
	handles := make([]datasource.KeyHandleID, len(handleIDs))
	for index, value := range handleIDs {
		handle, err := datasource.NewKeyHandleID(value)
		if err != nil {
			return nil, err
		}
		handles[index] = handle
	}
	internalProfiles := make([]datasource.Profile, len(profiles))
	for index := range profiles {
		internalProfiles[index] = profiles[index].value
	}
	internalPolicies := make([]datasource.Policy, len(policies))
	for index := range policies {
		internalPolicies[index] = policies[index].value
	}
	immutable, err := memory.New(
		generation, handles, internalProfiles, internalPolicies, limits,
	)
	if err != nil {
		return nil, err
	}
	return &Dataset{generation: generation, provider: immutable}, nil
}

// Valid reports whether the dataset owns one complete immutable snapshot.
func (d *Dataset) Valid() bool {
	return d != nil && d.generation != 0 && d.provider != nil && d.provider.Valid()
}

// Generation returns the exact immutable generation number.
func (d *Dataset) Generation() uint64 {
	if !d.Valid() {
		return 0
	}
	return d.generation
}

// Equivalent reports whether two valid datasets contain the exact same
// immutable generation facts without exposing those facts.
func (d *Dataset) Equivalent(other *Dataset) bool {
	return d.Valid() && other.Valid() &&
		d.generation == other.generation &&
		d.provider.Equivalent(other.provider)
}

// ResolveProfile resolves one exact profile without backend I/O.
func (d *Dataset) ResolveProfile(
	ctx context.Context,
	profileID string,
	use ProfileUse,
	at time.Time,
) (Profile, error) {
	if !d.Valid() {
		return Profile{}, datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	id, err := datasource.NewProfileID(profileID)
	if err != nil {
		return Profile{}, err
	}
	request, err := datasource.NewProfileRequest(id, use, at, datasource.DefaultLimits())
	if err != nil {
		return Profile{}, err
	}
	result, err := d.provider.ResolveProfile(ctx, request)
	if err != nil {
		return Profile{}, err
	}
	return Profile{value: result.Profile()}, nil
}

// ResolvePolicy resolves one exact policy and embedded profile without backend I/O.
func (d *Dataset) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use ProfileUse,
	at time.Time,
) (Policy, Profile, error) {
	if !d.Valid() {
		return Policy{}, Profile{}, datasource.NewError(datasource.ErrorCodeUnavailable)
	}
	tenantID, err := datasource.NewTenantID(tenant)
	if err != nil {
		return Policy{}, Profile{}, err
	}
	request, err := datasource.NewPolicyRequest(
		tenantID, domain, use, at, datasource.DefaultLimits(),
	)
	if err != nil {
		return Policy{}, Profile{}, err
	}
	result, err := d.provider.ResolvePolicy(ctx, request)
	if err != nil {
		return Policy{}, Profile{}, err
	}
	return Policy{value: result.Policy()}, Profile{value: result.Profile()}, nil
}

// String returns a constant protected dataset summary.
func (*Dataset) String() string { return redacted }

// GoString returns a constant protected dataset representation.
func (*Dataset) GoString() string { return redacted }

// Format prevents formatting verbs from traversing dataset state.
func (*Dataset) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without dataset facts.
func (*Dataset) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
