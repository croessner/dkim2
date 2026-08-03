package datasourceadmin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/provider"
)

const (
	planDigestDomain       = "DKIM2-DOMAIN-PLAN-V1\x00"
	candidateDigestDomain  = "DKIM2-CANDIDATE-CONTENT-V1\x00"
	domainIntentVersionV1  = "dkim2-domain-intent-v1"
	recordStatusActive     = "active"
	resolverClassSystem    = "system"
	resolverClassRecursive = "recursive"
	algorithmEd25519SHA256 = string(provider.AlgorithmEd25519SHA256)
	algorithmRSASHA256     = string(provider.AlgorithmRSASHA256)
	profileUseOriginator   = "originator"
	rolloutEnforce         = "enforce"
	compatibilityStrict    = "strict"
)

// PlanDigest is the key-free operation-plan identity.
type PlanDigest struct{ value [sha256.Size]byte }

// CandidateContentDigest is the immutable full-candidate identity.
type CandidateContentDigest struct{ value [sha256.Size]byte }

// ParsePlanDigest validates and detaches one exact stored plan digest.
func ParsePlanDigest(value []byte) (PlanDigest, error) {
	if len(value) != sha256.Size {
		return PlanDigest{}, newError(CodeInvalid)
	}
	var digest PlanDigest
	copy(digest.value[:], value)
	if !digest.Valid() {
		return PlanDigest{}, newError(CodeInvalid)
	}
	return digest, nil
}

// ParseCandidateContentDigest validates and detaches one exact stored digest.
func ParseCandidateContentDigest(value []byte) (CandidateContentDigest, error) {
	if len(value) != sha256.Size {
		return CandidateContentDigest{}, newError(CodeInvalid)
	}
	var digest CandidateContentDigest
	copy(digest.value[:], value)
	if !digest.Valid() {
		return CandidateContentDigest{}, newError(CodeInvalid)
	}
	return digest, nil
}

// BackendClass identifies one closed administrative provider family.
type BackendClass string

const (
	// BackendLDAP identifies the LDAP administrative provider.
	BackendLDAP BackendClass = "ldap"
	// BackendPostgreSQL identifies the PostgreSQL administrative provider.
	BackendPostgreSQL BackendClass = "postgresql"
	// BackendMySQL identifies the MySQL administrative provider.
	BackendMySQL BackendClass = "mysql"
	// BackendMariaDB identifies the MariaDB administrative provider.
	BackendMariaDB BackendClass = "mariadb"
)

// AuthorityEndpoint is one ordered canonical verified-TLS provider endpoint.
type AuthorityEndpoint struct {
	Scheme        string
	Host          string
	Port          uint16
	TLSServerName string
}

// LDAPAuthority is the exact base and three-principal administrative binding.
type LDAPAuthority struct {
	BaseDN              string
	SnapshotPrincipal   string
	StagingPrincipal    string
	ActivationPrincipal string
}

// SQLAuthority is the exact database/schema and three-role administrative binding.
type SQLAuthority struct {
	Database       string
	Schema         string
	SnapshotRole   string
	StagingRole    string
	ActivationRole string
}

// AuthorityDescriptor is one protected canonical provider authority binding.
type AuthorityDescriptor struct {
	AuthorityID                  string
	Endpoints                    []AuthorityEndpoint
	LDAP                         *LDAPAuthority
	SQL                          *SQLAuthority
	TrustFingerprints            [][sha256.Size]byte
	ClientCertificateFingerprint *[sha256.Size]byte
}

// ValidateAuthority rejects a backend descriptor outside the canonical authority grammar.
func ValidateAuthority(backend BackendClass, descriptor AuthorityDescriptor) error {
	if !validAuthority(backend, descriptor) {
		return newError(CodeInvalid)
	}
	return nil
}

// ValidateDNSPolicy rejects resolver and proof policy outside the canonical plan grammar.
func ValidateDNSPolicy(policy DNSPolicy) error {
	if !validDNSPolicy(policy) {
		return newError(CodeInvalid)
	}
	return nil
}

// PlanIntent is the canonical key-free domain intent projection.
type PlanIntent struct {
	Version       string
	Domain        string
	TenantID      string
	ProfileUse    string
	Algorithms    []string
	Rollout       string
	Compatibility string
}

// AllocatedCredential is one algorithm-sorted key-free selector allocation.
type AllocatedCredential struct {
	Algorithm string
	HandleID  string
	Selector  string
}

// DNSPolicy is the exact key-proof policy bound into a plan.
type DNSPolicy struct {
	ResolverClass        string
	ResolverEndpoints    []string
	ExportTTLSeconds     uint64
	ProofLifetimeSeconds uint64
}

// PlanProjection is the complete typed key-free plan digest input.
type PlanProjection struct {
	Backend             BackendClass
	Authority           AuthorityDescriptor
	ExpectedCurrent     uint64
	Current             *PlanSource
	Intent              PlanIntent
	ProfileID           string
	Credentials         []AllocatedCredential
	CandidateGeneration uint64
	DNS                 DNSPolicy
	OperationID         string
}

// NewPlanDigest validates and hashes the exact typed key-free plan grammar.
func NewPlanDigest(projection PlanProjection) (PlanDigest, error) {
	if !validPlanProjection(projection) {
		return PlanDigest{}, newError(CodeInvalid)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(planDigestDomain))
	writeFramedString(hash, "dkim2-domain-operation-v1")
	writeFramedString(hash, SchemaVersionV3)
	writeFramedString(hash, string(projection.Backend))
	writeAuthorityDescriptor(hash, projection.Authority)
	writeUint64(hash, projection.ExpectedCurrent)
	if projection.Current == nil {
		_, _ = hash.Write([]byte{0})
	} else {
		_, _ = hash.Write([]byte{1})
		writeFramedString(hash, projection.Current.SchemaVersion())
		writeUint64(hash, projection.Current.Generation())
		writeFramedString(hash, "committed")
		if err := projection.Current.WithRows(context.Background(), func(rows Rows) error {
			writeSourceRows(hash, rows)
			return nil
		}); err != nil {
			return PlanDigest{}, err
		}
	}
	writeFramedString(hash, projection.Intent.Version)
	writeFramedString(hash, projection.Intent.Domain)
	writeFramedString(hash, projection.Intent.TenantID)
	writeFramedString(hash, projection.Intent.ProfileUse)
	writeCount(hash, len(projection.Intent.Algorithms))
	for _, algorithm := range projection.Intent.Algorithms {
		writeFramedString(hash, algorithm)
	}
	writeFramedString(hash, projection.Intent.Rollout)
	writeFramedString(hash, projection.Intent.Compatibility)
	writeFramedString(hash, projection.ProfileID)
	writeCount(hash, len(projection.Credentials))
	for _, credential := range projection.Credentials {
		writeFramedString(hash, credential.Algorithm)
		writeFramedString(hash, credential.HandleID)
		writeFramedString(hash, credential.Selector)
	}
	writeUint64(hash, projection.CandidateGeneration)
	writeFramedString(hash, projection.DNS.ResolverClass)
	writeCount(hash, len(projection.DNS.ResolverEndpoints))
	for _, endpoint := range projection.DNS.ResolverEndpoints {
		writeFramedString(hash, endpoint)
	}
	writeUint64(hash, projection.DNS.ExportTTLSeconds)
	writeUint64(hash, projection.DNS.ProofLifetimeSeconds)
	writeFramedString(hash, projection.OperationID)
	var value [sha256.Size]byte
	copy(value[:], hash.Sum(nil))
	return PlanDigest{value: value}, nil
}

// validPlanProjection enforces closed vocabulary, ordering, and generation fences.
func validPlanProjection(plan PlanProjection) bool {
	if !validPlanShape(plan) {
		return false
	}
	if !validAuthority(plan.Backend, plan.Authority) || !validPlanIntent(plan.Intent, plan.ProfileID, plan.Credentials) ||
		!validDNSPolicy(plan.DNS) {
		return false
	}
	return validPlanGenerationFence(plan) && validAllocatedCredentials(plan.Intent.Algorithms, plan.Credentials)
}

// validPlanShape validates closed scalar and collection preconditions.
func validPlanShape(plan PlanProjection) bool {
	backendKnown := plan.Backend == BackendLDAP || plan.Backend == BackendPostgreSQL ||
		plan.Backend == BackendMySQL || plan.Backend == BackendMariaDB
	return validOperationID(plan.OperationID) && validOperationID(plan.Authority.AuthorityID) && backendKnown &&
		plan.Intent.Version == domainIntentVersionV1 && plan.Intent.Domain != "" && plan.Intent.TenantID != "" &&
		plan.Intent.ProfileUse != "" && plan.Intent.Rollout != "" && plan.Intent.Compatibility != "" &&
		plan.ProfileID != "" && len(plan.Credentials) > 0 && len(plan.Credentials) <= 2 &&
		len(plan.Intent.Algorithms) == len(plan.Credentials) && plan.CandidateGeneration != 0 &&
		plan.DNS.ExportTTLSeconds != 0 && plan.DNS.ProofLifetimeSeconds != 0
}

// validPlanGenerationFence validates empty and established current projections.
func validPlanGenerationFence(plan PlanProjection) bool {
	if (plan.Current == nil) != (plan.ExpectedCurrent == 0) {
		return false
	}
	return plan.Current == nil ||
		plan.Current.Generation() == plan.ExpectedCurrent && plan.CandidateGeneration > plan.ExpectedCurrent
}

// validAllocatedCredentials validates exact ordered intent-to-allocation correspondence.
func validAllocatedCredentials(algorithms []string, credentials []AllocatedCredential) bool {
	for index := range credentials {
		credential := credentials[index]
		if credential.Algorithm == "" || credential.HandleID == "" || credential.Selector == "" ||
			credential.Algorithm != algorithms[index] || index > 0 && credentials[index-1].Algorithm >= credential.Algorithm {
			return false
		}
	}
	return true
}

// validAuthority validates exact backend-conditioned typed descriptor fields.
func validAuthority(backend BackendClass, descriptor AuthorityDescriptor) bool {
	if len(descriptor.Endpoints) == 0 || len(descriptor.Endpoints) > 8 || len(descriptor.TrustFingerprints) == 0 || len(descriptor.TrustFingerprints) > 128 {
		return false
	}
	if descriptor.ClientCertificateFingerprint != nil && *descriptor.ClientCertificateFingerprint == [sha256.Size]byte{} {
		return false
	}
	seenEndpoints := make(map[AuthorityEndpoint]struct{}, len(descriptor.Endpoints))
	for _, endpoint := range descriptor.Endpoints {
		if !validAuthorityEndpoint(backend, endpoint) {
			return false
		}
		if _, duplicate := seenEndpoints[endpoint]; duplicate {
			return false
		}
		seenEndpoints[endpoint] = struct{}{}
	}
	seenTrust := make(map[[sha256.Size]byte]struct{}, len(descriptor.TrustFingerprints))
	for _, fingerprint := range descriptor.TrustFingerprints {
		if _, duplicate := seenTrust[fingerprint]; duplicate || fingerprint == [sha256.Size]byte{} {
			return false
		}
		seenTrust[fingerprint] = struct{}{}
	}
	if backend == BackendLDAP {
		return descriptor.LDAP != nil && descriptor.SQL == nil &&
			validBoundedIdentity(descriptor.LDAP.BaseDN, 4096) &&
			validDistinctAuthorities(descriptor.LDAP.SnapshotPrincipal, descriptor.LDAP.StagingPrincipal, descriptor.LDAP.ActivationPrincipal, 4096)
	}
	return descriptor.SQL != nil && descriptor.LDAP == nil &&
		validBoundedIdentity(descriptor.SQL.Database, 128) && validBoundedIdentity(descriptor.SQL.Schema, 128) &&
		validDistinctAuthorities(descriptor.SQL.SnapshotRole, descriptor.SQL.StagingRole, descriptor.SQL.ActivationRole, 128)
}

// validAuthorityEndpoint enforces canonical endpoint and TLS identity syntax.
func validAuthorityEndpoint(backend BackendClass, endpoint AuthorityEndpoint) bool {
	wantScheme := map[BackendClass]string{BackendLDAP: "ldaps", BackendPostgreSQL: "postgresql", BackendMySQL: "mysql", BackendMariaDB: "mariadb"}[backend]
	if endpoint.Scheme != wantScheme || endpoint.Port == 0 || endpoint.Host == "" || endpoint.Host != strings.ToLower(endpoint.Host) ||
		endpoint.TLSServerName == "" || endpoint.TLSServerName != strings.ToLower(endpoint.TLSServerName) || len(endpoint.TLSServerName) > 253 {
		return false
	}
	hostValid := false
	if address, err := netip.ParseAddr(endpoint.Host); err == nil {
		hostValid = address.String() == endpoint.Host && !address.IsUnspecified() && !address.IsMulticast()
	} else {
		hostValid = validAuthorityDNSName(endpoint.Host)
	}
	return hostValid && validAuthorityDNSName(endpoint.TLSServerName)
}

// validAuthorityDNSName reuses the canonical DNS signing-name validator.
func validAuthorityDNSName(value string) bool {
	return strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00') &&
		provider.ValidateDomainSelector(value, "authority", provider.AlgorithmEd25519SHA256) == nil
}

// validBoundedIdentity rejects empty, whitespace-bearing, and oversized authority fields.
func validBoundedIdentity(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

// validDistinctAuthorities validates the least-privilege three-principal split.
func validDistinctAuthorities(snapshot, staging, activation string, maximum int) bool {
	return validBoundedIdentity(snapshot, maximum) && validBoundedIdentity(staging, maximum) && validBoundedIdentity(activation, maximum) &&
		snapshot != staging && snapshot != activation && staging != activation
}

// validPlanIntent reuses authoritative datasource vocabularies and identity validation.
func validPlanIntent(intent PlanIntent, profileID string, credentials []AllocatedCredential) bool {
	use, err := provider.ParseProfileUse(intent.ProfileUse)
	if err != nil || use != provider.ProfileUseOriginator {
		return false
	}
	rollout, err := provider.ParseRollout(intent.Rollout)
	if err != nil || rollout != provider.RolloutEnforce {
		return false
	}
	compatibility, err := provider.ParseCompatibility(intent.Compatibility)
	if err != nil || compatibility != provider.CompatibilityStrict {
		return false
	}
	if _, err := provider.NewPolicy(intent.TenantID, intent.Domain, use, profileID, provider.RecordStatusActive, rollout, compatibility, "", provider.DefaultLimits()); err != nil {
		return false
	}
	for _, credential := range credentials {
		algorithm := provider.Algorithm(credential.Algorithm)
		if (algorithm != provider.AlgorithmRSASHA256 && algorithm != provider.AlgorithmEd25519SHA256) ||
			provider.ValidateDomainSelector(intent.Domain, credential.Selector, algorithm) != nil ||
			ValidateHandleDeclaration(credential.HandleID) != nil {
			return false
		}
	}
	return true
}

// validDNSPolicy validates resolver class, canonical endpoints, and finite times.
func validDNSPolicy(policy DNSPolicy) bool {
	if policy.ExportTTLSeconds == 0 || policy.ExportTTLSeconds > 604800 || policy.ProofLifetimeSeconds == 0 || policy.ProofLifetimeSeconds > 900 {
		return false
	}
	if policy.ResolverClass == resolverClassSystem {
		return len(policy.ResolverEndpoints) == 0
	}
	if policy.ResolverClass != resolverClassRecursive || len(policy.ResolverEndpoints) == 0 || len(policy.ResolverEndpoints) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(policy.ResolverEndpoints))
	for _, endpoint := range policy.ResolverEndpoints {
		if _, duplicate := seen[endpoint]; duplicate {
			return false
		}
		seen[endpoint] = struct{}{}
		host, port, err := net.SplitHostPort(endpoint)
		number, parseErr := strconv.ParseUint(port, 10, 16)
		if err != nil || parseErr != nil || number == 0 || strconv.FormatUint(number, 10) != port || host == "" || host != strings.ToLower(host) {
			return false
		}
		if address, addressErr := netip.ParseAddr(host); addressErr == nil {
			if address.String() != host || address.IsUnspecified() || address.IsMulticast() {
				return false
			}
		} else if !validAuthorityDNSName(host) {
			return false
		}
	}
	return true
}

// writeAuthorityDescriptor writes the protected ordered provider authority.
func writeAuthorityDescriptor(output hash.Hash, descriptor AuthorityDescriptor) {
	writeFramedString(output, descriptor.AuthorityID)
	writeCount(output, len(descriptor.Endpoints))
	for _, endpoint := range descriptor.Endpoints {
		writeFramedString(output, endpoint.Scheme)
		writeFramedString(output, endpoint.Host)
		writeFramedString(output, strconv.FormatUint(uint64(endpoint.Port), 10))
		writeFramedString(output, endpoint.TLSServerName)
	}
	if descriptor.LDAP != nil {
		writeFramedString(output, descriptor.LDAP.BaseDN)
		writeFramedString(output, descriptor.LDAP.SnapshotPrincipal)
		writeFramedString(output, descriptor.LDAP.StagingPrincipal)
		writeFramedString(output, descriptor.LDAP.ActivationPrincipal)
	} else {
		writeFramedString(output, descriptor.SQL.Database)
		writeFramedString(output, descriptor.SQL.Schema)
		writeFramedString(output, descriptor.SQL.SnapshotRole)
		writeFramedString(output, descriptor.SQL.StagingRole)
		writeFramedString(output, descriptor.SQL.ActivationRole)
	}
	writeCount(output, len(descriptor.TrustFingerprints))
	for _, fingerprint := range descriptor.TrustFingerprints {
		writeFramedBytes(output, fingerprint[:])
	}
	if descriptor.ClientCertificateFingerprint == nil {
		_, _ = output.Write([]byte{0})
	} else {
		_, _ = output.Write([]byte{1})
		writeFramedBytes(output, descriptor.ClientCertificateFingerprint[:])
	}
}

// writeSourceRows writes a current projection while deliberately omitting private PKCS#8.
func writeSourceRows(output hash.Hash, rows Rows) {
	withoutPrivate := cloneRows(rows)
	defer clearRows(&withoutPrivate)
	for index := range withoutPrivate.KeyMaterial {
		clear(withoutPrivate.KeyMaterial[index].PrivatePKCS8)
		withoutPrivate.KeyMaterial[index].PrivatePKCS8 = nil
	}
	writeCandidateRows(output, withoutPrivate, false)
}

// digestCandidate hashes one canonical full private candidate projection.
func digestCandidate(schema string, generation uint64, operation string, rows Rows) CandidateContentDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(candidateDigestDomain))
	writeFramedString(hash, schema)
	writeUint64(hash, generation)
	writeFramedString(hash, operation)
	writeCandidateRows(hash, rows, true)
	var value [sha256.Size]byte
	copy(value[:], hash.Sum(nil))
	return CandidateContentDigest{value: value}
}

// writeCandidateRows writes the fixed class order and canonical row order.
func writeCandidateRows(output hash.Hash, rows Rows, includePrivate bool) {
	handles := append([]HandleRow(nil), rows.Handles...)
	slices.SortFunc(handles, func(a, b HandleRow) int { return bytes.Compare([]byte(a.ID), []byte(b.ID)) })
	writeCount(output, len(handles))
	for _, row := range handles {
		writeFramedString(output, row.ID)
	}
	profiles := append([]ProfileRow(nil), rows.Profiles...)
	slices.SortFunc(profiles, func(a, b ProfileRow) int { return bytes.Compare([]byte(a.ID), []byte(b.ID)) })
	writeCount(output, len(profiles))
	for _, row := range profiles {
		writeFramedString(output, row.ID)
		writeFramedString(output, row.Domain)
		writeFramedString(output, row.Status)
		writeNullable(output, row.NotBeforeUTC)
		writeNullable(output, row.NotAfterUTC)
	}
	credentials := append([]CredentialRow(nil), rows.Credentials...)
	slices.SortFunc(credentials, func(a, b CredentialRow) int {
		if c := bytes.Compare([]byte(a.ProfileID), []byte(b.ProfileID)); c != 0 {
			return c
		}
		return bytes.Compare([]byte(a.Algorithm), []byte(b.Algorithm))
	})
	writeCount(output, len(credentials))
	for _, row := range credentials {
		writeFramedString(output, row.ProfileID)
		writeFramedString(output, row.Algorithm)
		writeFramedString(output, row.Selector)
		writeFramedBytes(output, row.PublicSPKI)
		writeFramedString(output, row.HandleID)
	}
	policies := append([]PolicyRow(nil), rows.Policies...)
	slices.SortFunc(policies, func(a, b PolicyRow) int {
		left, right := a.TenantID+"\x00"+a.Domain+"\x00"+a.Use, b.TenantID+"\x00"+b.Domain+"\x00"+b.Use
		return bytes.Compare([]byte(left), []byte(right))
	})
	writeCount(output, len(policies))
	for _, row := range policies {
		writeFramedString(output, row.TenantID)
		writeFramedString(output, row.Domain)
		writeFramedString(output, row.Use)
		writeFramedString(output, row.ProfileID)
		writeFramedString(output, row.Status)
		writeFramedString(output, row.Rollout)
		writeFramedString(output, row.Compatibility)
		writeNullable(output, row.FeedbackRouteID)
	}
	materials := append([]KeyMaterialRow(nil), rows.KeyMaterial...)
	slices.SortFunc(materials, func(a, b KeyMaterialRow) int { return bytes.Compare([]byte(a.HandleID), []byte(b.HandleID)) })
	writeCount(output, len(materials))
	for _, row := range materials {
		writeFramedString(output, row.TenantID)
		writeFramedString(output, row.Domain)
		writeFramedString(output, row.Use)
		writeFramedString(output, row.HandleID)
		writeFramedString(output, row.Algorithm)
		writeFramedBytes(output, row.PublicSPKI)
		if includePrivate {
			writeFramedBytes(output, row.PrivatePKCS8)
		}
	}
}

// writeCount writes one bounded row count.
func writeCount(output hash.Hash, count int) {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], uint32(count))
	_, _ = output.Write(value[:])
}

// writeUint64 writes one fixed-width generation.
func writeUint64(output hash.Hash, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = output.Write(encoded[:])
}

// writeFramedString writes one canonical UTF-8 or closed ASCII string.
func writeFramedString(output hash.Hash, value string) { writeFramedBytes(output, []byte(value)) }

// writeFramedBytes writes one uint32-length-delimited value.
func writeFramedBytes(output hash.Hash, value []byte) {
	writeCount(output, len(value))
	_, _ = output.Write(value)
}

// writeNullable writes the exact absent/present framing.
func writeNullable(output hash.Hash, value *string) {
	if value == nil {
		_, _ = output.Write([]byte{0})
		return
	}
	_, _ = output.Write([]byte{1})
	writeFramedString(output, *value)
}

// Equal reports whether two plan digests are identical.
func (d PlanDigest) Equal(other PlanDigest) bool {
	return d.Valid() && other.Valid() && subtle.ConstantTimeCompare(d.value[:], other.value[:]) == 1
}

// Equal reports whether two candidate digests are identical.
func (d CandidateContentDigest) Equal(other CandidateContentDigest) bool {
	return subtle.ConstantTimeCompare(d.value[:], other.value[:]) == 1
}

// Valid reports whether the candidate digest is initialized.
func (d CandidateContentDigest) Valid() bool {
	var combined byte
	for _, octet := range d.value {
		combined |= octet
	}
	return combined != 0
}

// Valid reports whether the plan digest is initialized.
func (d PlanDigest) Valid() bool {
	var combined byte
	for _, octet := range d.value {
		combined |= octet
	}
	return combined != 0
}

// Bytes returns a detached protected plan digest for the internal journal codec only.
func (d PlanDigest) Bytes() []byte { return append([]byte(nil), d.value[:]...) }

// Bytes returns a detached protected candidate digest for backend metadata only.
func (d CandidateContentDigest) Bytes() []byte { return append([]byte(nil), d.value[:]...) }

// String returns a constant protected plan-digest representation.
func (PlanDigest) String() string { return redacted }

// GoString returns a constant protected plan-digest representation.
func (PlanDigest) GoString() string { return redacted }

// Format prevents plan-digest correlation through formatting.
func (PlanDigest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected plan-digest serialization.
func (PlanDigest) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected candidate-digest representation.
func (CandidateContentDigest) String() string { return redacted }

// GoString returns a constant protected candidate-digest representation.
func (CandidateContentDigest) GoString() string { return redacted }

// Format prevents candidate-digest correlation through formatting.
func (CandidateContentDigest) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected candidate-digest serialization.
func (CandidateContentDigest) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected authority representation.
func (AuthorityDescriptor) String() string { return redacted }

// GoString returns a constant protected authority representation.
func (AuthorityDescriptor) GoString() string { return redacted }

// Format prevents authority identifiers and principals from reaching formatting sinks.
func (AuthorityDescriptor) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected authority serialization.
func (AuthorityDescriptor) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// String returns a constant protected plan representation.
func (PlanProjection) String() string { return redacted }

// GoString returns a constant protected plan representation.
func (PlanProjection) GoString() string { return redacted }

// Format prevents plan intent and authority data from reaching formatting sinks.
func (PlanProjection) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic protected plan serialization.
func (PlanProjection) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }
