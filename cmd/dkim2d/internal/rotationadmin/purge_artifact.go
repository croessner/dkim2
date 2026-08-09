package rotationadmin

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const (
	purgeArtifactVersion  = "dkim2-purge-plan-artifact-v1"
	maxPurgeArtifactBytes = 262144
)

type purgeArtifactWire struct {
	Version            string                       `json:"version"`
	Backend            datasourceadmin.BackendClass `json:"backend"`
	Authority          purgeAuthorityWire           `json:"authority"`
	Current            uint64                       `json:"current"`
	InventoryVersion   string                       `json:"inventory_version"`
	PolicyVersion      string                       `json:"policy_version"`
	PolicyCommitment   string                       `json:"policy_commitment"`
	Targets            []purgeTargetWire            `json:"targets"`
	PlanDigest         string                       `json:"plan_digest"`
	ArtifactDigest     string                       `json:"artifact_digest"`
	ExpectedRetained   uint32                       `json:"expected_retained"`
	ExpectedUnresolved uint32                       `json:"expected_unresolved"`
}

type purgeAuthorityWire struct {
	ID         string                  `json:"id"`
	Endpoints  []purgeEndpointWire     `json:"endpoints"`
	LDAP       *purgeLDAPAuthorityWire `json:"ldap,omitempty"`
	SQL        *purgeSQLAuthorityWire  `json:"sql,omitempty"`
	Trust      []string                `json:"trust"`
	ClientCert string                  `json:"client_cert,omitempty"`
}

type purgeEndpointWire struct {
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	Port          uint16 `json:"port"`
	TLSServerName string `json:"tls_server_name"`
}

type purgeLDAPAuthorityWire struct {
	BaseDN     string `json:"base_dn"`
	Snapshot   string `json:"snapshot"`
	Staging    string `json:"staging"`
	Activation string `json:"activation"`
	Purge      string `json:"purge"`
}

type purgeSQLAuthorityWire struct {
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Snapshot   string `json:"snapshot"`
	Staging    string `json:"staging"`
	Activation string `json:"activation"`
	Purge      string `json:"purge"`
}

type purgeTargetWire struct {
	Generation    uint64 `json:"generation"`
	Schema        string `json:"schema"`
	Lifecycle     string `json:"lifecycle"`
	ContentDigest string `json:"content_digest"`
}

// MarshalPurgePlanArtifact serializes one exact protected plan in canonical key-free form.
func MarshalPurgePlanArtifact(plan *PurgePlan) ([]byte, error) {
	if plan == nil || plan.closed || !plan.digest.Valid() || !plan.artifactDigest.Valid() {
		return nil, errInvalid
	}
	wire, err := purgePlanWireFromPlan(plan)
	if err != nil {
		return nil, errInvalid
	}
	document, err := json.Marshal(wire)
	if err != nil || len(document) == 0 || len(document) > maxPurgeArtifactBytes {
		clear(document)
		return nil, errLimit
	}
	return document, nil
}

// ParsePurgePlanArtifact verifies and reconstructs one exact protected plan without granting execution.
func ParsePurgePlanArtifact(document []byte) (*PurgePlan, error) {
	if len(document) == 0 || len(document) > maxPurgeArtifactBytes || rejectDuplicateJSONKeys(document) != nil {
		return nil, errInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire purgeArtifactWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Version != purgeArtifactVersion {
		return nil, errInvalid
	}
	plan, err := purgePlanFromWire(wire)
	if err != nil {
		return nil, errInvalid
	}
	canonical, err := MarshalPurgePlanArtifact(plan)
	if err != nil || !bytes.Equal(document, canonical) {
		clear(canonical)
		_ = plan.Close()
		return nil, errInvalid
	}
	clear(canonical)
	return plan, nil
}

// purgePlanWireFromPlan projects the complete plan into a canonical key-free wire representation.
func purgePlanWireFromPlan(plan *PurgePlan) (purgeArtifactWire, error) {
	authority, err := purgeAuthorityWireFromDescriptor(plan.authority)
	if err != nil {
		return purgeArtifactWire{}, err
	}
	targets := make([]purgeTargetWire, len(plan.targets))
	for index, target := range plan.targets {
		targets[index] = purgeTargetWire{Generation: target.Generation, Schema: target.Schema, Lifecycle: target.Lifecycle, ContentDigest: target.ContentDigest.Hex()}
	}
	return purgeArtifactWire{Version: purgeArtifactVersion, Backend: plan.backend, Authority: authority, Current: plan.current, InventoryVersion: plan.inventoryVersion, PolicyVersion: plan.policyVersion, PolicyCommitment: plan.policyCommitment.Hex(), Targets: targets, PlanDigest: plan.digest.Hex(), ArtifactDigest: plan.artifactDigest.Hex(), ExpectedRetained: plan.expectedRetained, ExpectedUnresolved: plan.expectedUnresolved}, nil
}

// purgePlanFromWire reconstructs and recomputes every protected artifact commitment.
func purgePlanFromWire(wire purgeArtifactWire) (*PurgePlan, error) {
	authority, err := purgeAuthorityDescriptorFromWire(wire.Authority)
	if err != nil {
		return nil, errInvalid
	}
	authorityCommitment, err := datasourceadmin.RetentionAuthorityCommitment(wire.Backend, authority)
	if err != nil {
		return nil, errInvalid
	}
	if wire.Current == 0 || len(wire.Targets) == 0 || len(wire.Targets) > 4096 {
		return nil, errInvalid
	}
	targets := make([]admincontract.PurgeTarget, len(wire.Targets))
	for index, target := range wire.Targets {
		digest, parseErr := admincontract.ParseDigestHex(target.ContentDigest)
		if parseErr != nil {
			return nil, errInvalid
		}
		targets[index] = admincontract.PurgeTarget{Generation: target.Generation, Schema: target.Schema, Lifecycle: target.Lifecycle, ContentDigest: digest}
	}
	policyCommitment, err := admincontract.ParseDigestHex(wire.PolicyCommitment)
	if err != nil {
		return nil, errInvalid
	}
	digest, err := newPurgePlanDigest(wire.Current, wire.InventoryVersion, wire.PolicyVersion, policyCommitment, targets)
	if err != nil {
		return nil, errInvalid
	}
	wantPlan, err := admincontract.ParseDigestHex(wire.PlanDigest)
	if err != nil || !wantPlan.Equal(digest) {
		return nil, errInvalid
	}
	artifact, err := newPurgeArtifactDigest(authorityCommitment, policyCommitment, digest, uint32(len(targets)), wire.ExpectedRetained, wire.ExpectedUnresolved)
	if err != nil {
		return nil, errInvalid
	}
	wantArtifact, err := admincontract.ParseDigestHex(wire.ArtifactDigest)
	if err != nil || !wantArtifact.Equal(artifact) {
		return nil, errInvalid
	}
	return &PurgePlan{backend: wire.Backend, authority: authority, authorityCommitment: authorityCommitment, current: wire.Current, inventoryVersion: wire.InventoryVersion, policyVersion: wire.PolicyVersion, policyCommitment: policyCommitment, targets: targets, digest: digest, artifactDigest: artifact, expectedRetained: wire.ExpectedRetained, expectedUnresolved: wire.ExpectedUnresolved}, nil
}

// purgeAuthorityWireFromDescriptor converts protected authority evidence without generic JSON exposure.
func purgeAuthorityWireFromDescriptor(authority datasourceadmin.AuthorityDescriptor) (purgeAuthorityWire, error) {
	result := purgeAuthorityWire{ID: authority.AuthorityID, Endpoints: make([]purgeEndpointWire, len(authority.Endpoints)), Trust: make([]string, len(authority.TrustFingerprints))}
	for index, endpoint := range authority.Endpoints {
		result.Endpoints[index] = purgeEndpointWire{Scheme: endpoint.Scheme, Host: endpoint.Host, Port: endpoint.Port, TLSServerName: endpoint.TLSServerName}
	}
	for index, fingerprint := range authority.TrustFingerprints {
		result.Trust[index] = hex.EncodeToString(fingerprint[:])
	}
	if authority.ClientCertificateFingerprint != nil {
		result.ClientCert = hex.EncodeToString(authority.ClientCertificateFingerprint[:])
	}
	if authority.LDAP != nil {
		result.LDAP = &purgeLDAPAuthorityWire{BaseDN: authority.LDAP.BaseDN, Snapshot: authority.LDAP.SnapshotPrincipal, Staging: authority.LDAP.StagingPrincipal, Activation: authority.LDAP.ActivationPrincipal, Purge: authority.LDAP.PurgePrincipal}
	}
	if authority.SQL != nil {
		result.SQL = &purgeSQLAuthorityWire{Database: authority.SQL.Database, Schema: authority.SQL.Schema, Snapshot: authority.SQL.SnapshotRole, Staging: authority.SQL.StagingRole, Activation: authority.SQL.ActivationRole, Purge: authority.SQL.PurgeRole}
	}
	if !canonicalPurgeAuthorityWire(result) {
		return purgeAuthorityWire{}, errInvalid
	}
	return result, nil
}

// purgeAuthorityDescriptorFromWire converts strict canonical key-free authority evidence.
func purgeAuthorityDescriptorFromWire(wire purgeAuthorityWire) (datasourceadmin.AuthorityDescriptor, error) {
	if !canonicalPurgeAuthorityWire(wire) {
		return datasourceadmin.AuthorityDescriptor{}, errInvalid
	}
	authority := datasourceadmin.AuthorityDescriptor{AuthorityID: wire.ID, Endpoints: make([]datasourceadmin.AuthorityEndpoint, len(wire.Endpoints)), TrustFingerprints: make([][32]byte, len(wire.Trust))}
	for index, endpoint := range wire.Endpoints {
		authority.Endpoints[index] = datasourceadmin.AuthorityEndpoint{Scheme: endpoint.Scheme, Host: endpoint.Host, Port: endpoint.Port, TLSServerName: endpoint.TLSServerName}
	}
	for index, encoded := range wire.Trust {
		decoded, err := decodeFingerprint(encoded)
		if err != nil {
			return datasourceadmin.AuthorityDescriptor{}, err
		}
		authority.TrustFingerprints[index] = decoded
	}
	if wire.ClientCert != "" {
		fingerprint, err := decodeFingerprint(wire.ClientCert)
		if err != nil {
			return datasourceadmin.AuthorityDescriptor{}, err
		}
		authority.ClientCertificateFingerprint = &fingerprint
	}
	if wire.LDAP != nil {
		authority.LDAP = &datasourceadmin.LDAPAuthority{BaseDN: wire.LDAP.BaseDN, SnapshotPrincipal: wire.LDAP.Snapshot, StagingPrincipal: wire.LDAP.Staging, ActivationPrincipal: wire.LDAP.Activation, PurgePrincipal: wire.LDAP.Purge}
	}
	if wire.SQL != nil {
		authority.SQL = &datasourceadmin.SQLAuthority{Database: wire.SQL.Database, Schema: wire.SQL.Schema, SnapshotRole: wire.SQL.Snapshot, StagingRole: wire.SQL.Staging, ActivationRole: wire.SQL.Activation, PurgeRole: wire.SQL.Purge}
	}
	return authority, nil
}

// canonicalPurgeAuthorityWire rejects reordered, duplicated, or ambiguous protected authority evidence.
func canonicalPurgeAuthorityWire(wire purgeAuthorityWire) bool {
	if wire.ID == "" || len(wire.Endpoints) == 0 || len(wire.Trust) == 0 || wire.LDAP != nil && wire.SQL != nil || wire.LDAP == nil && wire.SQL == nil {
		return false
	}
	for index := range wire.Endpoints {
		if index > 0 && endpointKey(wire.Endpoints[index-1]) >= endpointKey(wire.Endpoints[index]) {
			return false
		}
	}
	for index := range wire.Trust {
		if index > 0 && wire.Trust[index-1] >= wire.Trust[index] {
			return false
		}
		if _, err := decodeFingerprint(wire.Trust[index]); err != nil {
			return false
		}
	}
	if wire.ClientCert != "" {
		if _, err := decodeFingerprint(wire.ClientCert); err != nil {
			return false
		}
	}
	return true
}

// endpointKey produces one unambiguous canonical endpoint ordering key.
func endpointKey(endpoint purgeEndpointWire) string {
	return endpoint.Scheme + "\x00" + endpoint.Host + "\x00" + string(rune(endpoint.Port)) + "\x00" + endpoint.TLSServerName
}

// decodeFingerprint validates one canonical fixed-width lowercase hexadecimal fingerprint.
func decodeFingerprint(value string) ([32]byte, error) {
	if len(value) != 64 || value != string(bytes.ToLower([]byte(value))) {
		return [32]byte{}, errInvalid
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		return [32]byte{}, errInvalid
	}
	var fingerprint [32]byte
	copy(fingerprint[:], decoded)
	clear(decoded)
	return fingerprint, nil
}
