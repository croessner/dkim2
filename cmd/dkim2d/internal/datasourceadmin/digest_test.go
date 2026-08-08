package datasourceadmin

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const digestTestID = "aebagbafaydqqcikbmga2dqpca"

const testHandleRSA = "handle-rsa"

// TestPlanDigestGoldenEmptyAndSourceV2 freezes exact typed key-free framing.
func TestPlanDigestGoldenEmptyAndSourceV2(t *testing.T) {
	empty := planFixture(nil, 0, 1)
	emptyDigest, err := NewPlanDigest(empty)
	if err != nil {
		t.Fatal("empty plan rejected")
	}
	if got := hex.EncodeToString(emptyDigest.value[:]); got != "941d89e09537dd0450bd62113697ed10860d875727337eaa12cae870966ccb00" {
		t.Fatalf("empty plan digest = %s", got)
	}
	rows := deterministicRows(t)
	current, err := NewSnapshot(SchemaVersionV2, 7, rows)
	if err != nil {
		t.Fatal("source v2 fixture rejected")
	}
	defer current.Close() //nolint:errcheck // Test cleanup has no recovery.
	currentSource, err := current.PlanSource(t.Context())
	if err != nil {
		t.Fatal("source projection rejected")
	}
	defer currentSource.Close() //nolint:errcheck // Test cleanup has no recovery.
	source := planFixture(currentSource, 7, 9)
	sourceDigest, err := NewPlanDigest(source)
	if err != nil {
		t.Fatal("source v2 plan rejected")
	}
	if got := hex.EncodeToString(sourceDigest.value[:]); got != "015695b703db350757c7efd8fa9c10cff1f56893a624052ca48465c80ed66a48" {
		t.Fatalf("source v2 plan digest = %s", got)
	}
	other, err := NewSnapshot(SchemaVersionV2, 7, deterministicRows(t))
	if err != nil {
		t.Fatal("second source fixture rejected")
	}
	defer other.Close() //nolint:errcheck // Test cleanup has no recovery.
	otherSource, err := other.PlanSource(t.Context())
	if err != nil {
		t.Fatal("second source projection rejected")
	}
	defer otherSource.Close() //nolint:errcheck // Test cleanup has no recovery.
	otherDigest, err := NewPlanDigest(planFixture(otherSource, 7, 9))
	if err != nil || !sourceDigest.Equal(otherDigest) {
		t.Fatal("source plan digest included private PKCS8")
	}
}

// TestCandidateDigestGoldenRSAEd25519Nullable freezes class and field grammar.
func TestCandidateDigestGoldenRSAEd25519Nullable(t *testing.T) {
	rows := deterministicRows(t)
	rsaPKCS8, err := base64.StdEncoding.DecodeString("MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAK57EkTF1k7XMVkdbBBttq/7ULMjlxWlIp6eVQlvQbzQExbnbThIvaUD8OrxGzVsXCrrqgdsRLaKuOyoPGNkL9rjQ9CrLzdyustih+QKOb26fr76ldLe8vWcFwzcIf9iYjQT5sU1rG3nkx8Z6+o56pfrpjDKt+fvtrAEcEN1bggHAgMBAAECgYBS/svT1t94JTieETbEIcwSrdLXQ4isjR6IoPwGPtvgOoG6FV+ItGExS0ygFQxCP0cgS3VXjpKo2hfYyrXe+VshVHSkC2vSonjtq0bJVgjaSCMGC5/96M/qe983KWKQA3hq8QoOkHAB4JjpNHTlKwdXGEVxAqtJQWSbX9IvtHXGkQJBANi4mD9CkoPWtKMN2TtD67Hm2ZvAZDH1cAdmckQtsz2Ro9Qn3cN201+0xaGPfVupoFVdLKS+vzkHO98L4KQOKKMCQQDOGp0dw5FJpzyrTewnlRB8VqzNEifMwXLkYZzWtmJVEJBvIxO0YHN8blb+zn4dK3Nk2EFcBaRQi8ZLjG51BuVNAkAdAtD2nu3IEkTKEv+CbHwvq2xz6hQ/j9B4XSFsuQVmd4mLy+5mzRBMnoFaOEAatiFNbBSe1R35/1rnZ8qhi3erAkEAmwTfefyXsatM8ZfZcOgojyzuKgxmzRYPoYFd4w0pJswfpsfeUUReeI/RdTPBHZWJ5KbXeixwK3kGO9qzVehK3QJAaHdQbSAF1KTTzRJUksbcfnhHJAiPtX0wUROBhaJ1IUEqk6tNv5UA9s75BkfGNl+sZKG0wSoEOKwmG7cObRx5zw==")
	if err != nil {
		t.Fatal("decode fixed RSA PKCS8")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(rsaPKCS8)
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok {
		t.Fatal("parse fixed RSA PKCS8")
	}
	rsaSPKI, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal("marshal fixed RSA SPKI")
	}
	rows.Handles = append(rows.Handles, HandleRow{ID: testHandleRSA})
	rows.Credentials = append(rows.Credentials, CredentialRow{ProfileID: testProfileID, Algorithm: algorithmRSASHA256, Selector: "selector-rsa", PublicSPKI: rsaSPKI, HandleID: testHandleRSA})
	rows.KeyMaterial = append(rows.KeyMaterial, KeyMaterialRow{TenantID: testTenant, Domain: testDomain, Use: profileUseOriginator, HandleID: testHandleRSA, Algorithm: algorithmRSASHA256, PublicSPKI: append([]byte(nil), rsaSPKI...), PrivatePKCS8: rsaPKCS8})
	snapshot, err := NewSnapshot(SchemaVersionV3, 9, rows)
	if err != nil {
		t.Fatal("canonical dual-algorithm snapshot rejected")
	}
	content, err := NewCandidateContent(snapshot)
	if err != nil {
		t.Fatal("canonical dual-algorithm candidate content rejected")
	}
	candidate, err := NewPublicationEnvelope(digestTestID, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("canonical dual-algorithm publication envelope rejected")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	digest := candidate.Digest()
	if got := hex.EncodeToString(digest.value[:]); got != "848c7fa623a31163c4a6652dfe79cb323de2ebdb0eaf314a7abbabf5dbc2355d" {
		t.Fatalf("candidate digest = %s", got)
	}
}

// TestSourceProjectionOmitsPrivateFieldEntirely freezes the v2 key-free row ending.
func TestSourceProjectionOmitsPrivateFieldEntirely(t *testing.T) {
	rows := Rows{KeyMaterial: []KeyMaterialRow{{TenantID: testTenant, Domain: testDomain, Use: profileUseOriginator, HandleID: "handle", Algorithm: algorithmRSASHA256, PublicSPKI: []byte{1}, PrivatePKCS8: []byte{2}}}}
	first := sha256.New()
	writeSourceRows(first, rows)
	rows.KeyMaterial[0].PrivatePKCS8[0] = 3
	second := sha256.New()
	writeSourceRows(second, rows)
	if hex.EncodeToString(first.Sum(nil)) != hex.EncodeToString(second.Sum(nil)) {
		t.Fatal("source projection included private-key bytes")
	}
	withPrivate := sha256.New()
	writeCandidateRows(withPrivate, rows, true)
	withoutPrivate := sha256.New()
	writeCandidateRows(withoutPrivate, rows, false)
	if hex.EncodeToString(withPrivate.Sum(nil)) == hex.EncodeToString(withoutPrivate.Sum(nil)) {
		t.Fatal("source projection emitted a zero-length private-key frame")
	}
}

// TestOperationIDRejectsAlternateTailBitsAndZero freezes canonical base32.
func TestOperationIDRejectsAlternateTailBitsAndZero(t *testing.T) {
	for _, invalid := range []string{"aaaaaaaaaaaaaaaaaaaaaaaaaa", "aebagbafaydqqcikbmga2dqpcc", "AEBAGBAFAYDQQCIKBMGA2DQPCA"} {
		if validOperationID(invalid) {
			t.Fatal("noncanonical operation ID accepted")
		}
	}
}

// TestProtectedPlanAggregatesRejectGenericSinks freezes nested formatting and JSON privacy.
func TestProtectedPlanAggregatesRejectGenericSinks(t *testing.T) {
	plan := planFixture(nil, 0, 1)
	sql := SQLAuthority{Database: "marker-database", Schema: "marker-schema", SnapshotRole: "marker-reader", StagingRole: "marker-stager", ActivationRole: "marker-activator"}
	digest, err := NewPlanDigest(plan)
	if err != nil {
		t.Fatal("plan fixture rejected")
	}
	candidate := mustCandidate(t, deterministicRows(t))
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery.
	prepared := candidate.PreparedEvidence()
	staged := NewStagedEvidence(candidate.Digest())
	formatted := []string{
		fmt.Sprintf("%+v", plan),
		fmt.Sprintf("%+v", struct{ Plan PlanProjection }{Plan: plan}),
		fmt.Sprintf("%+v", plan.Authority),
		fmt.Sprintf("%+v", struct{ Authority AuthorityDescriptor }{Authority: plan.Authority}),
		fmt.Sprintf("%+v", plan.Authority.Endpoints[0]),
		fmt.Sprintf("%+v", plan.Authority.LDAP),
		fmt.Sprintf("%+v", sql),
		fmt.Sprintf("%+v", plan.Intent),
		fmt.Sprintf("%+v", plan.Credentials[0]),
		fmt.Sprintf("%+v", plan.DNS),
		fmt.Sprintf("%+v", struct{ Intent PlanIntent }{Intent: plan.Intent}),
		fmt.Sprintf("%+v", digest),
		fmt.Sprintf("%+v", candidate.Digest()),
		fmt.Sprintf("%+v", prepared),
		fmt.Sprintf("%+v", staged),
	}
	for _, rendered := range formatted {
		if !strings.Contains(rendered, redacted) || strings.Contains(rendered, plan.Intent.Domain) ||
			strings.Contains(rendered, plan.Authority.Endpoints[0].Host) ||
			strings.Contains(rendered, plan.Authority.LDAP.SnapshotPrincipal) || strings.Contains(rendered, plan.OperationID) ||
			strings.Contains(rendered, sql.Database) {
			t.Fatal("protected aggregate reached a formatting sink")
		}
	}
	protected := []any{
		plan,
		struct{ Plan PlanProjection }{Plan: plan},
		plan.Authority,
		struct{ Authority AuthorityDescriptor }{Authority: plan.Authority},
		plan.Authority.Endpoints[0],
		plan.Authority.LDAP,
		sql,
		plan.Intent,
		plan.Credentials[0],
		plan.DNS,
		struct{ Intent PlanIntent }{Intent: plan.Intent},
		digest,
		candidate.Digest(),
		prepared,
		staged,
	}
	for _, value := range protected {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("protected aggregate reached a JSON sink")
		}
	}
}

// TestPlanProjectionRejectsAmbiguousTransportEvidence freezes fail-closed policy inputs.
func TestPlanProjectionRejectsAmbiguousTransportEvidence(t *testing.T) {
	plan := planFixture(nil, 0, 1)
	zero := [sha256.Size]byte{}
	plan.Authority.ClientCertificateFingerprint = &zero
	if _, err := NewPlanDigest(plan); err == nil {
		t.Fatal("zero client-certificate fingerprint accepted")
	}
	plan = planFixture(nil, 0, 1)
	plan.DNS = DNSPolicy{ResolverClass: resolverClassRecursive, ResolverEndpoints: []string{"224.0.0.1:53"}, ExportTTLSeconds: 300, ProofLifetimeSeconds: 60}
	if _, err := NewPlanDigest(plan); err == nil {
		t.Fatal("multicast resolver endpoint accepted")
	}
	plan = planFixture(nil, 0, 1)
	plan.DNS = DNSPolicy{ResolverClass: resolverClassRecursive, ResolverEndpoints: []string{"resolver.example.test:53", "resolver.example.test:53"}, ExportTTLSeconds: 300, ProofLifetimeSeconds: 60}
	if _, err := NewPlanDigest(plan); err == nil {
		t.Fatal("duplicate resolver endpoint accepted")
	}
	plan = planFixture(nil, 0, 1)
	plan.Credentials[0].HandleID = "Invalid-Handle"
	if _, err := NewPlanDigest(plan); err == nil {
		t.Fatal("noncanonical datasource handle ID accepted")
	}
}

// planFixture constructs one fully typed deterministic LDAP plan.
func planFixture(current *PlanSource, expected, candidate uint64) PlanProjection {
	var trust [32]byte
	trust[0] = 1
	return PlanProjection{
		Backend: BackendLDAP,
		Authority: AuthorityDescriptor{
			AuthorityID:       digestTestID,
			Endpoints:         []AuthorityEndpoint{{Scheme: authoritySchemeLDAPS, Host: testLDAPAuthorityHost, Port: 636, TLSServerName: testLDAPAuthorityHost}},
			LDAP:              &LDAPAuthority{BaseDN: "dc=example,dc=test", SnapshotPrincipal: "snapshot", StagingPrincipal: testStagingPrincipal, ActivationPrincipal: "activation"},
			TrustFingerprints: [][32]byte{trust},
		},
		ExpectedCurrent:     expected,
		Current:             current,
		Intent:              PlanIntent{Version: domainIntentVersionV1, Domain: testDomain, TenantID: testTenant, ProfileUse: profileUseOriginator, Algorithms: []string{algorithmEd25519SHA256}, Rollout: rolloutEnforce, Compatibility: compatibilityStrict},
		ProfileID:           testProfileID,
		Credentials:         []AllocatedCredential{{Algorithm: algorithmEd25519SHA256, HandleID: testHandleEd, Selector: testSelector}},
		CandidateGeneration: candidate,
		DNS:                 DNSPolicy{ResolverClass: resolverClassSystem, ExportTTLSeconds: 300, ProofLifetimeSeconds: 60},
		OperationID:         digestTestID,
	}
}
