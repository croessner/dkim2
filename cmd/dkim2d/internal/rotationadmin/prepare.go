package rotationadmin

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

// GeneratedKey owns one canonical private/public key pair until candidate transfer.
type GeneratedKey struct {
	PublicSPKI   []byte
	PrivatePKCS8 []byte
}

// KeyFactory creates one exact native algorithm key pair.
type KeyFactory interface {
	Generate(context.Context, string) (GeneratedKey, error)
}

// NativeKeyFactory is the production crypto/rand key generator.
type NativeKeyFactory struct{ RSABits int }

// Generate creates canonical PKCS#8 and SPKI bytes for one native algorithm.
func (f NativeKeyFactory) Generate(ctx context.Context, algorithm string) (GeneratedKey, error) {
	if ctx == nil || ctx.Err() != nil || (f.RSABits != 2048 && f.RSABits != 3072 && f.RSABits != 4096) {
		return GeneratedKey{}, errInvalid
	}
	reader := &contextReader{ctx: ctx, source: rand.Reader}
	var private crypto.PrivateKey
	var public any
	var err error
	switch algorithm {
	case string(provider.AlgorithmEd25519SHA256):
		var edPublic ed25519.PublicKey
		edPublic, private, err = ed25519.GenerateKey(reader)
		public = edPublic
	case string(provider.AlgorithmRSASHA256):
		var rsaPrivate *rsa.PrivateKey
		rsaPrivate, err = rsa.GenerateKey(reader, f.RSABits)
		private = rsaPrivate
		if rsaPrivate != nil {
			public = &rsaPrivate.PublicKey
		}
	default:
		return GeneratedKey{}, errInvalid
	}
	if private != nil {
		defer signingstore.ClearPrivateKey(private)
	}
	if err != nil || ctx.Err() != nil {
		return GeneratedKey{}, errBackend
	}
	privatePKCS8, privateErr := x509.MarshalPKCS8PrivateKey(private)
	publicSPKI, publicErr := x509.MarshalPKIXPublicKey(public)
	if privateErr != nil || publicErr != nil || len(privatePKCS8) == 0 || len(publicSPKI) == 0 {
		clear(privatePKCS8)
		clear(publicSPKI)
		return GeneratedKey{}, errBackend
	}
	return GeneratedKey{PublicSPKI: publicSPKI, PrivatePKCS8: privatePKCS8}, nil
}

// Preparer owns candidate key generation and finite validation limits.
type Preparer struct {
	keys   KeyFactory
	limits provider.Limits
}

// NewPreparer constructs one campaign candidate preparer.
func NewPreparer(keys KeyFactory, limits provider.Limits) (*Preparer, error) {
	if keys == nil || limits.Validate() != nil {
		return nil, errInvalid
	}
	return &Preparer{keys: keys, limits: limits}, nil
}

// Prepared owns one immutable operation-bound candidate and its plan commitments.
type Prepared struct {
	mu           sync.Mutex
	envelope     *datasourceadmin.PublicationEnvelope
	planDigest   admincontract.Digest
	frozenDigest admincontract.Digest
	workCount    int
	dnsRecords   int
	dnsInputs    []dnsRecordInput
	closed       bool
}

type dnsRecordInput struct {
	domain     string
	selector   string
	algorithm  provider.Algorithm
	publicSPKI []byte
}

// Prepare replaces every frozen binding in one complete candidate exactly once.
func (p *Preparer) Prepare(ctx context.Context, plan *Plan, source *datasourceadmin.Snapshot) (*Prepared, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || plan == nil || source == nil || p.limits.Validate() != nil {
		return nil, errInvalid
	}
	if err := plan.VerifySource(ctx, source); err != nil {
		return nil, errConflict
	}
	plan.mu.Lock()
	if plan.closed || plan.preparationStarted {
		plan.mu.Unlock()
		return nil, errConflict
	}
	plan.preparationStarted = true
	work := make([]frozenBinding, len(plan.work))
	for index := range plan.work {
		work[index] = frozenBinding{policyIndex: plan.work[index].policyIndex, item: cloneWorkItem(plan.work[index].item)}
	}
	operation := plan.intent.operationValue
	candidateGeneration := plan.candidateGeneration
	planDigest, frozenDigest := plan.planDigest, plan.frozenDigest
	plan.mu.Unlock()
	var candidateRows datasourceadmin.Rows
	err := source.WithRows(ctx, func(rows datasourceadmin.Rows) error {
		candidateRows = cloneAdminRows(rows)
		return p.replaceBindings(ctx, &candidateRows, work, operation, candidateGeneration)
	})
	if err != nil {
		clearAdminRows(&candidateRows)
		return nil, errBackend
	}
	dnsInputs, err := captureDNSInputs(candidateRows, work, operation, candidateGeneration)
	if err != nil {
		clearAdminRows(&candidateRows)
		return nil, err
	}
	snapshot, err := datasourceadmin.NewSnapshotWithLimits(datasourceadmin.SchemaVersionV3, candidateGeneration, candidateRows, p.limits)
	clearAdminRows(&candidateRows)
	if err != nil {
		clearDNSInputs(dnsInputs)
		return nil, errBackend
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		clearDNSInputs(dnsInputs)
		return nil, errBackend
	}
	envelope, err := datasourceadmin.NewCampaignPublicationEnvelope(operation, plan.sourceGeneration, content)
	if err != nil {
		_ = content.Close()
		clearDNSInputs(dnsInputs)
		return nil, errBackend
	}
	return &Prepared{envelope: envelope, planDigest: planDigest, frozenDigest: frozenDigest, workCount: len(work), dnsRecords: len(dnsInputs), dnsInputs: dnsInputs}, nil
}

// RecoverPrepared rebuilds only DNS-proof inputs from an exact staged or committed
// backend candidate. It never generates a key and refuses pre-stage journals.
func RecoverPrepared(ctx context.Context, journal *Journal, envelope *datasourceadmin.PublicationEnvelope) (*Prepared, error) {
	if ctx == nil || ctx.Err() != nil || journal == nil || envelope == nil {
		return nil, errInvalid
	}
	journal.mu.Lock()
	if journal.closed || (journal.state != StateStaged && journal.state != StateDNSInProgress && journal.state != StateDNSComplete && journal.state != StateActivating && journal.state != StateActivated) || !journal.candidateDigest.Valid() || envelope.Generation() != journal.candidateGeneration {
		journal.mu.Unlock()
		return nil, errConflict
	}
	digest, frozenDigest := journal.candidateDigest, journal.frozenDigest
	work, operation, generation := cloneJournalItems(journal.work), journal.operation, journal.candidateGeneration
	journal.mu.Unlock()
	defer clearJournalWork(work)
	actualBytes := envelope.Digest().Bytes()
	actual, parseErr := admincontract.ParseDigest(actualBytes)
	clear(actualBytes)
	if parseErr != nil || !digest.Equal(actual) {
		return nil, errConflict
	}
	var rows datasourceadmin.Rows
	if err := envelope.WithRows(ctx, func(value datasourceadmin.Rows) error { rows = cloneAdminRows(value); return nil }); err != nil {
		return nil, errBackend
	}
	defer clearAdminRows(&rows)
	frozenBindings := make([]frozenBinding, len(work))
	for ordinal, item := range work {
		for index, policy := range rows.Policies {
			if policy.TenantID == item.Tenant && policy.Domain == item.Domain && policy.Use == item.Use {
				frozenBindings[ordinal] = frozenBinding{policyIndex: index, item: cloneWorkItem(item)}
				break
			}
		}
		if frozenBindings[ordinal].item.Domain == "" {
			return nil, errConflict
		}
	}
	inputs, err := captureDNSInputs(rows, frozenBindings, operation, generation)
	if err != nil {
		return nil, errConflict
	}
	return &Prepared{envelope: envelope, planDigest: admincontract.Digest{}, frozenDigest: frozenDigest, workCount: len(work), dnsRecords: len(inputs), dnsInputs: inputs}, nil
}

// captureDNSInputs selects every replacement credential exactly once from the complete candidate.
func captureDNSInputs(rows datasourceadmin.Rows, work []frozenBinding, operation string, generation uint64) ([]dnsRecordInput, error) {
	inputs := make([]dnsRecordInput, 0)
	for ordinal, binding := range work {
		if binding.policyIndex < 0 || binding.policyIndex >= len(rows.Policies) {
			clearDNSInputs(inputs)
			return nil, fmt.Errorf("%w: dns policy index", errConflict)
		}
		profileID := rows.Policies[binding.policyIndex].ProfileID
		if profileID != derivedIdentity("profile", operation, generation, ordinal, "") {
			clearDNSInputs(inputs)
			return nil, fmt.Errorf("%w: dns profile binding", errConflict)
		}
		for _, algorithm := range binding.item.Algorithms {
			matches := 0
			for _, credential := range rows.Credentials {
				if credential.ProfileID != profileID || credential.Algorithm != algorithm {
					continue
				}
				matches++
				inputs = append(inputs, dnsRecordInput{domain: binding.item.Domain, selector: credential.Selector, algorithm: provider.Algorithm(algorithm), publicSPKI: append([]byte(nil), credential.PublicSPKI...)})
			}
			if matches != 1 {
				clearDNSInputs(inputs)
				return nil, fmt.Errorf("%w: dns credential cardinality", errConflict)
			}
		}
	}
	return inputs, nil
}

// clearDNSInputs erases detached DNS proof inputs.
func clearDNSInputs(inputs []dnsRecordInput) {
	for index := range inputs {
		clear(inputs[index].publicSPKI)
		inputs[index] = dnsRecordInput{}
	}
	clear(inputs)
}

// replaceBindings builds replacements then drops only unreferenced prior profile state.
func (p *Preparer) replaceBindings(ctx context.Context, rows *datasourceadmin.Rows, work []frozenBinding, operation string, generation uint64) error {
	if rows == nil || len(work) == 0 {
		return errInvalid
	}
	for ordinal, binding := range work {
		if ctx.Err() != nil || binding.policyIndex < 0 || binding.policyIndex >= len(rows.Policies) {
			return errBackend
		}
		policy := &rows.Policies[binding.policyIndex]
		if policy.TenantID != binding.item.Tenant || policy.Domain != binding.item.Domain ||
			policy.Use != binding.item.Use || policy.ProfileID != binding.item.Profile {
			return errConflict
		}
		profileID := derivedIdentity("profile", operation, generation, ordinal, "")
		policy.ProfileID = profileID
		rows.Profiles = append(rows.Profiles, datasourceadmin.ProfileRow{ID: profileID, Domain: binding.item.Domain, Status: "active"})
		for _, algorithm := range binding.item.Algorithms {
			generated, err := p.keys.Generate(ctx, algorithm)
			if err != nil || len(generated.PublicSPKI) == 0 || len(generated.PrivatePKCS8) == 0 {
				clear(generated.PublicSPKI)
				clear(generated.PrivatePKCS8)
				return errBackend
			}
			handleID := derivedIdentity("handle", operation, generation, ordinal, algorithm)
			selector := derivedSelector(operation, generation, ordinal, algorithm)
			rows.Handles = append(rows.Handles, datasourceadmin.HandleRow{ID: handleID})
			rows.Credentials = append(rows.Credentials, datasourceadmin.CredentialRow{ProfileID: profileID, Algorithm: algorithm, Selector: selector, PublicSPKI: generated.PublicSPKI, HandleID: handleID})
			rows.KeyMaterial = append(rows.KeyMaterial, datasourceadmin.KeyMaterialRow{TenantID: binding.item.Tenant, Domain: binding.item.Domain, Use: binding.item.Use, HandleID: handleID, Algorithm: algorithm, PublicSPKI: append([]byte(nil), generated.PublicSPKI...), PrivatePKCS8: generated.PrivatePKCS8})
		}
	}
	removeUnreferencedState(rows)
	return nil
}

// removeUnreferencedState removes prior rows no remaining policy can select.
func removeUnreferencedState(rows *datasourceadmin.Rows) {
	referencedProfiles := make(map[string]struct{}, len(rows.Policies))
	for _, policy := range rows.Policies {
		referencedProfiles[policy.ProfileID] = struct{}{}
	}
	profiles := rows.Profiles[:0]
	for _, profile := range rows.Profiles {
		if _, keep := referencedProfiles[profile.ID]; keep {
			profiles = append(profiles, profile)
		}
	}
	rows.Profiles = profiles
	referencedHandles := make(map[string]struct{}, len(rows.Credentials))
	credentials := rows.Credentials[:0]
	for _, credential := range rows.Credentials {
		if _, keep := referencedProfiles[credential.ProfileID]; keep {
			credentials = append(credentials, credential)
			referencedHandles[credential.HandleID] = struct{}{}
		} else {
			clear(credential.PublicSPKI)
		}
	}
	rows.Credentials = credentials
	handles := rows.Handles[:0]
	for _, handle := range rows.Handles {
		if _, keep := referencedHandles[handle.ID]; keep {
			handles = append(handles, handle)
		}
	}
	rows.Handles = handles
	materials := rows.KeyMaterial[:0]
	for _, material := range rows.KeyMaterial {
		if _, keep := referencedHandles[material.HandleID]; keep {
			materials = append(materials, material)
		} else {
			clear(material.PublicSPKI)
			clear(material.PrivatePKCS8)
		}
	}
	rows.KeyMaterial = materials
}

// WithEnvelope supplies the one immutable candidate to a bounded backend callback.
func (p *Prepared) WithEnvelope(ctx context.Context, use func(*datasourceadmin.PublicationEnvelope) error) error {
	if p == nil || ctx == nil || ctx.Err() != nil || use == nil {
		return errInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.envelope == nil {
		return errConflict
	}
	if err := use(p.envelope); err != nil {
		return errBackend
	}
	return nil
}

// CandidateDigest returns the immutable backend candidate commitment.
func (p *Prepared) CandidateDigest() (admincontract.Digest, error) {
	if p == nil {
		return admincontract.Digest{}, errInvalid
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.envelope == nil {
		return admincontract.Digest{}, errConflict
	}
	return admincontract.ParseDigest(p.envelope.Digest().Bytes())
}

// WorkCount returns the exact prepared binding count.
func (p *Prepared) WorkCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return p.workCount
}

// DNSRecordCount returns the exact prepared credential count.
func (p *Prepared) DNSRecordCount() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0
	}
	return p.dnsRecords
}

// Close erases the complete candidate and invalidates preparation evidence.
func (p *Prepared) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	envelope := p.envelope
	p.envelope = nil
	p.planDigest = admincontract.Digest{}
	p.frozenDigest = admincontract.Digest{}
	p.workCount = 0
	p.dnsRecords = 0
	clearDNSInputs(p.dnsInputs)
	p.dnsInputs = nil
	p.closed = true
	p.mu.Unlock()
	if envelope != nil {
		return envelope.Close()
	}
	return nil
}

// String returns a constant protected prepared representation.
func (*Prepared) String() string { return redacted }

// GoString returns a constant protected prepared representation.
func (*Prepared) GoString() string { return redacted }

// Format prevents candidate facts from reaching formatting sinks.
func (*Prepared) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic prepared serialization.
func (*Prepared) MarshalJSON() ([]byte, error) { return nil, errInvalid }

// derivedIdentity creates one bounded collision-resistant opaque identifier.
func derivedIdentity(kind, operation string, generation uint64, ordinal int, algorithm string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("DKIM2-CAMPAIGN-ID-V1\x00%s\x00%s\x00%d\x00%d\x00%s", kind, operation, generation, ordinal, algorithm)))
	return "campaign-" + hex.EncodeToString(sum[:16])
}

// derivedSelector creates one LDH selector distinct per candidate credential.
func derivedSelector(operation string, generation uint64, ordinal int, algorithm string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("DKIM2-CAMPAIGN-SELECTOR-V1\x00%s\x00%d\x00%d\x00%s", operation, generation, ordinal, algorithm)))
	prefix := "e"
	if algorithm == string(provider.AlgorithmRSASHA256) {
		prefix = "r"
	}
	return prefix + hex.EncodeToString(sum[:12])
}

// cloneAdminRows detaches complete protected rows for one candidate assembly.
func cloneAdminRows(rows datasourceadmin.Rows) datasourceadmin.Rows {
	clone := datasourceadmin.Rows{Handles: append([]datasourceadmin.HandleRow(nil), rows.Handles...)}
	for _, row := range rows.Profiles {
		row.NotBeforeUTC, row.NotAfterUTC = cloneText(row.NotBeforeUTC), cloneText(row.NotAfterUTC)
		clone.Profiles = append(clone.Profiles, row)
	}
	for _, row := range rows.Credentials {
		row.PublicSPKI = append([]byte(nil), row.PublicSPKI...)
		clone.Credentials = append(clone.Credentials, row)
	}
	for _, row := range rows.Policies {
		row.FeedbackRouteID = cloneText(row.FeedbackRouteID)
		clone.Policies = append(clone.Policies, row)
	}
	for _, row := range rows.KeyMaterial {
		row.PublicSPKI = append([]byte(nil), row.PublicSPKI...)
		row.PrivatePKCS8 = append([]byte(nil), row.PrivatePKCS8...)
		clone.KeyMaterial = append(clone.KeyMaterial, row)
	}
	return clone
}

// cloneText detaches one optional text value.
func cloneText(value *string) *string {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

// clearAdminRows erases every candidate key byte before releasing rows.
func clearAdminRows(rows *datasourceadmin.Rows) {
	if rows == nil {
		return
	}
	for index := range rows.Credentials {
		clear(rows.Credentials[index].PublicSPKI)
	}
	for index := range rows.KeyMaterial {
		clear(rows.KeyMaterial[index].PublicSPKI)
		clear(rows.KeyMaterial[index].PrivatePKCS8)
	}
	*rows = datasourceadmin.Rows{}
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

// Read stops entropy consumption after cancellation.
func (r *contextReader) Read(output []byte) (int, error) {
	if r == nil || r.ctx == nil || r.source == nil || r.ctx.Err() != nil {
		return 0, errBackend
	}
	return r.source.Read(output)
}
