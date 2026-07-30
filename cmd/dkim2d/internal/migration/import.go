package migration

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
)

var keyImportAttributes = []string{
	legacySelector, legacyDomain, legacyAssociatedDomain, legacyKeyType, legacyKey,
}

// KeyImportClient is the separate protected principal allowed to read DKIMKey.
type KeyImportClient interface {
	FetchKey(context.Context, string, string, []string, int) ([]byte, error)
}

// DNSProver performs one cache-bypassed exact DNS/SPKI proof.
type DNSProver interface {
	Prove(context.Context, string, string, Algorithm, []byte) error
}

// ImportedCredential owns one short-lived validated private key and mapping.
type ImportedCredential struct {
	mapping Mapping
	key     *signingstore.ImportedPrivateKey
}

// StageImportedRegistry creates one inert exact generation registry.
func StageImportedRegistry(
	plan Plan,
	imported []*ImportedCredential,
) (string, error) {
	generation, err := parseGeneration(plan.Generation)
	if err != nil || len(imported) != len(plan.Mappings) ||
		len(imported) == 0 || plan.RegistryRoot == "" {
		return "", errors.New("protected registry staging unavailable")
	}
	entries := make([]signingstore.RegistryStagingEntry, 0, len(imported))
	for index, credential := range imported {
		if credential == nil || credential.key == nil ||
			credential.mapping != plan.Mappings[index] {
			return "", errors.New("protected registry staging unavailable")
		}
		entry, entryErr := signingstore.NewRegistryStagingEntry(
			credential.mapping.TenantID,
			credential.mapping.Domain,
			credential.mapping.ProfileUse,
			credential.mapping.HandleID,
			credential.key,
		)
		if entryErr != nil {
			return "", errors.New("protected registry staging unavailable")
		}
		entries = append(entries, entry)
	}
	path, err := signingstore.StageRegistry(plan.RegistryRoot, generation, entries)
	if err != nil {
		return "", errors.New("protected registry staging unavailable")
	}
	return path, nil
}

// Close clears the retained protected key.
func (c *ImportedCredential) Close() error {
	if c == nil || c.key == nil {
		return nil
	}
	err := c.key.Close()
	c.key = nil
	c.mapping = Mapping{}
	return err
}

// String returns a constant protected imported-credential summary.
func (*ImportedCredential) String() string { return redacted }

// GoString returns a constant protected imported-credential representation.
func (*ImportedCredential) GoString() string { return redacted }

// ImportKeys fetches private values only after inventory and plan validation.
func ImportKeys(
	ctx context.Context,
	records []LegacyRecord,
	plan Plan,
	client KeyImportClient,
	prover DNSProver,
) ([]*ImportedCredential, error) {
	counts := InventoryCounts{}
	if ctx == nil || client == nil || prover == nil ||
		ValidatePlan(records, plan, &counts) != nil {
		return nil, errors.New("protected key import unavailable")
	}
	active := make(map[string]LegacyRecord, len(records))
	for _, record := range records {
		if record.active {
			active[record.domain+"\x00"+record.selector] = record
		}
	}
	imported := make([]*ImportedCredential, 0, len(plan.Mappings))
	success := false
	defer func() {
		if !success {
			closeImported(imported)
		}
	}()
	for _, mapping := range plan.Mappings {
		record, exists := active[mapping.Domain+"\x00"+mapping.Selector]
		if !exists {
			return nil, errors.New("protected key import unavailable")
		}
		encoded, err := client.FetchKey(
			ctx, record.domain, record.sourceSelector,
			append([]string(nil), keyImportAttributes...), 64<<10,
		)
		if err != nil || len(encoded) == 0 || len(encoded) > 64<<10 {
			clear(encoded)
			return nil, errors.New("protected key import unavailable")
		}
		key, err := signingstore.InspectImportedPrivateKey(
			encoded, string(record.algorithm),
		)
		clear(encoded)
		if err != nil || key == nil {
			return nil, errors.New("protected key import unavailable")
		}
		publicDER := key.PublicSPKIDER()
		if len(publicDER) == 0 ||
			prover.Prove(
				ctx, record.domain, record.selector, record.algorithm, publicDER,
			) != nil {
			clear(publicDER)
			_ = key.Close()
			return nil, errors.New("protected key import unavailable")
		}
		clear(publicDER)
		imported = append(imported, &ImportedCredential{
			mapping: mapping, key: key,
		})
	}
	success = true
	return imported, nil
}

// FreshDNSProver creates one new DNS provider per credential to bypass caches.
type FreshDNSProver struct {
	transport dkim2.TXTTransport
}

// NewFreshDNSProver constructs one exact injected DNS proof owner.
func NewFreshDNSProver(transport dkim2.TXTTransport) (*FreshDNSProver, error) {
	if transport == nil {
		return nil, errors.New("migration dns unavailable")
	}
	return &FreshDNSProver{transport: transport}, nil
}

// Prove requires exactly one matching algorithm and canonical public SPKI.
func (p *FreshDNSProver) Prove(
	ctx context.Context,
	domain string,
	selector string,
	algorithm Algorithm,
	expectedSPKI []byte,
) error {
	if p == nil || p.transport == nil || ctx == nil || len(expectedSPKI) == 0 {
		return errors.New("migration dns unavailable")
	}
	publicAlgorithm := dkim2.AlgorithmRSASHA256
	if algorithm == AlgorithmEd25519 {
		publicAlgorithm = dkim2.AlgorithmEd25519SHA256
	} else if algorithm != AlgorithmRSA {
		return errors.New("migration dns unavailable")
	}
	query, err := dkim2.NewPublicKeyQuery(domain, selector, publicAlgorithm)
	if err != nil {
		return errors.New("migration dns unavailable")
	}
	provider, err := dkim2.NewDNSPublicKeyProvider(p.transport)
	if err != nil {
		return errors.New("migration dns unavailable")
	}
	result, err := provider.LookupPublicKey(ctx, query)
	if err != nil || result.Status() != dkim2.PublicKeyStatusFound ||
		result.Algorithm() != publicAlgorithm {
		return errors.New("migration dns unavailable")
	}
	var public any
	if rsaKey, ok := result.RSAPublicKey(); ok {
		public = rsaKey
	} else if ed25519Key, ok := result.Ed25519PublicKey(); ok {
		public = ed25519Key
	} else {
		return errors.New("migration dns unavailable")
	}
	actualSPKI, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return errors.New("migration dns unavailable")
	}
	defer clear(actualSPKI)
	if !bytes.Equal(actualSPKI, expectedSPKI) {
		return errors.New("migration dns unavailable")
	}
	return nil
}

// closeImported clears every imported credential.
func closeImported(imported []*ImportedCredential) {
	for _, credential := range imported {
		_ = credential.Close()
	}
}
