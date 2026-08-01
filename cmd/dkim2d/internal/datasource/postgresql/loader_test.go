// Package postgresql tests the daemon-owned PostgreSQL datasource adapter.
package postgresql

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/provider"
)

type fakePool struct {
	transaction *fakeTransaction
}

// Begin returns one synthetic stable transaction.
func (p fakePool) Begin(context.Context) (Transaction, error) { return p.transaction, nil }

// Close completes the synthetic pool lifecycle.
func (fakePool) Close() {}

type fakeTransaction struct {
	rows         DatasetRows
	isolation    string
	readOnly     bool
	currentReads int
	committed    bool
}

// Isolation returns the injected effective transaction properties.
func (t *fakeTransaction) Isolation(context.Context) (string, bool, error) {
	return t.isolation, t.readOnly, nil
}

// ReadCurrent returns the initial and final metadata fences.
func (t *fakeTransaction) ReadCurrent(context.Context) (MetadataRow, error) {
	t.currentReads++
	if t.currentReads == 1 {
		return t.rows.Current, nil
	}
	return t.rows.Final, nil
}

// HandlePage returns one page and then completion.
func (t *fakeTransaction) HandlePage(_ context.Context, after string, _ int) ([]HandleRow, error) {
	if after != "" {
		return nil, nil
	}
	return t.rows.Handles, nil
}

// ProfilePage returns one page and then completion.
func (t *fakeTransaction) ProfilePage(_ context.Context, after string, _ int) ([]ProfileRow, error) {
	if after != "" {
		return nil, nil
	}
	return t.rows.Profiles, nil
}

// CredentialPage returns one page and then completion.
func (t *fakeTransaction) CredentialPage(
	_ context.Context,
	afterProfile string,
	_ string,
	_ int,
) ([]CredentialRow, error) {
	if afterProfile != "" {
		return nil, nil
	}
	return t.rows.Credentials, nil
}

// PolicyPage returns one page and then completion.
func (t *fakeTransaction) PolicyPage(
	_ context.Context,
	afterTenant string,
	_ string,
	_ string,
	_ int,
) ([]PolicyRow, error) {
	if afterTenant != "" {
		return nil, nil
	}
	return t.rows.Policies, nil
}

// KeyMaterialPage returns one native-key page and then completion.
func (t *fakeTransaction) KeyMaterialPage(
	_ context.Context,
	afterHandle string,
	_ int,
) ([]KeyMaterialRow, error) {
	if afterHandle != "" {
		return nil, nil
	}
	return t.rows.KeyMaterial, nil
}

// Commit marks the read-only transaction complete.
func (t *fakeTransaction) Commit(context.Context) error {
	t.committed = true
	return nil
}

// Rollback completes an incomplete synthetic transaction.
func (*fakeTransaction) Rollback(context.Context) error { return nil }

// TestLoaderRequiresProvenStableReadOnlySnapshot proves isolation is an
// explicit success precondition rather than an assumed driver default.
func TestLoaderRequiresProvenStableReadOnlySnapshot(t *testing.T) {
	t.Parallel()
	transaction := &fakeTransaction{
		rows: minimalRows(t), isolation: "read committed", readOnly: true,
	}
	loader, err := NewLoader(
		fakePool{transaction: transaction},
		provider.DefaultLimits(), 2, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := loader.Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeUnavailable {
		t.Fatal("weak isolation must fail closed")
	}
}

// TestLoaderCommitsCompleteGenerationBeforePublication proves the fixed
// transaction path produces one generation-matched candidate.
func TestLoaderCommitsCompleteGenerationBeforePublication(t *testing.T) {
	t.Parallel()
	transaction := &fakeTransaction{
		rows: minimalRows(t), isolation: repeatableReadIsolation, readOnly: true,
	}
	loader, err := NewLoader(
		fakePool{transaction: transaction},
		provider.DefaultLimits(), 2, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	candidate, err := loader.Load(ctx)
	if err != nil || !candidate.Valid() || !transaction.committed {
		t.Fatal("complete stable snapshot did not publish")
	}
}

// TestLoaderRejectsMissingNativeKeyMaterial proves a public-only transaction
// cannot publish a network signing candidate.
func TestLoaderRejectsMissingNativeKeyMaterial(t *testing.T) {
	rows := minimalRows(t)
	rows.KeyMaterial = nil
	transaction := &fakeTransaction{
		rows: rows, isolation: repeatableReadIsolation, readOnly: true,
	}
	loader, err := NewLoader(
		fakePool{transaction: transaction}, provider.DefaultLimits(),
		2, 1<<20, 2*time.Second,
	)
	if err != nil {
		t.Fatal("construct loader")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := loader.Load(ctx); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData {
		t.Fatal("PostgreSQL loader accepted missing native key material")
	}
}
