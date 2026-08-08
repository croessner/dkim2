package rotationadmin

import (
	"context"
	"fmt"
	"io"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
)

// Batch is one deterministic contiguous credential range over immutable content.
type Batch struct {
	Ordinal uint32
	Start   uint32
	End     uint32
	Total   uint32
	digest  admincontract.Digest
}

// BuildDNSBatches slices one immutable candidate without changing it.
func BuildDNSBatches(ctx context.Context, prepared *Prepared, batchSize uint32, limits Limits) ([]Batch, error) {
	if ctx == nil || ctx.Err() != nil || prepared == nil || limits.Validate() != nil ||
		batchSize == 0 || batchSize > limits.MaxDNSBatchRecords {
		return nil, errInvalid
	}
	candidate, err := prepared.CandidateDigest()
	if err != nil {
		return nil, errConflict
	}
	prepared.mu.Lock()
	if prepared.closed || !prepared.frozenDigest.Valid() || prepared.dnsRecords <= 0 ||
		len(prepared.dnsInputs) != prepared.dnsRecords {
		prepared.mu.Unlock()
		return nil, errConflict
	}
	frozen, total := prepared.frozenDigest, uint32(prepared.dnsRecords)
	inputs := make([]dnsRecordInput, len(prepared.dnsInputs))
	for index := range prepared.dnsInputs {
		inputs[index] = prepared.dnsInputs[index]
		inputs[index].publicSPKI = append([]byte(nil), prepared.dnsInputs[index].publicSPKI...)
	}
	prepared.mu.Unlock()
	defer clearDNSInputs(inputs)
	for _, input := range inputs {
		if err := domainadmin.ValidateCanonicalDNSRecord(ctx, input.domain, input.selector, input.algorithm, input.publicSPKI); err != nil {
			return nil, errConflict
		}
	}
	count := (total + batchSize - 1) / batchSize
	if count == 0 || count > limits.MaxDNSBatches {
		return nil, errLimit
	}
	batches := make([]Batch, 0, count)
	for ordinal, start := uint32(1), uint32(0); start < total; ordinal++ {
		end := min(start+batchSize, total)
		digest, digestErr := admincontract.DNSBatchDigest(admincontract.DNSBatch{CandidateDigest: candidate, FrozenWorkDigest: frozen, Ordinal: ordinal, Start: start, End: end, Total: total})
		if digestErr != nil {
			return nil, errConflict
		}
		batches = append(batches, Batch{Ordinal: ordinal, Start: start, End: end, Total: total, digest: digest})
		start = end
	}
	return batches, nil
}

// Digest returns the protected exact batch commitment.
func (b Batch) Digest() admincontract.Digest { return b.digest }

// String returns a bounded identity-free batch summary.
func (b Batch) String() string {
	return fmt.Sprintf("dns_batch ordinal=%d count=%d", b.Ordinal, b.End-b.Start)
}

// GoString returns the bounded identity-free batch summary.
func (b Batch) GoString() string { return b.String() }

// Format prevents candidate and work commitments from reaching output.
func (b Batch) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, b.String()) }

// MarshalJSON rejects generic serialization of protected batch commitments.
func (Batch) MarshalJSON() ([]byte, error) { return nil, errInvalid }
