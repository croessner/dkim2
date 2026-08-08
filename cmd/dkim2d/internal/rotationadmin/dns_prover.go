package rotationadmin

import (
	"context"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
)

const (
	explicitRecursiveResolver  = "explicit_recursive"
	canonicalRecursiveResolver = "recursive"
)

// DNSBatchProver adapts immutable campaign batches to the production DNS
// resolver/parser/proof owner. It has no DNS write capability.
type DNSBatchProver struct {
	engine *domainadmin.DNSProofEngine
	policy datasourceadmin.DNSPolicy
}

// ExportBatchDNS writes one deterministic owner-only artifact for an external
// authorized publisher. It neither records proof nor changes campaign state.
func (p *DNSBatchProver) ExportBatchDNS(ctx context.Context, path string, prepared *Prepared, batch Batch) (domainadmin.DNSExportResult, error) {
	if p == nil || p.engine == nil || ctx == nil || ctx.Err() != nil || batch.Ordinal == 0 || batch.Start >= batch.End || batch.Total == 0 || batch.End > batch.Total {
		return domainadmin.DNSExportResult{}, errInvalid
	}
	prepared.mu.Lock()
	if prepared.closed || prepared.dnsRecords != len(prepared.dnsInputs) || int(batch.Total) != prepared.dnsRecords || int(batch.End) > len(prepared.dnsInputs) {
		prepared.mu.Unlock()
		return domainadmin.DNSExportResult{}, errConflict
	}
	inputs := make([]domainadmin.DNSProofInput, 0, batch.End-batch.Start)
	for _, record := range prepared.dnsInputs[batch.Start:batch.End] {
		input, err := domainadmin.NewDNSProofInput(ctx, record.domain, record.selector, record.algorithm, record.publicSPKI)
		if err != nil {
			prepared.mu.Unlock()
			for index := range inputs {
				_ = inputs[index].Close()
			}
			return domainadmin.DNSExportResult{}, errConflict
		}
		inputs = append(inputs, input)
	}
	prepared.mu.Unlock()
	defer func() {
		for index := range inputs {
			_ = inputs[index].Close()
		}
	}()
	limits := domainadmin.DefaultLimits()
	limits.MaxDNSRecords = 256
	limits.MaxDNSExportBytes = 1 << 20
	return domainadmin.ExportCanonicalDNSBatch(ctx, path, inputs, p.policy.ExportTTLSeconds, limits)
}

// NewDNSBatchProver constructs a strictly explicit recursive-resolver proof
// authority. DNS writes, TSIG, and zone transfer credentials are intentionally
// absent: campaign DNS publication remains an operator action.
func NewDNSBatchProver(policy datasourceadmin.DNSPolicy, lookupTimeout time.Duration) (*DNSBatchProver, error) {
	if datasourceadmin.ValidateDNSPolicy(policy) != nil || policy.ResolverClass != canonicalRecursiveResolver ||
		len(policy.ResolverEndpoints) == 0 || lookupTimeout <= 0 || lookupTimeout > 30*time.Second {
		return nil, errInvalid
	}
	limits := domainadmin.DefaultLimits()
	limits.MaxDNSRecords = 256
	limits.BackendDeadline = lookupTimeout
	limits.DNSProofLifetime = time.Duration(policy.ProofLifetimeSeconds) * time.Second
	if limits.Validate() != nil {
		return nil, errInvalid
	}
	engine, err := domainadmin.NewDNSProofEngine(limits)
	if err != nil {
		return nil, errInvalid
	}
	owned := datasourceadmin.DNSPolicy{ResolverClass: policy.ResolverClass, ResolverEndpoints: append([]string(nil), policy.ResolverEndpoints...), ExportTTLSeconds: policy.ExportTTLSeconds, ProofLifetimeSeconds: policy.ProofLifetimeSeconds}
	return &DNSBatchProver{engine: engine, policy: owned}, nil
}

// ProveBatch validates the exact immutable batch range then obtains one fresh
// resolver-path proof for every record. It returns no DNS identity or record.
func (p *DNSBatchProver) ProveBatch(ctx context.Context, prepared *Prepared, batch Batch) (time.Time, error) {
	if p == nil || p.engine == nil || ctx == nil || ctx.Err() != nil || datasourceadmin.ValidateDNSPolicy(p.policy) != nil ||
		batch.Ordinal == 0 || batch.Start >= batch.End || batch.Total == 0 || batch.End > batch.Total {
		return time.Time{}, errInvalid
	}
	prepared.mu.Lock()
	if prepared.closed || prepared.dnsRecords != len(prepared.dnsInputs) || int(batch.Total) != prepared.dnsRecords || int(batch.End) > len(prepared.dnsInputs) {
		prepared.mu.Unlock()
		return time.Time{}, errConflict
	}
	inputs := make([]domainadmin.DNSProofInput, 0, batch.End-batch.Start)
	for _, record := range prepared.dnsInputs[batch.Start:batch.End] {
		input, err := domainadmin.NewDNSProofInput(ctx, record.domain, record.selector, record.algorithm, record.publicSPKI)
		if err != nil {
			prepared.mu.Unlock()
			for index := range inputs {
				_ = inputs[index].Close()
			}
			return time.Time{}, errConflict
		}
		inputs = append(inputs, input)
	}
	prepared.mu.Unlock()
	defer func() {
		for index := range inputs {
			_ = inputs[index].Close()
		}
	}()
	return p.engine.ProveCanonicalBatch(ctx, p.policy, inputs)
}
