package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
)

const batchRevisionRouteScope = "dkim2d-batch-revision"

type batchSigningProfiles struct {
	final, via dkim2.SigningProfile
}

// ReviseBatch verifies original evidence once and seals all actual copies before any external release.
func (s *SigningService) ReviseBatch(ctx context.Context, request BatchRevisionRequest) (BatchRevisionResult, error) {
	if s == nil || s.store == nil || s.publicKeys == nil || s.clock == nil || ctx == nil || !request.Valid() {
		return BatchRevisionResult{}, &DomainError{}
	}
	if err := ctx.Err(); err != nil {
		return BatchRevisionResult{}, err
	}
	lease, err := s.store.Acquire(ctx)
	if err != nil || lease == nil {
		return batchRevisionFailure(request, OperationTemperror), nil
	}
	defer func() { _ = lease.Close() }()
	at := s.clock().UTC()
	profiles, err := resolveBatchProfiles(ctx, lease, request.state.copies, at)
	if err != nil {
		if permanentPolicyResolutionFailure(err) {
			return batchRevisionFailure(request, OperationPermerror), nil
		}
		return batchRevisionFailure(request, OperationTemperror), nil
	}
	metadata, err := s.policies.ordinaryTransit.metadata()
	if err != nil {
		return BatchRevisionResult{}, &DomainError{}
	}
	signer, err := dkim2.NewSigner(s.publicKeys, dkim2.NewRequestRouteAuthority(),
		batchRevisionAuthorizer{copies: request.state.copies}, lease,
		dkim2.WithSigningClock(func() time.Time { return at }))
	if err != nil {
		return batchRevisionError(request, err)
	}
	original := request.state.original.state
	verification, capability, err := signer.VerifyForRevision(ctx,
		dkim2.NewVerifyRequest(original.raw, original.reverse, original.recipients))
	if err != nil {
		return batchRevisionError(request, err)
	}
	if verification.Status() != dkim2.RevisionVerificationVerified || !capability.Valid() {
		class := OperationPermerror
		if verification.Status() == dkim2.RevisionVerificationProviderTemporary ||
			verification.Status() == dkim2.RevisionVerificationProviderContract {
			class = OperationTemperror
		}
		return batchRevisionFailure(request, class), nil
	}
	tickets, err := planBatchRevision(ctx, signer, capability, request.state.copies)
	if err != nil {
		return batchRevisionError(request, err)
	}
	outputs := make([]BatchRevisionOutput, 0, len(profiles))
	for index, branch := range request.state.copies {
		if branch.local {
			continue
		}
		output, signErr := completeBatchCopy(ctx, signer, capability, branch, tickets[index], profiles[index], metadata)
		if signErr != nil {
			return batchRevisionError(request, signErr)
		}
		outputs = append(outputs, output)
	}
	return BatchRevisionResult{binding: request.state.binding, originalSHA256: batchSHA256(original.raw),
		result: OperationPass, disposition: OperationAccept, outputs: outputs}, nil
}

// resolveBatchProfiles pins every external copy to exact policies in one provider generation.
func resolveBatchProfiles(ctx context.Context, lease SigningLease, copies []BatchCopy, at time.Time) (map[int]batchSigningProfiles, error) {
	profiles := make(map[int]batchSigningProfiles, len(copies))
	for index, branch := range copies {
		if branch.local {
			continue
		}
		profile, err := lease.ResolvePolicy(ctx, branch.tenant, branch.domain, signingstore.PolicyOrdinaryTransit, at)
		if err != nil {
			return nil, err
		}
		selected := batchSigningProfiles{final: profile}
		if branch.via != nil {
			selected.via, err = lease.ResolvePolicy(ctx, branch.via.tenant, branch.via.domain, signingstore.PolicyOrdinaryTransit, at)
			if err != nil {
				return nil, err
			}
			path := branch.via.recipients[0]
			separator := bytes.LastIndexByte(path, '@')
			if separator < 1 || len(path) < separator+3 || path[len(path)-1] != '>' {
				return nil, &DomainError{}
			}
			domain := strings.ToLower(string(path[separator+1 : len(path)-1]))
			if err := lease.ResolveAnyProfile(ctx, branch.via.tenant, domain, at); err != nil {
				return nil, err
			}
		}
		profiles[index] = selected
	}
	return profiles, nil
}

// planBatchRevision declares local and external route classes under one verified original capability.
func planBatchRevision(ctx context.Context, signer *dkim2.Signer, capability dkim2.VerifiedRevisionInput, copies []BatchCopy) ([]dkim2.RouteCopyTicket, error) {
	entries := make([]dkim2.RouteEntry, len(copies))
	for index, branch := range copies {
		message := branch.message.state
		reverse, recipients := message.reverse, message.recipients
		if branch.via != nil {
			reverse, recipients = branch.via.reverse, branch.via.recipients
		}
		source, err := dkim2.NewSigningSource(message.raw)
		if err != nil {
			return nil, err
		}
		var entry dkim2.RouteEntry
		if branch.local {
			entry, err = dkim2.NewInControlExistingRouteEntry(capability, source, message.reverse, message.recipients,
				dkim2.RouteDisclosureSingle, []byte(batchRevisionRouteScope), nil)
		} else {
			entry, err = dkim2.NewExistingRouteEntry(capability, source, reverse, recipients,
				dkim2.RouteDisclosureSingle, []byte(batchRevisionRouteScope))
		}
		if err != nil {
			return nil, err
		}
		entries[index] = entry
	}
	fanout, err := dkim2.NewRouteFanoutRequest(entries)
	if err != nil {
		return nil, err
	}
	plan, tickets, err := signer.PlanRouteFanout(ctx, fanout)
	if err != nil {
		return nil, err
	}
	if !plan.Valid() || plan.CopyCount() != len(copies) || len(tickets) != len(copies) {
		return nil, &DomainError{}
	}
	return tickets, nil
}

// completeBatchCopy executes an optional same-control intermediate hop before the final external signature.
func completeBatchCopy(ctx context.Context, signer *dkim2.Signer, capability dkim2.VerifiedRevisionInput,
	branch BatchCopy, ticket dkim2.RouteCopyTicket, profiles batchSigningProfiles, metadata dkim2.SigningMetadata) (BatchRevisionOutput, error) {
	if branch.via == nil {
		return completeBatchRevision(ctx, signer, capability, branch, ticket, profiles.final, metadata)
	}
	intermediate := branch
	intermediate.via = nil
	intermediate.message = BatchMessage{state: &batchMessageState{raw: branch.message.state.raw,
		reverse: branch.via.reverse, recipients: branch.via.recipients, fidelity: branch.message.state.fidelity}}
	first, err := completeBatchRevision(ctx, signer, capability, intermediate, ticket, profiles.via, metadata)
	if err != nil {
		return BatchRevisionOutput{}, err
	}
	raw := insertBatchFields(branch.message.state.raw, first.insertionOffset, first.fields)
	verification, nextCapability, err := signer.VerifyForRevision(ctx, dkim2.NewVerifyRequest(raw, branch.via.reverse, branch.via.recipients))
	if err != nil {
		return BatchRevisionOutput{}, err
	}
	if verification.Status() != dkim2.RevisionVerificationVerified || !nextCapability.Valid() {
		class := OperationPermerror
		if verification.Status() == dkim2.RevisionVerificationProviderTemporary || verification.Status() == dkim2.RevisionVerificationProviderContract {
			class = OperationTemperror
		}
		return BatchRevisionOutput{}, &batchVerificationFailure{class: class}
	}
	final := branch
	final.via = nil
	final.message = BatchMessage{state: &batchMessageState{raw: raw, reverse: branch.message.state.reverse,
		recipients: branch.message.state.recipients, fidelity: branch.message.state.fidelity}}
	tickets, err := planBatchRevision(ctx, signer, nextCapability, []BatchCopy{final})
	if err != nil {
		return BatchRevisionOutput{}, err
	}
	last, err := completeBatchRevision(ctx, signer, nextCapability, final, tickets[0], profiles.final, metadata)
	if err != nil {
		return BatchRevisionOutput{}, err
	}
	last.currentSHA256 = first.currentSHA256
	last.insertionOffset = first.insertionOffset
	last.fields = append(first.Fields(), last.fields...)
	if len(last.fields) > 3 || batchSHA256(insertBatchFields(branch.message.state.raw, last.insertionOffset, last.fields)) != last.resultSHA256 {
		return BatchRevisionOutput{}, &DomainError{}
	}
	return last, nil
}

// insertBatchFields applies an already library-proved append-only header delta without normalization.
func insertBatchFields(raw []byte, offset int, fields []CompletedField) []byte {
	result := append([]byte(nil), raw[:offset]...)
	for _, field := range fields {
		result = append(result, field.bytes...)
	}
	return append(result, raw[offset:]...)
}

// completeBatchRevision extracts only a public unrestricted result and verifies its exact insertion delta.
func completeBatchRevision(ctx context.Context, signer *dkim2.Signer, capability dkim2.VerifiedRevisionInput,
	branch BatchCopy, ticket dkim2.RouteCopyTicket, profile dkim2.SigningProfile, metadata dkim2.SigningMetadata) (BatchRevisionOutput, error) {
	message := branch.message.state
	result, recovery, err := signer.SignExisting(ctx, dkim2.NewExistingSigningRequest(capability,
		message.raw, message.reverse, message.recipients, ticket, profile, metadata,
		dkim2.SigningTransportFinalNetworkPreDotStuffing, dkim2.RejectUnavailableBody, dkim2.RecipeCopyOnly))
	if err != nil {
		return BatchRevisionOutput{}, err
	}
	unrestricted, ok := result.Unrestricted()
	if recovery.Valid() || !ok || !unrestricted.Valid() {
		return BatchRevisionOutput{}, &DomainError{}
	}
	fields := unrestricted.GeneratedFields()
	completed := unrestricted.Bytes()
	insertion := bytes.Index(message.raw, []byte("\r\n\r\n")) + 2
	if insertion < 2 || len(fields) == 0 || len(fields) > 3 {
		return BatchRevisionOutput{}, &DomainError{}
	}
	combined := make([]byte, 0, len(completed))
	combined = append(combined, message.raw[:insertion]...)
	outputFields := make([]CompletedField, 0, len(fields))
	for _, raw := range fields {
		field, fieldErr := NewCompletedField(raw)
		if fieldErr != nil {
			return BatchRevisionOutput{}, fieldErr
		}
		outputFields = append(outputFields, field)
		combined = append(combined, raw...)
	}
	combined = append(combined, message.raw[insertion:]...)
	if !bytes.Equal(combined, completed) {
		return BatchRevisionOutput{}, &DomainError{}
	}
	return BatchRevisionOutput{id: branch.id, currentSHA256: batchSHA256(message.raw), resultSHA256: batchSHA256(completed),
		insertionOffset: insertion, fields: outputFields}, nil
}

// batchRevisionAuthorizer accepts only unrestricted library-derived policy and one exact private recipient.
type batchRevisionAuthorizer struct{ copies []BatchCopy }

// Authorize keeps authenticated request flags and recipient disclosure under sealed library authority.
func (a batchRevisionAuthorizer) Authorize(_ context.Context, query dkim2.SigningAuthorizationQuery) (dkim2.SigningAuthorizationResult, error) {
	if !query.Valid() {
		return dkim2.SigningAuthorizationResult{}, &DomainError{}
	}
	authorized := false
	switch query.Purpose() {
	case dkim2.SigningAuthorizationPolicy:
		facts, restriction, ok := query.PolicyFacts()
		authorized = ok && facts.Valid() && restriction == dkim2.SigningRestrictionUnrestricted
	case dkim2.SigningAuthorizationRecipientDisclosure:
		for _, branch := range a.copies {
			if !branch.local && sameRecipients(branch.message.state.recipients, query.Recipients()) {
				authorized = true
				break
			}
			if branch.via != nil && sameRecipients(branch.via.recipients, query.Recipients()) {
				authorized = true
				break
			}
		}
	}
	if authorized {
		return dkim2.AuthorizeSigning(query), nil
	}
	return dkim2.DenySigning(query), nil
}

// batchRevisionFailure binds a mutation-free permanent or temporary result to the submitted batch.
func batchRevisionFailure(request BatchRevisionRequest, class OperationResultClass) BatchRevisionResult {
	disposition := OperationReject
	if class == OperationTemperror {
		disposition = OperationTempfail
	}
	return BatchRevisionResult{binding: request.state.binding, originalSHA256: batchSHA256(request.state.original.state.raw),
		result: class, disposition: disposition}
}

// batchRevisionError reuses the established closed signing and context failure mapping.
func batchRevisionError(request BatchRevisionRequest, err error) (BatchRevisionResult, error) {
	var verification *batchVerificationFailure
	if errors.As(err, &verification) {
		return batchRevisionFailure(request, verification.class), nil
	}
	result, failureErr := operationFailureFromError(OperationRevise, err)
	if failureErr != nil {
		return BatchRevisionResult{}, failureErr
	}
	return batchRevisionFailure(request, result.Result()), nil
}

// batchVerificationFailure carries only the closed result of intermediate verification.
type batchVerificationFailure struct{ class OperationResultClass }

// Error deliberately excludes message, address, signature, and provider diagnostics.
func (*batchVerificationFailure) Error() string { return "batch intermediate verification failed" }

var _ BatchRevisionService = (*SigningService)(nil)
