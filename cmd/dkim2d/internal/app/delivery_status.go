package app

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
)

// DeliveryStatusRequest carries exact outer DSN evidence into the daemon's
// dedicated signing operation.
type DeliveryStatusRequest struct {
	raw             []byte
	outerReverse    []byte
	outerRecipients [][]byte
	tenant          string
}

// deliveryStatusEvidencePrivateKeySigner makes the pre-policy evidence signer
// unusable for private-key operations. Evidence evaluation never invokes it.
type deliveryStatusEvidencePrivateKeySigner struct{}

// SignDigest rejects private signing before a delivery-status profile lease is acquired.
func (deliveryStatusEvidencePrivateKeySigner) SignDigest(
	context.Context,
	dkim2.PrivateKeyHandle,
	dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
}

// NewPostfixDeliveryStatusRequest snapshots one Postfix-exclusive DSN request
// after the HTTP boundary authenticated the dedicated route capability.
func NewPostfixDeliveryStatusRequest(raw, outerReverse []byte, outerRecipients [][]byte, tenant string) (DeliveryStatusRequest, error) {
	if len(raw) == 0 || !bytes.Equal(outerReverse, []byte("<>")) || len(outerRecipients) != 1 ||
		tenant == "" {
		return DeliveryStatusRequest{}, &DomainError{}
	}
	return DeliveryStatusRequest{
		raw: bytes.Clone(raw), outerReverse: bytes.Clone(outerReverse),
		outerRecipients: cloneOperationRecipients(outerRecipients), tenant: tenant,
	}, nil
}

// RawMessage returns an isolated exact outer DSN message snapshot.
func (r DeliveryStatusRequest) RawMessage() []byte { return bytes.Clone(r.raw) }

// OuterReversePath returns the exact outer DSN null reverse-path evidence.
func (r DeliveryStatusRequest) OuterReversePath() []byte { return bytes.Clone(r.outerReverse) }

// OuterRecipients returns isolated outer DSN recipient evidence.
func (r DeliveryStatusRequest) OuterRecipients() [][]byte {
	return cloneOperationRecipients(r.outerRecipients)
}

// Tenant returns the bounded administrative tenant.
func (r DeliveryStatusRequest) Tenant() string { return r.tenant }

// String prevents raw message and SMTP evidence from escaping diagnostics.
func (DeliveryStatusRequest) String() string { return operationRedacted }

// GoString returns the constant secret-safe request representation.
func (r DeliveryStatusRequest) GoString() string { return r.String() }

// SignDeliveryStatus signs one validated DSN only through the dedicated policy
// use, library evidence boundary, and route purpose.
func (s *SigningService) SignDeliveryStatus(ctx context.Context, request DeliveryStatusRequest) (OperationResult, error) {
	if s == nil || ctx == nil || s.store == nil || nilInterface(s.publicKeys) || s.clock == nil ||
		len(request.raw) == 0 {
		s.observeDSNEvidence(dkim2.DSNEvidenceStagePreflight, telemetryResultInternal)
		return OperationResult{}, &DomainError{}
	}
	if err := ctx.Err(); err != nil {
		s.observeDSNEvidence(dkim2.DSNEvidenceStagePreflight, telemetryResultTemporary)
		return OperationResult{}, err
	}
	operationTime := s.clock().UTC()
	evidenceSigner, err := dkim2.NewSigner(
		s.publicKeys,
		dkim2.NewRequestRouteAuthority(),
		exactSigningAuthorizer{recipients: request.OuterRecipients()},
		deliveryStatusEvidencePrivateKeySigner{},
		dkim2.WithSigningClock(func() time.Time { return operationTime }),
	)
	if err != nil {
		s.observeDSNEvidence(dkim2.DSNEvidenceStagePreflight, telemetryResultInternal)
		return OperationResult{}, &DomainError{}
	}
	evidenceRequest := dkim2.NewPostfixDerivedDSNSigningEvidenceRequest(
		request.RawMessage(), request.OuterReversePath(), request.OuterRecipients(),
	)
	evidence, err := evidenceSigner.EvaluateDSNForSigning(ctx, evidenceRequest)
	if err != nil {
		s.observeDSNEvidenceFailure(err)
		return operationFailureFromError(OperationDeliveryStatus, err)
	}
	s.observeDSNEvidence(dkim2.DSNEvidenceStageAuthorized, "success")
	lease, err := s.store.Acquire(ctx)
	if err != nil {
		return NewOperationResult(OperationDeliveryStatus, OperationTemperror, OperationTempfail, nil)
	}
	defer func() { _ = lease.Close() }()
	profile, err := lease.ResolvePolicy(ctx, request.Tenant(), evidence.SigningDomain(), signingstore.PolicyDeliveryStatus, operationTime)
	if err != nil {
		if permanentPolicyResolutionFailure(err) {
			return NewOperationResult(OperationDeliveryStatus, OperationPermerror, OperationReject, nil)
		}
		return NewOperationResult(OperationDeliveryStatus, OperationTemperror, OperationTempfail, nil)
	}
	signer, err := dkim2.NewSigner(
		s.publicKeys,
		dkim2.NewRequestRouteAuthority(),
		exactSigningAuthorizer{recipients: request.OuterRecipients()},
		lease,
		dkim2.WithSigningClock(func() time.Time { return operationTime }),
	)
	if err != nil {
		return OperationResult{}, &DomainError{}
	}
	source, err := dkim2.NewSigningSource(request.RawMessage())
	if err != nil {
		return operationPermanentFailure(OperationDeliveryStatus)
	}
	entry, err := dkim2.NewDeliveryStatusRouteEntry(source, request.OuterReversePath(), request.OuterRecipients(), dkim2.RouteDisclosureSingle, []byte(signingRouteScope))
	if err != nil {
		return operationFailureFromError(OperationDeliveryStatus, err)
	}
	plan, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		return operationFailureFromError(OperationDeliveryStatus, err)
	}
	_, tickets, err := signer.PlanRouteFanout(ctx, plan)
	if err != nil || len(tickets) != 1 || !tickets[0].Valid() {
		return operationFailureFromError(OperationDeliveryStatus, err)
	}
	result, recovery, err := signer.SignDSN(ctx, dkim2.NewDSNSigningRequest(evidence, tickets[0], profile, dkim2.SigningMetadata{}, dkim2.SigningTransportFinalNetworkPreDotStuffing))
	if err != nil || recovery.Valid() || !result.Valid() {
		return operationFailureFromError(OperationDeliveryStatus, err)
	}
	unrestricted, ok := result.Unrestricted()
	if !ok {
		return OperationResult{}, &DomainError{}
	}
	generated := unrestricted.GeneratedFields()
	fields := make([]CompletedField, len(generated))
	for index := range generated {
		fields[index], err = NewCompletedField(generated[index])
		if err != nil {
			return OperationResult{}, &DomainError{}
		}
	}
	return NewOperationResult(OperationDeliveryStatus, OperationPass, OperationAccept, fields)
}

// observeDSNEvidenceFailure maps one typed pre-policy error to a closed stage/result pair.
func (s *SigningService) observeDSNEvidenceFailure(err error) {
	stage := dkim2.DSNEvidenceStageOf(err)
	if !stage.Known() {
		stage = dkim2.DSNEvidenceStagePreflight
	}
	result := telemetryResultFailure
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		result = "temporary"
	} else {
		var signingError *dkim2.SigningError
		if !errors.As(err, &signingError) {
			result = "internal"
		} else if signingError.Code() == dkim2.SigningErrorCallbackTemporary {
			result = "temporary"
		}
	}
	s.observeDSNEvidence(stage, result)
}

// observeDSNEvidence contains the optional telemetry boundary and its panics.
func (s *SigningService) observeDSNEvidence(stage dkim2.DSNEvidenceStage, result string) {
	if s != nil && !nilInterface(s.dsnObserver) {
		func() {
			defer func() { _ = recover() }()
			s.dsnObserver.ObserveDSNEvidence(string(stage), result)
		}()
	}
}
