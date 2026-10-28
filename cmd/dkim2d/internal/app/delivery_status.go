package app

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
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
// use, library evidence boundary, and route purpose. A returned original
// without any DKIM2-Signature header field yields the unsigned assessment only
// under the explicit continue compatibility policy; every other evidence
// failure, and the default reject policy, keep the refusal. After the
// evidence passed, a report that Draft-08 Section 16.2 or Sections 11 and
// 12.4 forbid signing yields the unsigned assessment with its closed reason.
func (s *SigningService) SignDeliveryStatus(ctx context.Context, request DeliveryStatusRequest) (SigningAssessment, error) {
	if s == nil || ctx == nil || s.store == nil || nilInterface(s.publicKeys) || s.clock == nil ||
		len(request.raw) == 0 {
		s.observeDSNEvidence(dkim2.DSNEvidenceStagePreflight, telemetryResultInternal)
		return SigningAssessment{}, &DomainError{}
	}
	if err := ctx.Err(); err != nil {
		s.observeDSNEvidence(dkim2.DSNEvidenceStagePreflight, telemetryResultTemporary)
		return SigningAssessment{}, err
	}
	metadata, err := daemonSigningMetadata()
	if err != nil {
		s.observeDSNEvidence(dkim2.DSNEvidenceStagePreflight, telemetryResultInternal)
		return SigningAssessment{}, &DomainError{}
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
		return SigningAssessment{}, &DomainError{}
	}
	evidenceRequest := dkim2.NewPostfixDSNSigningEvidenceRequest(
		request.RawMessage(), request.OuterReversePath(), request.OuterRecipients(),
	).WithPreferredIdentity(s.policies.reportingIdentity)
	evidence, err := evidenceSigner.EvaluateDSNForSigning(ctx, evidenceRequest)
	if err != nil {
		if s.policies.continueUnsignedOriginal &&
			dkim2.DSNEvidenceStageOf(err) == dkim2.DSNEvidenceStageEmbeddedUnsigned {
			s.observeDSNEvidence(dkim2.DSNEvidenceStageEmbeddedUnsigned, telemetryResultNotApplicable)
			return s.unsignedDeliveryStatus(DeliveryStatusUnsignedOriginal), nil
		}
		s.observeDSNEvidenceFailure(err)
		return deliveryStatusAssessment(operationFailureFromError(OperationDeliveryStatus, err))
	}
	s.observeDSNEvidence(dkim2.DSNEvidenceStageAuthorized, "success")
	return s.signAuthorizedDeliveryStatus(ctx, request, evidence, metadata, operationTime)
}

// unsignedDeliveryStatus records one closed unsigned outcome and returns its
// mutation-free assessment.
func (s *SigningService) unsignedDeliveryStatus(reason DeliveryStatusUnsignedReason) SigningAssessment {
	if s != nil && !nilInterface(s.dsnObserver) {
		func() {
			defer func() { _ = recover() }()
			s.dsnObserver.ObserveDSNUnsigned(string(reason))
		}()
	}
	return NewUnsignedDeliveryStatusAssessment(reason)
}

// deliveryStatusAssessment seals one applicable delivery-status result while
// propagating an operation error unchanged.
func deliveryStatusAssessment(result OperationResult, err error) (SigningAssessment, error) {
	if err != nil {
		return SigningAssessment{}, err
	}
	return NewApplicableSigningAssessment(result)
}

// deliveryStatusProfileSource exposes one pinned signing generation to the
// library's Draft-08 Section 16.2 identity resolver. It answers only the
// delivery_status policy use of one tenant at one operation instant.
type deliveryStatusProfileSource struct {
	lease  SigningLease
	tenant string
	at     time.Time
}

// DeliveryStatusProfile resolves the delivery_status profile of one candidate
// domain. A provider's permanent absence answer (not found, inactive, or a
// domain it cannot hold) is reported as found=false; malformed profile data
// and every temporary or undecided answer stay errors, so resolution never
// skips past a broken more specific profile.
func (p deliveryStatusProfileSource) DeliveryStatusProfile(ctx context.Context, domain string) (dkim2.SigningProfile, bool, error) {
	profile, err := p.lease.ResolvePolicy(ctx, p.tenant, domain, signingstore.PolicyDeliveryStatus, p.at)
	if err == nil {
		return profile, true, nil
	}
	if deliveryStatusProfileAbsent(err) {
		return dkim2.SigningProfile{}, false, nil
	}
	return dkim2.SigningProfile{}, false, err
}

// deliveryStatusProfileAbsent narrows the shared permanent-absence rule to
// genuine absence: malformed provider data is a defect, not an absent profile.
func deliveryStatusProfileAbsent(err error) bool {
	return permanentPolicyResolutionFailure(err) && provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData
}

// signAuthorizedDeliveryStatus resolves the Draft-08 Section 16.2 signing
// identity through the library resolver over the delivery_status profiles of
// the pinned generation and signs the exact DSN. It runs only after the
// library issued opaque evidence, so no profile or key is touched earlier.
// A report without an admissible identity leaves unsigned with its reason.
func (s *SigningService) signAuthorizedDeliveryStatus(
	ctx context.Context,
	request DeliveryStatusRequest,
	evidence dkim2.DSNSigningEvidence,
	metadata dkim2.SigningMetadata,
	operationTime time.Time,
) (SigningAssessment, error) {
	lease, err := s.store.Acquire(ctx)
	if err != nil {
		return deliveryStatusAssessment(NewOperationResult(OperationDeliveryStatus, OperationTemperror, OperationTempfail, nil))
	}
	defer func() { _ = lease.Close() }()
	signer, err := dkim2.NewSigner(
		s.publicKeys,
		dkim2.NewRequestRouteAuthority(),
		exactSigningAuthorizer{recipients: request.OuterRecipients()},
		lease,
		dkim2.WithSigningClock(func() time.Time { return operationTime }),
	)
	if err != nil {
		return SigningAssessment{}, &DomainError{}
	}
	evidence, profile, err := signer.ResolveDSNSigningIdentity(ctx, evidence, deliveryStatusProfileSource{
		lease: lease, tenant: request.Tenant(), at: operationTime,
	})
	if err != nil {
		switch dkim2.DSNEvidenceStageOf(err) {
		case dkim2.DSNEvidenceStageIdentityUnavailable:
			return s.unsignedDeliveryStatus(DeliveryStatusIdentityUnavailable), nil
		case dkim2.DSNEvidenceStageFromNotAuthentic:
			return s.unsignedDeliveryStatus(DeliveryStatusFromNotAuthentic), nil
		}
		return deliveryStatusAssessment(deliveryStatusResolutionFailure(err))
	}
	return deliveryStatusAssessment(s.signResolvedDeliveryStatus(ctx, request, signer, evidence, profile, metadata))
}

// deliveryStatusResolutionFailure classifies a failed identity resolution
// from the cause the library stage error wraps: a permanent provider answer
// (malformed profile data) or an inconsistent profile is a permanent refusal,
// everything else (unavailable, ambiguous, canceled) is temporary.
func deliveryStatusResolutionFailure(err error) (OperationResult, error) {
	var signingError *dkim2.SigningError
	if permanentPolicyResolutionFailure(errors.Unwrap(err)) ||
		errors.As(err, &signingError) && signingError.Code() == dkim2.SigningErrorInvalidRequest {
		return NewOperationResult(OperationDeliveryStatus, OperationPermerror, OperationReject, nil)
	}
	return NewOperationResult(OperationDeliveryStatus, OperationTemperror, OperationTempfail, nil)
}

// signResolvedDeliveryStatus plans the dedicated delivery-status route and
// signs the exact DSN under the resolved identity and profile.
func (s *SigningService) signResolvedDeliveryStatus(
	ctx context.Context,
	request DeliveryStatusRequest,
	signer *dkim2.Signer,
	evidence dkim2.DSNSigningEvidence,
	profile dkim2.SigningProfile,
	metadata dkim2.SigningMetadata,
) (OperationResult, error) {
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
	result, recovery, err := signer.SignDSN(ctx, dkim2.NewDSNSigningRequest(evidence, tickets[0], profile, metadata, dkim2.SigningTransportFinalNetworkPreDotStuffing))
	if err != nil || recovery.Valid() || !result.Valid() {
		return operationFailureFromError(OperationDeliveryStatus, err)
	}
	unrestricted, ok := result.Unrestricted()
	if !ok {
		return OperationResult{}, &DomainError{}
	}
	fields, err := completedSigningFields(unrestricted, s.policies.interopInfo)
	if err != nil {
		return OperationResult{}, err
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
