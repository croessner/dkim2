package app

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/croessner/dkim2"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const signingRouteScope = "dkim2d-local-signing"

// SigningService composes exact signing-policy resolution with request-scoped
// route, authorization, verification, and private signing.
type SigningService struct {
	publicKeys dkim2.PublicKeyProvider
	store      signingAuthority
	clock      func() time.Time
}

type signingAuthority interface {
	Acquire(context.Context) (signingLease, error)
}

type signingLease interface {
	ResolvePolicy(
		context.Context,
		string,
		string,
		signingstore.PolicyUse,
		time.Time,
	) (dkim2.SigningProfile, error)
	dkim2.PrivateKeySigner
	Close() error
}

type flatSigningAuthority struct {
	runtime *signingstore.Runtime
}

type datasourceSigningAuthority struct {
	runtime *datasourceruntime.Runtime
}

type datasourceSigningLease struct {
	lease *datasourceruntime.Lease
}

// NewSigningService constructs one immutable daemon signing application service.
func NewSigningService(
	publicKeys dkim2.PublicKeyProvider,
	store *signingstore.Runtime,
	allowRecipientGroup bool,
) (*SigningService, error) {
	if nilInterface(publicKeys) || store == nil || allowRecipientGroup {
		return nil, &DomainError{}
	}
	return &SigningService{
		publicKeys: publicKeys, store: flatSigningAuthority{runtime: store},
		clock: time.Now,
	}, nil
}

// NewDatasourceSigningService constructs signing over a joined network generation.
func NewDatasourceSigningService(
	publicKeys dkim2.PublicKeyProvider,
	runtime *datasourceruntime.Runtime,
	allowRecipientGroup bool,
) (*SigningService, error) {
	if nilInterface(publicKeys) || runtime == nil || allowRecipientGroup {
		return nil, &DomainError{}
	}
	return &SigningService{
		publicKeys: publicKeys,
		store:      datasourceSigningAuthority{runtime: runtime},
		clock:      time.Now,
	}, nil
}

// Acquire pins one flat-file signing generation.
func (a flatSigningAuthority) Acquire(ctx context.Context) (signingLease, error) {
	if a.runtime == nil || ctx == nil {
		return nil, &DomainError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.runtime.Acquire()
}

// Acquire pins one joined datasource and signer-registry generation.
func (a datasourceSigningAuthority) Acquire(ctx context.Context) (signingLease, error) {
	if a.runtime == nil || ctx == nil {
		return nil, &DomainError{}
	}
	lease, err := a.runtime.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	return datasourceSigningLease{lease: lease}, nil
}

// ResolvePolicy maps the daemon's closed use onto the storage-neutral bridge.
func (l datasourceSigningLease) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use signingstore.PolicyUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	if l.lease == nil {
		return dkim2.SigningProfile{}, &DomainError{}
	}
	profileUse := provider.ProfileUseOriginator
	switch use {
	case signingstore.PolicyOrdinaryTransit:
		profileUse = provider.ProfileUseOrdinaryTransit
	case signingstore.PolicyDeliveryStatus:
		profileUse = provider.ProfileUseDeliveryStatus
	}
	return l.lease.ResolvePolicy(ctx, tenant, domain, profileUse, at)
}

// SignDigest delegates to the joined private registry generation.
func (l datasourceSigningLease) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	if l.lease == nil {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	return l.lease.SignDigest(ctx, handle, request)
}

// Close releases the joined generation lease.
func (l datasourceSigningLease) Close() error {
	if l.lease == nil {
		return nil
	}
	return l.lease.Close()
}

// Sign performs exact originator policy resolution and signing.
func (s *SigningService) Sign(
	ctx context.Context,
	request OperationRequest,
) (SigningAssessment, error) {
	execution, err := s.execute(ctx, request, OperationSign)
	if err != nil {
		return SigningAssessment{}, err
	}
	if !execution.applicable {
		return NewNotApplicableSigningAssessment(), nil
	}
	return NewApplicableSigningAssessment(execution.result)
}

// Revise verifies inherited evidence before exact ordinary-transit signing.
func (s *SigningService) Revise(
	ctx context.Context,
	request OperationRequest,
) (OperationResult, error) {
	execution, err := s.execute(ctx, request, OperationRevise)
	if err != nil {
		return OperationResult{}, err
	}
	if !execution.applicable || !execution.result.Valid() {
		return OperationResult{}, &DomainError{}
	}
	return execution.result, nil
}

type operationExecution struct {
	applicable bool
	result     OperationResult
}

// applicableOperationExecution seals one applicable operation result.
func applicableOperationExecution(result OperationResult) (operationExecution, error) {
	if !result.Valid() {
		return operationExecution{}, &DomainError{}
	}
	return operationExecution{applicable: true, result: result}, nil
}

// notApplicableOperationExecution constructs the originator-only no-op variant.
func notApplicableOperationExecution(operation Operation) (operationExecution, error) {
	if operation != OperationSign {
		return operationExecution{}, &DomainError{}
	}
	return operationExecution{}, nil
}

// execute owns the shared bounded ordinary route and signing sequence.
func (s *SigningService) execute(
	ctx context.Context,
	request OperationRequest,
	operation Operation,
) (operationExecution, error) {
	if s == nil || ctx == nil || request.Operation() != operation ||
		s.store == nil || nilInterface(s.publicKeys) || s.clock == nil {
		return operationExecution{}, &DomainError{}
	}
	if err := ctx.Err(); err != nil {
		return operationExecution{}, err
	}
	recipients := request.Recipients()
	disclosure := dkim2.RouteDisclosureSingle
	use := signingstore.PolicyOriginator
	if operation == OperationRevise {
		use = signingstore.PolicyOrdinaryTransit
	}
	operationTime := s.clock().UTC()
	lease, err := s.store.Acquire(ctx)
	if err != nil {
		result, resultErr := NewOperationResult(
			operation, OperationTemperror, OperationTempfail, nil,
		)
		if resultErr != nil {
			return operationExecution{}, resultErr
		}
		return applicableOperationExecution(result)
	}
	defer func() { _ = lease.Close() }()
	profile, err := lease.ResolvePolicy(
		ctx, request.Tenant(), request.Domain(), use, operationTime,
	)
	if err != nil {
		if operation == OperationSign && absentSigningPolicy(err) {
			return notApplicableOperationExecution(operation)
		}
		if permanentPolicyResolutionFailure(err) {
			result, resultErr := NewOperationResult(
				operation, OperationPermerror, OperationReject, nil,
			)
			if resultErr != nil {
				return operationExecution{}, resultErr
			}
			return applicableOperationExecution(result)
		}
		result, resultErr := NewOperationResult(
			operation, OperationTemperror, OperationTempfail, nil,
		)
		if resultErr != nil {
			return operationExecution{}, resultErr
		}
		return applicableOperationExecution(result)
	}
	if len(recipients) != 1 {
		result, resultErr := NewOperationResult(
			operation, OperationPermerror, OperationReject, nil,
		)
		if resultErr != nil {
			return operationExecution{}, resultErr
		}
		return applicableOperationExecution(result)
	}
	signer, err := dkim2.NewSigner(
		s.publicKeys,
		dkim2.NewRequestRouteAuthority(),
		exactSigningAuthorizer{recipients: recipients},
		lease,
		dkim2.WithSigningClock(func() time.Time { return operationTime }),
	)
	if err != nil {
		return operationExecution{}, &DomainError{}
	}
	result, err := completeOperation(
		ctx, request, operation, signer, profile, recipients, disclosure,
	)
	if err != nil {
		return operationExecution{}, err
	}
	return applicableOperationExecution(result)
}

// absentSigningPolicy recognizes only healthy authoritative originator absence.
func absentSigningPolicy(err error) (absent bool) {
	defer func() {
		if recover() != nil {
			absent = false
		}
	}()
	switch provider.ErrorCodeOf(err) {
	case provider.ErrorCodeNotFound, provider.ErrorCodeInactive:
		return true
	default:
		return false
	}
}

// permanentPolicyResolutionFailure recognizes malformed active configuration
// and explicit permanent signing failures; every ambiguous class remains retryable.
func permanentPolicyResolutionFailure(err error) (permanent bool) {
	defer func() {
		if recover() != nil {
			permanent = false
		}
	}()
	if _, granular := err.(interface{ Code() provider.ErrorCode }); granular {
		switch provider.ErrorCodeOf(err) {
		case provider.ErrorCodeInvalidRequest, provider.ErrorCodeNotFound,
			provider.ErrorCodeInactive, provider.ErrorCodeMalformedData:
			return true
		default:
			return false
		}
	}
	return dkim2.ProviderErrorClassOf(err) == dkim2.ProviderErrorClassPermanent
}

// completeOperation verifies revision evidence, plans one request-local route,
// and returns only complete daemon-owned fields.
func completeOperation(
	ctx context.Context,
	request OperationRequest,
	operation Operation,
	signer *dkim2.Signer,
	profile dkim2.SigningProfile,
	recipients [][]byte,
	disclosure dkim2.RouteDisclosure,
) (OperationResult, error) {
	raw := request.RawMessage()
	reverse := request.ReversePath()
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		return operationPermanentFailure(operation)
	}
	var ticket dkim2.RouteCopyTicket
	var capability dkim2.VerifiedRevisionInput
	if operation == OperationRevise {
		incomingReverse := request.IncomingReversePath()
		incomingRecipients := request.IncomingRecipients()
		if len(incomingRecipients) == 0 {
			return operationPermanentFailure(operation)
		}
		verification, verified, verifyErr := signer.VerifyForRevision(
			ctx, dkim2.NewVerifyRequest(raw, incomingReverse, incomingRecipients),
		)
		if verifyErr != nil {
			return operationFailureFromError(operation, verifyErr)
		}
		if verification.Status() != dkim2.RevisionVerificationVerified ||
			!verified.Valid() {
			return operationPermanentFailure(operation)
		}
		capability = verified
	}
	entry, err := signingRouteEntry(
		operation, capability, source, reverse, recipients, disclosure,
	)
	if err != nil {
		return operationFailureFromError(operation, err)
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		return operationFailureFromError(operation, err)
	}
	_, tickets, err := signer.PlanRouteFanout(ctx, fanout)
	if err != nil || len(tickets) != 1 || !tickets[0].Valid() {
		return operationFailureFromError(operation, err)
	}
	ticket = tickets[0]
	var result dkim2.SigningResult
	var recovery dkim2.SigningRecovery
	if operation == OperationSign {
		result, recovery, err = signer.SignOriginator(
			ctx,
			dkim2.NewOriginatorSigningRequest(
				raw, reverse, recipients, ticket, profile, dkim2.SigningMetadata{},
				dkim2.SigningTransportFinalNetworkPreDotStuffing,
			),
		)
	} else {
		result, recovery, err = signer.SignExisting(
			ctx,
			dkim2.NewExistingSigningRequest(
				capability, raw, reverse, recipients, ticket, profile,
				dkim2.SigningMetadata{},
				dkim2.SigningTransportFinalNetworkPreDotStuffing,
				dkim2.RejectUnavailableBody,
				dkim2.RecipeCopyOnly,
			),
		)
	}
	if err != nil || recovery.Valid() || !result.Valid() {
		return operationFailureFromError(operation, err)
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
	return NewOperationResult(operation, OperationPass, OperationAccept, fields)
}

type exactSigningAuthorizer struct {
	recipients [][]byte
}

// Authorize approves only the exact query and recipients derived inside one
// already policy-resolved request.
func (a exactSigningAuthorizer) Authorize(
	ctx context.Context,
	query dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.SigningAuthorizationResult{}, err
	}
	if !query.Valid() ||
		(query.Purpose() != dkim2.SigningAuthorizationPolicy &&
			query.Purpose() != dkim2.SigningAuthorizationRecipientDisclosure) ||
		(query.Purpose() == dkim2.SigningAuthorizationRecipientDisclosure &&
			!sameRecipients(a.recipients, query.Recipients())) {
		return dkim2.DenySigning(query), nil
	}
	return dkim2.AuthorizeSigning(query), nil
}

// sameRecipients compares exact ordered route recipients including duplicates.
func sameRecipients(expected, actual [][]byte) bool {
	if len(expected) != len(actual) {
		return false
	}
	for index := range expected {
		if !bytes.Equal(expected[index], actual[index]) {
			return false
		}
	}
	return true
}

// signingRouteEntry constructs one ordinary request-local route entry.
func signingRouteEntry(
	operation Operation,
	capability dkim2.VerifiedRevisionInput,
	source dkim2.SigningSource,
	reverse []byte,
	recipients [][]byte,
	disclosure dkim2.RouteDisclosure,
) (dkim2.RouteEntry, error) {
	if operation == OperationSign {
		return dkim2.NewOriginatorRouteEntry(
			source, reverse, recipients, disclosure, []byte(signingRouteScope),
		)
	}
	return dkim2.NewExistingRouteEntry(
		capability, source, reverse, recipients, disclosure, []byte(signingRouteScope),
	)
}

// operationPermanentFailure returns one mutation-free permanent rejection.
func operationPermanentFailure(operation Operation) (OperationResult, error) {
	return NewOperationResult(
		operation, OperationPermerror, OperationReject, nil,
	)
}

// operationFailureFromError maps only bounded signing/context classes.
func operationFailureFromError(
	operation Operation,
	err error,
) (OperationResult, error) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return OperationResult{}, err
	}
	var signingError *dkim2.SigningError
	if errors.As(err, &signingError) {
		switch signingError.Code() {
		case dkim2.SigningErrorCallbackTemporary:
			return NewOperationResult(
				operation, OperationTemperror, OperationTempfail, nil,
			)
		default:
			return operationPermanentFailure(operation)
		}
	}
	if err == nil {
		return OperationResult{}, &DomainError{}
	}
	return NewOperationResult(
		operation, OperationTemperror, OperationTempfail, nil,
	)
}

var _ OperationService = (*SigningService)(nil)
