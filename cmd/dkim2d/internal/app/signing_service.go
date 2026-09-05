package app

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

const signingRouteScope = "dkim2d-local-signing"

// SigningService composes exact signing-policy resolution with request-scoped
// route, authorization, verification, and private signing.
type SigningService struct {
	publicKeys  dkim2.PublicKeyProvider
	store       SigningAuthority
	policies    signingPolicies
	clock       func() time.Time
	dsnObserver dsnEvidenceObserver
}

type signingFlagPolicy struct {
	doNotModify  bool
	doNotExplode bool
}

type signingPolicies struct {
	originator      signingFlagPolicy
	ordinaryTransit signingFlagPolicy
	deliveryStatus  signingFlagPolicy
}

// metadata constructs validated library-owned signing metadata in canonical flag order.
func (p signingFlagPolicy) metadata() (dkim2.SigningMetadata, error) {
	flags := make([]dkim2.SigningFlag, 0, 2)
	if p.doNotModify {
		flags = append(flags, dkim2.SigningFlagDoNotModify)
	}
	if p.doNotExplode {
		flags = append(flags, dkim2.SigningFlagDoNotExplode)
	}
	return dkim2.NewSigningMetadata(nil, false, flags)
}

// signingPoliciesFromConfig freezes validated configuration into application policy.
func signingPoliciesFromConfig(policy config.SigningPoliciesConfig) signingPolicies {
	convert := func(source config.SigningFlagPolicyConfig) signingFlagPolicy {
		return signingFlagPolicy{doNotModify: source.DoNotModify(), doNotExplode: source.DoNotExplode()}
	}
	return signingPolicies{
		originator:      convert(policy.Originator()),
		ordinaryTransit: convert(policy.OrdinaryTransit()),
		deliveryStatus:  convert(policy.DeliveryStatus()),
	}
}

// selectPolicy validates the optional compatibility constructor argument.
func selectPolicy(values []signingPolicies) (signingPolicies, error) {
	if len(values) > 1 {
		return signingPolicies{}, &DomainError{}
	}
	if len(values) == 1 {
		return values[0], nil
	}
	return signingPolicies{}, nil
}

type dsnEvidenceObserver interface {
	ObserveDSNEvidence(string, string)
}

// attachObservability binds the instance-owned observer before publication.
func (s *SigningService) attachObservability(runtime dsnEvidenceObserver) {
	if s != nil {
		s.dsnObserver = runtime
	}
}

// SigningAuthority pins one provider-neutral signing generation per
// operation. Flat-file and datasource providers satisfy the same contract so
// that no protocol package sees a provider model.
type SigningAuthority interface {
	Acquire(context.Context) (SigningLease, error)
}

// SigningLease is one acquired signing generation: policy resolution, local
// authority probing, and private-key signing over provider-owned handles.
type SigningLease interface {
	ResolvePolicy(
		context.Context,
		string,
		string,
		signingstore.PolicyUse,
		time.Time,
	) (dkim2.SigningProfile, error)
	// ResolveAnyProfile reports local authority over one canonical domain.
	// It returns nil when the tenant holds an active signing profile of any
	// use for the domain, a permanent provider error when it holds none, and
	// a temporary provider error when the answer is unavailable. Each
	// provider owns its own complete profile-use inventory.
	ResolveAnyProfile(context.Context, string, string, time.Time) error
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
	policy ...signingPolicies,
) (*SigningService, error) {
	if nilInterface(publicKeys) || store == nil || allowRecipientGroup {
		return nil, &DomainError{}
	}
	selected, err := selectPolicy(policy)
	if err != nil {
		return nil, err
	}
	return &SigningService{
		publicKeys: publicKeys, store: flatSigningAuthority{runtime: store},
		policies: selected, clock: time.Now,
	}, nil
}

// NewDatasourceSigningService constructs signing over a joined network generation.
func NewDatasourceSigningService(
	publicKeys dkim2.PublicKeyProvider,
	runtime *datasourceruntime.Runtime,
	allowRecipientGroup bool,
	policy ...signingPolicies,
) (*SigningService, error) {
	if nilInterface(publicKeys) || runtime == nil || allowRecipientGroup {
		return nil, &DomainError{}
	}
	selected, err := selectPolicy(policy)
	if err != nil {
		return nil, err
	}
	return &SigningService{
		publicKeys: publicKeys,
		store:      datasourceSigningAuthority{runtime: runtime},
		policies:   selected,
		clock:      time.Now,
	}, nil
}

// Acquire pins one flat-file signing generation.
func (a flatSigningAuthority) Acquire(ctx context.Context) (SigningLease, error) {
	if a.runtime == nil || ctx == nil {
		return nil, &DomainError{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.runtime.Acquire()
}

// Acquire pins one joined datasource and signer-registry generation.
func (a datasourceSigningAuthority) Acquire(ctx context.Context) (SigningLease, error) {
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

// ResolveAnyProfile reports local authority over one canonical domain by
// probing the datasource's complete profile-use inventory in canonical order.
// It returns nil as soon as one use resolves, the last permanent failure when
// no use resolves, and the first temporary failure unchanged, so that a
// datasource outage never degrades into an authoritative absence.
func (l datasourceSigningLease) ResolveAnyProfile(
	ctx context.Context,
	tenant string,
	domain string,
	at time.Time,
) error {
	if l.lease == nil {
		return &DomainError{}
	}
	uses := []provider.ProfileUse{
		provider.ProfileUseOriginator,
		provider.ProfileUseOrdinaryTransit,
		provider.ProfileUseNextDomainTransit,
		provider.ProfileUseDeliveryStatus,
	}
	var permanent error
	for _, use := range uses {
		_, err := l.lease.ResolvePolicy(ctx, tenant, domain, use, at)
		if err == nil {
			return nil
		}
		if !signingstore.PermanentProfileAbsence(err) {
			return err
		}
		permanent = err
	}
	if permanent == nil {
		return &DomainError{}
	}
	return permanent
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
	policy := s.policies.originator
	if operation == OperationRevise {
		policy = s.policies.ordinaryTransit
	}
	metadata, err := policy.metadata()
	if err != nil {
		return operationExecution{}, &DomainError{}
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
		ctx, request, operation, signer, profile, recipients, disclosure, metadata,
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
func permanentPolicyResolutionFailure(err error) bool {
	return signingstore.PermanentProfileAbsence(err)
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
	metadata dkim2.SigningMetadata,
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
				raw, reverse, recipients, ticket, profile, metadata,
				dkim2.SigningTransportFinalNetworkPreDotStuffing,
			),
		)
	} else {
		result, recovery, err = signer.SignExisting(
			ctx,
			dkim2.NewExistingSigningRequest(
				capability, raw, reverse, recipients, ticket, profile,
				metadata,
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
