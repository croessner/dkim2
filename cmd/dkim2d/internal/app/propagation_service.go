package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
)

const (
	// propagationRouteScope is the daemon's fixed propagation route scope.
	propagationRouteScope = "dkim2d-delivery-status-propagation"
	// propagationStageEvaluation identifies the received-DSN evaluation rows.
	propagationStageEvaluation = "evaluation"
	// propagationStageReplay identifies the two-phase replay gate.
	propagationStageReplay = "replay"
	// propagationStageRebuild identifies the Section 12.1.1 rebuild.
	propagationStageRebuild = "rebuild"
	// propagationStagePreviousHop identifies the previous-hop verification inside the rebuild.
	propagationStagePreviousHop = "previous_hop_verification"
	// propagationStageSigningDomain identifies delivery-status profile resolution.
	propagationStageSigningDomain = "signing_domain"
	// propagationStagePolicy identifies the matrix rows re-evaluated after the rebuild.
	propagationStagePolicy = "policy"
	// propagationStageSigning identifies route planning and signing.
	propagationStageSigning = "signing"
	// propagationStageCompleted identifies a completed propagation or commit.
	propagationStageCompleted = "completed"
)

// propagationOuterState is the closed classification of the outer assessment.
// The route distinguishes a notification that is not DKIM2 at all from an
// assessment that could not be used, because the first is permanent evidence
// and the second is a temporary condition.
type propagationOuterState uint8

const (
	// propagationOuterUnusable reports an assessment the route cannot read.
	propagationOuterUnusable propagationOuterState = iota
	// propagationOuterNotApplicable reports a notification with no DKIM2 field family.
	propagationOuterNotApplicable
	// propagationOuterAssessed reports a usable verification result.
	propagationOuterAssessed
)

// ReceivedDSNEvaluator is the narrow library-owned received-DSN evaluation seam.
type ReceivedDSNEvaluator interface {
	EvaluateReceivedDSN(
		context.Context,
		dkim2.ReceivedDSNRequest,
	) (dkim2.ReceivedDSNEvaluation, error)
}

// propagationSigner is the per-request library rebuild, planning, and signing
// seam. One value serves one request: the rebuilt evidence is bound to the
// signer that produced it, so the route ticket and the signature must come
// from that same signer.
type propagationSigner interface {
	RebuildDSNForPropagation(
		context.Context,
		dkim2.DSNPropagationRequest,
	) (dkim2.DSNPropagationEvidence, error)
	PlanPropagationRoute(
		context.Context,
		dkim2.DSNPropagationEvidence,
		[]byte,
	) (dkim2.RouteCopyTicket, error)
	SignPropagatedDSN(
		context.Context,
		dkim2.DSNPropagationSigningRequest,
	) (dkim2.PropagatedDSN, dkim2.SigningRecovery, error)
}

// propagationSignerFactory constructs one request-scoped signer over the
// acquired lease and the recipient authorizer that is bound after the rebuild.
type propagationSignerFactory func(
	lease SigningLease,
	authorizer dkim2.SigningAuthorizer,
	at time.Time,
) (propagationSigner, error)

// propagationObserver records only closed stage and result classes.
type propagationObserver interface {
	ObservePropagation(stage string, result string)
}

// PropagationDependencies carries the explicit constructor inputs of the
// propagation service. The signing domain and the recipient are never
// inputs: both are derived from the notification's verified evidence.
type PropagationDependencies struct {
	// Verifier performs the ordinary inbound verification of the notification.
	Verifier VerificationService
	// Evaluator performs the Section 12.1.2 received-DSN evaluation.
	Evaluator ReceivedDSNEvaluator
	// PublicKeys is the bounded DNS provider shared with verification.
	PublicKeys dkim2.PublicKeyProvider
	// Authority resolves local authority, delivery-status profiles, and keys.
	Authority SigningAuthority
	// Authorities is the shared per-tenant local-authority registry. When it
	// is nil the coordinator owns a private registry, which keeps the
	// negative cache alive across requests but not across routes.
	Authorities *LocalAuthorityRegistry
	// Policy carries the delivery-status signing flags.
	Policy config.SigningFlagPolicyConfig
	// Replay is the two-phase propagation replay gate.
	Replay PropagationReplayService
	// TokenRetention bounds how long an issued commit token stays resolvable.
	TokenRetention time.Duration
	// Clock supplies the operation instant; nil selects the wall clock.
	Clock func() time.Time
}

// PropagationCoordinator owns the daemon's two-phase propagation operation:
// outer verification, received-DSN evaluation under the tenant's local
// authority, the coherence matrix, the propagation replay gate, the Section
// 12.1.1 rebuild, delivery-status profile resolution for the derived signing
// domain, route planning, and signing. Every ambiguous state fails closed
// before the replay gate, the rebuild, and any private-key access.
type PropagationCoordinator struct {
	verifier    VerificationService
	evaluator   ReceivedDSNEvaluator
	newSigner   propagationSignerFactory
	authority   SigningAuthority
	authorities *LocalAuthorityRegistry
	policy      signingFlagPolicy
	gate        PropagationReplayService
	tokens      *propagationTokenLedger
	clock       func() time.Time
	observer    propagationObserver
}

// NewPropagationCoordinator constructs one immutable propagation service.
func NewPropagationCoordinator(deps PropagationDependencies) (*PropagationCoordinator, error) {
	if nilInterface(deps.Verifier) || nilInterface(deps.Evaluator) || nilInterface(deps.PublicKeys) ||
		nilInterface(deps.Authority) || nilInterface(deps.Replay) || deps.TokenRetention <= 0 {
		return nil, &DomainError{}
	}
	clock := deps.Clock
	if clock == nil {
		clock = time.Now
	}
	tokens, err := newPropagationTokenLedger(clock, deps.TokenRetention, nil)
	if err != nil {
		return nil, err
	}
	publicKeys := deps.PublicKeys
	factory := func(lease SigningLease, authorizer dkim2.SigningAuthorizer, at time.Time) (propagationSigner, error) {
		signer, err := dkim2.NewSigner(
			publicKeys, dkim2.NewRequestRouteAuthority(), authorizer, lease,
			dkim2.WithSigningClock(func() time.Time { return at }),
		)
		if err != nil {
			return nil, &DomainError{}
		}
		return signer, nil
	}
	authorities := deps.Authorities
	if authorities == nil {
		authorities, err = NewLocalAuthorityRegistry(deps.Authority, clock)
		if err != nil {
			return nil, err
		}
	}
	return &PropagationCoordinator{
		verifier: deps.Verifier, evaluator: deps.Evaluator, newSigner: factory,
		authority: deps.Authority, authorities: authorities,
		policy: signingFlagPolicy{doNotModify: deps.Policy.DoNotModify(), doNotExplode: deps.Policy.DoNotExplode()},
		gate:   deps.Replay, tokens: tokens, clock: clock,
	}, nil
}

// attachObservability binds the instance-owned observer before publication.
func (c *PropagationCoordinator) attachObservability(observer propagationObserver) {
	if c != nil {
		c.observer = observer
	}
}

// propagationRecipientAuthorizer admits exactly the previous-hop recipient
// that the rebuild authenticated. It denies every query until that recipient
// is bound, so no route can be planned or signed before the evidence exists.
type propagationRecipientAuthorizer struct {
	mu        sync.Mutex
	recipient []byte
}

// bind records the single authenticated recipient exactly once.
func (a *propagationRecipientAuthorizer) bind(recipient []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.recipient != nil || len(recipient) == 0 {
		return false
	}
	a.recipient = bytes.Clone(recipient)
	return true
}

// Authorize approves only policy queries and the exact bound recipient disclosure.
func (a *propagationRecipientAuthorizer) Authorize(
	ctx context.Context,
	query dkim2.SigningAuthorizationQuery,
) (dkim2.SigningAuthorizationResult, error) {
	if err := ctx.Err(); err != nil {
		return dkim2.SigningAuthorizationResult{}, err
	}
	a.mu.Lock()
	recipient := a.recipient
	a.mu.Unlock()
	if recipient == nil || !query.Valid() {
		return dkim2.DenySigning(query), nil
	}
	switch query.Purpose() {
	case dkim2.SigningAuthorizationPolicy:
		return dkim2.AuthorizeSigning(query), nil
	case dkim2.SigningAuthorizationRecipientDisclosure:
		if sameRecipients([][]byte{recipient}, query.Recipients()) {
			return dkim2.AuthorizeSigning(query), nil
		}
		return dkim2.DenySigning(query), nil
	default:
		return dkim2.DenySigning(query), nil
	}
}

// Propagate applies the complete propagation coherence matrix in
// specification order. Rows are evaluated top-down and the first match
// decides. The received-DSN evaluation is re-run on this request's own input
// and never trusts a prior process result.
func (c *PropagationCoordinator) Propagate(
	ctx context.Context,
	request PropagationRequest,
) (PropagationResult, error) {
	if c == nil || nilInterface(ctx) || !request.Valid() {
		return PropagationResult{}, &DomainError{}
	}
	if err := domainContextError(ctx); err != nil {
		return PropagationResult{}, err
	}
	verification, outerState, err := c.verifyOuter(ctx, request)
	if err != nil {
		return PropagationResult{}, err
	}
	if outerState == propagationOuterNotApplicable {
		c.observe(propagationStageEvaluation, PropagationDispositionReject)
		return c.notApplicableResult()
	}
	authority, err := c.authorityFor(request.Tenant())
	if err != nil {
		return PropagationResult{}, err
	}
	evaluation, err := c.evaluator.EvaluateReceivedDSN(ctx, dkim2.NewReceivedDSNRequest(
		request.RawMessage(), request.OuterReversePath(), request.OuterRecipients(), authority,
	))
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		c.observe(propagationStageEvaluation, PropagationDispositionTempfail)
		return c.unevaluatedResult()
	}
	projection, err := NewDeliveryStatusProjection(evaluation)
	if err != nil {
		c.observe(propagationStageEvaluation, PropagationDispositionTempfail)
		return c.unevaluatedResult()
	}
	outer := dkim2.ResultStateTEMPERROR
	if outerState == propagationOuterAssessed {
		outer = verification.State()
	}
	if decision := classifyPropagationEvaluation(outer, projection); decision.decided {
		c.observe(propagationStageEvaluation, decision.disposition)
		return NewPropagationResult(decision.result, decision.disposition, decision.failure,
			projection, ReplayResultNotChecked, PropagationOutput{})
	}
	return c.reserveAndSign(ctx, request, verification, projection, authority)
}

// verifyOuter performs the ordinary inbound verification of the received
// notification itself and classifies the assessment into the three states the
// coherence matrix distinguishes. A notification without a DKIM2 field family
// is not applicable and is a permanent refusal on this route, because the
// adapter socket is reserved for our own return-path addresses and Draft-06
// Section 12.1.2 has nothing to propagate from it. An assessment that is
// unusable for any other reason stays temporary and never borrows the
// permanent verdict.
func (c *PropagationCoordinator) verifyOuter(
	ctx context.Context,
	request PropagationRequest,
) (dkim2.VerifyResult, propagationOuterState, error) {
	verifyRequest := dkim2.NewVerifyRequest(
		request.RawMessage(), request.OuterReversePath(), request.OuterRecipients(),
	)
	assessment, err := c.verifier.Assess(ctx, verifyRequest)
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return dkim2.VerifyResult{}, propagationOuterUnusable, contextErr
		}
		return dkim2.VerifyResult{}, propagationOuterUnusable, nil
	}
	if !assessment.Valid() {
		return dkim2.VerifyResult{}, propagationOuterUnusable, nil
	}
	if !assessment.Applicable() {
		return dkim2.VerifyResult{}, propagationOuterNotApplicable, nil
	}
	verification, ok := assessment.Verification()
	if !ok || !verification.Valid() {
		return dkim2.VerifyResult{}, propagationOuterUnusable, nil
	}
	return verification, propagationOuterAssessed, nil
}

// authorityFor returns the tenant-scoped local-authority resolver shared with
// the process route, so that one bounded negative cache spans both routes and
// every request instead of dying with the request that populated it.
func (c *PropagationCoordinator) authorityFor(tenant string) (dkim2.LocalAuthority, error) {
	resolver, err := c.authorities.resolverFor(tenant)
	if err != nil {
		return nil, err
	}
	if nilInterface(resolver) {
		return nil, &DomainError{}
	}
	return resolver, nil
}

// reserveAndSign acquires the signing generation, runs the replay gate, and
// continues into the rebuild for an eligible notification. The lease is
// acquired before the reservation so that a datasource outage never burns a
// pending lease.
func (c *PropagationCoordinator) reserveAndSign(
	ctx context.Context,
	request PropagationRequest,
	verification dkim2.VerifyResult,
	projection DeliveryStatusProjection,
	authority dkim2.LocalAuthority,
) (PropagationResult, error) {
	lease, err := c.authority.Acquire(ctx)
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		c.observe(propagationStageSigningDomain, PropagationDispositionTempfail)
		return c.temporaryResult(projection, ReplayResultNotChecked)
	}
	defer func() { _ = lease.Close() }()
	reservation, key, err := c.gate.ReservePropagation(ctx, verification)
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		c.observe(propagationStageReplay, PropagationDispositionTempfail)
		return c.temporaryResult(projection, ReplayResultIndeterminate)
	}
	replayClass := ReplayResultFirstSeen
	switch reservation {
	case dkim2.ReplayPropagationAlreadyCommitted:
		c.observe(propagationStageReplay, PropagationDispositionDiscard)
		return NewPropagationResult(PropagationPass, PropagationDispositionDiscard,
			PropagationFailureNone, projection, ReplayResultReplayed, PropagationOutput{})
	case dkim2.ReplayPropagationPending:
		c.observe(propagationStageReplay, PropagationDispositionTempfail)
		return c.temporaryResult(projection, ReplayResultIndeterminate)
	case dkim2.ReplayPropagationReserved:
		if !key.Valid() {
			c.observe(propagationStageReplay, PropagationDispositionTempfail)
			return c.temporaryResult(projection, ReplayResultIndeterminate)
		}
	case dkim2.ReplayPropagationReservationDisabled:
		replayClass = ReplayResultDisabled
	default:
		c.observe(propagationStageReplay, PropagationDispositionTempfail)
		return c.temporaryResult(projection, ReplayResultIndeterminate)
	}
	return c.rebuildAndSign(ctx, request, lease, key, projection, replayClass, authority)
}

// rebuildAndSign performs the Section 12.1.1 rebuild with a request-scoped
// signer and, when the derived signing domain holds an active delivery-status
// profile, plans the single route ticket and signs the report.
func (c *PropagationCoordinator) rebuildAndSign(
	ctx context.Context,
	request PropagationRequest,
	lease SigningLease,
	key dkim2.ReplayKey,
	projection DeliveryStatusProjection,
	replayClass ReplayResultClass,
	authority dkim2.LocalAuthority,
) (PropagationResult, error) {
	operationTime := c.clock().UTC()
	authorizer := &propagationRecipientAuthorizer{}
	signer, err := c.newSigner(lease, authorizer, operationTime)
	if err != nil || nilInterface(signer) {
		c.observe(propagationStageRebuild, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	evidence, err := signer.RebuildDSNForPropagation(ctx, dkim2.NewDSNPropagationRequest(
		request.RawMessage(), request.OuterReversePath(), request.OuterRecipients(),
		authority, request.ReportingMTA(),
	))
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		c.observe(propagationStageRebuild, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	rebuiltProjection, err := NewDeliveryStatusProjection(evidence.Evaluation())
	if err != nil {
		c.observe(propagationStageRebuild, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	switch evidence.Outcome() {
	case dkim2.DSNPropagationRebuilt:
	case dkim2.DSNPropagationTemporaryError:
		c.observe(propagationStagePreviousHop, PropagationDispositionTempfail)
		return c.temporaryResult(rebuiltProjection, replayClass)
	case dkim2.DSNPropagationNotEligible:
		decision := classifyPropagationEvaluation(dkim2.ResultStatePASS, rebuiltProjection)
		if !decision.decided {
			c.observe(propagationStagePolicy, PropagationDispositionTempfail)
			return c.temporaryResult(rebuiltProjection, replayClass)
		}
		c.observe(propagationStagePolicy, decision.disposition)
		return NewPropagationResult(decision.result, decision.disposition, decision.failure,
			rebuiltProjection, replayClass, PropagationOutput{})
	default:
		c.observe(propagationStageRebuild, PropagationDispositionDiscard)
		return NewPropagationResult(PropagationPermerror, PropagationDispositionDiscard,
			PropagationFailureNotReconstructable, rebuiltProjection, replayClass,
			PropagationOutput{})
	}
	profile, err := lease.ResolvePolicy(ctx, request.Tenant(), evidence.SigningDomain(),
		signingstore.PolicyDeliveryStatus, operationTime)
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		if signingstore.PermanentProfileAbsence(err) {
			c.observe(propagationStageSigningDomain, PropagationDispositionDiscard)
			return NewPropagationResult(PropagationPermerror, PropagationDispositionDiscard,
				PropagationFailureUnprovisionedDomain, rebuiltProjection, replayClass,
				PropagationOutput{})
		}
		c.observe(propagationStageSigningDomain, PropagationDispositionTempfail)
		return c.temporaryResult(rebuiltProjection, replayClass)
	}
	if !authorizer.bind(evidence.NextHopRecipient()) {
		c.observe(propagationStageSigning, PropagationDispositionTempfail)
		return c.temporaryResult(rebuiltProjection, replayClass)
	}
	return c.sign(ctx, signer, evidence, profile, key, rebuiltProjection, replayClass)
}

// sign plans the single-use propagation route ticket over the rebuilt report
// bytes, signs the report, and binds the commit token to the coordinate.
func (c *PropagationCoordinator) sign(
	ctx context.Context,
	signer propagationSigner,
	evidence dkim2.DSNPropagationEvidence,
	profile dkim2.SigningProfile,
	key dkim2.ReplayKey,
	projection DeliveryStatusProjection,
	replayClass ReplayResultClass,
) (PropagationResult, error) {
	metadata, err := c.policy.metadata()
	if err != nil {
		return PropagationResult{}, &DomainError{}
	}
	ticket, err := signer.PlanPropagationRoute(ctx, evidence, []byte(propagationRouteScope))
	if err != nil || !ticket.Valid() {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		c.observe(propagationStageSigning, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	signed, recovery, err := signer.SignPropagatedDSN(ctx,
		dkim2.NewDSNPropagationSigningRequest(evidence, ticket, profile, metadata,
			dkim2.SigningTransportFinalNetworkPreDotStuffing))
	if err != nil || recovery.Valid() || !signed.Valid() {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return PropagationResult{}, contextErr
		}
		c.observe(propagationStageSigning, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	token := ""
	if replayClass != ReplayResultDisabled {
		token, err = c.tokens.Issue(key)
	} else {
		token, err = c.tokens.IssueDetached()
	}
	if err != nil {
		c.observe(propagationStageSigning, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	output := PropagationOutput{state: &propagationOutputState{
		raw:             signed.Bytes(),
		nextHop:         signed.NextHopRecipient(),
		commitToken:     token,
		smtputf8:        signed.SMTPUTF8Required(),
		eightBitMIME:    signed.EightBitMIMERequired(),
		signingDomainOK: signed.SigningDomain() == evidence.SigningDomain(),
	}}
	if !output.Valid() {
		c.observe(propagationStageSigning, PropagationDispositionTempfail)
		return c.temporaryResult(projection, replayClass)
	}
	c.observe(propagationStageCompleted, PropagationDispositionAccept)
	return NewPropagationResult(PropagationPass, PropagationDispositionAccept,
		PropagationFailureNone, projection, replayClass, output)
}

// CommitPropagation moves the coordinate bound to the token from pending to
// committed by compare-and-set. It is idempotent for a committed coordinate
// and reports every unknown, malformed, or expired token as unresolved, which
// the route answers 409 so that the caller defers.
func (c *PropagationCoordinator) CommitPropagation(
	ctx context.Context,
	token string,
) (PropagationCommitState, error) {
	if c == nil || nilInterface(ctx) {
		return "", &DomainError{}
	}
	if err := domainContextError(ctx); err != nil {
		return "", err
	}
	key, detached, ok := c.tokens.Resolve(token)
	if !ok {
		c.observe(propagationStageReplay, PropagationDispositionTempfail)
		return PropagationCommitUnresolved, nil
	}
	if detached {
		c.observe(propagationStageCompleted, PropagationDispositionAccept)
		return PropagationCommitCommitted, nil
	}
	outcome, err := c.gate.CommitPropagation(ctx, key)
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return "", contextErr
		}
		c.observe(propagationStageReplay, PropagationDispositionTempfail)
		return PropagationCommitUnresolved, nil
	}
	switch outcome {
	case dkim2.ReplayPropagationCommitted, dkim2.ReplayPropagationCommitDisabled:
		c.observe(propagationStageCompleted, PropagationDispositionAccept)
		return PropagationCommitCommitted, nil
	default:
		c.observe(propagationStageReplay, PropagationDispositionTempfail)
		return PropagationCommitUnresolved, nil
	}
}

// temporaryResult seals the fail-closed temporary outcome.
func (c *PropagationCoordinator) temporaryResult(
	projection DeliveryStatusProjection,
	replayClass ReplayResultClass,
) (PropagationResult, error) {
	return NewPropagationResult(PropagationTemperror, PropagationDispositionTempfail,
		PropagationFailureNone, projection, replayClass, PropagationOutput{})
}

// unevaluatedResult seals the fail-closed temporary outcome for a
// notification whose evaluation could not be projected at all. It omits the
// projection rather than fabricating a malformed structure, because no
// structural evidence was ever established.
func (c *PropagationCoordinator) unevaluatedResult() (PropagationResult, error) {
	return NewPropagationResult(PropagationTemperror, PropagationDispositionTempfail,
		PropagationFailureNone, DeliveryStatusProjection{}, ReplayResultNotChecked,
		PropagationOutput{})
}

// notApplicableResult seals the permanent refusal of a notification that
// carries no DKIM2 field family. The received-DSN evaluation never runs, so
// the response omits the projection instead of claiming evidence.
func (c *PropagationCoordinator) notApplicableResult() (PropagationResult, error) {
	return NewPropagationResult(PropagationFail, PropagationDispositionReject,
		PropagationFailureNone, DeliveryStatusProjection{}, ReplayResultNotChecked,
		PropagationOutput{})
}

// observe contains the optional telemetry boundary and its panics. Only the
// closed stage vocabulary and the closed propagation disposition reach it.
func (c *PropagationCoordinator) observe(stage string, result PropagationDispositionClass) {
	if c == nil || nilInterface(c.observer) || !result.Known() {
		return
	}
	func() {
		defer func() { _ = recover() }()
		c.observer.ObservePropagation(stage, string(result))
	}()
}

// String returns a content-free coordinator representation.
func (*PropagationCoordinator) String() string { return propagationRedacted }

// GoString returns a content-free coordinator representation.
func (*PropagationCoordinator) GoString() string { return propagationRedacted }

// Format prevents formatting from traversing coordinator dependencies.
func (*PropagationCoordinator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, propagationRedacted)
}

// MarshalJSON rejects serialization of coordinator dependencies.
func (*PropagationCoordinator) MarshalJSON() ([]byte, error) { return nil, &DomainError{} }

// MarshalText rejects diagnostic serialization of coordinator dependencies.
func (*PropagationCoordinator) MarshalText() ([]byte, error) { return nil, &DomainError{} }

var _ PropagationService = (*PropagationCoordinator)(nil)
