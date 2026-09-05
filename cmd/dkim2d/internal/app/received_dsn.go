package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"strings"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

const (
	receivedDSNRedacted = "dkim2d_received_dsn"
	// receivedDSNMaxHeaderBytes bounds the top-level header scan of the
	// classification gate. The library parser owns the exact structure
	// rules; the gate only decides whether the evaluation runs at all.
	receivedDSNMaxHeaderBytes = 256 << 10
	// receivedDSNStageStructure through receivedDSNStageCompleted are the
	// closed observation stages of the received-DSN evaluation.
	receivedDSNStageStructure         = "structure"
	receivedDSNStageEmbedded          = "embedded_verification"
	receivedDSNStageLocalHop          = "local_hop"
	receivedDSNStageOuterAlignment    = "outer_alignment"
	receivedDSNStageRecipientLinkage  = "recipient_linkage"
	receivedDSNStageFailureClass      = "failure_class"
	receivedDSNStagePreviousHop       = "previous_hop"
	receivedDSNStageCompleted         = "completed"
	receivedDSNResultOK               = "ok"
	receivedDSNResultPermanent        = "permanent"
	receivedDSNResultTemporary        = "temporary"
	receivedDSNContentTypeReport      = "multipart/report"
	receivedDSNReportTypeParameter    = "report-type"
	receivedDSNReportTypeDeliveryStat = "delivery-status"
)

// InboundRequest is one process-route input: the exact verification request
// and the optional administrative tenant that keys received-DSN locality.
type InboundRequest struct {
	verify dkim2.VerifyRequest
	tenant string
}

// NewInboundRequest binds one verification request to an optional tenant. An
// empty tenant means the request carried none; a present tenant must be valid.
func NewInboundRequest(verify dkim2.VerifyRequest, tenant string) (InboundRequest, error) {
	if tenant != "" && !config.ValidTenant(tenant) {
		return InboundRequest{}, &DomainError{}
	}
	return InboundRequest{verify: verify, tenant: tenant}, nil
}

// VerifyRequest returns the immutable library verification request.
func (r InboundRequest) VerifyRequest() dkim2.VerifyRequest { return r.verify }

// Tenant returns the request tenant or an empty string.
func (r InboundRequest) Tenant() string { return r.tenant }

// String returns a content-free inbound-request representation.
func (InboundRequest) String() string { return receivedDSNRedacted }

// GoString returns a content-free inbound-request representation.
func (InboundRequest) GoString() string { return receivedDSNRedacted }

// Format prevents formatting from traversing message and envelope data.
func (InboundRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, receivedDSNRedacted)
}

// ReceivedDSNBinding is the process route's received-DSN evaluation policy:
// the library evaluator, the shared per-tenant local-authority registry, and
// the tenant precedence rule. Without an authority every evaluation runs
// without a tenant, which leaves the local-hop and propagation members not
// evaluated.
type ReceivedDSNBinding struct {
	evaluator     ReceivedDSNEvaluator
	authorities   *LocalAuthorityRegistry
	defaultTenant string
}

// NewReceivedDSNBinding constructs one received-DSN policy over the shared
// per-tenant authority registry. A nil registry means the daemon holds no
// datasource, which leaves every evaluation without a local authority; the
// default tenant, when set, must be valid and is only meaningful with one.
func NewReceivedDSNBinding(
	evaluator ReceivedDSNEvaluator,
	authorities *LocalAuthorityRegistry,
	defaultTenant string,
) (*ReceivedDSNBinding, error) {
	if nilInterface(evaluator) || (defaultTenant != "" && !config.ValidTenant(defaultTenant)) {
		return nil, &DomainError{}
	}
	return &ReceivedDSNBinding{
		evaluator: evaluator, authorities: authorities, defaultTenant: defaultTenant,
	}, nil
}

// tenantFor applies the precedence request member, then the configured
// default, then none. A tenant is only usable with a local authority.
func (b *ReceivedDSNBinding) tenantFor(requestTenant string) string {
	if b == nil || !b.authorities.Available() {
		return ""
	}
	if requestTenant != "" {
		return requestTenant
	}
	return b.defaultTenant
}

// resolverFor returns the shared tenant-scoped authority resolver.
func (b *ReceivedDSNBinding) resolverFor(tenant string) (dkim2.LocalAuthority, error) {
	if tenant == "" {
		return nil, nil
	}
	return b.authorities.resolverFor(tenant)
}

// evaluate runs the received-DSN evaluation for one classified notification
// under the bound tenant precedence and reports whether an evaluation exists.
// The library requires a readable outer signature; when it refuses the outer
// message at its structure stage and the outer verification did not pass,
// that refusal is the outer verdict's own consequence and no evaluation is
// reported. Every other library contract error is returned so that the
// process route fails closed instead of guessing a projection.
func (b *ReceivedDSNBinding) evaluate(
	ctx context.Context,
	request InboundRequest,
	outerVerified bool,
) (dkim2.ReceivedDSNEvaluation, bool, error) {
	if b == nil || nilInterface(b.evaluator) {
		return dkim2.ReceivedDSNEvaluation{}, false, &DomainError{}
	}
	authority, err := b.resolverFor(b.tenantFor(request.Tenant()))
	if err != nil {
		return dkim2.ReceivedDSNEvaluation{}, false, err
	}
	verify := request.VerifyRequest()
	evaluation, err := b.evaluator.EvaluateReceivedDSN(ctx, dkim2.NewReceivedDSNRequest(
		verify.RawMessage(), verify.ReversePath(), verify.ForwardPaths(), authority,
	))
	if err != nil {
		if contextErr := domainContextError(ctx); contextErr != nil {
			return dkim2.ReceivedDSNEvaluation{}, false, contextErr
		}
		if !outerVerified && dkim2.ReceivedDSNStageOf(err) == dkim2.ReceivedDSNStageStructure {
			return dkim2.ReceivedDSNEvaluation{}, false, nil
		}
		return dkim2.ReceivedDSNEvaluation{}, false, &DomainError{}
	}
	if !evaluation.Valid() {
		return dkim2.ReceivedDSNEvaluation{}, false, &DomainError{}
	}
	return evaluation, true, nil
}

// String returns a content-free binding representation.
func (*ReceivedDSNBinding) String() string { return receivedDSNRedacted }

// GoString returns a content-free binding representation.
func (*ReceivedDSNBinding) GoString() string { return receivedDSNRedacted }

// Format prevents formatting from traversing the tenant and provider state.
func (*ReceivedDSNBinding) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, receivedDSNRedacted)
}

// receivedDSNCandidate reports whether an applicable inbound message is a
// Received DSN by the specification's definition: a null reverse path,
// exactly one observed recipient, and a top-level multipart/report with
// report-type=delivery-status. The DKIM2 field-family condition is the
// verifier's applicability, which the caller has already established. The
// library evaluation owns every exact structure rule; this gate only decides
// whether that evaluation runs.
func receivedDSNCandidate(request dkim2.VerifyRequest) bool {
	if !bytes.Equal(request.ReversePath(), []byte("<>")) || len(request.ForwardPaths()) != 1 {
		return false
	}
	header, ok := topLevelHeaderBlock(request.RawMessage())
	if !ok {
		return false
	}
	for _, value := range headerFieldValues(header, "content-type") {
		mediaType, parameters, err := mime.ParseMediaType(value)
		if err != nil || mediaType != receivedDSNContentTypeReport {
			continue
		}
		if strings.EqualFold(parameters[receivedDSNReportTypeParameter], receivedDSNReportTypeDeliveryStat) {
			return true
		}
	}
	return false
}

// topLevelHeaderBlock returns the bounded RFC 5322 header block of a message.
func topLevelHeaderBlock(raw []byte) ([]byte, bool) {
	limit := min(len(raw), receivedDSNMaxHeaderBytes)
	window := raw[:limit]
	if index := bytes.Index(window, []byte("\r\n\r\n")); index >= 0 {
		return window[:index+2], true
	}
	if index := bytes.Index(window, []byte("\n\n")); index >= 0 {
		return window[:index+1], true
	}
	if limit == len(raw) {
		return window, true
	}
	return nil, false
}

// headerFieldValues returns the unfolded values of every header field with
// the canonical lower-case name, in field order. The classification gate must
// see all of them: a message that names a delivery-status report in any
// top-level Content-Type field is a candidate, and the library parser is the
// single authority that refuses a duplicated field as a malformed structure.
// Selecting one field here would let a second field hide the candidate from
// the evaluation and from the policy that rejects it.
func headerFieldValues(header []byte, name string) []string {
	var values []string
	lines := bytes.Split(header, []byte("\n"))
	for index := 0; index < len(lines); index++ {
		line := bytes.TrimRight(lines[index], "\r")
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 || len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if !strings.EqualFold(string(line[:colon]), name) {
			continue
		}
		unfolded := append([]byte(nil), line[colon+1:]...)
		for index+1 < len(lines) {
			next := bytes.TrimRight(lines[index+1], "\r")
			if len(next) == 0 || (next[0] != ' ' && next[0] != '\t') {
				break
			}
			unfolded = append(unfolded, ' ')
			unfolded = append(unfolded, bytes.TrimSpace(next)...)
			index++
		}
		values = append(values, strings.TrimSpace(string(unfolded)))
	}
	return values
}

// receivedDSNObservation maps one closed projection to the stage at which the
// evaluation stopped and the closed result class of that stop.
func receivedDSNObservation(projection DeliveryStatusProjection) (string, string) {
	if !projection.Valid() {
		return receivedDSNStageStructure, receivedDSNResultTemporary
	}
	if projection.Structure() != dkim2.ReceivedDSNStructureValid {
		return receivedDSNStageStructure, receivedDSNResultPermanent
	}
	switch projection.Embedded() {
	case dkim2.ReceivedDSNEmbeddedUnverified:
		return receivedDSNStageEmbedded, receivedDSNResultPermanent
	case dkim2.ReceivedDSNEmbeddedAbsent:
		return receivedDSNStageEmbedded, receivedDSNResultOK
	case dkim2.ReceivedDSNEmbeddedTemperror:
		return receivedDSNStageEmbedded, receivedDSNResultTemporary
	}
	switch projection.LocalHop() {
	case dkim2.ReceivedDSNLocalHopTemperror:
		return receivedDSNStageLocalHop, receivedDSNResultTemporary
	case dkim2.ReceivedDSNLocalHopMismatch:
		return receivedDSNStageLocalHop, receivedDSNResultPermanent
	case dkim2.ReceivedDSNLocalHopNotLocal, dkim2.ReceivedDSNLocalHopNotEvaluated:
		return receivedDSNStageLocalHop, receivedDSNResultOK
	}
	if projection.OuterAlignment() != dkim2.ReceivedDSNOuterAlignmentAligned {
		return receivedDSNStageOuterAlignment, receivedDSNResultPermanent
	}
	if projection.RecipientLinkage() != dkim2.ReceivedDSNRecipientLinkageLinked {
		return receivedDSNStageRecipientLinkage, receivedDSNResultPermanent
	}
	switch projection.Propagation() {
	case dkim2.ReceivedDSNPropagationNotFailure:
		return receivedDSNStageFailureClass, receivedDSNResultOK
	case dkim2.ReceivedDSNPropagationTerminalOrigin, dkim2.ReceivedDSNPropagationUnsupportedChain,
		dkim2.ReceivedDSNPropagationForbiddenNullPreviousSender, dkim2.ReceivedDSNPropagationNotReconstructable:
		return receivedDSNStagePreviousHop, receivedDSNResultOK
	default:
		return receivedDSNStageCompleted, receivedDSNResultOK
	}
}
