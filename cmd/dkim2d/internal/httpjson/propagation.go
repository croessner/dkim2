package httpjson

import (
	"bytes"
	"encoding/base64"
	"unicode/utf8"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
)

// MapPropagationRequest maps one generated propagation request to the
// daemon-owned domain request. The route admits exactly the null reverse path
// and one forward path; the signing domain is never a request member.
func MapPropagationRequest(input generated.DSNPropagateRequest) (app.PropagationRequest, error) {
	if input.ApiVersion != generated.V1 || input.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		!input.Message.Fidelity.Valid() || !validTenant(input.Context.Tenant) ||
		!validSigningDomain(input.Context.ReportingMta) {
		return app.PropagationRequest{}, newMappingError(MappingInvalidContract)
	}
	encoded, err := input.Message.RawRfc5322Base64.Bytes()
	if err != nil {
		return app.PropagationRequest{}, newMappingError(MappingInvalidContract)
	}
	raw, err := decodeCanonicalBase64(encoded)
	if err != nil {
		return app.PropagationRequest{}, err
	}
	if len(raw) == 0 {
		return app.PropagationRequest{}, newMappingError(MappingInvalidContract)
	}
	reverse, err := input.OuterSmtp.MailFrom.Bytes()
	if err != nil {
		return app.PropagationRequest{}, newMappingError(MappingInvalidContract)
	}
	if !bytes.Equal(reverse, []byte("<>")) {
		return app.PropagationRequest{}, newMappingError(MappingInvalidContract)
	}
	recipients, err := mapDSNOuterRecipients(input.OuterSmtp.RcptTo)
	if err != nil {
		return app.PropagationRequest{}, err
	}
	request, err := app.NewPropagationRequest(
		raw, reverse, recipients, input.OuterSmtp.Smtputf8,
		input.Context.Tenant, input.Context.ReportingMta,
		app.MessageFidelity(input.Message.Fidelity),
	)
	if err != nil {
		return app.PropagationRequest{}, newMappingError(MappingInvalidContract)
	}
	return request, nil
}

// MapPropagationCommitRequest extracts one bounded opaque commit token.
func MapPropagationCommitRequest(input generated.DSNPropagateCommitRequest) (string, error) {
	if input.ApiVersion != generated.V1 || input.Draft != generated.DraftIetfDkimDkim2Spec06 {
		return "", newMappingError(MappingInvalidContract)
	}
	token, err := input.CommitToken.Bytes()
	if err != nil || !utf8.Valid(token) || !app.ValidPropagationCommitToken(string(token)) {
		return "", newMappingError(MappingInvalidContract)
	}
	return string(token), nil
}

// MapPropagationResult projects one coherent domain result into the generated
// response. It refuses every incoherent result, disposition, failure, and
// output combination so that an internal regression never reaches the wire.
// The delivery-status member is omitted when the evaluation never ran, so the
// response never carries a fabricated structure verdict.
func MapPropagationResult(result app.PropagationResult) (generated.DSNPropagateResponse, error) {
	if !result.Valid() {
		return generated.DSNPropagateResponse{}, newMappingError(MappingInternalContract)
	}
	var projection *generated.DeliveryStatusProjection
	if evidence := result.Projection(); !evidence.Absent() {
		mapped, err := mapDeliveryStatusProjection(evidence)
		if err != nil {
			return generated.DSNPropagateResponse{}, err
		}
		projection = &mapped
	}
	resultClass := generated.DSNPropagateResponseResult(result.Result())
	disposition := generated.PropagationDisposition(result.Disposition())
	replayClass, replayOK := mapReplayClass(result.Replay())
	if !resultClass.Valid() || !disposition.Valid() || !replayOK {
		return generated.DSNPropagateResponse{}, newMappingError(MappingInternalContract)
	}
	response := generated.DSNPropagateResponse{
		ApiVersion:     generated.V1,
		Draft:          generated.DraftIetfDkimDkim2Spec06,
		Operation:      generated.PropagationOperationDeliveryStatusPropagation,
		Result:         resultClass,
		Disposition:    disposition,
		DeliveryStatus: projection,
		Replay:         generated.ReplayResult{Class: replayClass},
	}
	if failure := result.Failure(); failure != app.PropagationFailureNone {
		value := generated.DSNPropagateResponsePropagationFailure(failure)
		if !value.Valid() {
			return generated.DSNPropagateResponse{}, newMappingError(MappingInternalContract)
		}
		response.PropagationFailure = &value
	}
	output, present := result.Output()
	if !present {
		return response, nil
	}
	projected, err := mapPropagationOutput(output)
	if err != nil {
		return generated.DSNPropagateResponse{}, err
	}
	response.Propagation = &projected
	return response, nil
}

// mapPropagationOutput projects the signed notification and its transport
// requirements into the generated output member.
func mapPropagationOutput(output app.PropagationOutput) (generated.PropagationOutput, error) {
	raw := output.RawMessage()
	nextHop := output.NextHopRecipient()
	if len(raw) == 0 || len(raw) > dkim2.HardMaxRawMessageBytes ||
		len(nextHop) == 0 || len(nextHop) > maxSMTPPathBytes || !utf8.Valid(nextHop) {
		return generated.PropagationOutput{}, newMappingError(MappingInternalContract)
	}
	encoded, err := wire.NewProtectedString(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return generated.PropagationOutput{}, newMappingError(MappingInternalContract)
	}
	recipient, err := wire.NewProtectedString(string(nextHop))
	if err != nil {
		return generated.PropagationOutput{}, newMappingError(MappingInternalContract)
	}
	token := output.CommitToken()
	if !app.ValidPropagationCommitToken(token) {
		return generated.PropagationOutput{}, newMappingError(MappingInternalContract)
	}
	protectedToken, err := wire.NewProtectedString(token)
	if err != nil {
		return generated.PropagationOutput{}, newMappingError(MappingInternalContract)
	}
	return generated.PropagationOutput{
		RawRfc5322Base64:     encoded,
		NextHopRecipient:     recipient,
		CommitToken:          protectedToken,
		Smtputf8Required:     output.SMTPUTF8Required(),
		EightBitMimeRequired: output.EightBitMIMERequired(),
	}, nil
}

// mapDeliveryStatusProjection projects the closed received-DSN projection.
func mapDeliveryStatusProjection(
	projection app.DeliveryStatusProjection,
) (generated.DeliveryStatusProjection, error) {
	if !projection.Valid() {
		return generated.DeliveryStatusProjection{}, newMappingError(MappingInternalContract)
	}
	mapped := generated.DeliveryStatusProjection{
		Structure:        generated.DeliveryStatusProjectionStructure(projection.Structure()),
		Embedded:         generated.DeliveryStatusProjectionEmbedded(projection.Embedded()),
		LocalHop:         generated.DeliveryStatusProjectionLocalHop(projection.LocalHop()),
		OuterAlignment:   generated.DeliveryStatusProjectionOuterAlignment(projection.OuterAlignment()),
		RecipientLinkage: generated.DeliveryStatusProjectionRecipientLinkage(projection.RecipientLinkage()),
		Propagation:      generated.DeliveryStatusProjectionPropagation(projection.Propagation()),
	}
	if !mapped.Structure.Valid() || !mapped.Embedded.Valid() || !mapped.LocalHop.Valid() ||
		!mapped.OuterAlignment.Valid() || !mapped.RecipientLinkage.Valid() ||
		!mapped.Propagation.Valid() {
		return generated.DeliveryStatusProjection{}, newMappingError(MappingInternalContract)
	}
	return mapped, nil
}

// MapPropagationCommitResult projects one closed commit state. An unresolved
// token has no success representation: the route answers 409 instead, so that
// the caller defers rather than leaving a coordinate uncommitted.
func MapPropagationCommitResult(
	state app.PropagationCommitState,
) (generated.DSNPropagateCommitResponse, error) {
	if state != app.PropagationCommitCommitted {
		return generated.DSNPropagateCommitResponse{}, newMappingError(MappingInternalContract)
	}
	return generated.DSNPropagateCommitResponse{
		ApiVersion: generated.V1,
		Draft:      generated.DraftIetfDkimDkim2Spec06,
		State:      generated.PropagationStateCommitted,
	}, nil
}
