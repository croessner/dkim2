package httpjson

import (
	"bytes"
	"context"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
)

// MapSignRequest maps one generated originator request to domain-owned values.
func MapSignRequest(input generated.SignRequest) (app.OperationRequest, error) {
	return mapOperationRequest(
		app.OperationSign, input.ApiVersion, input.Draft,
		input.Message, input.Smtp, nil, input.Context,
	)
}

// MapReviseRequest maps one generated ordinary-transit request to domain-owned values.
func MapReviseRequest(input generated.ReviseRequest) (app.OperationRequest, error) {
	return mapOperationRequest(
		app.OperationRevise, input.ApiVersion, input.Draft,
		input.Message, input.Smtp, &input.IncomingSmtp, input.Context,
	)
}

// MapDeliveryStatusRequest maps one generated DSN-sign request to the
// dedicated daemon-owned evidence request.
func MapDeliveryStatusRequest(input generated.DSNSignRequest) (app.DeliveryStatusRequest, error) {
	if input.ApiVersion != generated.V1 || input.Draft != generated.DraftIetfDkimDkim2Spec05 ||
		!validTenant(input.Context.Tenant) {
		return app.DeliveryStatusRequest{}, newMappingError(MappingInvalidContract)
	}
	encoded, err := input.Message.RawRfc5322Base64.Bytes()
	if err != nil {
		return app.DeliveryStatusRequest{}, newMappingError(MappingInvalidContract)
	}
	raw, err := decodeCanonicalBase64(encoded)
	if err != nil || len(raw) == 0 {
		return app.DeliveryStatusRequest{}, newMappingError(MappingInvalidContract)
	}
	outerReverse, err := input.OuterSmtp.MailFrom.Bytes()
	if err != nil {
		return app.DeliveryStatusRequest{}, newMappingError(MappingInvalidContract)
	}
	if !bytes.Equal(outerReverse, []byte("<>")) || len(input.OuterSmtp.RcptTo) != 1 {
		return app.DeliveryStatusRequest{}, newMappingError(MappingInvalidContract)
	}
	outerRecipients, err := mapDSNOuterRecipients(input.OuterSmtp.RcptTo)
	if err != nil {
		return app.DeliveryStatusRequest{}, err
	}
	request, err := app.NewPostfixDeliveryStatusRequest(
		raw, outerReverse, outerRecipients,
		input.Context.Tenant,
	)
	if err != nil {
		return app.DeliveryStatusRequest{}, newMappingError(MappingInvalidContract)
	}
	return request, nil
}

// mapDSNOuterRecipients validates the single exact ASCII outer DSN recipient.
func mapDSNOuterRecipients(values []wire.ProtectedString) ([][]byte, error) {
	if len(values) != 1 {
		return nil, newMappingError(MappingInvalidContract)
	}
	path, err := values[0].Bytes()
	if err != nil {
		return nil, newMappingError(MappingInvalidContract)
	}
	if len(path) == 0 || len(path) > maxSMTPPathBytes || !utf8.Valid(path) || !asciiEnvelopePath(path) {
		return nil, newMappingError(MappingInvalidContract)
	}
	return [][]byte{bytes.Clone(path)}, nil
}

// mapOperationRequest owns the shared exact request admission rules.
func mapOperationRequest(
	operation app.Operation,
	apiVersion generated.APIVersion,
	draft generated.DraftVersion,
	message generated.MessageInput,
	smtp generated.SMTPInput,
	incomingSMTP *generated.SMTPInput,
	signing generated.SigningContext,
) (app.OperationRequest, error) {
	if apiVersion != generated.V1 || draft != generated.DraftIetfDkimDkim2Spec05 ||
		message.Fidelity == nil || !message.Fidelity.Valid() ||
		!validTenant(signing.Tenant) || !validSigningDomain(signing.Domain) {
		return app.OperationRequest{}, newMappingError(MappingInvalidContract)
	}
	encoded, err := message.RawRfc5322Base64.Bytes()
	if err != nil {
		return app.OperationRequest{}, newMappingError(MappingInvalidContract)
	}
	raw, err := decodeCanonicalBase64(encoded)
	if err != nil || len(raw) == 0 {
		return app.OperationRequest{}, err
	}
	reverse, recipients, err := mapSigningSMTP(smtp)
	if err != nil {
		return app.OperationRequest{}, err
	}
	if operation == app.OperationSign && bytes.Equal(reverse, []byte("<>")) {
		return app.OperationRequest{}, newMappingError(MappingInvalidContract)
	}
	fidelity := app.MessageFidelity(*message.Fidelity)
	if operation == app.OperationRevise {
		if bytes.Equal(reverse, []byte("<>")) {
			return app.OperationRequest{}, newMappingError(MappingInvalidContract)
		}
		if incomingSMTP == nil {
			return app.OperationRequest{}, newMappingError(MappingInvalidContract)
		}
		incomingReverse, incomingRecipients, incomingErr := mapSigningSMTP(*incomingSMTP)
		if incomingErr != nil {
			return app.OperationRequest{}, incomingErr
		}
		request, requestErr := app.NewRevisionOperationRequest(
			raw,
			incomingReverse,
			incomingRecipients,
			reverse,
			recipients,
			signing.Tenant,
			signing.Domain,
			fidelity,
		)
		if requestErr != nil {
			return app.OperationRequest{}, newMappingError(MappingInvalidContract)
		}
		return request, nil
	}
	request, err := app.NewOperationRequest(
		operation, raw, reverse, recipients, signing.Tenant, signing.Domain, fidelity,
	)
	if err != nil {
		return app.OperationRequest{}, newMappingError(MappingInvalidContract)
	}
	return request, nil
}

// mapSigningSMTP validates one complete ASCII signing-envelope evidence set.
func mapSigningSMTP(smtp generated.SMTPInput) ([]byte, [][]byte, error) {
	reverse, err := smtp.MailFrom.Bytes()
	if err != nil || len(reverse) > maxSMTPPathBytes || !utf8.Valid(reverse) ||
		!asciiEnvelopePath(reverse) {
		return nil, nil, newMappingError(MappingInvalidContract)
	}
	if len(smtp.RcptTo) == 0 || len(smtp.RcptTo) > dkim2.HardMaxRecipients {
		return nil, nil, newMappingError(MappingInvalidContract)
	}
	recipients := make([][]byte, len(smtp.RcptTo))
	total := len(reverse)
	for index := range smtp.RcptTo {
		path, pathErr := smtp.RcptTo[index].Bytes()
		if pathErr != nil || len(path) > maxSMTPPathBytes || !utf8.Valid(path) ||
			!asciiEnvelopePath(path) {
			return nil, nil, newMappingError(MappingInvalidContract)
		}
		total += len(path)
		if total > maxEnvelopeBytes {
			return nil, nil, newMappingError(MappingRequestTooLarge)
		}
		recipients[index] = bytes.Clone(path)
	}
	return reverse, recipients, nil
}

// MapOperationResult projects only complete signing-engine fields into an action plan.
func MapOperationResult(result app.OperationResult) (generated.OperationResponse, error) {
	if !result.Valid() {
		return generated.OperationResponse{}, newMappingError(MappingInternalContract)
	}
	operation := generated.OperationResponseOperation(result.Operation())
	resultClass := generated.OperationResponseResult(result.Result())
	disposition := generated.Disposition(result.Disposition())
	if !operation.Valid() || !resultClass.Valid() || !disposition.Valid() {
		return generated.OperationResponse{}, newMappingError(MappingInternalContract)
	}
	fields := result.Fields()
	actions := make(generated.ActionPlan, len(fields))
	for index := range fields {
		name, value, err := projectCompletedField(fields[index].Bytes())
		if err != nil {
			return generated.OperationResponse{}, err
		}
		actions[index] = generated.AddHeaderAction{
			Type:  generated.AddHeader,
			Name:  generated.AddHeaderActionName(name),
			Value: value,
		}
	}
	if !validOperationActionMatrix(operation, disposition, actions) {
		return generated.OperationResponse{}, newMappingError(MappingInternalContract)
	}
	return generated.OperationResponse{
		ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec05,
		Operation: operation, Result: resultClass, Disposition: disposition,
		Actions: actions,
	}, nil
}

// projectCompletedField strictly removes framing and legal FWS only.
func projectCompletedField(field []byte) (string, string, error) {
	if len(field) < 4 || !bytes.HasSuffix(field, []byte("\r\n")) {
		return "", "", newMappingError(MappingInternalContract)
	}
	colon := bytes.IndexByte(field, ':')
	if colon < 1 {
		return "", "", newMappingError(MappingInternalContract)
	}
	name := string(field[:colon])
	if name != "Message-Instance" && name != "DKIM2-Signature" &&
		name != "Authentication-Results" {
		return "", "", newMappingError(MappingInternalContract)
	}
	value := field[colon+1 : len(field)-2]
	unfolded := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		switch value[index] {
		case '\r':
			if index+2 >= len(value) || value[index+1] != '\n' ||
				(value[index+2] != ' ' && value[index+2] != '\t') {
				return "", "", newMappingError(MappingInternalContract)
			}
			index++
		case '\n', 0:
			return "", "", newMappingError(MappingInternalContract)
		default:
			unfolded = append(unfolded, value[index])
		}
	}
	if len(unfolded) == 0 || len(unfolded) > 65535 {
		return "", "", newMappingError(MappingInternalContract)
	}
	return name, string(unfolded), nil
}

// validOperationActionMatrix enforces exact action order before serialization.
func validOperationActionMatrix(
	operation generated.OperationResponseOperation,
	disposition generated.Disposition,
	actions generated.ActionPlan,
) bool {
	if disposition != generated.DispositionAccept {
		return len(actions) == 0
	}
	switch operation {
	case generated.Sign:
		return len(actions) == 2 &&
			actions[0].Name == generated.MessageInstance &&
			actions[1].Name == generated.DKIM2Signature
	case generated.Revise:
		return len(actions) == 1 && actions[0].Name == generated.DKIM2Signature ||
			len(actions) == 2 && actions[0].Name == generated.MessageInstance &&
				actions[1].Name == generated.DKIM2Signature
	case generated.DeliveryStatus:
		return len(actions) == 2 && actions[0].Name == generated.MessageInstance &&
			actions[1].Name == generated.DKIM2Signature
	default:
		return false
	}
}

// validTenant accepts one bounded canonical administrative identifier.
func validTenant(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, char := range value {
		letter := char >= 'a' && char <= 'z'
		digit := char >= '0' && char <= '9'
		punctuation := index > 0 && (char == '.' || char == '_' || char == '-')
		if !letter && !digit && !punctuation {
			return false
		}
	}
	return true
}

// validSigningDomain accepts a canonical lower-case ASCII domain.
func validSigningDomain(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!asciiDNSAlphanumeric(label[0]) ||
			!asciiDNSAlphanumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiDNSAlphanumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

// asciiDNSAlphanumeric reports whether one byte is a lower-case DNS edge.
func asciiDNSAlphanumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

// asciiEnvelopePath enforces the current signing-engine baseline.
func asciiEnvelopePath(value []byte) bool {
	for _, current := range value {
		if current > 0x7f || current == 0 || current == '\r' || current == '\n' {
			return false
		}
	}
	return true
}

// executeSignOperation invokes only the originator applicability boundary.
func executeSignOperation(
	ctx context.Context,
	service app.OperationService,
	request app.OperationRequest,
) (app.SigningAssessment, error) {
	if service == nil || request.Operation() != app.OperationSign {
		return app.SigningAssessment{}, &strictAdapterError{class: strictFailureInvalidContract}
	}
	return service.Sign(ctx, request)
}

// executeRevisionOperation invokes only the applicable ordinary-transit boundary.
func executeRevisionOperation(
	ctx context.Context,
	service app.OperationService,
	request app.OperationRequest,
) (app.OperationResult, error) {
	if service == nil || request.Operation() != app.OperationRevise {
		return app.OperationResult{}, &strictAdapterError{class: strictFailureInvalidContract}
	}
	return service.Revise(ctx, request)
}
