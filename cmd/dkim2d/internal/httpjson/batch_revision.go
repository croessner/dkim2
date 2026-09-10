package httpjson

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/wire"
)

const (
	batchSignatureHeaderName = "DKIM2-Signature"
	batchInstanceHeaderName  = "Message-Instance"
)

// MapBatchRevisionRequest converts the generated complete-fanout contract to immutable domain evidence.
func MapBatchRevisionRequest(input generated.BatchRevisionRequest) (app.BatchRevisionRequest, error) {
	if input.ApiVersion != generated.V1 || input.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		len(input.Copies) == 0 || len(input.Copies) > app.MaxBatchRevisionCopies {
		return app.BatchRevisionRequest{}, newMappingError(MappingInvalidContract)
	}
	original, err := mapBatchMessage(input.Original.Message, input.Original.Smtp)
	if err != nil {
		return app.BatchRevisionRequest{}, err
	}
	total := original.RawSize()
	copies := make([]app.BatchCopy, 0, len(input.Copies))
	for _, branch := range input.Copies {
		message, messageErr := mapBatchMessage(branch.Message, branch.Smtp)
		if messageErr != nil {
			return app.BatchRevisionRequest{}, messageErr
		}
		total += message.RawSize()
		if total > app.MaxBatchRevisionMessageBytes {
			return app.BatchRevisionRequest{}, newMappingError(MappingRequestTooLarge)
		}
		local := branch.Delivery == generated.Local
		if !local && branch.Delivery != generated.External || local && branch.Context != nil || !local && branch.Context == nil {
			return app.BatchRevisionRequest{}, newMappingError(MappingInvalidContract)
		}
		tenant, domain := "", ""
		if branch.Context != nil {
			tenant, domain = branch.Context.Tenant, branch.Context.Domain
			if !validTenant(tenant) || !validSigningDomain(domain) {
				return app.BatchRevisionRequest{}, newMappingError(MappingInvalidContract)
			}
		}
		value, copyErr := app.NewBatchCopy(branch.Id, local, message, tenant, domain)
		if copyErr != nil {
			return app.BatchRevisionRequest{}, newMappingError(MappingInvalidContract)
		}
		if branch.Via != nil {
			value, copyErr = mapBatchVia(value, *branch.Via)
			if copyErr != nil {
				return app.BatchRevisionRequest{}, copyErr
			}
		}
		copies = append(copies, value)
	}
	request, err := app.NewBatchRevisionRequest(input.Binding, original, copies)
	if err != nil {
		return app.BatchRevisionRequest{}, newMappingError(MappingInvalidContract)
	}
	return request, nil
}

// mapBatchVia preserves one explicit same-control intermediate envelope and signing context.
func mapBatchVia(branch app.BatchCopy, via generated.BatchRevisionHop) (app.BatchCopy, error) {
	if !validTenant(via.Context.Tenant) || !validSigningDomain(via.Context.Domain) {
		return app.BatchCopy{}, newMappingError(MappingInvalidContract)
	}
	reverse, recipients, err := mapSigningSMTP(via.Smtp)
	if err != nil {
		return app.BatchCopy{}, err
	}
	if len(recipients) != 1 || bytes.Equal(recipients[0], []byte("<>")) {
		return app.BatchCopy{}, newMappingError(MappingInvalidContract)
	}
	value, err := branch.WithVia(reverse, recipients, via.Context.Tenant, via.Context.Domain)
	if err != nil {
		return app.BatchCopy{}, newMappingError(MappingInvalidContract)
	}
	return value, nil
}

// mapBatchMessage preserves exact message bytes and reuses the established SMTP envelope parser.
func mapBatchMessage(message generated.MessageInput, smtp generated.SMTPInput) (app.BatchMessage, error) {
	if message.Fidelity == nil {
		return app.BatchMessage{}, newMappingError(MappingInvalidContract)
	}
	encoded, err := message.RawRfc5322Base64.Bytes()
	if err != nil {
		return app.BatchMessage{}, newMappingError(MappingInvalidContract)
	}
	raw, err := decodeCanonicalBase64(encoded)
	if err != nil {
		return app.BatchMessage{}, err
	}
	reverse, recipients, err := mapSigningSMTP(smtp)
	if err != nil {
		return app.BatchMessage{}, err
	}
	for _, recipient := range recipients {
		if bytes.Equal(recipient, []byte("<>")) {
			return app.BatchMessage{}, newMappingError(MappingInvalidContract)
		}
	}
	value, err := app.NewBatchMessage(raw, reverse, recipients, app.MessageFidelity(*message.Fidelity))
	if err != nil {
		return app.BatchMessage{}, newMappingError(MappingInvalidContract)
	}
	return value, nil
}

// MapBatchRevisionResult exposes only exact completed header fields and bound content digests.
func MapBatchRevisionResult(result app.BatchRevisionResult) (generated.BatchRevisionResponse, error) {
	if !result.Valid() {
		return generated.BatchRevisionResponse{}, newMappingError(MappingInternalContract)
	}
	response := generated.BatchRevisionResponse{ApiVersion: generated.V1, Draft: generated.DraftIetfDkimDkim2Spec06,
		Binding: result.Binding(), OriginalSha256: result.OriginalSHA256(),
		Result: generated.BatchRevisionResponseResult(result.Result()), Disposition: generated.Disposition(result.Disposition()),
		Outputs: make([]generated.BatchRevisionOutput, 0, len(result.Outputs()))}
	for _, output := range result.Outputs() {
		mapped := generated.BatchRevisionOutput{Id: output.ID(), CurrentSha256: output.CurrentSHA256(),
			ResultSha256: output.ResultSHA256(), InsertionOffset: int64(output.InsertionOffset()),
			HeaderFieldsBase64: make([]generated.CompletedHeaderField, 0, len(output.Fields()))}
		for _, field := range output.Fields() {
			encoded, err := wire.NewProtectedString(base64.StdEncoding.EncodeToString(field.Bytes()))
			if err != nil {
				return generated.BatchRevisionResponse{}, newMappingError(MappingInternalContract)
			}
			mapped.HeaderFieldsBase64 = append(mapped.HeaderFieldsBase64, encoded)
		}
		response.Outputs = append(response.Outputs, mapped)
	}
	if !validBatchRevisionResponse(response) {
		return generated.BatchRevisionResponse{}, newMappingError(MappingInternalContract)
	}
	return response, nil
}

// validBatchRevisionResponse enforces the closed output matrix and exact protected header framing.
func validBatchRevisionResponse(response generated.BatchRevisionResponse) bool {
	if response.ApiVersion != generated.V1 || response.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		!validBatchWireDigest(response.Binding) || !validBatchWireDigest(response.OriginalSha256) ||
		!validWireOperationOutcome(generated.OperationResponseResult(response.Result), response.Disposition) ||
		response.Disposition == generated.DispositionContinue || len(response.Outputs) > app.MaxBatchRevisionCopies {
		return false
	}
	if response.Result != generated.BatchRevisionResponseResultPass {
		return len(response.Outputs) == 0
	}
	if len(response.Outputs) == 0 {
		return false
	}
	ids := make(map[string]bool, len(response.Outputs))
	for _, output := range response.Outputs {
		if !app.ValidBatchCopyID(output.Id) || ids[output.Id] || !validBatchWireDigest(output.CurrentSha256) ||
			!validBatchWireDigest(output.ResultSha256) || output.InsertionOffset < 2 || output.InsertionOffset > app.MaxBatchRevisionMessageBytes ||
			len(output.HeaderFieldsBase64) < 1 || len(output.HeaderFieldsBase64) > 3 {
			return false
		}
		ids[output.Id] = true
		for index, field := range output.HeaderFieldsBase64 {
			encoded, err := field.Bytes()
			if err != nil || len(encoded) > 87384 {
				return false
			}
			raw, err := decodeCanonicalBase64(encoded)
			if err != nil {
				return false
			}
			name, _, err := projectCompletedField(raw)
			if err != nil || (name != batchInstanceHeaderName && name != batchSignatureHeaderName) ||
				(name == batchInstanceHeaderName && index != 0) ||
				(index == len(output.HeaderFieldsBase64)-1 && name != batchSignatureHeaderName) {
				return false
			}
		}
	}
	return true
}

// validBatchWireDigest accepts a lowercase SHA-256 binding without normalizing it.
func validBatchWireDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

// ReviseBatch dispatches the separately authorized fanout operation through its narrow service seam.
func (a *strictAdapter) ReviseBatch(ctx context.Context, request generated.ReviseBatchRequestObject) (generated.ReviseBatchResponseObject, error) {
	if a == nil || request.Body == nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	service, ok := a.operations.(app.BatchRevisionService)
	if !ok || nilInterfaceValue(service) {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	domain, err := MapBatchRevisionRequest(*request.Body)
	if err != nil {
		return nil, classifyMappingFailure(err)
	}
	result, err := service.ReviseBatch(ctx, domain)
	if err != nil {
		return nil, classifyStrictContextFailure(ctx)
	}
	response, err := MapBatchRevisionResult(result)
	if err != nil {
		return nil, &strictAdapterError{class: strictFailureInternal}
	}
	date, present := responseDate(ctx)
	output, err := newJSONResponse(http.StatusOK, response, false, date, present)
	if err != nil {
		return nil, err
	}
	return batchRevisionResponse{output}, nil
}

type batchRevisionResponse struct{ preMarshaledResponse }

// VisitReviseBatchResponse writes only the already bounded and validated batch response.
func (r batchRevisionResponse) VisitReviseBatchResponse(writer http.ResponseWriter) error {
	return r.write(writer)
}
