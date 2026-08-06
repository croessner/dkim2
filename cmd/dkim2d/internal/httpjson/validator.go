package httpjson

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/legacy"
)

const validatorErrorText = "http contract validation failure"

// ValidationError reports a closed runtime OpenAPI failure.
type ValidationError struct{}

// Error returns a constant content-free validation diagnostic.
func (*ValidationError) Error() string { return validatorErrorText }

// Is recognizes the bounded validator failure type.
func (*ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok
}

// RequestValidator owns the immutable embedded OpenAPI router and filter options.
type RequestValidator struct {
	router  routers.Router
	options *openapi3filter.Options
}

// NewRequestValidator loads and validates the embedded contract without external references.
func NewRequestValidator() (*RequestValidator, error) {
	specification, err := generated.GetSpecJSON()
	if err != nil {
		return nil, &ValidationError{}
	}
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false
	document, err := loader.LoadFromData(specification)
	if err != nil || document == nil || document.Validate(context.Background()) != nil {
		return nil, &ValidationError{}
	}
	router, err := legacy.NewRouter(document)
	if err != nil {
		return nil, &ValidationError{}
	}
	return &RequestValidator{
		router: router,
		options: &openapi3filter.Options{
			AuthenticationFunc:  authenticateOpenAPIRequest,
			SkipSettingDefaults: true,
		},
	}, nil
}

// ValidateProcess validates one body snapshot through the exact embedded operation.
func (v *RequestValidator) ValidateProcess(request *http.Request, body []byte) error {
	if request == nil || request.URL == nil || request.URL.Path != processPath {
		return &ValidationError{}
	}
	return v.ValidateOperation(request, body)
}

// ValidateOperation validates one body snapshot through its exact embedded
// process, sign, or revise operation.
func (v *RequestValidator) ValidateOperation(request *http.Request, body []byte) error {
	if v == nil || v.router == nil || v.options == nil || request == nil ||
		request.Method != http.MethodPost || request.URL == nil {
		return &ValidationError{}
	}
	operationID := map[string]string{
		processPath: "processMessage",
		signPath:    "signMessage",
		revisePath:  "reviseMessage",
		dsnSignPath: "signDeliveryStatus",
	}[request.URL.Path]
	if operationID == "" {
		return &ValidationError{}
	}
	validationRequest := request.Clone(request.Context())
	validationRequest.Body = io.NopCloser(bytes.NewReader(body))
	validationRequest.ContentLength = int64(len(body))
	route, pathParameters, err := v.router.FindRoute(validationRequest)
	if err != nil || route == nil || route.Operation == nil ||
		route.Operation.OperationID != operationID ||
		route.Operation.RequestBody == nil {
		return &ValidationError{}
	}
	input := &openapi3filter.RequestValidationInput{
		Request:    validationRequest,
		PathParams: pathParameters,
		Route:      route,
		Options:    v.options,
	}
	if err := openapi3filter.ValidateRequest(validationRequest.Context(), input); err != nil {
		return &ValidationError{}
	}
	return nil
}

// authenticateOpenAPIRequest accepts only the private outer-preflight marker.
func authenticateOpenAPIRequest(ctx context.Context, _ *openapi3filter.AuthenticationInput) error {
	if !localCapabilityAuthenticated(ctx) {
		return &ValidationError{}
	}
	return nil
}

// IsValidationError reports whether err belongs to the closed validator class.
func IsValidationError(err error) bool {
	return errors.Is(err, &ValidationError{})
}

// String returns a content-free validator representation.
func (RequestValidator) String() string { return "dkim2d_request_validator" }

// GoString returns a content-free validator representation.
func (RequestValidator) GoString() string { return "dkim2d_request_validator" }

// Format prevents formatting from traversing validator internals.
func (RequestValidator) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "dkim2d_request_validator")
}
