package daemon

import (
	"context"
	"net/http"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/daemon/generated"
)

// FilterClient is the generated signing and revision client authority.
type FilterClient interface {
	SignMessage(context.Context, generated.SignMessageJSONRequestBody, ...generated.RequestEditorFn) (*http.Response, error)
	ReviseMessage(context.Context, generated.ReviseMessageJSONRequestBody, ...generated.RequestEditorFn) (*http.Response, error)
}

// FilterProcessor maps one immutable filter request through exactly one daemon operation.
type FilterProcessor struct {
	client FilterClient
	tenant string
	domain string
}

// NewFilterProcessor validates generated-client signing context authority.
func NewFilterProcessor(client FilterClient, tenant, domain string) (*FilterProcessor, error) {
	if client == nil || !validSigningContext(tenant, domain) {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	return &FilterProcessor{client: client, tenant: tenant, domain: domain}, nil
}

// Process sends one generated sign or revise request and strictly admits its raw response.
func (p *FilterProcessor) Process(ctx context.Context, input adapter.FilterRequest) (adapter.Plan, error) {
	if p == nil || p.client == nil || ctx == nil {
		return adapter.Plan{}, adapter.NewError(adapter.FailureContract)
	}
	var response *http.Response
	var err error
	switch input.Operation() {
	case adapter.FilterSign:
		request, mapErr := MapSignRequest(input, p.tenant, p.domain)
		if mapErr != nil {
			return adapter.Plan{}, mapErr
		}
		response, err = p.client.SignMessage(ctx, request)
	case adapter.FilterRevise:
		request, mapErr := MapReviseRequest(input, p.tenant, p.domain)
		if mapErr != nil {
			return adapter.Plan{}, mapErr
		}
		response, err = p.client.ReviseMessage(ctx, request)
	default:
		return adapter.Plan{}, adapter.NewError(adapter.FailureContract)
	}
	if err != nil {
		if response != nil {
			if response.Body != nil {
				_ = response.Body.Close()
			}
			return adapter.Plan{}, adapter.NewError(adapter.FailureContract)
		}
		return adapter.Plan{}, classifyProcessError(ctx, err)
	}
	body, err := readProcessResponse(response)
	if err != nil {
		return adapter.Plan{}, err
	}
	plan, err := AdmitOperationJSON(body, operationName(input.Operation()))
	clear(body)
	return plan, err
}

// operationName returns the sole generated operation discriminator for a filter path.
func operationName(operation adapter.FilterOperation) string {
	if operation == adapter.FilterSign {
		return daemonOperationSign
	}
	if operation == adapter.FilterRevise {
		return daemonOperationRevise
	}
	return ""
}
