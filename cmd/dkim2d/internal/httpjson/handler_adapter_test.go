package httpjson

import (
	"context"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
)

type adapterReadinessStub struct{}

// Ready returns one stable readiness value.
func (*adapterReadinessStub) Ready() bool { return true }

type adapterProcessorStub struct{}

// Process returns one empty result for constructor-only tests.
func (*adapterProcessorStub) Process(
	context.Context,
	dkim2.VerifyRequest,
) (app.InboundResult, error) {
	return app.InboundResult{}, nil
}

// TestNewStrictAdapterRejectsNilAndTypedNilDependencies proves fail-closed composition.
func TestNewStrictAdapterRejectsNilAndTypedNilDependencies(t *testing.T) {
	var typedNilReadiness *adapterReadinessStub
	var typedNilProcessor *adapterProcessorStub
	tests := []struct {
		name      string
		readiness readinessSource
		processor inboundProcessService
	}{
		{name: "direct nil readiness", processor: &adapterProcessorStub{}},
		{name: "direct nil processor", readiness: &adapterReadinessStub{}},
		{name: "typed nil readiness", readiness: typedNilReadiness, processor: &adapterProcessorStub{}},
		{name: "typed nil processor", readiness: &adapterReadinessStub{}, processor: typedNilProcessor},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter, err := newStrictAdapter(test.readiness, test.processor)
			if adapter != nil || !IsStrictAdapterError(err, strictFailureInternal) {
				t.Fatalf("newStrictAdapter() = %v/%v", adapter, err)
			}
		})
	}
	if adapter, err := newStrictAdapter(&adapterReadinessStub{}, &adapterProcessorStub{}); err != nil || adapter == nil {
		t.Fatalf("valid newStrictAdapter() = %v/%v", adapter, err)
	}
}
