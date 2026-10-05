package app

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

// TestInteropInfoSigningAndRevision proves real signatures survive the optional diagnostic header.
func TestInteropInfoSigningAndRevision(t *testing.T) {
	fixture := newSigningServiceFixtureWithDualCredentials(t, true)
	for _, enabled := range []bool{false, true} {
		service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false, signingPolicies{interopInfo: enabled})
		if err != nil {
			t.Fatal(err)
		}
		service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
		raw := signingServiceRawMessage()
		recipients := [][]byte{[]byte("<recipient@origin.example.test>")}
		request := newSigningServiceRequest(t, OperationSign, raw, recipients)
		assessment, err := service.Sign(context.Background(), request)
		result, ok := assessment.Result()
		if err != nil || !ok || result.Result() != OperationPass {
			t.Fatal("sign failed")
		}
		fields := result.Fields()
		wantCount := 2
		if enabled {
			wantCount++
		}
		if len(fields) != wantCount {
			t.Fatalf("field count = %d, want %d", len(fields), wantCount)
		}
		if enabled {
			want := "X-DKIM2-Info: draft=ietf-dkim-dkim2-spec-06;\r\n\trepo=github.com/croessner/dkim2; date=2023-11-14; sw=dkim2d;\r\n\taction=sign d=origin.example.test a=rsa-sha256,ed25519-sha256;\r\n"
			if string(fields[len(fields)-1].Bytes()) != want {
				t.Fatal("unexpected interop header")
			}
		}
		signed := insertSigningServiceFields(fields, raw)
		revise := newSigningServiceRequest(t, OperationRevise, signed, recipients)
		revised, err := service.Revise(context.Background(), revise)
		if err != nil || revised.Result() != OperationPass {
			t.Fatal("revision rejected signed message with interop header")
		}
		output := insertSigningServiceFields(revised.Fields(), signed)
		if enabled && bytes.Count(output, []byte("X-DKIM2-Info:")) != 2 {
			t.Fatal("revision did not preserve prior diagnostic and append local diagnostic")
		}
		verifier, err := dkim2.NewVerifier(fixture.publicKeys, dkim2.WithVerificationClock(service.clock))
		if err != nil {
			t.Fatal(err)
		}
		verification, err := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(output, request.ReversePath(), recipients))
		if err != nil || verification.State() != dkim2.ResultStatePASS {
			t.Fatal("completed output did not verify")
		}
	}
}

// TestInteropInfoDeliveryStatusAndNoOp proves only successful DSN signing emits diagnostics.
func TestInteropInfoDeliveryStatusAndNoOp(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false, signingPolicies{interopInfo: true})
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	request := authenticatedDeliveryStatusRequest(t, service)
	assessment, err := service.SignDeliveryStatus(context.Background(), request)
	result, ok := assessment.Result()
	if err != nil || !ok || result.Result() != OperationPass || len(result.Fields()) != 3 {
		t.Fatal("DSN interop signing failed")
	}
	if !bytes.HasPrefix(result.Fields()[2].Bytes(), []byte("X-DKIM2-Info:")) {
		t.Fatal("DSN diagnostic missing")
	}
	invalid, err := NewPostfixDeliveryStatusRequest([]byte("From: x@example.test\r\n\r\nbody"), []byte("<>"), [][]byte{[]byte("<x@example.test>")}, signingServiceTestTenant)
	if err != nil {
		t.Fatal(err)
	}
	assessment, err = service.SignDeliveryStatus(context.Background(), invalid)
	result, ok = assessment.Result()
	if err != nil || !ok || len(result.Fields()) != 0 {
		t.Fatal("failed DSN emitted diagnostics")
	}
}
