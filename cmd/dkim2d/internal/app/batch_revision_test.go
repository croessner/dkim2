package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
)

// TestBatchRevisionSealsLocalAndPrivateExternalCopies exercises actual originator and transit cryptography.
func TestBatchRevisionSealsLocalAndPrivateExternalCopies(t *testing.T) {
	service, fixture, original := newBatchRevisionFixture(t, signingFlagPolicy{})
	current := append([]byte("Received: by queue.example.test; Tue, 14 Nov 2023 22:13:20 +0000\r\n"), original...)
	request := newBatchRevisionTestRequest(t, original, current, 2)
	result, err := service.ReviseBatch(context.Background(), request)
	if err != nil || !result.Valid() || result.Result() != OperationPass || len(result.Outputs()) != 2 {
		inspectBatchRevisionStages(t, service, request)
		t.Fatalf("batch failed: valid=%t result=%s outputs=%d err=%v", result.Valid(), result.Result(), len(result.Outputs()), err)
	}
	if result.Binding() != strings.Repeat("a", 64) || result.OriginalSHA256() != batchSHA256(original) {
		t.Fatal("request binding lost")
	}
	verifier, err := dkim2.NewVerifier(fixture.publicKeys, dkim2.WithVerificationClock(service.clock))
	if err != nil {
		t.Fatal("verifier construction failed")
	}
	for index, output := range result.Outputs() {
		branch := request.state.copies[index+1]
		actual := insertSigningServiceFields(output.Fields(), current)
		if output.CurrentSHA256() != batchSHA256(current) || output.ResultSHA256() != batchSHA256(actual) ||
			output.InsertionOffset() != bytes.Index(current, []byte("\r\n\r\n"))+2 || output.ID() != branch.id {
			t.Fatal("exact output binding or placement lost")
		}
		assessment, verifyErr := verifier.Verify(context.Background(), dkim2.NewVerifyRequest(actual, branch.message.state.reverse, branch.message.state.recipients))
		if verifyErr != nil || assessment.State() != dkim2.ResultStatePASS {
			t.Fatalf("external verification failed: state=%s reason=%s err=%v", assessment.State(), assessment.PrimaryReason(), verifyErr)
		}
		last := output.Fields()[len(output.Fields())-1].Bytes()
		if !bytes.Contains(last, []byte("exploded")) || !bytes.Contains(last, []byte(base64.StdEncoding.EncodeToString(branch.message.state.recipients[0]))) {
			t.Fatal("fanout flag or private recipient missing")
		}
		other := request.state.copies[2-index].message.state.recipients[0]
		if bytes.Contains(last, []byte(base64.StdEncoding.EncodeToString(other))) {
			t.Fatal("other external recipient disclosed")
		}
	}
	if !bytes.Equal(request.state.original.state.raw, original) || !bytes.Equal(request.state.copies[0].message.state.raw, current) {
		t.Fatal("input or local copy changed")
	}
}

// inspectBatchRevisionStages reports only closed library failures for a failed real-crypto fixture.
func inspectBatchRevisionStages(t *testing.T, service *SigningService, request BatchRevisionRequest) {
	t.Helper()
	ctx := context.Background()
	lease, err := service.store.Acquire(ctx)
	if err != nil {
		t.Fatal("diagnostic lease unavailable")
	}
	defer func() { _ = lease.Close() }()
	signer, err := dkim2.NewSigner(service.publicKeys, dkim2.NewRequestRouteAuthority(), batchRevisionAuthorizer{copies: request.state.copies}, lease, dkim2.WithSigningClock(service.clock))
	if err != nil {
		t.Fatal("diagnostic signer unavailable")
	}
	incoming := request.state.original.state
	verification, capability, err := signer.VerifyForRevision(ctx, dkim2.NewVerifyRequest(incoming.raw, incoming.reverse, incoming.recipients))
	if err != nil || !capability.Valid() {
		t.Fatalf("verification stage %s %v", verification.Status(), err)
	}
	tickets, err := planBatchRevision(ctx, signer, capability, request.state.copies)
	if err != nil {
		t.Fatalf("route stage %v", err)
	}
	profiles, err := resolveBatchProfiles(ctx, lease, request.state.copies, service.clock())
	if err != nil {
		t.Fatal("diagnostic policy unavailable")
	}
	metadata, err := service.policies.ordinaryTransit.metadata()
	if err != nil {
		t.Fatal("diagnostic metadata invalid")
	}
	for index, branch := range request.state.copies {
		if branch.local {
			continue
		}
		_, err = completeBatchCopy(ctx, signer, capability, branch, tickets[index], profiles[index], metadata)
		var signingErr *dkim2.SigningError
		if errors.As(err, &signingErr) {
			t.Fatalf("signing stage %s", signingErr.Code())
		}
		if err != nil {
			t.Fatalf("signing stage %v", err)
		}
	}
}

// TestBatchRevisionRejectsInvalidEvidenceAndAuthenticatedRestrictions proves no partial release or unsigned restart.
func TestBatchRevisionRejectsInvalidEvidenceAndAuthenticatedRestrictions(t *testing.T) {
	for _, test := range []struct {
		name                          string
		policy                        signingFlagPolicy
		mutateOriginal, mutateCurrent bool
		external                      int
		want                          OperationResultClass
	}{
		{name: "donotexplode local plus external", policy: signingFlagPolicy{doNotExplode: true}, external: 1, want: OperationPermerror},
		{name: "donotmodify changed body", policy: signingFlagPolicy{doNotModify: true}, mutateCurrent: true, external: 2, want: OperationPermerror},
		{name: "corrupt original", mutateOriginal: true, external: 2, want: OperationPermerror},
		{name: "donotmodify received only", policy: signingFlagPolicy{doNotModify: true}, external: 2, want: OperationPass},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, _, original := newBatchRevisionFixture(t, test.policy)
			if test.mutateOriginal {
				original = append(original, []byte("unverified extra line\r\n")...)
			}
			current := append([]byte("Received: by queue.example.test\r\n"), original...)
			if test.mutateCurrent {
				current = append(current, []byte("new body line\r\n")...)
			}
			result, err := service.ReviseBatch(context.Background(), newBatchRevisionTestRequest(t, original, current, test.external))
			if err != nil || !result.Valid() || result.Result() != test.want {
				t.Fatalf("wrong classification: %s %v", result.Result(), err)
			}
			if test.want != OperationPass && len(result.Outputs()) != 0 {
				t.Fatal("partial external output escaped")
			}
		})
	}
}

// TestBatchRevisionRejectsRemovedProtocolFieldsAndWrongEnvelope protects the original/current evidence boundary.
func TestBatchRevisionRejectsRemovedProtocolFieldsAndWrongEnvelope(t *testing.T) {
	service, _, original := newBatchRevisionFixture(t, signingFlagPolicy{})
	for _, raw := range [][]byte{signingServiceRawMessage(), bytes.Replace(original, []byte("DKIM2-Signature:"), []byte("X-Removed-DKIM2-Signature:"), 1)} {
		result, err := service.ReviseBatch(context.Background(), newBatchRevisionTestRequest(t, original, raw, 2))
		if err != nil || result.Result() == OperationPass || len(result.Outputs()) != 0 {
			t.Fatal("removed inherited evidence accepted")
		}
	}
	request := newBatchRevisionTestRequest(t, original, original, 2)
	request.state.original.state.reverse = []byte("<forged@origin.example.test>")
	result, err := service.ReviseBatch(context.Background(), request)
	if err != nil || result.Result() == OperationPass || len(result.Outputs()) != 0 {
		t.Fatal("wrong incoming envelope accepted")
	}
}

// TestBatchRevisionInputBoundsAndRedaction rejects ambiguous plans without exposing protected input.
func TestBatchRevisionInputBoundsAndRedaction(t *testing.T) {
	_, _, original := newBatchRevisionFixture(t, signingFlagPolicy{})
	request := newBatchRevisionTestRequest(t, original, original, 2)
	for _, copies := range [][]BatchCopy{nil, request.state.copies[:1], {request.state.copies[1], request.state.copies[1]}} {
		if _, err := NewBatchRevisionRequest(strings.Repeat("a", 64), request.state.original, copies); err == nil {
			t.Fatal("invalid fanout accepted")
		}
	}
	for _, value := range []any{request, request.state.original, request.state.copies[1]} {
		if strings.Contains(fmt.Sprintf("%+v %#v", value, value), "sender@") {
			t.Fatal("protected bytes reached formatting")
		}
	}
}

// newBatchRevisionFixture signs a real inherited message with configurable authenticated originator requests.
func newBatchRevisionFixture(t *testing.T, policy signingFlagPolicy) (*SigningService, signingServiceFixture, []byte) {
	t.Helper()
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false, signingPolicies{originator: policy})
	if err != nil {
		t.Fatal("service construction failed")
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	raw := signingServiceRawMessage()
	request := newSigningServiceRequest(t, OperationSign, raw, [][]byte{[]byte("<recipient@origin.example.test>")})
	assessment, err := service.Sign(context.Background(), request)
	result, ok := assessment.Result()
	if err != nil || !ok || result.Result() != OperationPass {
		t.Fatal("originator fixture signing failed")
	}
	return service, fixture, insertSigningServiceFields(result.Fields(), raw)
}

// newBatchRevisionTestRequest constructs one actual local copy and distinct external prepared envelopes.
func newBatchRevisionTestRequest(t *testing.T, original, current []byte, external int) BatchRevisionRequest {
	t.Helper()
	incoming, err := NewBatchMessage(original, []byte("<sender@origin.example.test>"), [][]byte{[]byte("<recipient@origin.example.test>")}, FidelityRawRFC5322)
	if err != nil {
		t.Fatal("original fixture invalid")
	}
	local, err := NewBatchMessage(current, []byte("<sender@origin.example.test>"), [][]byte{[]byte("<local@origin.example.test>")}, FidelityRawRFC5322)
	if err != nil {
		t.Fatal("local fixture invalid")
	}
	branch, err := NewBatchCopy("local", true, local, "", "")
	if err != nil {
		t.Fatal("local copy invalid")
	}
	copies := []BatchCopy{branch}
	for index := range external {
		message, messageErr := NewBatchMessage(current, []byte(fmt.Sprintf("<prepared-%d@return.origin.example.test>", index)), [][]byte{[]byte(fmt.Sprintf("<private-%d@destination.example.test>", index))}, FidelityRawRFC5322)
		if messageErr != nil {
			t.Fatal("external fixture invalid")
		}
		branch, err = NewBatchCopy(fmt.Sprintf("external-%d", index), false, message, signingServiceTestTenant, signingServiceTransitDomain)
		if err != nil {
			t.Fatal("external copy invalid")
		}
		copies = append(copies, branch)
	}
	request, err := NewBatchRevisionRequest(strings.Repeat("a", 64), incoming, copies)
	if err != nil {
		t.Fatal("batch fixture invalid")
	}
	return request
}
