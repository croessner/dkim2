package dkim2

import (
	"testing"

	"github.com/croessner/dkim2/internal/service"
)

// TestPublicAdaptersCoverClosedServiceVocabularies verifies one-to-one public DTO tokens.
func TestPublicAdaptersCoverClosedServiceVocabularies(t *testing.T) {
	states := []service.State{service.StatePASS, service.StateFAIL, service.StatePERMERROR, service.StateTEMPERROR}
	for _, state := range states {
		mapped, ok := adaptState(state)
		if !ok || string(mapped) != string(state) {
			t.Fatalf("state %q mapped to %q/%t", state, mapped, ok)
		}
	}
	custodyValues := []service.Custody{
		service.CustodyNotEvaluated, service.CustodyNotPresent,
		service.CustodyNDLinksEvaluated, service.CustodyTerminalNDRequiresOOB,
	}
	for _, custody := range custodyValues {
		mapped, ok := adaptCustody(custody)
		if !ok || string(mapped) != string(custody) {
			t.Fatalf("custody %q mapped to %q/%t", custody, mapped, ok)
		}
	}
	if _, ok := adaptState(service.State("future")); ok {
		t.Fatal("unknown state was accepted")
	}
	if _, ok := adaptCustody(service.Custody("future")); ok {
		t.Fatal("unknown custody was accepted")
	}
	checks := []service.CheckClass{service.CheckMessage, service.CheckProtocol, service.CheckBodyHash, service.CheckHeaderHash, service.CheckSignature, service.CheckKey, service.CheckTimestamp, service.CheckEnvelope, service.CheckDomainAlignment, service.CheckNextDomain, service.CheckProvider, service.CheckInternalContract}
	for _, check := range checks {
		if mapped, ok := adaptCheckClass(check); !ok || string(mapped) != string(check) {
			t.Fatalf("check %q mapped to %q/%t", check, mapped, ok)
		}
	}
	reasons := []service.Reason{service.ReasonNone, service.ReasonInvalidRequest, service.ReasonLimitExceeded, service.ReasonMalformedMessage, service.ReasonMalformedProtocol, service.ReasonMissingProtocol, service.ReasonSequenceInvalid, service.ReasonUnsupportedAlgorithm, service.ReasonHashMismatch, service.ReasonSignatureMismatch, service.ReasonMissingKey, service.ReasonInvalidKey, service.ReasonAmbiguousKey, service.ReasonRevokedKey, service.ReasonUnsupportedKeyType, service.ReasonKeyAlgorithmMismatch, service.ReasonProviderTemporary, service.ReasonProviderPermanent, service.ReasonProviderContract, service.ReasonTimestampInvalid, service.ReasonEnvelopeMismatch, service.ReasonDomainAlignmentMismatch, service.ReasonNextDomainMismatch, service.ReasonOutOfBandRequired, service.ReasonInternalContract}
	for _, reason := range reasons {
		if mapped, ok := adaptReason(reason); !ok || string(mapped) != string(reason) {
			t.Fatalf("reason %q mapped to %q/%t", reason, mapped, ok)
		}
	}
	for _, algorithm := range []service.Algorithm{service.AlgorithmRSASHA256, service.AlgorithmEd25519SHA256, service.AlgorithmUnknown} {
		if mapped, ok := adaptAlgorithm(algorithm); !ok || string(mapped) != string(algorithm) {
			t.Fatalf("algorithm %q mapped to %q/%t", algorithm, mapped, ok)
		}
	}
	for _, status := range []service.SignatureStatus{service.SignaturePASS, service.SignatureFAIL, service.SignaturePERMERROR, service.SignatureTEMPERROR, service.SignatureIgnored} {
		if mapped, ok := adaptSignatureStatus(status); !ok || string(mapped) != string(status) {
			t.Fatalf("signature status %q mapped to %q/%t", status, mapped, ok)
		}
	}
	if _, ok := adaptCheckClass(service.CheckClass("future")); ok {
		t.Fatal("unknown check class accepted")
	}
	if _, ok := adaptReason(service.Reason("future")); ok {
		t.Fatal("unknown reason accepted")
	}
	if _, ok := adaptAlgorithm(service.Algorithm("future")); ok {
		t.Fatal("unknown algorithm accepted")
	}
	if _, ok := adaptSignatureStatus(service.SignatureStatus("future")); ok {
		t.Fatal("unknown signature status accepted")
	}
}
