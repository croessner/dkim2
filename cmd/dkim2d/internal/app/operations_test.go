package app

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestSigningAssessmentRejectsDiagnosticTraversal proves the applicability
// wrapper cannot expose generated signing fields through formatting or encoding.
func TestSigningAssessmentRejectsDiagnosticTraversal(t *testing.T) {
	t.Parallel()
	const marker = "PRIVATE-SIGNING-ASSESSMENT-FIELD"
	fieldBytes := []byte("DKIM2-Signature: b=" + marker + "\r\n")
	field, err := NewCompletedField(fieldBytes)
	if err != nil {
		t.Fatal("protected completed field rejected")
	}
	result, err := NewOperationResult(
		OperationSign,
		OperationPass,
		OperationAccept,
		[]CompletedField{field},
	)
	if err != nil {
		t.Fatal("protected operation result rejected")
	}
	assessment, err := NewApplicableSigningAssessment(result)
	if err != nil {
		t.Fatal("protected signing assessment rejected")
	}

	formatted := fmt.Sprintf(
		"%s|%q|%v|%+v|%#v|%x|%X|%p",
		assessment, assessment, assessment, assessment,
		assessment, assessment, assessment, &assessment,
	)
	if strings.Contains(formatted, marker) ||
		strings.Contains(formatted, hex.EncodeToString(fieldBytes)) ||
		strings.Contains(formatted, strings.ToUpper(hex.EncodeToString(fieldBytes))) ||
		!strings.Contains(formatted, operationRedacted) {
		t.Fatal("signing assessment formatting traversed protected result state")
	}

	textMarshaler, ok := any(assessment).(interface {
		MarshalText() ([]byte, error)
	})
	if !ok {
		t.Fatal("signing assessment does not reject text serialization")
	}
	if encoded, marshalErr := textMarshaler.MarshalText(); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("signing assessment allowed text serialization")
	}
	if encoded, marshalErr := json.Marshal(assessment); marshalErr == nil || len(encoded) != 0 {
		t.Fatal("signing assessment allowed JSON serialization")
	}
}

// TestOriginatorConstructorRejectsRevisionWithoutIncomingEvidence proves a
// revision cannot enter the service through the single-envelope constructor.
func TestOriginatorConstructorRejectsRevisionWithoutIncomingEvidence(t *testing.T) {
	if _, err := NewOperationRequest(
		OperationRevise,
		[]byte("From: sender@example.test\r\n\r\nbody\r\n"),
		[]byte("<sender@example.test>"),
		[][]byte{[]byte("<recipient@example.net>")},
		"tenant-a",
		"example.test",
		FidelityRawRFC5322,
	); err == nil {
		t.Fatal("single-envelope revision request constructed")
	}
}

// TestEximFidelityCompatibilityRejectsCrossRouteEvidence proves exact route ownership.
func TestEximFidelityCompatibilityRejectsCrossRouteEvidence(t *testing.T) {
	if !AdmitsProcessFidelity(FidelityEximLocalScanObservedCRLF) ||
		AdmitsProcessFidelity(FidelityEximTransportFilterCRLF) ||
		!AdmitsOperationFidelity(OperationSign, FidelityEximTransportFilterCRLF) ||
		!AdmitsOperationFidelity(OperationRevise, FidelityEximTransportFilterCRLF) ||
		AdmitsOperationFidelity(OperationSign, FidelityEximLocalScanObservedCRLF) {
		t.Fatal("Exim fidelity route compatibility drifted")
	}
	if _, err := NewOperationRequest(
		OperationSign,
		[]byte("From: sender@example.test\r\n\r\nbody\r\n"),
		[]byte("<sender@example.test>"),
		[][]byte{[]byte("<recipient@example.net>")},
		"tenant-a", "example.test", FidelityEximTransportFilterCRLF,
	); err != nil {
		t.Fatal("Exim transport-filter sign fidelity was rejected")
	}
}

// TestPostfixDSNFidelityIsConfinedToDeliveryStatus proves a qualified null-
// sender representation cannot cross into process, sign, or revision routes.
func TestPostfixDSNFidelityIsConfinedToDeliveryStatus(t *testing.T) {
	fidelity := FidelityPostfixDSNMilterReconstructedCRLF
	if AdmitsProcessFidelity(fidelity) ||
		AdmitsOperationFidelity(OperationSign, fidelity) ||
		AdmitsOperationFidelity(OperationRevise, fidelity) ||
		!AdmitsDeliveryStatusFidelity(fidelity) {
		t.Fatal("Postfix DSN fidelity route confinement drifted")
	}
}
