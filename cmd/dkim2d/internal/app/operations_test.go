package app

import "testing"

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
