package main

import (
	"errors"
	"testing"
)

// TestQualificationFailureStageIsClosedAndContentFree proves diagnostics expose
// only the fixed stage vocabulary and never arbitrary error content.
func TestQualificationFailureStageIsClosedAndContentFree(t *testing.T) {
	for _, want := range []qualificationStage{
		stageOriginValidation,
		stageDSNQueue,
		stageDSNCardinality,
		stageDSNCrypto,
	} {
		err := qualificationFailure(want)
		stage, ok := qualificationFailureStage(err)
		if !ok || stage != want || err.Error() != "qualification failed" {
			t.Fatalf("closed qualification failure = %q/%t/%q", stage, ok, err)
		}
	}
	if stage, ok := qualificationFailureStage(errors.New("toxic-private-marker")); ok || stage != "" {
		t.Fatalf("arbitrary error exposed as stage %q/%t", stage, ok)
	}
	forged := &qualificationStageError{stage: "future-private-marker"}
	if stage, ok := qualificationFailureStage(forged); ok || stage != "" {
		t.Fatalf("unrecognized stage exposed as %q/%t", stage, ok)
	}
}

// TestQueuedDSNDetectionDoesNotPrejudgeSignature proves queue discovery leaves
// signature cardinality and cryptographic validation to their owning checks.
func TestQueuedDSNDetectionDoesNotPrejudgeSignature(t *testing.T) {
	unsigned := []byte("Content-Type: multipart/report\r\n\r\nmessage/delivery-status\r\n")
	if !isDeliveryStatusReport(unsigned) {
		t.Fatal("unsigned delivery-status report was hidden from validation")
	}
	if isDeliveryStatusReport([]byte("Content-Type: text/plain\r\n\r\nbody\r\n")) {
		t.Fatal("ordinary message was classified as a delivery-status report")
	}
}
