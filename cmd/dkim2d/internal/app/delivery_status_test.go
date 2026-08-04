package app

import (
	"bytes"
	"context"
	"testing"
	"time"
)

type deliveryStatusAcquireSpy struct{ calls int }

// Acquire records forbidden profile access from an invalid DSN evidence request.
func (s *deliveryStatusAcquireSpy) Acquire(context.Context) (signingLease, error) {
	s.calls++
	return nil, &DomainError{}
}

// TestNewDeliveryStatusRequestRejectsUntrustedShapes proves the dedicated
// daemon request cannot be used as a generic null-sender signing wrapper.
func TestNewDeliveryStatusRequestRejectsUntrustedShapes(t *testing.T) {
	validOuterRecipient := [][]byte{[]byte("<postmaster@example.test>")}
	validOriginalRecipient := [][]byte{[]byte("<bob@example.test>")}
	valid := func() (DeliveryStatusRequest, error) {
		return NewDeliveryStatusRequest(
			[]byte("From: postmaster@example.test\r\n\r\n"),
			[]byte("<>"),
			validOuterRecipient,
			[]byte("<alice@example.test>"),
			validOriginalRecipient,
			"tenant-a",
			"example.test",
			FidelityRawRFC5322,
		)
	}
	request, err := valid()
	if err != nil {
		t.Fatalf("NewDeliveryStatusRequest() error = %v", err)
	}
	if !bytes.Equal(request.OuterReversePath(), []byte("<>")) || len(request.OuterRecipients()) != 1 {
		t.Fatal("valid request did not retain exact outer DSN envelope")
	}
	for _, testCase := range []struct {
		name   string
		mutate func() (DeliveryStatusRequest, error)
	}{
		{
			name: "non-null outer reverse path",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewDeliveryStatusRequest([]byte("x"), []byte("<sender@example.test>"), validOuterRecipient, []byte("<alice@example.test>"), validOriginalRecipient, "tenant-a", "example.test", FidelityRawRFC5322)
			},
		},
		{
			name: "multiple outer recipients",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewDeliveryStatusRequest([]byte("x"), []byte("<>"), [][]byte{[]byte("<one@example.test>"), []byte("<two@example.test>")}, []byte("<alice@example.test>"), validOriginalRecipient, "tenant-a", "example.test", FidelityRawRFC5322)
			},
		},
		{
			name: "missing original recipients",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewDeliveryStatusRequest([]byte("x"), []byte("<>"), validOuterRecipient, []byte("<alice@example.test>"), nil, "tenant-a", "example.test", FidelityRawRFC5322)
			},
		},
		{
			name: "non-raw fidelity",
			mutate: func() (DeliveryStatusRequest, error) {
				return NewDeliveryStatusRequest([]byte("x"), []byte("<>"), validOuterRecipient, []byte("<alice@example.test>"), validOriginalRecipient, "tenant-a", "example.test", FidelityMilterReconstructedCRLF)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := testCase.mutate(); err == nil {
				t.Fatal("NewDeliveryStatusRequest() accepted unsafe request")
			}
		})
	}
}

// TestSigningServiceRejectsInvalidDSNBeforePolicyAccess proves malformed DSN
// bytes cannot probe a delivery-status profile or private-key source.
func TestSigningServiceRejectsInvalidDSNBeforePolicyAccess(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	spy := &deliveryStatusAcquireSpy{}
	service := &SigningService{
		publicKeys: fixture.publicKeys,
		store:      spy,
		clock:      time.Now,
	}
	request, err := NewDeliveryStatusRequest(
		[]byte("From: postmaster@example.test\r\n\r\nnot a DSN\r\n"),
		[]byte("<>"),
		[][]byte{[]byte("<alice@example.test>")},
		[]byte("<alice@example.test>"),
		[][]byte{[]byte("<bob@example.test>")},
		"tenant-a",
		"example.test",
		FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignDeliveryStatus(context.Background(), request)
	if err != nil || !result.Valid() || result.Result() != OperationPermerror ||
		result.Disposition() != OperationReject || spy.calls != 0 {
		t.Fatalf(
			"SignDeliveryStatus() result=%v error=%v policy_calls=%d",
			result, err, spy.calls,
		)
	}
}

// TestSigningServiceSignsAuthenticatedDeliveryStatus proves the daemon uses a
// real delivery-status policy only after exact embedded evidence succeeds.
func TestSigningServiceSignsAuthenticatedDeliveryStatus(t *testing.T) {
	fixture := newSigningServiceFixture(t)
	service, err := NewSigningService(fixture.publicKeys, fixture.runtime, false)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }
	originalRaw := signingServiceRawMessage()
	originalRecipients := [][]byte{[]byte("<recipient@origin.example.test>")}
	originalRequest := newSigningServiceRequest(t, OperationSign, originalRaw, originalRecipients)
	originalAssessment, err := service.Sign(context.Background(), originalRequest)
	if err != nil {
		t.Fatal(err)
	}
	original, applicable := originalAssessment.Result()
	if !applicable {
		t.Fatal("originator signing was not applicable")
	}
	assertSigningServicePass(t, original, nil, signingServiceOriginSelector)
	embedded := insertSigningServiceFields(original.Fields(), originalRaw)
	outer := []byte("From: postmaster@origin.example.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\nhuman\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; origin.example.test\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(embedded) + "\r\n--dsn--\r\n")
	request, err := NewDeliveryStatusRequest(
		outer,
		[]byte("<>"),
		[][]byte{[]byte("<sender@origin.example.test>")},
		originalRequest.ReversePath(),
		originalRequest.Recipients(),
		signingServiceTestTenant,
		signingServiceOriginDomain,
		FidelityRawRFC5322,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.SignDeliveryStatus(context.Background(), request)
	assertSigningServicePass(t, result, err, signingServiceDSNSelector)
}
