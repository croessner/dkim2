package verify

import (
	"time"

	"github.com/croessner/dkim2/internal/signature"
)

const maxRepresentableUnixSeconds = uint64(1<<63 - 1)

type timestampEvaluation struct {
	check CheckResult
	pass  bool
}

// checkTimestamps applies Draft-07 Section 14.3 to every DKIM2-Signature at
// the request's delivery reference instant, which defaults to the verifier
// clock: any signature older than 14 days or more than one day in the future
// makes the message invalid. The check reports the first offending signature
// in ascending i= order, or the selected target when every signature passes.
func (v Verifier) checkTimestamps(request Request, signatures []signature.Signature, target Target) timestampEvaluation {
	reference := v.referenceTime(request)
	status := TimestampStatusPass
	checkTarget := target
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil {
		// Sequence validity is enforced before this check; an unordered chain
		// here is ambiguous attribution and fails closed.
		status = TimestampStatusInvalid
		ordered = nil
	}
	for _, parsed := range ordered {
		if current := timestampStatusAt(reference, parsed.TimestampSeconds()); current != TimestampStatusPass {
			status = current
			checkTarget = Target{Sequence: parsed.Sequence(), InstanceNumber: parsed.InstanceNumber()}
			break
		}
	}
	checkStatus := CheckStatusFail
	code := ErrorCodeTimestampInvalid
	if status == TimestampStatusPass {
		checkStatus = CheckStatusPass
		code = ""
	}

	return timestampEvaluation{
		check: CheckResult{
			Kind:            CheckKindTimestamp,
			Status:          checkStatus,
			Code:            code,
			TimestampStatus: status,
			Target:          checkTarget,
		},
		pass: checkStatus == CheckStatusPass,
	}
}

// referenceTime returns the explicit request reference instant or the clock reading.
func (v Verifier) referenceTime(request Request) time.Time {
	if !request.ReferenceTime.IsZero() {
		return request.ReferenceTime
	}
	return v.options.Clock.Now()
}

// timestampStatusAt classifies one timestamp against an already captured
// reference instant with the fixed Draft-07 Section 14.3 windows.
func timestampStatusAt(now time.Time, seconds uint64) TimestampStatus {
	if seconds > maxRepresentableUnixSeconds {
		return TimestampStatusInvalid
	}

	timestamp := time.Unix(int64(seconds), 0)
	futureLimit, ok := safeAddDuration(now, signatureFutureTolerance)
	if !ok {
		return TimestampStatusInvalid
	}
	if timestamp.After(futureLimit) {
		return TimestampStatusFuture
	}
	if now.After(timestamp) && now.Sub(timestamp) > signatureMaxAge {
		return TimestampStatusExpired
	}

	return TimestampStatusPass
}

// safeAddDuration adds a duration while turning time overflow panics into failure.
func safeAddDuration(value time.Time, duration time.Duration) (result time.Time, ok bool) {
	defer func() {
		if recover() != nil {
			result = time.Time{}
			ok = false
		}
	}()

	return value.Add(duration), true
}
