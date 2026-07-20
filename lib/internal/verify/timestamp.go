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

// checkTimestamp applies local timestamp policy to the selected signature.
func (v Verifier) checkTimestamp(targetSignature signature.Signature, target Target) timestampEvaluation {
	status := v.timestampStatus(targetSignature.TimestampSeconds())
	checkStatus := CheckStatusFail
	code := ErrorCodeTimestampInvalid
	if status == TimestampStatusPass || status == TimestampStatusNoMaxAge {
		checkStatus = CheckStatusPass
		code = ""
	}

	return timestampEvaluation{
		check: CheckResult{
			Kind:            CheckKindTimestamp,
			Status:          checkStatus,
			Code:            code,
			TimestampStatus: status,
			Target:          target,
		},
		pass: checkStatus == CheckStatusPass,
	}
}

// timestampStatus classifies t= seconds using deterministic verifier policy.
func (v Verifier) timestampStatus(seconds uint64) TimestampStatus {
	return timestampStatusAt(v.options.Clock.Now(), seconds, v.options.TimestampPolicy)
}

// timestampStatusAt classifies one timestamp against an already captured clock.
func timestampStatusAt(now time.Time, seconds uint64, policy TimestampPolicy) TimestampStatus {
	if seconds > maxRepresentableUnixSeconds {
		return TimestampStatusInvalid
	}

	timestamp := time.Unix(int64(seconds), 0)
	futureLimit, ok := safeAddDuration(now, policy.FutureTolerance)
	if !ok {
		return TimestampStatusInvalid
	}
	if timestamp.After(futureLimit) {
		return TimestampStatusFuture
	}
	if policy.MaxAge <= 0 {
		return TimestampStatusNoMaxAge
	}
	if now.After(timestamp) && now.Sub(timestamp) > policy.MaxAge {
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
