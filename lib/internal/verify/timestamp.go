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
	if seconds > maxRepresentableUnixSeconds {
		return TimestampStatusInvalid
	}

	timestamp := time.Unix(int64(seconds), 0)
	now := v.options.Clock.Now()
	futureLimit, ok := safeAddDuration(now, v.options.TimestampPolicy.FutureTolerance)
	if !ok {
		return TimestampStatusInvalid
	}
	if timestamp.After(futureLimit) {
		return TimestampStatusFuture
	}
	if v.options.TimestampPolicy.MaxAge <= 0 {
		return TimestampStatusNoMaxAge
	}
	if now.After(timestamp) && now.Sub(timestamp) > v.options.TimestampPolicy.MaxAge {
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
