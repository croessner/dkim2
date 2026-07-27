// Package resource owns shared adapter transport and allocation limits.
package resource

const (
	// DaemonResponseBytes is the maximum admitted daemon HTTP response body.
	DaemonResponseBytes int64 = 4 << 20
	// MilterActionFrameBytes is the maximum encoded size of one action frame.
	MilterActionFrameBytes int64 = 65536
	// MilterActionAggregateBytes bounds all action frames from one daemon result.
	MilterActionAggregateBytes int64 = 3 * MilterActionFrameBytes
	// EnvelopePathBytes bounds one preserved SMTP reverse or recipient path.
	EnvelopePathBytes int64 = 256
	// RetainedMessageCopyCount covers collection capacity and raw reconstruction.
	RetainedMessageCopyCount int64 = 2
	// EOMRequestCopyCount covers raw, Base64, protected scalar, JSON, and HTTP copies.
	EOMRequestCopyCount int64 = 5
	// DaemonResponseCopyCount bounds the body, generated and strict DTOs,
	// structural validation copies, and the final adapter result.
	DaemonResponseCopyCount int64 = 7
	// EOMResponseWorkingSetBytes covers daemon response processing and Milter
	// action serialization until the complete terminal reply has been written.
	EOMResponseWorkingSetBytes int64 = DaemonResponseCopyCount*DaemonResponseBytes +
		MilterActionAggregateBytes
	// MinimumBufferedBytes admits the fixed response working set plus bounded
	// request and retained-message accounting for at least one small message.
	MinimumBufferedBytes int64 = 32 << 20
)

// MaximumEOMWorkingSetBytes returns the complete aggregate reservation needed
// to carry one configured maximum message and envelope through its final write.
func MaximumEOMWorkingSetBytes(messageBytes int64, recipientCount int) (int64, bool) {
	if messageBytes < 1 || recipientCount < 1 {
		return 0, false
	}
	envelopeBytes, ok := checkedMultiply(
		int64(recipientCount)+1,
		EnvelopePathBytes,
	)
	if !ok {
		return 0, false
	}
	requestInputBytes, ok := checkedAdd(messageBytes, envelopeBytes)
	if !ok {
		return 0, false
	}
	retainedBytes, ok := checkedMultiply(messageBytes, RetainedMessageCopyCount)
	if !ok {
		return 0, false
	}
	retainedBytes, ok = checkedAdd(retainedBytes, envelopeBytes)
	if !ok {
		return 0, false
	}
	requestBytes, ok := checkedMultiply(requestInputBytes, EOMRequestCopyCount)
	if !ok {
		return 0, false
	}
	workingBytes, ok := checkedAdd(retainedBytes, requestBytes)
	if !ok {
		return 0, false
	}
	return checkedAdd(workingBytes, EOMResponseWorkingSetBytes)
}

// checkedAdd adds two non-negative byte counts without signed overflow.
func checkedAdd(left, right int64) (int64, bool) {
	const maximumInt64 = int64(^uint64(0) >> 1)
	if left < 0 || right < 0 || left > maximumInt64-right {
		return 0, false
	}
	return left + right, true
}

// checkedMultiply multiplies two non-negative byte counts without signed overflow.
func checkedMultiply(left, right int64) (int64, bool) {
	const maximumInt64 = int64(^uint64(0) >> 1)
	if left < 0 || right < 0 || left != 0 && right > maximumInt64/left {
		return 0, false
	}
	return left * right, true
}
