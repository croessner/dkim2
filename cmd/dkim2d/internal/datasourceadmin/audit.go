package datasourceadmin

import (
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/croessner/dkim2/admincontract"
)

// AuditLog retains a finite compact set of key-free purge receipts.
type AuditLog struct {
	maximum  uint32
	receipts []admincontract.AuditReceipt
}

// NewAuditLog creates a finite receipt owner without any snapshot or identity storage.
func NewAuditLog(maximum uint32) (*AuditLog, error) {
	if maximum == 0 || maximum > maxRetentionInventory {
		return nil, newError(CodeInvalid)
	}
	return &AuditLog{maximum: maximum}, nil
}

// Append validates and retains one compact completed destruction receipt.
func (l *AuditLog) Append(receipt admincontract.AuditReceipt) error {
	if l == nil {
		return newError(CodeInvalid)
	}
	if _, err := admincontract.AuditCommitment(receipt); err != nil {
		return newError(CodeInvalid)
	}
	l.receipts = append(l.receipts, receipt)
	slices.SortFunc(l.receipts, compareAuditReceipts)
	if len(l.receipts) > int(l.maximum) {
		clear(l.receipts[:len(l.receipts)-int(l.maximum)])
		l.receipts = append([]admincontract.AuditReceipt(nil), l.receipts[len(l.receipts)-int(l.maximum):]...)
	}
	return nil
}

// Count returns the finite retained receipt count.
func (l *AuditLog) Count() uint32 {
	if l == nil {
		return 0
	}
	return uint32(len(l.receipts))
}

// Commitments returns detached key-free receipt commitments in stable retention order.
func (l *AuditLog) Commitments() ([]admincontract.Digest, error) {
	if l == nil {
		return nil, newError(CodeInvalid)
	}
	result := make([]admincontract.Digest, 0, len(l.receipts))
	for _, receipt := range l.receipts {
		commitment, err := admincontract.AuditCommitment(receipt)
		if err != nil {
			return nil, newError(CodeConflict)
		}
		result = append(result, commitment)
	}
	return result, nil
}

// Close erases the finite audit receipt cache.
func (l *AuditLog) Close() error {
	if l == nil {
		return nil
	}
	clear(l.receipts)
	l.receipts = nil
	l.maximum = 0
	return nil
}

// String prevents receipt metadata from becoming generic output.
func (*AuditLog) String() string { return redacted }

// GoString prevents receipt metadata from becoming generic output.
func (*AuditLog) GoString() string { return redacted }

// Format prevents receipt metadata from becoming generic output.
func (*AuditLog) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic audit serialization.
func (*AuditLog) MarshalJSON() ([]byte, error) { return nil, newError(CodeInvalid) }

// compareAuditReceipts orders old receipts first for deterministic finite eviction.
func compareAuditReceipts(left, right admincontract.AuditReceipt) int {
	if left.DestroyedAt.Before(right.DestroyedAt) {
		return -1
	}
	if left.DestroyedAt.After(right.DestroyedAt) {
		return 1
	}
	if left.Generation < right.Generation {
		return -1
	}
	if left.Generation > right.Generation {
		return 1
	}
	return 0
}

// NewAuditReceipt validates one compact result using only safe target metadata.
func NewAuditReceipt(target admincontract.PurgeTarget, operationClass string, destroyedAt time.Time, policyVersion string, purgePlan admincontract.Digest) (admincontract.AuditReceipt, error) {
	receipt := admincontract.AuditReceipt{Version: admincontract.ContractVersion, Generation: target.Generation, Schema: target.Schema,
		Lifecycle: target.Lifecycle, OperationClass: operationClass, ContentDigest: target.ContentDigest, DestroyedAt: destroyedAt,
		Result: "purged", PolicyVersion: policyVersion, PurgePlanDigest: purgePlan}
	if _, err := admincontract.AuditCommitment(receipt); err != nil {
		return admincontract.AuditReceipt{}, newError(CodeInvalid)
	}
	return receipt, nil
}
