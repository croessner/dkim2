package rotationadmin

import (
	"fmt"
	"io"

	"github.com/croessner/dkim2/admincontract"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

const redacted = "rotation_admin{redacted}"

// Limits bounds one campaign plan and preparation operation.
type Limits struct {
	MaxWorkItems       uint32
	MaxDNSBatchRecords uint32
	MaxDNSBatches      uint32
}

// DefaultLimits returns finite production campaign work bounds.
func DefaultLimits() Limits {
	return Limits{MaxWorkItems: 32768, MaxDNSBatchRecords: 256, MaxDNSBatches: 1024}
}

// Validate rejects zero or widened campaign work limits.
func (l Limits) Validate() error {
	if l.MaxWorkItems == 0 || l.MaxWorkItems > 131072 || l.MaxDNSBatchRecords == 0 ||
		l.MaxDNSBatchRecords > 4096 || l.MaxDNSBatches == 0 || l.MaxDNSBatches > 1024 {
		return errLimit
	}
	return nil
}

// Intent is one immutable protected campaign request.
type Intent struct {
	mode                   admincontract.Mode
	operation              datasourceadmin.OperationBinding
	operationValue         string
	emergencyReason        string
	rotationPolicyVersion  string
	dnsPolicyVersion       string
	retentionPolicyVersion string
	limitProfileVersion    string
	emergencyBinding       BindingSelector
}

// BindingSelector identifies one exact emergency policy binding.
type BindingSelector struct {
	Tenant  string
	Domain  string
	Use     string
	Profile string
}

// NewIntent validates one explicit normal or emergency campaign request.
func NewIntent(mode admincontract.Mode, operation, emergencyReason string) (Intent, error) {
	if mode != admincontract.ModeNormal || emergencyReason != "" {
		return Intent{}, errInvalid
	}
	return newIntent(mode, operation, emergencyReason, BindingSelector{})
}

// NewEmergencyIntent constructs one explicit one-binding emergency request.
func NewEmergencyIntent(operation, reason string, binding BindingSelector) (Intent, error) {
	if reason == "" || binding.Tenant == "" || binding.Domain == "" || binding.Use == "" || binding.Profile == "" {
		return Intent{}, errInvalid
	}
	return newIntent(admincontract.ModeEmergency, operation, reason, binding)
}

// newIntent owns common operation and policy-version initialization.
func newIntent(mode admincontract.Mode, operation, emergencyReason string, selector BindingSelector) (Intent, error) {
	operationBinding, err := datasourceadmin.NewOperationBinding(operation)
	if err != nil {
		return Intent{}, errInvalid
	}
	intent := Intent{
		mode: mode, operation: operationBinding, operationValue: operation, emergencyReason: emergencyReason, emergencyBinding: selector,
		rotationPolicyVersion: "rotation-v1", dnsPolicyVersion: "dns-v1",
		retentionPolicyVersion: "retention-v1", limitProfileVersion: "production-v1",
	}
	return intent, nil
}

// Mode returns the closed normal or emergency class.
func (i Intent) Mode() admincontract.Mode { return i.mode }

// String returns a constant protected intent representation.
func (Intent) String() string { return redacted }

// GoString returns a constant protected intent representation.
func (Intent) GoString() string { return redacted }

// Format prevents intent identities from reaching formatting sinks.
func (Intent) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects generic intent serialization.
func (Intent) MarshalJSON() ([]byte, error) { return nil, errInvalid }
