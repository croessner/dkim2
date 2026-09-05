package testclient

import (
	"encoding/json"
	"io"
	"slices"
)

const outputSchema = "dkim2ctl.result.v1"
const draftVersion = "draft-ietf-dkim-dkim2-spec-06"
const outcomeMatch = "match"
const outcomeMismatch = "mismatch"
const outcomeError = "error"
const errorClassInternal = "internal"

// ResultRecord is the exact stable JSONL projection for one executed case.
type ResultRecord struct {
	Schema              string  `json:"schema"`
	Draft               string  `json:"draft"`
	Fixture             *string `json:"fixture"`
	Case                *string `json:"case"`
	Operation           *string `json:"operation"`
	Outcome             string  `json:"outcome"`
	HTTPStatus          *int    `json:"http_status"`
	ErrorClass          *string `json:"error_class"`
	DurationBucket      *string `json:"duration_bucket"`
	Disposition         *string `json:"disposition"`
	VerificationState   *string `json:"verification_state"`
	AuthenticationState *string `json:"authentication_state"`
	PolicyVerdict       *string `json:"policy_verdict"`
	ReplayClass         *string `json:"replay_class"`
	// PropagationResult is the closed propagation-route operation result.
	PropagationResult *string `json:"propagation_result"`
	// PropagationDisposition is the closed propagation-route disposition.
	PropagationDisposition *string `json:"propagation_disposition"`
	// PropagationFailure is the closed permanent propagation failure reason.
	PropagationFailure *string `json:"propagation_failure"`
	// PropagationState is the closed committed-coordinate state.
	PropagationState *string `json:"propagation_state"`
	// PropagationDigest is the lowercase hexadecimal SHA-256 of the signed
	// notification. The notification bytes themselves never reach the output.
	PropagationDigest *string `json:"propagation_digest"`
	// DeliveryStatus is the closed received delivery-status projection.
	DeliveryStatus *ResultDeliveryStatus `json:"delivery_status"`
}

// ResultDeliveryStatus is the stable closed projection of the received
// delivery-status evaluation. Every member is a closed vocabulary value; no
// address, message byte, or identifier enters this record.
type ResultDeliveryStatus struct {
	Structure        string `json:"structure"`
	Embedded         string `json:"embedded"`
	OuterAlignment   string `json:"outer_alignment"`
	RecipientLinkage string `json:"recipient_linkage"`
	LocalHop         string `json:"local_hop"`
	Propagation      string `json:"propagation"`
}

// WriteFailure emits one content-free command-level failure record.
func WriteFailure(output io.Writer, class ExitClass) error {
	value := class.String()
	return writeRecord(output, ResultRecord{
		Schema: outputSchema, Draft: draftVersion, Outcome: outcomeError, ErrorClass: &value,
	})
}

// String returns the canonical decimal exit class.
func (c ExitClass) String() string {
	switch c {
	case ExitUsage:
		return "usage"
	case ExitFixture:
		return "fixture"
	case ExitCapability:
		return "capability"
	case ExitTransport:
		return "transport"
	case ExitContract:
		return "contract"
	case ExitMismatch:
		return outcomeMismatch
	case ExitInternal:
		return errorClassInternal
	default:
		return errorClassInternal
	}
}

// writeRecord emits exactly one compact JSON object followed by LF.
func writeRecord(output io.Writer, record ResultRecord) error {
	if output == nil || !validResultRecord(record) {
		return NewExitError(ExitInternal)
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(record); err != nil {
		return NewExitError(ExitInternal)
	}
	return nil
}

// validResultRecord enforces closed fields before any caller-controlled text is encoded.
func validResultRecord(record ResultRecord) bool {
	if record.Schema != outputSchema || record.Draft != draftVersion ||
		!validOutcome(record.Outcome) ||
		(record.Fixture != nil && !validIdentifier(*record.Fixture)) ||
		(record.Case != nil && !validIdentifier(*record.Case)) ||
		(record.Operation != nil && !validOutputOperation(*record.Operation)) ||
		(record.HTTPStatus != nil && (*record.HTTPStatus < 100 || *record.HTTPStatus > 599)) ||
		(record.ErrorClass != nil && !validErrorClass(*record.ErrorClass)) ||
		(record.DurationBucket != nil && !validDurationBucket(*record.DurationBucket)) {
		return false
	}
	if record.PropagationDigest != nil && !validNotificationDigest(*record.PropagationDigest) {
		return false
	}
	if record.DeliveryStatus != nil && !validDeliveryStatusExpectation(
		fixtureDeliveryStatus(*record.DeliveryStatus),
	) {
		return false
	}
	if !validOptionalEnum(record.PropagationResult, "pass", "fail", "permerror", "temperror") ||
		!validOptionalEnum(record.PropagationDisposition,
			"accept", "discard", "reject", "tempfail") ||
		!validOptionalEnum(record.PropagationFailure,
			"not_reconstructable", "unprovisioned_domain") ||
		!validOptionalEnum(record.PropagationState, "committed") {
		return false
	}
	return validOptionalEnum(record.Disposition, "accept", "reject", "tempfail", "continue") &&
		validOptionalEnum(record.VerificationState, "PASS", "FAIL", "PERMERROR", "TEMPERROR") &&
		validOptionalEnum(record.AuthenticationState, "PASS", "FAIL", "PERMERROR", "TEMPERROR") &&
		validOptionalEnum(record.PolicyVerdict, "accept", "reject", "tempfail", "continue") &&
		validOptionalEnum(record.ReplayClass,
			"not_checked", "disabled", "first_seen", "exploded", "replayed", "indeterminate")
}

// validDurationBucket checks the exact bounded timing vocabulary.
func validDurationBucket(value string) bool {
	switch value {
	case durationUnder100, durationUnder1S, durationUnder10S, durationAtLeast:
		return true
	default:
		return false
	}
}

// validOutcome checks the exact stable result vocabulary.
func validOutcome(value string) bool {
	return value == outcomeMatch || value == outcomeMismatch || value == outcomeError
}

// validOutputOperation checks the exact command and case operation vocabulary.
func validOutputOperation(value string) bool {
	switch value {
	case "validate", "smoke", caseHealth, caseReadiness, caseProcess,
		caseSign, caseRevise, caseDSNSign, caseDSNPropagate, caseDSNPropagateCommit,
		caseNegative:
		return true
	default:
		return false
	}
}

// validErrorClass checks the exact stable error-class vocabulary.
func validErrorClass(value string) bool {
	switch value {
	case "usage", "fixture", "capability", "transport", "contract",
		outcomeMismatch, errorClassInternal:
		return true
	default:
		return false
	}
}

// validOptionalEnum checks one optional pointer against a short closed vocabulary.
func validOptionalEnum(value *string, allowed ...string) bool {
	if value == nil {
		return true
	}
	return slices.Contains(allowed, *value)
}
