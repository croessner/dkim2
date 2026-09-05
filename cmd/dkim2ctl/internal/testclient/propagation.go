package testclient

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode/utf8"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/wire"
)

const (
	// maxCommitTokenBytes bounds the opaque coordinate token the contract admits.
	maxCommitTokenBytes = 512
	// minCommitTokenBytes bounds the opaque coordinate token from below.
	minCommitTokenBytes = 16
	// maxNotificationBytes bounds one signed notification the route may return.
	maxNotificationBytes = 1024 * 1024
)

// validDSNPropagate validates one complete propagation response, including the
// route-specific coherence between result, disposition, and the conditional
// members. Every ambiguous or contradictory combination fails closed.
func validDSNPropagate(value generated.DSNPropagateResponse) bool {
	if value.ApiVersion != generated.V1 ||
		value.Draft != generated.DraftIetfDkimDkim2Spec06 ||
		value.Operation != generated.PropagationOperationDeliveryStatusPropagation ||
		!value.Result.Valid() || !value.Disposition.Valid() ||
		!value.Replay.Class.Valid() ||
		!validPropagationOutcome(value.Result, value.Disposition) {
		return false
	}
	if (value.Propagation != nil) != (value.Disposition == generated.PropagationDispositionAccept) {
		return false
	}
	if (value.PropagationFailure != nil) !=
		(value.Result == generated.PropagationResultPermerror) {
		return false
	}
	if value.PropagationFailure != nil && !value.PropagationFailure.Valid() {
		return false
	}
	if value.Propagation != nil && !validPropagationOutput(*value.Propagation) {
		return false
	}
	return validDeliveryStatusProjection(value.DeliveryStatus)
}

// validPropagationOutcome enforces the route's own result and disposition rule:
// pass permits accept or discard, permerror requires discard, fail requires
// reject, and temperror requires tempfail.
func validPropagationOutcome(
	result generated.DSNPropagateResponseResult,
	disposition generated.PropagationDisposition,
) bool {
	switch result {
	case generated.PropagationResultPass:
		return disposition == generated.PropagationDispositionAccept ||
			disposition == generated.PropagationDispositionDiscard
	case generated.PropagationResultPermerror:
		return disposition == generated.PropagationDispositionDiscard
	case generated.PropagationResultFail:
		return disposition == generated.PropagationDispositionReject
	case generated.PropagationResultTemperror:
		return disposition == generated.PropagationDispositionTempfail
	default:
		return false
	}
}

// validPropagationOutput validates the bounded re-injection evidence without
// interpreting the notification bytes it carries.
func validPropagationOutput(value generated.PropagationOutput) bool {
	notification, ok := protectedValue(value.RawRfc5322Base64)
	if !ok || len(notification) == 0 || len(notification) > maxNotificationBytes {
		return false
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(notification); err != nil {
		return false
	}
	recipient, ok := protectedValue(value.NextHopRecipient)
	if !ok || len(recipient) < 3 || len(recipient) > maxEnvelopeText ||
		!utf8.ValidString(recipient) || !strings.HasPrefix(recipient, "<") ||
		!strings.HasSuffix(recipient, ">") || strings.ContainsAny(recipient, "\r\n\x00") {
		return false
	}
	token, ok := protectedValue(value.CommitToken)
	return ok && validCommitTokenText(token)
}

// validCommitTokenText checks the bounded opaque coordinate token shape without
// attributing any caller-readable structure to its content.
func validCommitTokenText(value string) bool {
	if len(value) < minCommitTokenBytes || len(value) > maxCommitTokenBytes {
		return false
	}
	for _, current := range []byte(value) {
		if (current < 'a' || current > 'z') && (current < 'A' || current > 'Z') &&
			(current < '0' || current > '9') && current != '-' && current != '_' {
			return false
		}
	}
	return true
}

// protectedValue reads one protected wire value without exposing it in errors.
func protectedValue(value wire.ProtectedString) (string, bool) {
	raw, err := value.Bytes()
	if err != nil {
		return "", false
	}
	return string(raw), true
}

// validDSNPropagateCommit validates the complete coordinate commit response.
func validDSNPropagateCommit(value generated.DSNPropagateCommitResponse) bool {
	return value.ApiVersion == generated.V1 &&
		value.Draft == generated.DraftIetfDkimDkim2Spec06 &&
		value.State == generated.PropagationStateCommitted
}

// validDeliveryStatusProjection validates the optional received delivery-status
// projection. Every one of its six members is a closed vocabulary, so an
// unknown value is contract drift rather than a tolerated extension.
func validDeliveryStatusProjection(value *generated.DeliveryStatusProjection) bool {
	if value == nil {
		return true
	}
	return value.Structure.Valid() && value.Embedded.Valid() &&
		value.OuterAlignment.Valid() && value.RecipientLinkage.Valid() &&
		value.LocalHop.Valid() && value.Propagation.Valid()
}

// notificationDigest reduces the signed notification bytes to one stable
// lowercase hexadecimal SHA-256 value. The projection records this digest so
// that a fixture can freeze the exact produced notification without any
// notification byte, address, or header reaching command output.
func notificationDigest(value wire.ProtectedString) (string, bool) {
	encoded, ok := protectedValue(value)
	if !ok {
		return "", false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(decoded)
	return hex.EncodeToString(sum[:]), true
}

// validNotificationDigest checks one lowercase hexadecimal SHA-256 projection.
func validNotificationDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, current := range []byte(value) {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}
