package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
)

const (
	// MaxBatchRevisionCopies bounds one complete fanout at the service boundary.
	MaxBatchRevisionCopies = 32
	// MaxBatchRevisionMessageBytes bounds the aggregate decoded message snapshots.
	MaxBatchRevisionMessageBytes = 32 << 20
	batchRevisionRedacted        = "dkim2d_batch_revision{redacted}"
)

// BatchMessage freezes one exact message representation and SMTP envelope.
type BatchMessage struct {
	state *batchMessageState
}

type batchMessageState struct {
	raw, reverse []byte
	recipients   [][]byte
	fidelity     MessageFidelity
}

// NewBatchMessage snapshots complete RFC5322 bytes with an explicit fidelity.
func NewBatchMessage(raw, reverse []byte, recipients [][]byte, fidelity MessageFidelity) (BatchMessage, error) {
	if len(raw) == 0 || len(raw) > MaxBatchRevisionMessageBytes ||
		!bytes.Contains(raw, []byte("\r\n\r\n")) || len(reverse) < 2 ||
		len(recipients) == 0 || len(recipients) > 2000 ||
		(!AdmitsProcessFidelity(fidelity) && !AdmitsOperationFidelity(OperationRevise, fidelity)) {
		return BatchMessage{}, &DomainError{}
	}
	return BatchMessage{state: &batchMessageState{
		raw: bytes.Clone(raw), reverse: bytes.Clone(reverse),
		recipients: cloneOperationRecipients(recipients), fidelity: fidelity,
	}}, nil
}

// Valid reports whether the message owns a constructor-validated snapshot.
func (m BatchMessage) Valid() bool { return m.state != nil }

// RawSize reports the bounded decoded message length without exposing content.
func (m BatchMessage) RawSize() int {
	if !m.Valid() {
		return 0
	}
	return len(m.state.raw)
}

// Format prevents diagnostic traversal of raw message or envelope data.
func (BatchMessage) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, batchRevisionRedacted)
}

// BatchCopy freezes one actual local or external delivery in the complete fanout.
type BatchCopy struct {
	id             string
	local          bool
	message        BatchMessage
	tenant, domain string
	via            *batchRevisionHop
}

type batchRevisionHop struct {
	reverse        []byte
	recipients     [][]byte
	tenant, domain string
}

// WithVia snapshots one explicit same-tenant controlled hop without adding another actual copy.
func (c BatchCopy) WithVia(reverse []byte, recipients [][]byte, tenant, domain string) (BatchCopy, error) {
	if !c.message.Valid() || c.local || c.via != nil || len(reverse) < 3 || bytes.Equal(reverse, []byte("<>")) ||
		len(recipients) != 1 || tenant != c.tenant || domain == "" {
		return BatchCopy{}, &DomainError{}
	}
	c.via = &batchRevisionHop{reverse: bytes.Clone(reverse), recipients: cloneOperationRecipients(recipients), tenant: tenant, domain: domain}
	return c, nil
}

// NewBatchCopy requires one recipient and an exact signing context only for external copies.
func NewBatchCopy(id string, local bool, message BatchMessage, tenant, domain string) (BatchCopy, error) {
	if !ValidBatchCopyID(id) || !message.Valid() || len(message.state.recipients) != 1 ||
		local && (tenant != "" || domain != "") ||
		!local && (tenant == "" || domain == "" || !AdmitsOperationFidelity(OperationRevise, message.state.fidelity)) {
		return BatchCopy{}, &DomainError{}
	}
	return BatchCopy{id: id, local: local, message: message, tenant: tenant, domain: domain}, nil
}

// ValidBatchCopyID accepts opaque bounded identifiers without whitespace or addresses.
func ValidBatchCopyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		c := value[index]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if index == 0 || c != '.' && c != '_' && c != ':' && c != '-' {
			return false
		}
	}
	return true
}

// Format prevents diagnostic traversal of a copy's protected routing evidence.
func (BatchCopy) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, batchRevisionRedacted) }

// BatchRevisionRequest owns one immutable original and the complete actual fanout.
type BatchRevisionRequest struct {
	state *batchRevisionRequestState
}

type batchRevisionRequestState struct {
	binding  string
	original BatchMessage
	copies   []BatchCopy
}

// NewBatchRevisionRequest enforces complete bounded inputs without assigning cryptographic authority.
func NewBatchRevisionRequest(binding string, original BatchMessage, copies []BatchCopy) (BatchRevisionRequest, error) {
	if !validBatchDigest(binding) || !original.Valid() ||
		!AdmitsProcessFidelity(original.state.fidelity) || len(copies) == 0 || len(copies) > MaxBatchRevisionCopies {
		return BatchRevisionRequest{}, &DomainError{}
	}
	ids := make(map[string]bool, len(copies))
	total, external := original.RawSize(), 0
	for _, branch := range copies {
		if !branch.message.Valid() || ids[branch.id] {
			return BatchRevisionRequest{}, &DomainError{}
		}
		ids[branch.id] = true
		total += branch.message.RawSize()
		if total > MaxBatchRevisionMessageBytes {
			return BatchRevisionRequest{}, &DomainError{}
		}
		if !branch.local {
			external++
		}
	}
	if external == 0 {
		return BatchRevisionRequest{}, &DomainError{}
	}
	return BatchRevisionRequest{state: &batchRevisionRequestState{binding: binding, original: original, copies: slices.Clone(copies)}}, nil
}

// Valid reports whether the request owns one immutable admitted batch.
func (r BatchRevisionRequest) Valid() bool { return r.state != nil }

// Format prevents diagnostic traversal of all protected batch evidence.
func (BatchRevisionRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, batchRevisionRedacted)
}

// BatchRevisionService is the isolated complete-fanout application boundary.
type BatchRevisionService interface {
	ReviseBatch(context.Context, BatchRevisionRequest) (BatchRevisionResult, error)
}

// BatchRevisionOutput contains only exact generated headers and byte bindings.
type BatchRevisionOutput struct {
	id, currentSHA256, resultSHA256 string
	insertionOffset                 int
	fields                          []CompletedField
}

// ID returns the opaque copy identifier.
func (o BatchRevisionOutput) ID() string { return o.id }

// CurrentSHA256 binds the exact input variant.
func (o BatchRevisionOutput) CurrentSHA256() string { return o.currentSHA256 }

// ResultSHA256 binds the library-proved complete output bytes.
func (o BatchRevisionOutput) ResultSHA256() string { return o.resultSHA256 }

// InsertionOffset returns the library-proved insertion point in current bytes.
func (o BatchRevisionOutput) InsertionOffset() int { return o.insertionOffset }

// Fields returns isolated complete generated header fields in insertion order.
func (o BatchRevisionOutput) Fields() []CompletedField { return slices.Clone(o.fields) }

// Format keeps signed material out of diagnostics.
func (BatchRevisionOutput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, batchRevisionRedacted)
}

// BatchRevisionResult is one all-or-nothing external revision outcome.
type BatchRevisionResult struct {
	binding, originalSHA256 string
	result                  OperationResultClass
	disposition             OperationDisposition
	outputs                 []BatchRevisionOutput
}

// Valid checks the closed result/action matrix before transport mapping.
func (r BatchRevisionResult) Valid() bool {
	if !validBatchDigest(r.binding) || !validBatchDigest(r.originalSHA256) {
		return false
	}
	if r.result == OperationPass {
		return r.disposition == OperationAccept && len(r.outputs) > 0 && len(r.outputs) <= MaxBatchRevisionCopies
	}
	return len(r.outputs) == 0 && (r.result == OperationTemperror && r.disposition == OperationTempfail ||
		(r.result == OperationFail || r.result == OperationPermerror) && r.disposition == OperationReject)
}

// Binding returns the caller-owned immutable plan correlation value.
func (r BatchRevisionResult) Binding() string { return r.binding }

// OriginalSHA256 returns the digest of exact verified input bytes.
func (r BatchRevisionResult) OriginalSHA256() string { return r.originalSHA256 }

// Result returns the closed overall operation result.
func (r BatchRevisionResult) Result() OperationResultClass { return r.result }

// Disposition returns the external release decision.
func (r BatchRevisionResult) Disposition() OperationDisposition { return r.disposition }

// Outputs returns the immutable successful external outputs in request order.
func (r BatchRevisionResult) Outputs() []BatchRevisionOutput { return slices.Clone(r.outputs) }

// Format prevents diagnostic traversal of any generated signature data.
func (BatchRevisionResult) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, batchRevisionRedacted)
}

// validBatchDigest accepts the canonical lowercase SHA-256 representation.
func validBatchDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// batchSHA256 hashes exact bytes without canonicalizing mail content.
func batchSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
