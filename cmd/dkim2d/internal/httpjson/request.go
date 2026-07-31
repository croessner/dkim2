package httpjson

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/app"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

const (
	maxEncodedMessageBytes  = 44_739_244
	maxSMTPPathBytes        = 256
	maxEnvelopeBytes        = 512_256
	domainRequestRedacted   = "dkim2d_domain_request"
	mappingErrorDescription = "http-json mapping failure"
)

// MappingErrorCode identifies one content-free mapper failure class.
type MappingErrorCode uint8

const (
	// MappingInvalidContract reports invalid or noncanonical transport values.
	MappingInvalidContract MappingErrorCode = iota + 1
	// MappingRequestTooLarge reports a request resource bound.
	MappingRequestTooLarge
	// MappingInternalContract reports an impossible domain result.
	MappingInternalContract
)

// MappingError reports one bounded mapper failure without retaining input.
type MappingError struct {
	code MappingErrorCode
}

// Error returns a constant content-free mapper diagnostic.
func (*MappingError) Error() string { return mappingErrorDescription }

// Code returns the closed mapper failure class.
func (e *MappingError) Code() MappingErrorCode {
	if e == nil {
		return 0
	}
	return e.code
}

// Is supports errors.Is without exposing a wrapped cause.
func (e *MappingError) Is(target error) bool {
	other, ok := target.(*MappingError)
	return ok && e != nil && e.code == other.code
}

// newMappingError constructs one content-free mapper error.
func newMappingError(code MappingErrorCode) *MappingError {
	return &MappingError{code: code}
}

type domainRequestState struct {
	request    dkim2.VerifyRequest
	authservID string
}

// AuthservID returns the optional validated local reporting authority.
func (r DomainRequest) AuthservID() string {
	if r.state == nil {
		return ""
	}
	return r.state.authservID
}

// DomainRequest owns one byte-preserving request mapped away from generated DTOs.
type DomainRequest struct {
	state *domainRequestState
}

// VerifyRequest returns the stored immutable library request by value.
func (r DomainRequest) VerifyRequest() (dkim2.VerifyRequest, error) {
	if r.state == nil {
		return dkim2.VerifyRequest{}, newMappingError(MappingInvalidContract)
	}
	return r.state.request, nil
}

// String returns a content-free diagnostic representation.
func (DomainRequest) String() string { return domainRequestRedacted }

// GoString returns a content-free Go-syntax representation.
func (DomainRequest) GoString() string { return domainRequestRedacted }

// Format prevents formatting verbs from traversing request bytes.
func (DomainRequest) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, domainRequestRedacted)
}

// MarshalJSON rejects serialization outside the package-owned request assembler.
func (DomainRequest) MarshalJSON() ([]byte, error) {
	return nil, newMappingError(MappingInternalContract)
}

// MarshalText rejects diagnostic serialization of request bytes.
func (DomainRequest) MarshalText() ([]byte, error) {
	return nil, newMappingError(MappingInternalContract)
}

// MapProcessRequest maps decoded values after lexical, schema, and resource preflight.
//
// The decoded generated wrapper cannot prove the spelling of the original JSON
// string token; the HTTP lexical preflight owns rejection of escaped-equivalent
// Base64 spellings. This mapper validates the decoded canonical Base64 value and
// preserves exact message and SMTP bytes.
func MapProcessRequest(input generated.ProcessRequest) (DomainRequest, error) {
	fidelity := app.FidelityRawRFC5322
	if input.Message.Fidelity != nil {
		fidelity = app.MessageFidelity(*input.Message.Fidelity)
	}
	if input.ApiVersion != generated.V1 || input.Draft != generated.DraftIetfDkimDkim2Spec04 ||
		!app.AdmitsProcessFidelity(fidelity) {
		return DomainRequest{}, newMappingError(MappingInvalidContract)
	}
	authservID := ""
	if input.Reporting != nil {
		authservID = input.Reporting.AuthservId
		if !validSigningDomain(authservID) {
			return DomainRequest{}, newMappingError(MappingInvalidContract)
		}
	}

	encoded, err := input.Message.RawRfc5322Base64.Bytes()
	if err != nil {
		return DomainRequest{}, newMappingError(MappingInvalidContract)
	}
	rawMessage, err := decodeCanonicalBase64(encoded)
	if err != nil {
		return DomainRequest{}, err
	}

	reversePath, err := input.Smtp.MailFrom.Bytes()
	if err != nil || !utf8.Valid(reversePath) {
		return DomainRequest{}, newMappingError(MappingInvalidContract)
	}
	if len(reversePath) > maxSMTPPathBytes {
		return DomainRequest{}, newMappingError(MappingRequestTooLarge)
	}
	if len(input.Smtp.RcptTo) == 0 {
		return DomainRequest{}, newMappingError(MappingInvalidContract)
	}
	if len(input.Smtp.RcptTo) > dkim2.HardMaxRecipients {
		return DomainRequest{}, newMappingError(MappingRequestTooLarge)
	}
	forwardPaths := make([][]byte, len(input.Smtp.RcptTo))
	envelopeBytes := len(reversePath)
	for index, value := range input.Smtp.RcptTo {
		path, pathErr := value.Bytes()
		if pathErr != nil || !utf8.Valid(path) {
			return DomainRequest{}, newMappingError(MappingInvalidContract)
		}
		if len(path) > maxSMTPPathBytes {
			return DomainRequest{}, newMappingError(MappingRequestTooLarge)
		}
		envelopeBytes += len(path)
		if envelopeBytes > maxEnvelopeBytes {
			return DomainRequest{}, newMappingError(MappingRequestTooLarge)
		}
		forwardPaths[index] = path
	}

	return DomainRequest{state: &domainRequestState{
		request:    dkim2.NewVerifyRequest(rawMessage, reversePath, forwardPaths),
		authservID: authservID,
	}}, nil
}

// decodeCanonicalBase64 validates the decoded JSON string value as canonical padded RFC 4648.
func decodeCanonicalBase64(encoded []byte) ([]byte, error) {
	if len(encoded) > maxEncodedMessageBytes {
		return nil, newMappingError(MappingRequestTooLarge)
	}
	if len(encoded)%4 != 0 {
		return nil, newMappingError(MappingInvalidContract)
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
	if err != nil {
		return nil, newMappingError(MappingInvalidContract)
	}
	if len(decoded) > dkim2.HardMaxRawMessageBytes {
		return nil, newMappingError(MappingRequestTooLarge)
	}
	canonical := base64.StdEncoding.EncodeToString(decoded)
	if !bytes.Equal(encoded, []byte(canonical)) {
		return nil, newMappingError(MappingInvalidContract)
	}
	return decoded, nil
}

// IsMappingError reports whether err belongs to one closed mapper class.
func IsMappingError(err error, code MappingErrorCode) bool {
	return errors.Is(err, &MappingError{code: code})
}
