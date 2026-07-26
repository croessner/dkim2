package testclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

const daemonProcessBodyLimit = int64(47_878_316)

const fixedNegativeBody = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","message":{"raw_rfc5322_base64":""},"smtp":{"mail_from":"","rcpt_to":[""]}}`

// CallNegative executes one closed raw-contract mutation.
func (r *Runtime) CallNegative(
	ctx context.Context,
	mutation string,
	capability *Capability,
) (ResponseFact, error) {
	if r == nil || r.raw == nil || !validNegativeMutation(mutation) || capability == nil {
		return ResponseFact{}, NewExitError(ExitInternal)
	}
	request, err := buildNegativeRequest(ctx, r.serverURL, mutation, capability)
	if err != nil {
		return ResponseFact{}, err
	}
	response, err := r.raw.Do(request)
	if err != nil {
		return ResponseFact{}, classifyTransportError(err)
	}
	return classifyNegativeResponse(response)
}

// buildNegativeRequest constructs only one declared route-family mutation.
func buildNegativeRequest(
	ctx context.Context,
	serverURL string,
	mutation string,
	capability *Capability,
) (*http.Request, error) {
	if ctx == nil {
		return nil, NewExitError(ExitInternal)
	}
	parsed, err := ParseServerURL(serverURL)
	if err != nil || !validNegativeMutation(mutation) {
		return nil, NewExitError(ExitInternal)
	}
	target := parsed.String() + processPath
	method := http.MethodPost
	contentType := mediaTypeJSON
	var body io.Reader = strings.NewReader(fixedNegativeBody)
	contentLength := int64(len(fixedNegativeBody))

	switch mutation {
	case mutationUnsupportedMedia:
		contentType = "text/plain"
	case mutationMalformedJSON:
		body = strings.NewReader(`{`)
		contentLength = 1
	case mutationUnknownMember:
		value := strings.TrimSuffix(fixedNegativeBody, "}") + `,"unknown":true}`
		body = strings.NewReader(value)
		contentLength = int64(len(value))
	case mutationTruncatedBody:
		value := strings.TrimSuffix(fixedNegativeBody, "}")
		body = strings.NewReader(value)
		contentLength = int64(len(value))
	case mutationBodyOverLimit:
		body = io.LimitReader(repeatingByteReader{}, daemonProcessBodyLimit+1)
		contentLength = daemonProcessBodyLimit + 1
	case mutationUnsupportedMethod:
		method = http.MethodPut
		body = nil
		contentLength = 0
	case mutationContaminatedTarget:
		target += "?unexpected=1"
	case mutationMissingCapability, mutationDuplicateCapability, mutationEmptyCapability,
		mutationMismatchingCapability:
	default:
		return nil, NewExitError(ExitInternal)
	}

	request, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, NewExitError(ExitInternal)
	}
	request.ContentLength = contentLength
	if body != nil {
		request.Header.Set("Content-Type", contentType)
	}
	if err := capability.editNegativeRequest(request, mutation); err != nil {
		return nil, err
	}
	if !validNegativeRequestShape(request, parsed, mutation) {
		return nil, NewExitError(ExitInternal)
	}
	return request, nil
}

// validNegativeRequestShape proves no mutation escaped its declared authority.
func validNegativeRequestShape(request *http.Request, authority *url.URL, mutation string) bool {
	if request == nil || request.URL == nil || authority == nil ||
		request.URL.Scheme != schemeHTTP || request.URL.Host != authority.Host ||
		request.URL.Path != processPath || request.URL.Fragment != "" {
		return false
	}
	if mutation == mutationContaminatedTarget {
		return request.URL.RawQuery == "unexpected=1"
	}
	return request.URL.RawQuery == ""
}

// classifyNegativeResponse validates bounded raw-boundary error metadata.
func classifyNegativeResponse(response *http.Response) (ResponseFact, error) {
	if response == nil || response.Body == nil {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	body, err := readAndClose(response.Body, processBodyLimit)
	if err != nil {
		return ResponseFact{}, err
	}
	if !validResponseMetadata(OperationProcess, response, body) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	var value generated.ErrorResponse
	if strictResponseJSON(body, &value) != nil || !validError(value) ||
		!coherentNegativeErrorStatus(response.StatusCode, value) {
		return ResponseFact{}, NewExitError(ExitContract)
	}
	return ResponseFact{
		Operation: OperationProcess,
		Status:    response.StatusCode,
		Error:     &value,
	}, nil
}

// coherentNegativeErrorStatus extends operation errors for raw route failures.
func coherentNegativeErrorStatus(status int, value generated.ErrorResponse) bool {
	if coherentErrorStatus(status, value) {
		return true
	}
	return value.Category == generated.Request &&
		(status == http.StatusNotFound && value.Code == generated.ErrorResponseCodeNotFound ||
			status == http.StatusMethodNotAllowed &&
				value.Code == generated.ErrorResponseCodeMethodNotAllowed)
}

// repeatingByteReader supplies a bounded body without request-sized allocation.
type repeatingByteReader struct{}

// Read fills the caller-owned buffer with a deterministic nonsecret byte.
func (repeatingByteReader) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = 'x'
	}
	return len(destination), nil
}

// buildHostileResponse constructs one fake-transport response for fuzz and tests.
func buildHostileResponse(status int, contentType string, body string) *http.Response {
	response := &http.Response{
		StatusCode: status,
		Close:      true,
		Header: http.Header{
			"Cache-Control":          {cacheNoStore},
			"X-Content-Type-Options": {contentNoSniff},
			"Connection":             {connectionClose},
			"Content-Type":           {contentType},
			"Content-Length":         {strconv.Itoa(len(body))},
		},
		Body: io.NopCloser(bytes.NewBufferString(body)),
	}
	if status == http.StatusOK {
		response.Header.Set(
			"ETag",
			`"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
		)
	}
	if status == http.StatusServiceUnavailable {
		response.Header.Set("Retry-After", "1")
	}
	if status == http.StatusMethodNotAllowed {
		response.Header.Set("Allow", http.MethodPost)
	}
	return response
}
