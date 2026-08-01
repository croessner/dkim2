package testclient

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2ctl/internal/testclient/generated"
)

const healthResponseBody = `{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04","status":"alive"}`

// countingBody records exact response-body close ownership.
type countingBody struct {
	mu       sync.Mutex
	reader   io.Reader
	closeErr error
	closes   int
}

// Read delegates to the configured deterministic reader.
func (b *countingBody) Read(destination []byte) (int, error) {
	return b.reader.Read(destination)
}

// Close records exactly one lifecycle release.
func (b *countingBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closes++
	return b.closeErr
}

// closeCount returns the synchronized close count.
func (b *countingBody) closeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closes
}

// staticDoer returns one deterministic response without network access.
type staticDoer struct {
	response *http.Response
	err      error
}

// Do returns the configured transport result.
func (d staticDoer) Do(_ *http.Request) (*http.Response, error) {
	return d.response, d.err
}

// TestRuntimeClassifiesGeneratedHealthAndClosesOnce proves strict typed handling.
func TestRuntimeClassifiesGeneratedHealthAndClosesOnce(t *testing.T) {
	t.Parallel()
	body := newCountingJSONBody(healthResponseBody)
	response := validJSONResponse(http.StatusOK, body)
	runtime, err := NewRuntimeWithDoer("http://127.0.0.1:8080", staticDoer{response: response})
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	fact, err := runtime.CallHealth(t.Context())
	if err != nil || fact.Health == nil || fact.Status != 200 {
		t.Fatal("valid health response rejected")
	}
	if body.closeCount() != 1 {
		t.Fatal("response body was not closed exactly once")
	}
}

// TestRuntimeAcceptsNetHTTPConnectionCloseProjection proves the client
// validates the parsed response state after net/http consumes the hop-by-hop
// Connection field.
func TestRuntimeAcceptsNetHTTPConnectionCloseProjection(t *testing.T) {
	t.Parallel()
	body := healthResponseBody
	raw := "HTTP/1.1 200 OK\r\n" +
		"Cache-Control: no-store\r\n" +
		"X-Content-Type-Options: nosniff\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		`ETag: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"` + "\r\n" +
		"Connection: close\r\n\r\n" + body
	response, err := http.ReadResponse(
		bufio.NewReader(strings.NewReader(raw)),
		&http.Request{Method: http.MethodGet},
	)
	if err != nil {
		t.Fatal("parse exact wire response")
	}
	if response.Header.Get(headerConnection) != "" || !response.Close {
		t.Fatal("net/http connection-close projection changed")
	}
	runtime, _ := NewRuntimeWithDoer(
		"http://127.0.0.1:8080",
		staticDoer{response: response},
	)
	if _, err := runtime.CallHealth(t.Context()); err != nil {
		t.Fatal("valid parsed connection-close response rejected")
	}
}

// TestRuntimeClosesEveryRejectedBodyPath proves malformed and oversized ownership.
func TestRuntimeClosesEveryRejectedBodyPath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body *countingBody
		resp *http.Response
	}{
		{
			name: "malformed",
			body: newCountingJSONBody(`{"api_version":`),
		},
		{
			name: "oversized",
			body: &countingBody{reader: strings.NewReader(strings.Repeat("x", statusBodyLimit+1))},
		},
		{
			name: "read failure",
			body: &countingBody{reader: errorReader{}},
		},
		{
			name: "close failure",
			body: &countingBody{
				reader:   strings.NewReader(healthResponseBody),
				closeErr: errors.New("marker-private-close"),
			},
		},
	}
	for index := range tests {
		test := &tests[index]
		test.resp = validJSONResponse(http.StatusOK, test.body)
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime, _ := NewRuntimeWithDoer("http://127.0.0.1:8080", staticDoer{response: test.resp})
			if _, err := runtime.CallHealth(t.Context()); ExitClassOf(err) != ExitContract {
				t.Fatal("hostile response not classified as contract failure")
			}
			if test.body.closeCount() != 1 {
				t.Fatal("hostile response body was not closed exactly once")
			}
		})
	}
}

// TestRuntimeErasesTransportErrors proves marker-bearing transport details stay private.
func TestRuntimeErasesTransportErrors(t *testing.T) {
	t.Parallel()
	runtime, _ := NewRuntimeWithDoer(
		"http://127.0.0.1:8080",
		staticDoer{err: errors.New("marker-private-url-message-capability")},
	)
	_, err := runtime.CallHealth(t.Context())
	if ExitClassOf(err) != ExitTransport || strings.Contains(err.Error(), "marker") {
		t.Fatal("transport marker escaped classification")
	}
}

// TestRuntimeClosesResponseReturnedWithTransportError proves hostile injected
// doers cannot transfer response-body ownership into an error path.
func TestRuntimeClosesResponseReturnedWithTransportError(t *testing.T) {
	t.Parallel()
	body := newCountingJSONBody(`{}`)
	response := validJSONResponse(http.StatusOK, body)
	runtime, _ := NewRuntimeWithDoer(
		"http://127.0.0.1:8080",
		staticDoer{response: response, err: errors.New("marker-private-transport")},
	)
	if _, err := runtime.CallHealth(t.Context()); ExitClassOf(err) != ExitTransport {
		t.Fatal("transport error class changed")
	}
	if body.closeCount() != 1 {
		t.Fatal("response accompanying transport error was not closed exactly once")
	}
}

// TestRuntimeUsesOneHTTPClientForTypedAndNegativeCalls freezes the single
// production-client ownership contract.
func TestRuntimeUsesOneHTTPClientForTypedAndNegativeCalls(t *testing.T) {
	t.Parallel()
	runtime, err := NewRuntime(DefaultOptions())
	if err != nil {
		t.Fatal("runtime construction failed")
	}
	defer func() { _ = runtime.Close() }()
	if runtime.client == nil || runtime.raw != runtime.client {
		t.Fatal("typed and negative calls do not share one owned HTTP client")
	}
}

// TestRuntimeRejectsRedirectWithoutFollowing proves generated transport is local-only.
func TestRuntimeRejectsRedirectWithoutFollowing(t *testing.T) {
	t.Parallel()
	body := newCountingJSONBody(`{}`)
	response := validJSONResponse(http.StatusFound, body)
	response.Header.Set("Location", "http://example.test/private")
	runtime, _ := NewRuntimeWithDoer("http://127.0.0.1:8080", staticDoer{response: response})
	if _, err := runtime.CallHealth(t.Context()); ExitClassOf(err) != ExitContract {
		t.Fatal("redirect response accepted")
	}
	if body.closeCount() != 1 {
		t.Fatal("redirect response body not closed")
	}
}

// TestRuntimeAcceptsDeclaredPreconditionFailure proves the generated health
// response map and structured error coherence remain aligned.
func TestRuntimeAcceptsDeclaredPreconditionFailure(t *testing.T) {
	t.Parallel()
	body := newCountingJSONBody(
		`{"api_version":"v1","draft":"draft-ietf-dkim-dkim2-spec-04",` +
			`"code":"precondition_failed","category":"request"}`,
	)
	response := validJSONResponse(http.StatusPreconditionFailed, body)
	runtime, _ := NewRuntimeWithDoer("http://127.0.0.1:8080", staticDoer{response: response})
	fact, err := runtime.CallHealth(t.Context())
	if err != nil || fact.Error == nil ||
		fact.Error.Code != generated.ErrorResponseCodePreconditionFailed {
		t.Fatal("declared precondition response rejected")
	}
}

// TestRuntimeRejectsMissingOrMultipleRequiredMetadata freezes OpenAPI and RFC
// response-header coherence rather than accepting status and JSON alone.
func TestRuntimeRejectsMissingOrMultipleRequiredMetadata(t *testing.T) {
	t.Parallel()
	health := healthResponseBody
	tests := []struct {
		name   string
		mutate func(*http.Response)
	}{
		{
			name: "missing etag",
			mutate: func(response *http.Response) {
				response.Header.Del("ETag")
			},
		},
		{
			name: "duplicate cache control",
			mutate: func(response *http.Response) {
				response.Header[headerCacheControl] = []string{"no-store", "no-store"}
			},
		},
		{
			name: "noncanonical content length",
			mutate: func(response *http.Response) {
				response.Header.Set(headerContentLength, "00")
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := newCountingJSONBody(health)
			response := validJSONResponse(http.StatusOK, body)
			test.mutate(response)
			runtime, _ := NewRuntimeWithDoer(
				"http://127.0.0.1:8080",
				staticDoer{response: response},
			)
			if _, err := runtime.CallHealth(t.Context()); ExitClassOf(err) != ExitContract {
				t.Fatal("invalid response metadata accepted")
			}
		})
	}
}

// TestDurationBucketFreezesClosedVocabulary verifies bounded diagnostic classes.
func TestDurationBucketFreezesClosedVocabulary(t *testing.T) {
	t.Parallel()
	values := []string{
		DurationBucket(-1),
		DurationBucket(0),
		DurationBucket(999999999),
		DurationBucket(9999999999),
		DurationBucket(10000000000),
	}
	want := []string{"invalid", "under_100ms", "under_1s", "under_10s", "at_least_10s"}
	if !slicesEqual(values, want) {
		t.Fatal("duration bucket vocabulary changed")
	}
}

// errorReader always returns one marker-bearing read failure.
type errorReader struct{}

// Read returns the deterministic hostile read error.
func (errorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("marker-private-read")
}

// newCountingJSONBody constructs a lifecycle-observable response body.
func newCountingJSONBody(value string) *countingBody {
	return &countingBody{reader: strings.NewReader(value)}
}

// validJSONResponse constructs exact response metadata around a controlled body.
func validJSONResponse(status int, body *countingBody) *http.Response {
	payload, _ := io.ReadAll(body.reader)
	body.reader = bytes.NewReader(payload)
	response := &http.Response{
		StatusCode: status,
		Close:      true,
		Header: http.Header{
			headerCacheControl:       {cacheNoStore},
			"X-Content-Type-Options": {contentNoSniff},
			headerConnection:         {connectionClose},
			headerContentType:        {mediaTypeJSON},
			headerContentLength:      {strconv.Itoa(len(payload))},
		},
		Body: body,
	}
	if status == http.StatusOK {
		response.Header.Set(
			"ETag",
			`"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"`,
		)
	}
	return response
}

// slicesEqual compares two short deterministic string vectors.
func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

var _ generated.HttpRequestDoer = staticDoer{}
var _ io.ReadCloser = (*countingBody)(nil)
