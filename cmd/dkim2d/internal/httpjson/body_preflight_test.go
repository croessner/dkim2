package httpjson

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type bodyPreflightReader struct {
	value []byte
	err   error
}

// Read returns one scripted body outcome.
func (r *bodyPreflightReader) Read(output []byte) (int, error) {
	if len(r.value) > 0 {
		count := copy(output, r.value)
		r.value = r.value[count:]
		return count, nil
	}
	return 0, r.err
}

// Close releases the scripted reader.
func (*bodyPreflightReader) Close() error { return nil }

type bodyTimeoutError struct{}

// Error returns one private-free timeout description.
func (bodyTimeoutError) Error() string { return "test timeout" }

// Timeout identifies the scripted deadline.
func (bodyTimeoutError) Timeout() bool { return true }

// Temporary reports no retry policy.
func (bodyTimeoutError) Temporary() bool { return false }

// TestReadProcessBodyClassifiesBoundsTransportAndTrailers proves closed body outcomes.
func TestReadProcessBodyClassifiesBoundsTransportAndTrailers(t *testing.T) {
	tests := []struct {
		name    string
		body    io.ReadCloser
		want    bodyFailure
		trailer http.Header
	}{
		{
			name:    "timeout",
			body:    &bodyPreflightReader{err: bodyTimeoutError{}},
			want:    bodyFailureTimeout,
			trailer: http.Header{testPrivateTrailerName: {testSecretValue}},
		},
		{
			name:    "disconnect",
			body:    &bodyPreflightReader{err: io.ErrUnexpectedEOF},
			want:    bodyFailureDisconnect,
			trailer: http.Header{testPrivateTrailerName: {testSecretValue}},
		},
		{
			name:    "bounded raw transport failure",
			body:    &bodyPreflightReader{err: errTransportRead},
			want:    bodyFailureDisconnect,
			trailer: http.Header{testPrivateTrailerName: {testSecretValue}},
		},
		{
			name:    "other",
			body:    &bodyPreflightReader{err: errors.New("private marker")},
			want:    bodyFailureInvalid,
			trailer: http.Header{testPrivateTrailerName: {testSecretValue}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, testProcessPath, nil)
			request.Body = test.body
			request.Trailer = test.trailer
			body, failure := readProcessBody(httptest.NewRecorder(), request, request)
			if body != nil || failure != test.want || request.Trailer != nil {
				t.Fatalf("readProcessBody() = %v/%v trailer=%v", body, failure, request.Trailer)
			}
		})
	}
}

// TestReadProcessBodyAcceptsExactLimitAndRejectsOneOver proves the outer body bound.
func TestReadProcessBodyAcceptsExactLimitAndRejectsOneOver(t *testing.T) {
	if testing.Short() {
		t.Skip("exact outer-body allocation proof is not a short test")
	}
	for _, test := range []struct {
		name string
		size int64
		want bodyFailure
	}{
		{name: testExactName, size: maxProcessBodyBytes},
		{name: "one over", size: maxProcessBodyBytes + 1, want: bodyFailureTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, testProcessPath, nil)
			request.Body = io.NopCloser(&repeatingReader{remaining: test.size})
			body, failure := readProcessBody(httptest.NewRecorder(), request, request)
			if failure != test.want {
				t.Fatalf("failure = %v, want %v", failure, test.want)
			}
			if test.want == 0 && int64(len(body)) != test.size {
				t.Fatalf("body size = %d, want %d", len(body), test.size)
			}
		})
	}
}

type repeatingReader struct {
	remaining int64
}

// Read emits bounded deterministic bytes without allocating the source body.
func (r *repeatingReader) Read(output []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	count := int64(len(output))
	if count > r.remaining {
		count = r.remaining
	}
	for index := range output[:count] {
		output[index] = 'x'
	}
	r.remaining -= count
	return int(count), nil
}

var _ net.Error = bodyTimeoutError{}
