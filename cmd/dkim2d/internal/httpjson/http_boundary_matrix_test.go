package httpjson

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/httpjson/generated"
)

type boundaryHeaderDeletionObservation struct {
	expectInertCount  int
	framingInertCount int
}

type boundaryHeaderDeletionSpy struct {
	generated.ServerInterface
	observations chan boundaryHeaderDeletionObservation
}

// ProcessMessage records whether transport-private inert fields reached generated code.
func (s *boundaryHeaderDeletionSpy) ProcessMessage(
	writer http.ResponseWriter,
	request *http.Request,
) {
	s.observations <- boundaryHeaderDeletionObservation{
		expectInertCount:  len(request.Header.Values("X-Dk2E")),
		framingInertCount: len(request.Header.Values("X-DKIM2-Framing-X")),
	}
	s.ServerInterface.ProcessMessage(writer, request)
}

// TestHTTPBoundaryRawVersionHostAndTargetForms freezes parsed request routing.
func TestHTTPBoundaryRawVersionHostAndTargetForms(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	tests := []struct {
		name       string
		request    string
		statusLine string
	}{
		{
			name:       "HTTP 1.0",
			request:    "GET /healthz HTTP/1.0\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP10OKLine,
		},
		{
			name:       "HTTP 1.0 origin missing Host",
			request:    "GET /healthz HTTP/1.0\r\n\r\n",
			statusLine: testHTTP10BadRequestLine,
		},
		{
			name:       "HTTP 1.0 origin alternate Host",
			request:    "GET /healthz HTTP/1.0\r\nHost: 127.0.0.1:1\r\n\r\n",
			statusLine: testHTTP10BadRequestLine,
		},
		{
			name:       "HTTP 1.0 absolute exact Host",
			request:    "GET http://" + address + "/healthz HTTP/1.0\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP10OKLine,
		},
		{
			name:       "HTTP 1.0 absolute disagreeing Host",
			request:    "GET http://" + address + "/healthz HTTP/1.0\r\nHost: 127.0.0.1:1\r\n\r\n",
			statusLine: testHTTP10OKLine,
		},
		{
			name:       "HTTP 1.0 absolute missing field Host",
			request:    "GET http://" + address + "/healthz HTTP/1.0\r\n\r\n",
			statusLine: testHTTP10BadRequestLine,
		},
		{
			name:       "HTTP 1.1",
			request:    "GET /healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11OKLine,
		},
		{
			name:       "HTTP 1.2",
			request:    "GET /healthz HTTP/1.2\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11OKLine,
		},
		{
			name:       "unsupported major",
			request:    "GET /healthz HTTP/2.0\r\nHost: " + address + "\r\n\r\n",
			statusLine: "HTTP/1.1 505 ",
		},
		{
			name:       "missing Host",
			request:    "GET /healthz HTTP/1.1\r\n\r\n",
			statusLine: testHTTP11BadRequestPrefix,
		},
		{
			name:       "duplicate Host",
			request:    "GET /healthz HTTP/1.1\r\nHost: " + address + "\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11BadRequestPrefix,
		},
		{
			name:       "malformed Host",
			request:    "GET /healthz HTTP/1.1\r\nHost: bad host\r\n\r\n",
			statusLine: testHTTP11BadRequestPrefix,
		},
		{
			name:       "origin alternate Host",
			request:    "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "absolute exact authority ignores Host value",
			request:    "GET http://" + address + "/healthz HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
			statusLine: testHTTP11OKLine,
		},
		{
			name:       "absolute mismatching authority",
			request:    "GET http://127.0.0.1:1/healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "absolute missing field Host",
			request:    "GET http://" + address + "/healthz HTTP/1.1\r\n\r\n",
			statusLine: testHTTP11BadRequestPrefix,
		},
		{
			name:       "absolute https scheme",
			request:    "GET https://" + address + "/healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "absolute userinfo",
			request:    "GET http://user@" + address + "/healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "CONNECT authority",
			request:    "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11NotImplementedLine,
		},
		{
			name:       "CONNECT origin mismatch",
			request:    "CONNECT /healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "CONNECT missing Host",
			request:    "CONNECT " + address + " HTTP/1.1\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "CONNECT mismatching Host",
			request:    "CONNECT " + address + " HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "OPTIONS asterisk",
			request:    "OPTIONS * HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11NoContentLine,
		},
		{
			name:       "OPTIONS asterisk mismatching Host",
			request:    "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
		{
			name:       "GET asterisk mismatch",
			request:    "GET * HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine: testHTTP11BadRequestLine,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address, testCase.request)
			if !strings.HasPrefix(response, testCase.statusLine) {
				t.Fatalf("response = %q, want prefix %q", response, testCase.statusLine)
			}
			if strings.Count(strings.ToLower(response), "\r\nconnection: close\r\n") != 1 {
				t.Fatalf("response did not contain one close field: %q", response)
			}
		})
	}
}

// TestHTTPBoundaryRawMethodTargetAndHeadLimits freezes exact resource edges.
func TestHTTPBoundaryRawMethodTargetAndHeadLimits(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	for _, methodLength := range []int{64, 65} {
		for _, targetLength := range []int{8_192, 8_193} {
			methodLength := methodLength
			targetLength := targetLength
			t.Run(
				"method_"+strconv.Itoa(methodLength)+"_target_"+strconv.Itoa(targetLength),
				func(t *testing.T) {
					method := strings.Repeat("A", methodLength)
					target := "/" + strings.Repeat("x", targetLength-1)
					response := rawBoundaryExchange(t, address,
						method+" "+target+" HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
					want := testHTTP11NotImplementedLine
					if targetLength == 8_193 {
						want = testHTTP11URITooLongLine
					}
					if !strings.HasPrefix(response, want) {
						t.Fatalf("response = %q, want prefix %q", response, want)
					}
				},
			)
		}
	}

	headSuffix := " /healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n"
	for _, totalLength := range []int{
		testRequestHeadLimit,
		testRequestHeadLimit + 1,
	} {
		method := strings.Repeat("A", totalLength-len(headSuffix))
		response := rawBoundaryExchange(t, address, method+headSuffix)
		want := testHTTP11NotImplementedLine
		if totalLength > testRequestHeadLimit {
			want = "HTTP/1.1 431 Request Header Fields Too Large\r\n"
		}
		if !strings.HasPrefix(response, want) {
			t.Fatalf("aggregate head length %d = %q, want %q",
				totalLength, response, want)
		}
	}
}

// TestHTTPBoundaryRawRequestLineReleaseAndSplitEdges freezes replay fidelity.
func TestHTTPBoundaryRawRequestLineReleaseAndSplitEdges(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	tests := []struct {
		name       string
		chunks     []string
		statusLine string
	}{
		{
			name: "split method delimiter",
			chunks: []string{
				testGETMethod,
				" /healthz",
				" HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			},
			statusLine: testHTTP11OKLine,
		},
		{
			name: "split target delimiter",
			chunks: []string{
				"GET /healthz",
				" HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			},
			statusLine: testHTTP11OKLine,
		},
		{
			name:       "invalid method tchar",
			chunks:     []string{"GE(T /healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n"},
			statusLine: testHTTP11BadRequestPrefix,
		},
		{
			name:       "bare LF request line",
			chunks:     []string{"GET /healthz HTTP/1.1\nHost: " + address + "\n\n"},
			statusLine: testHTTP11OKLine,
		},
		{
			name:       "bare CR request line",
			chunks:     []string{"GET /healthz HTTP/1.1\rHost: " + address + "\r\n\r\n"},
			statusLine: testHTTP11BadRequestPrefix,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryChunkedExchange(t, address, testCase.chunks)
			if !strings.HasPrefix(response, testCase.statusLine) {
				t.Fatalf("response = %q", response)
			}
		})
	}
}

// TestHTTPBoundaryRawRoutesPathsMethodsAndHEAD freezes exact operation dispatch.
func TestHTTPBoundaryRawRoutesPathsMethodsAndHEAD(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	tests := []struct {
		name       string
		method     string
		target     string
		statusLine string
		allow      string
	}{
		{name: "health exact", method: testGETMethod, target: testHealthPath, statusLine: testHTTP11OKLine},
		{name: "readiness exact", method: testGETMethod, target: testReadinessPath, statusLine: testHTTP11OKLine},
		{name: "trailing slash", method: testGETMethod, target: "/healthz/", statusLine: testHTTP11NotFoundLine},
		{name: "doubled slash", method: testGETMethod, target: "//healthz", statusLine: testHTTP11NotFoundLine},
		{name: "dot segment", method: testGETMethod, target: "/./healthz", statusLine: testHTTP11NotFoundLine},
		{name: "encoded path", method: testGETMethod, target: "/%68ealthz", statusLine: testHTTP11BadRequestLine},
		{name: "double encoded path", method: testGETMethod, target: "/%2568ealthz", statusLine: testHTTP11NotFoundLine},
		{name: "unknown", method: testGETMethod, target: testUnknownPath, statusLine: testHTTP11NotFoundLine},
		{name: "HEAD unknown", method: testHEADMethod, target: testUnknownPath, statusLine: testHTTP11NotFoundLine},
		{name: "POST health", method: "POST", target: testHealthPath, statusLine: testHTTP11MethodNotAllowedLine, allow: testStatusAllowMethods},
		{name: "OPTIONS health", method: testOPTIONSMethod, target: testHealthPath, statusLine: testHTTP11MethodNotAllowedLine, allow: testStatusAllowMethods},
		{name: "GET process", method: testGETMethod, target: testProcessPath, statusLine: testHTTP11MethodNotAllowedLine, allow: testProcessAllowMethods},
		{name: "HEAD process", method: testHEADMethod, target: testProcessPath, statusLine: testHTTP11MethodNotAllowedLine, allow: testProcessAllowMethods},
		{name: "OPTIONS process", method: testOPTIONSMethod, target: testProcessPath, statusLine: testHTTP11MethodNotAllowedLine, allow: testProcessAllowMethods},
		{name: "POST unknown", method: "POST", target: testUnknownPath, statusLine: testHTTP11NotFoundLine},
		{name: "OPTIONS unknown", method: testOPTIONSMethod, target: testUnknownPath, statusLine: testHTTP11NotFoundLine},
		{name: "registered unimplemented", method: "PUT", target: testHealthPath, statusLine: testHTTP11NotImplementedLine},
		{name: "lowercase", method: "get", target: testHealthPath, statusLine: testHTTP11NotImplementedLine},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				testCase.method+" "+testCase.target+" HTTP/1.1\r\nHost: "+
					address+"\r\n\r\n")
			if !strings.HasPrefix(response, testCase.statusLine) {
				t.Fatalf("response = %q", response)
			}
			if got := rawResponseHeader(response, "Allow"); got != testCase.allow {
				t.Fatalf("Allow = %q, want %q: %q", got, testCase.allow, response)
			}
			if testCase.method == testHEADMethod && strings.Contains(response, "\r\n\r\n{") {
				t.Fatalf("HEAD emitted application bytes: %q", response)
			}
		})
	}

	get := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	head := rawBoundaryExchange(t, address,
		"HEAD /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	for _, name := range []string{
		"Cache-Control", "Content-Length", "Content-Type",
		"ETag", "X-Content-Type-Options", "Connection",
	} {
		if rawResponseHeader(get, name) != rawResponseHeader(head, name) {
			t.Fatalf("HEAD %s differs from GET", name)
		}
	}
	if strings.Contains(head, `{"api_version"`) {
		t.Fatal("HEAD emitted selected representation bytes")
	}

	getMissingHost := rawBoundaryExchange(t, address, "GET /healthz HTTP/1.1\r\n\r\n")
	headMissingHost := rawBoundaryExchange(t, address, "HEAD /healthz HTTP/1.1\r\n\r\n")
	if !strings.HasPrefix(getMissingHost, testHTTP11BadRequestPrefix) ||
		!strings.HasPrefix(headMissingHost, testHTTP11BadRequestPrefix) ||
		!strings.Contains(getMissingHost, "\r\n\r\n400 ") ||
		strings.Contains(headMissingHost, "\r\n\r\n400 ") {
		t.Fatalf("pre-handler HEAD suppression differs: GET=%q HEAD=%q",
			getMissingHost, headMissingHost)
	}
}

// TestHTTPBoundaryRawUnsupportedVersionTransferPrecedence freezes Go ownership.
func TestHTTPBoundaryRawUnsupportedVersionTransferPrecedence(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	transferCases := []struct {
		name   string
		fields string
		status string
	}{
		{name: transportTestAbsent, status: testHTTPVersionNotSupported},
		{name: "single chunked", fields: testChunkedField, status: testHTTPVersionNotSupported},
		{name: "supported final chunked", fields: testGzipThenChunkedField, status: testStatusNotImplemented},
		{name: "non-final chunked", fields: testChunkedThenGzipField, status: testStatusNotImplemented},
		{name: "repeated chunked", fields: testRepeatedChunkedField, status: testStatusNotImplemented},
		{name: "parameterized chunked", fields: testChunkedParameterField, status: testStatusNotImplemented},
		{name: testOnlyEmptyName, fields: testTransferEncodingEmptyField, status: testStatusNotImplemented},
		{name: "coding without chunked", fields: testGzipField, status: testStatusNotImplemented},
		{
			name:   testTransferPlusLengthName,
			fields: testChunkedWithLengthFields,
			status: testHTTPVersionNotSupported,
		},
	}
	requestLines := []struct {
		name string
		line string
	}{
		{name: "PRI", line: "PRI * HTTP/2.0"},
		{name: "generic major", line: "GET /healthz HTTP/2.0"},
	}
	for _, requestLine := range requestLines {
		requestLine := requestLine
		for _, transferCase := range transferCases {
			transferCase := transferCase
			t.Run(requestLine.name+"_"+transferCase.name, func(t *testing.T) {
				response := rawBoundaryExchange(t, address,
					requestLine.line+"\r\nHost: "+address+"\r\n"+
						transferCase.fields+"\r\n")
				want := "HTTP/1.1 " + transferCase.status
				if !strings.HasPrefix(response, want) {
					t.Fatalf("response = %q, want prefix %q", response, want)
				}
			})
		}
	}
}

// TestHTTPBoundaryRawPRIPrefaceHostAndTransferMatrix freezes the sole 505 exception.
func TestHTTPBoundaryRawPRIPrefaceHostAndTransferMatrix(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	hostCases := []struct {
		name   string
		fields string
		status string
	}{
		{name: testMissingName, status: testHTTPVersionNotSupported},
		{name: testExactName, fields: "Host: " + address + "\r\n", status: testHTTPVersionNotSupported},
		{name: testMismatchName, fields: "Host: 127.0.0.1:1\r\n", status: testHTTPVersionNotSupported},
		{name: transportTestMalformed, fields: "Host: bad host\r\n", status: testBadRequestReason},
		{name: testDuplicateName, fields: "Host: " + address + "\r\nHost: " + address + "\r\n", status: testBadRequestReason},
	}
	transferCases := []struct {
		name   string
		fields string
		status string
	}{
		{name: transportTestAbsent},
		{name: "chunked", fields: testChunkedField},
		{name: "non-admitted", fields: testChunkedThenGzipField, status: testStatusNotImplemented},
		{name: testObsFoldName, fields: "Transfer-Encoding: chunked\r\n gzip\r\n", status: testStatusNotImplemented},
	}
	for _, hostCase := range hostCases {
		hostCase := hostCase
		for _, transferCase := range transferCases {
			transferCase := transferCase
			t.Run(hostCase.name+"_"+transferCase.name, func(t *testing.T) {
				want := hostCase.status
				if (want == testHTTPVersionNotSupported ||
					hostCase.name == transportTestMalformed) &&
					transferCase.status != "" {
					want = transferCase.status
				}
				response := rawBoundaryExchange(t, address,
					"PRI * HTTP/2.0\r\n"+hostCase.fields+
						transferCase.fields+"\r\nSM\r\n\r\n")
				if !strings.HasPrefix(response, "HTTP/1.1 "+want) {
					t.Fatalf("response = %q, want %s", response, want)
				}
			})
		}
	}

	h2c := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n"+
			"Connection: Upgrade, HTTP2-Settings\r\n"+
			"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n")
	if !strings.HasPrefix(h2c, testHTTP11OKLine) ||
		strings.Contains(h2c, "101 Switching Protocols") {
		t.Fatalf("h2c attempt escaped close-only HTTP/1: %q", h2c)
	}
}

// TestHTTPBoundaryRawTransferAndExpectClasses freezes admitted HTTP/1 behavior.
func TestHTTPBoundaryRawTransferAndExpectClasses(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	transferCases := []struct {
		name   string
		fields string
		body   string
		status string
	}{
		{name: transportTestAbsent, status: testStatusOK},
		{name: "single chunked", fields: testChunkedField, body: testZeroChunkTerminator, status: testBadRequestReason},
		{name: "normalized chunked", fields: "Transfer-Encoding: Chunked\r\n", body: testZeroChunkTerminator, status: testBadRequestReason},
		{name: "unsupported final", fields: testGzipThenChunkedField, status: testStatusNotImplemented},
		{name: "non-final", fields: testChunkedThenGzipField, status: testBadRequestReason},
		{name: testRepeatedName, fields: testRepeatedChunkedField, status: testBadRequestReason},
		{name: "parameterized", fields: testChunkedParameterField, status: testBadRequestReason},
		{name: testOnlyEmptyName, fields: testTransferEncodingEmptyField, status: testBadRequestReason},
		{name: testTransferPlusLengthName, fields: testChunkedWithLengthFields, status: testBadRequestReason},
	}
	for _, testCase := range transferCases {
		testCase := testCase
		t.Run("TE_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n"+testCase.body)
			if !strings.HasPrefix(response, "HTTP/1.1 "+testCase.status+"\r\n") {
				t.Fatalf("response = %q", response)
			}
		})
	}

	expectCases := []struct {
		name   string
		fields string
		status string
	}{
		{name: transportTestAbsent, status: testStatusOK},
		{name: transportTestEmpty, fields: "Expect:\r\n", status: testStatusOK},
		{name: "only empty members", fields: "Expect: , ,\r\n", status: testStatusOK},
		{name: "continue", fields: testExpectContinueField, status: testStatusExpectationFailed},
		{name: "continue case", fields: "Expect: 100-Continue\r\n", status: testStatusExpectationFailed},
		{name: "unsupported", fields: "Expect: other\r\n", status: testStatusExpectationFailed},
		{name: "parameterized extension", fields: "Expect: other=value; p=\"v\"\r\n", status: testStatusExpectationFailed},
		{name: testMixedName, fields: "Expect: 100-continue, other\r\n", status: testStatusExpectationFailed},
		{name: testRepeatedName, fields: "Expect: 100-continue\r\nExpect: 100-continue\r\n", status: testStatusExpectationFailed},
		{name: "multiple fields with empty", fields: "Expect: ,\r\nExpect: 100-continue\r\n", status: testStatusExpectationFailed},
		{name: transportTestMalformed, fields: "Expect: value=\"unterminated\r\n", status: testStatusExpectationFailed},
		{name: testObsFoldName, fields: "Expect: 100-continue\r\n other\r\n", status: testBadRequestReason},
	}
	for _, testCase := range expectCases {
		testCase := testCase
		t.Run("Expect_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n")
			if strings.Contains(response, "100 Continue") ||
				!strings.HasPrefix(response, "HTTP/1.1 "+testCase.status+"\r\n") {
				t.Fatalf("response = %q", response)
			}
		})
	}

	http10 := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.0\r\nHost: "+address+
			"\r\nExpect: 100-continue\r\nConnection: keep-alive\r\n\r\n")
	if !strings.HasPrefix(http10, testHTTP10OKLine) ||
		strings.Contains(http10, "100 Continue") ||
		strings.Contains(strings.ToLower(http10), "keep-alive") ||
		strings.Count(strings.ToLower(http10), "\r\nconnection: close\r\n") != 1 {
		t.Fatalf("HTTP/1.0 close repair = %q", http10)
	}

	http10Cases := []struct {
		name   string
		fields string
		body   string
		status string
	}{
		{name: "chunked", fields: testChunkedField, body: testZeroChunkTerminator, status: testBadRequestReason},
		{name: "unsupported final", fields: testGzipThenChunkedField, status: testBadRequestReason},
		{name: "coding without chunked", fields: testGzipField, status: testBadRequestReason},
		{name: "non-final", fields: testChunkedThenGzipField, status: testBadRequestReason},
		{name: testRepeatedName, fields: testRepeatedChunkedField, status: testBadRequestReason},
		{name: testMultipleFieldsName, fields: "Transfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n", status: testBadRequestReason},
		{name: "parameterized", fields: testChunkedParameterField, status: testBadRequestReason},
		{name: transportTestEmpty, fields: testTransferEncodingEmptyField, status: testBadRequestReason},
		{name: "empty normalized", fields: "Transfer-Encoding:\r\n", status: testBadRequestReason},
		{name: testTransferPlusLengthName, fields: testChunkedWithLengthFields, status: testBadRequestReason},
		{name: "TE obs fold", fields: "Transfer-Encoding: chunked\r\n gzip\r\n", status: testBadRequestReason},
		{name: "continue ignored", fields: testExpectContinueField, status: testStatusOK},
		{name: "unsupported expect", fields: "Expect: other\r\n", status: testStatusExpectationFailed},
		{name: "mixed expect", fields: "Expect: 100-continue, other\r\n", status: testStatusExpectationFailed},
		{name: "malformed expect", fields: "Expect: value=\"unterminated\r\n", status: testStatusExpectationFailed},
		{name: "Expect obs fold", fields: "Expect: 100-continue\r\n other\r\n", status: testBadRequestReason},
	}
	for _, testCase := range http10Cases {
		testCase := testCase
		t.Run("HTTP10_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"GET /healthz HTTP/1.0\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n"+testCase.body)
			if strings.Contains(response, "100 Continue") ||
				!strings.HasPrefix(response, "HTTP/1.0 "+testCase.status) {
				t.Fatalf("response = %q", response)
			}
		})
	}

	multiChunkedCases := []struct {
		name   string
		fields string
	}{
		{name: "empty members", fields: "Transfer-Encoding: , chunked,\r\n"},
		{name: testMultipleFieldsName, fields: "Transfer-Encoding: ,\r\nTransfer-Encoding: chunked\r\n"},
		{name: "mixed case multiple fields", fields: "Transfer-Encoding: \r\nTransfer-Encoding: Chunked\r\n"},
	}
	for _, testCase := range multiChunkedCases {
		testCase := testCase
		t.Run("semantic_single_chunked_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n0\r\n\r\n")
			if !strings.HasPrefix(response, testHTTP11BadRequestLine) ||
				!strings.Contains(response, `"code":"invalid_contract"`) {
				t.Fatalf("response = %q", response)
			}
		})
	}

	teObsFold := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+
			"\r\nTransfer-Encoding: chunked\r\n gzip\r\n\r\n")
	if !strings.HasPrefix(teObsFold, "HTTP/1.1 400 Bad Request") {
		t.Fatalf("HTTP/1.1 TE obs-fold = %q", teObsFold)
	}

	precedenceCases := []struct {
		name    string
		request string
		status  string
	}{
		{
			name: "unimplemented before Expect",
			request: "PUT /healthz HTTP/1.1\r\nHost: " + address +
				"\r\nExpect: 100-continue\r\n\r\n",
			status: testStatusNotImplemented,
		},
		{
			name: "unknown route before Expect",
			request: "GET /unknown HTTP/1.1\r\nHost: " + address +
				"\r\nExpect: 100-continue\r\n\r\n",
			status: "404 Not Found",
		},
		{
			name: "route method before Expect",
			request: "GET /v1/process HTTP/1.1\r\nHost: " + address +
				"\r\nExpect: 100-continue\r\n\r\n",
			status: "405 Method Not Allowed",
		},
		{
			name: "Expect inert-name collision",
			request: "GET /healthz HTTP/1.1\r\nHost: " + address +
				"\r\nX-Dk2E: collision\r\nExpect: 100-continue\r\n\r\n",
			status: testStatusExpectationFailed,
		},
		{
			name: "framing inert-name collision",
			request: "GET /healthz HTTP/1.1\r\nHost: " + address +
				"\r\nX-DKIM2-Framing-X: collision\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			status: testBadRequestReason,
		},
	}
	for _, testCase := range precedenceCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address, testCase.request)
			if strings.Contains(response, "100 Continue") ||
				!strings.HasPrefix(response, "HTTP/1.1 "+testCase.status) ||
				strings.Contains(strings.ToLower(response), "collision") {
				t.Fatalf("response = %q", response)
			}
		})
	}
}

// TestHTTPBoundaryRawAdmittedExpectIsSingletonAndInertAtLowerLayer freezes informational ownership.
func TestHTTPBoundaryRawAdmittedExpectIsSingletonAndInertAtLowerLayer(t *testing.T) {
	address, handler := startRawBoundaryServer(t)
	observations := make(chan boundaryHeaderDeletionObservation, 3)
	handler.generated = &boundaryHeaderDeletionSpy{
		ServerInterface: handler.generated,
		observations:    observations,
	}
	capability := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	tests := []struct {
		name   string
		expect string
	}{
		{name: testCaseName, expect: "Expect: 100-Continue\r\n"},
		{
			name:   testRepeatedName,
			expect: "Expect: 100-continue\r\nExpect: 100-continue\r\n",
		},
		{
			name:   "multifield empty and case",
			expect: "Expect: ,\r\nExpect: ,100-CONTINUE,\r\n",
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"POST /v1/process HTTP/1.1\r\n"+
					"Host: "+address+"\r\n"+
					testContentTypeJSONField+
					"X-DKIM2-Capability: "+capability+"\r\n"+
					"X-Dk2E: client-collision\r\n"+
					"X-DKIM2-Framing-X: client-collision\r\n"+
					"Content-Length: "+strconv.Itoa(len(validMinimalProcessJSON))+"\r\n"+
					testCase.expect+"\r\n"+
					validMinimalProcessJSON)
			if !strings.HasPrefix(response, "HTTP/1.1 100 Continue\r\n\r\n") ||
				strings.Count(response, "HTTP/1.1 100 Continue\r\n\r\n") != 1 ||
				strings.Count(response, "HTTP/1.1 500 Internal Server Error\r\n") != 1 ||
				strings.Count(response, "HTTP/1.1 ") != 2 {
				t.Fatalf("admitted Expect wire sequence differs: %q", response)
			}
			observation := <-observations
			if observation.expectInertCount != 0 ||
				observation.framingInertCount != 0 {
				t.Fatalf("inert fields reached generated code: %#v", observation)
			}
		})
	}
}

// TestHTTPBoundaryRawContentTypeAndCapabilityMatrices freezes process preflight.
func TestHTTPBoundaryRawContentTypeAndCapabilityMatrices(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xa5}, 32))
	mediaCases := []struct {
		name   string
		fields string
		status string
	}{
		{name: testExactName, fields: testContentTypeJSONField, status: testForbiddenReason},
		{name: testCaseName, fields: "Content-Type: Application/JSON\r\n", status: testForbiddenReason},
		{name: "token charset", fields: "Content-Type: application/json ; charset=UTF-8\r\n", status: testForbiddenReason},
		{name: "quoted charset", fields: "Content-Type: application/json;charset=\"utf-8\"\r\n", status: testForbiddenReason},
		{name: "quoted pair", fields: "Content-Type: application/json;charset=\"utf\\-8\"\r\n", status: testForbiddenReason},
		{name: testEmptyParametersName, fields: "Content-Type: application/json;;; charset=utf-8;;\r\n", status: testForbiddenReason},
		{name: transportTestAbsent, status: testUnsupportedMediaTypeReason},
		{name: transportTestEmpty, fields: "Content-Type:\r\n", status: testUnsupportedMediaTypeReason},
		{name: "duplicate fields", fields: "Content-Type: application/json\r\nContent-Type: application/json\r\n", status: testUnsupportedMediaTypeReason},
		{name: "comma list", fields: "Content-Type: application/json, application/json\r\n", status: testUnsupportedMediaTypeReason},
		{name: testWrongTypeName, fields: "Content-Type: text/json\r\n", status: testUnsupportedMediaTypeReason},
		{name: "wrong charset", fields: "Content-Type: application/json;charset=latin1\r\n", status: testUnsupportedMediaTypeReason},
		{name: "duplicate charset", fields: "Content-Type: application/json;charset=utf-8;charset=utf-8\r\n", status: testUnsupportedMediaTypeReason},
		{name: "space before equals", fields: "Content-Type: application/json;charset =utf-8\r\n", status: testUnsupportedMediaTypeReason},
		{name: "space after equals", fields: "Content-Type: application/json;charset= utf-8\r\n", status: testUnsupportedMediaTypeReason},
		{name: "extended", fields: "Content-Type: application/json;charset*=utf-8\r\n", status: testUnsupportedMediaTypeReason},
		{name: "continuation", fields: "Content-Type: application/json;charset*0=utf-8\r\n", status: testUnsupportedMediaTypeReason},
		{name: "extra", fields: "Content-Type: application/json;foo=bar\r\n", status: testUnsupportedMediaTypeReason},
		{name: "unterminated", fields: "Content-Type: application/json;charset=\"utf-8\r\n", status: testUnsupportedMediaTypeReason},
		{name: "dangling escape", fields: "Content-Type: application/json;charset=\"utf-8\\\"\r\n", status: testUnsupportedMediaTypeReason},
		{name: "missing value", fields: "Content-Type: application/json;charset=\r\n", status: testUnsupportedMediaTypeReason},
	}
	for _, testCase := range mediaCases {
		testCase := testCase
		t.Run("media_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"POST /v1/process HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"Content-Length: 2\r\n\r\n{}")
			if !strings.HasPrefix(response, "HTTP/1.1 "+testCase.status+"\r\n") {
				t.Fatalf("response = %q", response)
			}
		})
	}

	capabilityCases := []struct {
		name   string
		fields string
		status string
	}{
		{name: testMissingName, status: testForbiddenReason},
		{name: transportTestEmpty, fields: "X-DKIM2-Capability:\r\n", status: testForbiddenReason},
		{name: "OWS canonical", fields: "X-DKIM2-Capability: \t" + secret + " \t\r\n", status: testBadRequestReason},
		{name: "wrong length", fields: "X-DKIM2-Capability: " + secret[:42] + "\r\n", status: testForbiddenReason},
		{name: "padded", fields: "X-DKIM2-Capability: " + secret + "=\r\n", status: testForbiddenReason},
		{name: testCommaName, fields: "X-DKIM2-Capability: " + secret + ",\r\n", status: testForbiddenReason},
		{name: transportTestMalformed, fields: "X-DKIM2-Capability: " + strings.Repeat("x", 42) + "*\r\n", status: testForbiddenReason},
		{name: "noncanonical trailing bits", fields: "X-DKIM2-Capability: " + secret[:42] + "_\r\n", status: testForbiddenReason},
		{name: testMismatchName, fields: "X-DKIM2-Capability: " + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xb6}, 32)) + "\r\n", status: testForbiddenReason},
		{name: testDuplicateName, fields: "X-DKIM2-Capability: " + secret + "\r\nX-DKIM2-Capability: " + secret + "\r\n", status: testForbiddenReason},
		{name: "canonical", fields: "X-DKIM2-Capability: " + secret + "\r\n", status: testBadRequestReason},
	}
	for _, testCase := range capabilityCases {
		testCase := testCase
		t.Run("capability_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"POST /v1/process HTTP/1.1\r\nHost: "+address+"\r\n"+
					testContentTypeJSONField+testCase.fields+
					"Content-Length: 2\r\n\r\n{}")
			if !strings.HasPrefix(response, "HTTP/1.1 "+testCase.status+"\r\n") ||
				strings.Contains(strings.ToLower(response), "x-dkim2-capability") ||
				strings.Contains(response, secret) {
				t.Fatal("capability response shape differs")
			}
		})
	}

	statusWithCapability := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+
			"\r\nX-DKIM2-Capability: "+secret+"\r\n\r\n")
	if !strings.HasPrefix(statusWithCapability, testHTTP11OKLine) ||
		strings.Contains(statusWithCapability, secret) ||
		strings.Contains(strings.ToLower(statusWithCapability), "x-dkim2-capability") {
		t.Fatal("status route consumed or reflected process capability")
	}
}

// TestHTTPBoundaryRawStatusConditionals freezes selected-representation semantics.
func TestHTTPBoundaryRawStatusConditionals(t *testing.T) {
	address, handler := startRawBoundaryServer(t)
	selected := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	tag := rawResponseHeader(selected, "ETag")
	if tag == "" || !strings.HasPrefix(tag, `"`) || !strings.HasSuffix(tag, `"`) {
		t.Fatalf("selected ETag = %q", tag)
	}
	selectedBody := rawResponseBody(selected)
	digest := sha256.Sum256([]byte(selectedBody))
	wantTag := `"` + hex.EncodeToString(digest[:]) + `"`
	if tag != wantTag {
		t.Fatalf("selected ETag = %q, want body digest %q", tag, wantTag)
	}
	tests := []rawConditionalCase{
		{name: "If-Match strong", fields: "If-Match: " + tag + "\r\n", statusLine: testHTTP11OKLine},
		{name: "If-Match star", fields: "If-Match: *\r\n", statusLine: testHTTP11OKLine},
		{name: "If-Match weak fails", fields: "If-Match: W/" + tag + "\r\n", statusLine: testHTTP11PreconditionFailedLine, code: testPreconditionFailedCode},
		{name: "If-Match mismatch", fields: "If-Match: \"other\"\r\n", statusLine: testHTTP11PreconditionFailedLine, code: testPreconditionFailedCode},
		{name: "If-Match matching strong list", fields: "If-Match: \"other\", " + tag + "\r\n", statusLine: testHTTP11OKLine},
		{name: "If-Match nonmatching strong weak list", fields: "If-Match: W/" + tag + ", \"other\"\r\n", statusLine: testHTTP11PreconditionFailedLine, code: testPreconditionFailedCode},
		{name: "If-Match empty list", fields: "If-Match: ,,\r\n", statusLine: testHTTP11PreconditionFailedLine, code: testPreconditionFailedCode},
		{name: "If-None strong", fields: "If-None-Match: " + tag + "\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None weak", fields: "If-None-Match: W/" + tag + "\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None star", fields: "If-None-Match: *\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None matching strong list", fields: "If-None-Match: \"other\", " + tag + "\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None matching weak list", fields: "If-None-Match: \"other\", W/" + tag + "\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None nonmatching strong weak list", fields: "If-None-Match: \"other\", W/\"another\"\r\n", statusLine: testHTTP11OKLine},
		{name: "If-None empty members around match", fields: "If-None-Match: , " + tag + ",,\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None multiple fields", fields: "If-None-Match: \"other\"\r\nIf-None-Match: W/" + tag + "\r\n", statusLine: testHTTP11NotModifiedLine},
		{name: "If-None empty", fields: "If-None-Match: ,,\r\n", statusLine: testHTTP11OKLine},
		{name: "empty opaque", fields: "If-None-Match: \"\"\r\n", statusLine: testHTTP11OKLine},
		{name: "embedded comma opaque", fields: "If-None-Match: \"opaque,tag\"\r\n", statusLine: testHTTP11OKLine},
		{name: "literal backslash", fields: "If-None-Match: \"literal\\\\tag\"\r\n", statusLine: testHTTP11OKLine},
		{name: "obs text", fields: string([]byte("If-None-Match: \"\x80\xff\"\r\n")), statusLine: testHTTP11OKLine},
		{name: transportTestMalformed, fields: "If-None-Match: W/\"unterminated\r\n", statusLine: testHTTP11BadRequestLine, code: "invalid_contract"},
		{name: "mixed star", fields: "If-None-Match: *, \"other\"\r\n", statusLine: testHTTP11BadRequestLine, code: "invalid_contract"},
		{name: "If-Match order", fields: "If-Match: \"other\"\r\nIf-None-Match: W/\"unterminated\r\n", statusLine: testHTTP11PreconditionFailedLine, code: testPreconditionFailedCode},
		{name: "date and range ignored", fields: "If-Modified-Since: invalid\r\nIf-Unmodified-Since: invalid\r\nRange: invalid\r\nIf-Range: invalid\r\n", statusLine: testHTTP11OKLine},
	}
	assertRawConditionalCases(t, address, selected, tag, tests)

	unchanged := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	processor, ok := handler.strict.processor.(*boundaryProcessor)
	if !ok {
		t.Fatal("raw processor fixture type changed")
	}
	if rawResponseHeader(unchanged, "ETag") != tag ||
		rawResponseBody(unchanged) != selectedBody ||
		processor.calls.Load() != 0 {
		t.Fatal("conditional evaluation mutated representation or entered domain I/O")
	}

	const selectedDate = "Thu, 01 Jan 1970 00:00:00 GMT"
	datedAddress, _ := startRawBoundaryServerWithDate(
		t,
		func() (string, bool) { return selectedDate, true },
	)
	datedSelected := rawBoundaryExchange(t, datedAddress,
		"GET /healthz HTTP/1.1\r\nHost: "+datedAddress+"\r\n\r\n")
	datedTag := rawResponseHeader(datedSelected, "ETag")
	datedNotModified := rawBoundaryExchange(t, datedAddress,
		"GET /healthz HTTP/1.1\r\nHost: "+datedAddress+
			"\r\nIf-None-Match: "+datedTag+"\r\n\r\n")
	assertRawResponseExact(
		t,
		datedNotModified,
		"HTTP/1.1 304 Not Modified",
		map[string]string{
			testNoStoreHeader:    testNoStoreValue,
			testConnectionHeader: testCloseValue,
			"date":               selectedDate,
			"etag":               datedTag,
		},
		"",
	)

	lazy := rawBoundaryExchange(t, address,
		"POST /healthz HTTP/1.1\r\nHost: "+address+
			"\r\nIf-None-Match: W/\"unterminated\r\n\r\n")
	if !strings.HasPrefix(lazy, testHTTP11MethodNotAllowedLine) ||
		!strings.Contains(lazy, `"code":"method_not_allowed"`) {
		t.Fatalf("conditional preempted earlier route result: %q", lazy)
	}

	ordinaryBadRequest := rawBoundaryExchange(t, address,
		"GET /healthz?query HTTP/1.1\r\nHost: "+address+
			"\r\nIf-None-Match: W/\"unterminated\r\n\r\n")
	if !strings.HasPrefix(ordinaryBadRequest, testHTTP11BadRequestLine) ||
		!strings.Contains(ordinaryBadRequest, `"code":"invalid_contract"`) {
		t.Fatalf("conditional preempted ordinary 400: %q", ordinaryBadRequest)
	}

	notFound := rawBoundaryExchange(t, address,
		"GET /unknown HTTP/1.1\r\nHost: "+address+
			"\r\nIf-None-Match: W/\"unterminated\r\n\r\n")
	if !strings.HasPrefix(notFound, testHTTP11NotFoundLine) ||
		!strings.Contains(notFound, `"code":"not_found"`) {
		t.Fatalf("conditional preempted ordinary 404: %q", notFound)
	}

	readiness, ok := handler.strict.readiness.(*boundaryReadiness)
	if !ok {
		t.Fatal("raw readiness fixture type changed")
	}
	readiness.ready.Store(false)
	notReady := rawBoundaryExchange(t, address,
		"GET /readyz HTTP/1.1\r\nHost: "+address+
			"\r\nIf-None-Match: W/\"unterminated\r\n\r\n")
	if !strings.HasPrefix(notReady, "HTTP/1.1 503 Service Unavailable\r\n") ||
		!strings.Contains(notReady, `"code":"service_not_ready"`) {
		t.Fatalf("conditional preempted readiness 503: %q", notReady)
	}

	head304 := rawBoundaryExchange(t, address,
		"HEAD /healthz HTTP/1.1\r\nHost: "+address+
			"\r\nIf-None-Match: "+tag+"\r\n\r\n")
	if !strings.HasPrefix(head304, testHTTP11NotModifiedLine) ||
		strings.Contains(head304, "\r\n\r\n{") {
		t.Fatalf("HEAD 304 differs: %q", head304)
	}
	head412 := rawBoundaryExchange(t, address,
		"HEAD /healthz HTTP/1.1\r\nHost: "+address+
			"\r\nIf-Match: \"other\"\r\n\r\n")
	if !strings.HasPrefix(head412, testHTTP11PreconditionFailedLine) ||
		rawResponseHeader(head412, "Content-Length") == "" ||
		strings.Contains(head412, "\r\n\r\n{") {
		t.Fatalf("HEAD 412 differs: %q", head412)
	}

	ignoredCases := []struct {
		name    string
		request string
		status  string
	}{
		{
			name: "process",
			request: "POST /v1/process HTTP/1.1\r\nHost: " + address +
				"\r\nContent-Type: application/json\r\nContent-Length: 2\r\n" +
				"If-None-Match: W/\"unterminated\r\n\r\n{}",
			status: testForbiddenReason,
		},
		{
			name: testOPTIONSMethod,
			request: "OPTIONS * HTTP/1.1\r\nHost: " + address +
				"\r\nIf-None-Match: W/\"unterminated\r\n\r\n",
			status: "204 No Content",
		},
		{
			name: "CONNECT",
			request: "CONNECT " + address + " HTTP/1.1\r\nHost: " + address +
				"\r\nIf-None-Match: W/\"unterminated\r\n\r\n",
			status: testStatusNotImplemented,
		},
		{
			name: "unimplemented",
			request: "PUT /healthz HTTP/1.1\r\nHost: " + address +
				"\r\nIf-None-Match: W/\"unterminated\r\n\r\n",
			status: testStatusNotImplemented,
		},
	}
	for _, testCase := range ignoredCases {
		testCase := testCase
		t.Run("ignored_"+testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address, testCase.request)
			if !strings.HasPrefix(response, "HTTP/1.1 "+testCase.status) {
				t.Fatalf("conditional was not ignored: %q", response)
			}
		})
	}
}

type rawConditionalCase struct {
	name       string
	fields     string
	statusLine string
	code       string
}

// assertRawConditionalCases verifies each selected-representation conditional.
func assertRawConditionalCases(
	t *testing.T,
	address string,
	selected string,
	tag string,
	tests []rawConditionalCase,
) {
	t.Helper()
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address,
				"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n"+
					testCase.fields+"\r\n")
			if !strings.HasPrefix(response, testCase.statusLine) {
				t.Fatalf("response = %q", response)
			}
			if testCase.code != "" &&
				!strings.Contains(response, `"code":"`+testCase.code+`"`) {
				t.Fatalf("response code differs: %q", response)
			}
			if strings.Contains(testCase.statusLine, "304") {
				if rawResponseHeader(response, "ETag") != tag ||
					rawResponseHeader(response, "Cache-Control") != testNoStoreValue ||
					rawResponseHeader(response, "Connection") != testCloseValue ||
					strings.Contains(response, "\r\n\r\n{") {
					t.Fatalf("304 representation differs: %q", response)
				}
				headers := map[string]string{
					testNoStoreHeader:    testNoStoreValue,
					testConnectionHeader: testCloseValue,
					"etag":               tag,
				}
				if selectedDate := rawResponseHeader(selected, "Date"); selectedDate != "" {
					headers["date"] = selectedDate
				}
				assertRawResponseExact(
					t,
					response,
					"HTTP/1.1 304 Not Modified",
					headers,
					"",
				)
			}
			if strings.Contains(testCase.statusLine, "412") {
				body := `{"api_version":"v1","category":"request","code":"precondition_failed",` +
					`"draft":"draft-ietf-dkim-dkim2-spec-04"}`
				assertRawResponseExact(
					t,
					response,
					"HTTP/1.1 412 Precondition Failed",
					map[string]string{
						testNoStoreHeader:        testNoStoreValue,
						testConnectionHeader:     testCloseValue,
						"content-length":         strconv.Itoa(len(body)),
						"content-type":           jsonContentType,
						"x-content-type-options": testNoSniffValue,
					},
					body,
				)
			}
		})
	}
}

// TestHTTPBoundaryRawGETHEADParity freezes complete selected and error metadata.
func TestHTTPBoundaryRawGETHEADParity(t *testing.T) {
	address, handler := startRawBoundaryServer(t)
	selected := rawBoundaryExchange(t, address,
		"GET /healthz HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	tag := rawResponseHeader(selected, "ETag")
	readiness, ok := handler.strict.readiness.(*boundaryReadiness)
	if !ok {
		t.Fatal("raw readiness fixture type changed")
	}
	tests := []struct {
		name       string
		getTarget  string
		headTarget string
		fields     string
		before     func()
		statusLine string
		bodyInGET  bool
	}{
		{
			name:       "200",
			getTarget:  testHealthPath,
			headTarget: testHealthPath,
			statusLine: testHTTP11OKLine,
			bodyInGET:  true,
		},
		{
			name:       "200 readiness",
			getTarget:  testReadinessPath,
			headTarget: testReadinessPath,
			statusLine: testHTTP11OKLine,
			bodyInGET:  true,
		},
		{
			name:       "400",
			getTarget:  "/healthz?query",
			headTarget: "/healthz?query",
			statusLine: testHTTP11BadRequestLine,
			bodyInGET:  true,
		},
		{
			name:       "404",
			getTarget:  testUnknownPath,
			headTarget: testUnknownPath,
			statusLine: testHTTP11NotFoundLine,
			bodyInGET:  true,
		},
		{
			name:       "405 process",
			getTarget:  testProcessPath,
			headTarget: testProcessPath,
			statusLine: testHTTP11MethodNotAllowedLine,
			bodyInGET:  true,
		},
		{
			name:       "503 readiness",
			getTarget:  testReadinessPath,
			headTarget: testReadinessPath,
			before:     func() { readiness.ready.Store(false) },
			statusLine: "HTTP/1.1 503 Service Unavailable\r\n",
			bodyInGET:  true,
		},
		{
			name:       "304",
			getTarget:  testHealthPath,
			headTarget: testHealthPath,
			fields:     "If-None-Match: " + tag + "\r\n",
			statusLine: testHTTP11NotModifiedLine,
		},
		{
			name:       "412",
			getTarget:  testHealthPath,
			headTarget: testHealthPath,
			fields:     "If-Match: \"other\"\r\n",
			statusLine: testHTTP11PreconditionFailedLine,
			bodyInGET:  true,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			readiness.ready.Store(true)
			if testCase.before != nil {
				testCase.before()
			}
			get := rawBoundaryExchange(t, address,
				"GET "+testCase.getTarget+" HTTP/1.1\r\nHost: "+address+
					"\r\n"+testCase.fields+"\r\n")
			head := rawBoundaryExchange(t, address,
				"HEAD "+testCase.headTarget+" HTTP/1.1\r\nHost: "+address+
					"\r\n"+testCase.fields+"\r\n")
			if !strings.HasPrefix(get, testCase.statusLine) ||
				!strings.HasPrefix(head, testCase.statusLine) ||
				rawResponseHead(get) != rawResponseHead(head) {
				t.Fatalf("GET/HEAD metadata differs: GET=%q HEAD=%q", get, head)
			}
			if (rawResponseBody(get) != "") != testCase.bodyInGET ||
				rawResponseBody(head) != "" {
				t.Fatalf("GET/HEAD body presence differs: GET=%q HEAD=%q", get, head)
			}
		})
	}

	goGET := rawBoundaryExchange(t, address, "GET /healthz HTTP/1.1\r\n\r\n")
	goHEAD := rawBoundaryExchange(t, address, "HEAD /healthz HTTP/1.1\r\n\r\n")
	if !strings.HasPrefix(goGET, testHTTP11BadRequestPrefix) ||
		!strings.HasPrefix(goHEAD, testHTTP11BadRequestPrefix) ||
		rawResponseHead(goGET) != rawResponseHead(goHEAD) ||
		rawResponseBody(goGET) == "" || rawResponseBody(goHEAD) != "" {
		t.Fatalf("Go-owned GET/HEAD differs: GET=%q HEAD=%q", goGET, goHEAD)
	}

	oversizedTarget := "/" + strings.Repeat("x", transportRequestTargetLimit)
	tooLongGET := rawBoundaryExchange(t, address,
		"GET "+oversizedTarget+" HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	tooLongHEAD := rawBoundaryExchange(t, address,
		"HEAD "+oversizedTarget+" HTTP/1.1\r\nHost: "+address+"\r\n\r\n")
	if !strings.HasPrefix(tooLongGET, testHTTP11URITooLongLine) ||
		!strings.HasPrefix(tooLongHEAD, testHTTP11URITooLongLine) ||
		rawResponseHead(tooLongGET) != rawResponseHead(tooLongHEAD) ||
		rawResponseBody(tooLongGET) != "" || rawResponseBody(tooLongHEAD) != "" {
		t.Fatalf("pre-handler 414 GET/HEAD differs: GET=%q HEAD=%q",
			tooLongGET, tooLongHEAD)
	}
}

// TestHTTPBoundaryRawFinalResponsesAreSingletonAndNonreflecting freezes wire shape.
func TestHTTPBoundaryRawFinalResponsesAreSingletonAndNonreflecting(t *testing.T) {
	address, _ := startRawBoundaryServer(t)
	const marker = "DO-NOT-REFLECT-HTTP-BOUNDARY"
	tests := []struct {
		name          string
		request       string
		statusLine    string
		contentLength string
		contentType   bool
		body          bool
		exactBody     string
	}{
		{
			name: "application 404",
			request: "GET /" + marker + " HTTP/1.1\r\nHost: " + address +
				"\r\nX-Marker: " + marker + "\r\n\r\n",
			statusLine:  testHTTP11NotFoundLine,
			contentType: true,
			body:        true,
			exactBody: `{"api_version":"v1","category":"request","code":"not_found",` +
				`"draft":"draft-ietf-dkim-dkim2-spec-04"}`,
		},
		{
			name:          "header-only 501",
			request:       marker + " /healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine:    testHTTP11NotImplementedLine,
			contentLength: "0",
		},
		{
			name: "header-only 414",
			request: "GET /" + strings.Repeat("x", transportRequestTargetLimit) +
				" HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
			statusLine:    testHTTP11URITooLongLine,
			contentLength: "0",
		},
		{
			name: "application 417",
			request: "GET /healthz HTTP/1.1\r\nHost: " + address +
				"\r\nExpect: " + marker + "\r\n\r\n",
			statusLine:  "HTTP/1.1 417 Expectation Failed\r\n",
			contentType: true,
			body:        true,
			exactBody: `{"api_version":"v1","category":"request","code":"expectation_failed",` +
				`"draft":"draft-ietf-dkim-dkim2-spec-04"}`,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response := rawBoundaryExchange(t, address, testCase.request)
			lower := strings.ToLower(response)
			if !strings.HasPrefix(response, testCase.statusLine) ||
				strings.Count(response, "HTTP/1.1 ") != 1 ||
				strings.Count(lower, "\r\nconnection: close\r\n") != 1 ||
				strings.Count(lower, "\r\ncache-control: no-store\r\n") != 1 ||
				strings.Count(lower, "\r\nx-content-type-options: nosniff\r\n") != 1 ||
				strings.Contains(response, marker) {
				t.Fatal("final response singleton or nonreflection shape differs")
			}
			if got := rawResponseHeader(response, "Content-Length"); testCase.contentLength != "" && got != testCase.contentLength {
				t.Fatalf("Content-Length = %q, want %q", got, testCase.contentLength)
			}
			if (rawResponseHeader(response, "Content-Type") != "") != testCase.contentType ||
				(rawResponseBody(response) != "") != testCase.body {
				t.Fatal("final content metadata/body shape differs")
			}
			headers := map[string]string{
				testNoStoreHeader:        testNoStoreValue,
				testConnectionHeader:     testCloseValue,
				"content-length":         testCase.contentLength,
				"x-content-type-options": testNoSniffValue,
			}
			if testCase.body {
				headers["content-length"] = strconv.Itoa(len(testCase.exactBody))
				headers["content-type"] = jsonContentType
			}
			assertRawResponseExact(
				t,
				response,
				strings.TrimSuffix(testCase.statusLine, "\r\n"),
				headers,
				testCase.exactBody,
			)
		})
	}
}

// TestHTTPBoundaryRawHeaderOnlyDatePolicy freezes provider-only Date ownership.
func TestHTTPBoundaryRawHeaderOnlyDatePolicy(t *testing.T) {
	const validDate = "Thu, 01 Jan 1970 00:00:00 GMT"
	providers := []struct {
		name     string
		provider func() (string, bool)
		valid    bool
	}{
		{name: testUnavailableName},
		{
			name:     "invalid",
			provider: func() (string, bool) { return "not-an-http-date", true },
		},
		{
			name:     "valid",
			provider: func() (string, bool) { return validDate, true },
			valid:    true,
		},
	}
	for _, provider := range providers {
		provider := provider
		t.Run(provider.name, func(t *testing.T) {
			address, _ := startRawBoundaryServerWithDate(t, provider.provider)
			tests := []struct {
				name       string
				request    string
				statusLine string
				dated      bool
			}{
				{
					name:       testOPTIONSMethod,
					request:    "OPTIONS * HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
					statusLine: testHTTP11NoContentLine,
					dated:      true,
				},
				{
					name: "414",
					request: "GET /" + strings.Repeat("x", transportRequestTargetLimit) +
						" HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
					statusLine: testHTTP11URITooLongLine,
					dated:      true,
				},
				{
					name:       "501",
					request:    "PUT /healthz HTTP/1.1\r\nHost: " + address + "\r\n\r\n",
					statusLine: testHTTP11NotImplementedLine,
				},
				{
					name:       "505",
					request:    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
					statusLine: "HTTP/1.1 505 HTTP Version Not Supported\r\n",
				},
			}
			for _, testCase := range tests {
				testCase := testCase
				t.Run(testCase.name, func(t *testing.T) {
					response := rawBoundaryExchange(t, address, testCase.request)
					date := rawResponseHeader(response, "Date")
					wantDate := provider.valid && testCase.dated
					if !strings.HasPrefix(response, testCase.statusLine) ||
						wantDate && date != validDate ||
						!wantDate && date != "" ||
						strings.Count(strings.ToLower(response), "\r\ndate:") > 1 {
						t.Fatalf("header-only Date policy differs: %q", response)
					}
				})
			}
		})
	}
}

// rawResponseHeader returns one exact response header value.
func rawResponseHeader(response string, name string) string {
	prefix := strings.ToLower(name) + ":"
	for _, line := range strings.Split(response, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
	}
	return ""
}

// rawResponseBody returns bytes following the first complete response head.
func rawResponseBody(response string) string {
	_, body, found := strings.Cut(response, "\r\n\r\n")
	if !found {
		return ""
	}
	return body
}

// rawResponseHead returns the complete first response head.
func rawResponseHead(response string) string {
	head, _, found := strings.Cut(response, "\r\n\r\n")
	if !found {
		return response
	}
	return head + "\r\n\r\n"
}

// assertRawResponseExact requires one status, singleton header set, and exact terminal body.
func assertRawResponseExact(
	t testing.TB,
	response string,
	statusLine string,
	wantHeaders map[string]string,
	wantBody string,
) {
	t.Helper()
	head, body, found := strings.Cut(response, "\r\n\r\n")
	if !found || body != wantBody {
		t.Fatalf("raw response body = %q, want %q", body, wantBody)
	}
	lines := strings.Split(head, "\r\n")
	if len(lines) == 0 || lines[0] != statusLine {
		t.Fatalf("raw status line = %q, want %q", lines[0], statusLine)
	}
	gotHeaders := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		key := strings.ToLower(name)
		if !ok || key == "" {
			t.Fatalf("malformed raw response field %q", line)
		}
		if _, duplicate := gotHeaders[key]; duplicate {
			t.Fatalf("duplicate raw response field %q", name)
		}
		gotHeaders[key] = strings.TrimSpace(value)
	}
	if len(gotHeaders) != len(wantHeaders) {
		t.Fatalf("raw response header set = %#v, want %#v", gotHeaders, wantHeaders)
	}
	for name, want := range wantHeaders {
		if got := gotHeaders[name]; got != want {
			t.Fatalf("raw response header %s = %q, want %q", name, got, want)
		}
	}
}

// rawBoundaryChunkedExchange writes one request across explicit TCP segments.
func rawBoundaryChunkedExchange(
	t testing.TB,
	address string,
	chunks []string,
) string {
	t.Helper()
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal("raw chunked Dial() failed")
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal("raw chunked deadline failed")
	}
	for _, chunk := range chunks {
		if _, err := io.WriteString(connection, chunk); err != nil {
			t.Fatal("raw chunked request write failed")
		}
	}
	response, _ := io.ReadAll(connection)
	return string(response)
}

// FuzzHTTPBoundaryPrecedence retains bounded raw-head parser and outer-gate coverage.
func FuzzHTTPBoundaryPrecedence(f *testing.F) {
	seeds := [][]byte{
		[]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n"),
		[]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
		[]byte("GET /healthz HTTP/1.0\r\nHost: 127.0.0.1:8080\r\nExpect: 100-continue\r\n\r\n"),
		[]byte("GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
		[]byte("OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 0\r\n\r\n"),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}
	validator, err := NewRequestValidator()
	if err != nil {
		f.Fatal("NewRequestValidator() failed")
	}
	readiness := &boundaryReadiness{}
	readiness.ready.Store(true)
	handler, err := NewHTTPBoundary(BoundaryConfig{
		Authority:       boundaryTestAuthority,
		RequestDeadline: maxProcessAdmissionWait,
		MaxInFlight:     1,
		MaxWaiters:      0,
		AdmissionWait:   0,
	}, &boundaryCapabilityMatcher{value: bytes.Repeat([]byte{0xa5}, 32)},
		readiness, &boundaryProcessor{}, &boundaryFatalNotifier{}, validator)
	if err != nil {
		f.Fatal("NewHTTPBoundary() failed")
	}
	f.Cleanup(handler.Close)

	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) == 0 || len(raw) > testRequestHeadLimit {
			return
		}
		captured := append([]byte(nil), raw...)
		headEnd := transportHeadTerminator(captured)
		if headEnd < 0 {
			return
		}
		facts, normalized, _ := prepareTransportHeadPrefix(captured, headEnd)
		request, err := httpReadBoundedRequest(normalized)
		if err != nil {
			return
		}
		defer func() { _ = request.Body.Close() }()
		state := newTransportState(nil)
		state.publishFacts(facts)
		request = request.WithContext(context.WithValue(
			request.Context(),
			transportContextKey{},
			state,
		))
		recorder := newBoundedFuzzRecorder()
		_ = serveBoundary(handler, recorder, request)
		state.finishTransportOwnership()
		if facts := state.Facts(); facts.hostValue != "" {
			t.Fatal("outer boundary retained Host after dispatch")
		}
		if recorder.status != 0 &&
			(recorder.status < 100 || recorder.status > 599) {
			t.Fatal("outer boundary emitted invalid status")
		}
	})
}

// httpReadBoundedRequest parses one already-captured request without socket I/O.
func httpReadBoundedRequest(value []byte) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReaderSize(
		bytes.NewReader(value),
		testRequestHeadLimit,
	))
}

type boundedFuzzRecorder struct {
	header http.Header
	status int
}

// newBoundedFuzzRecorder constructs one content-discarding response sink.
func newBoundedFuzzRecorder() *boundedFuzzRecorder {
	return &boundedFuzzRecorder{header: make(http.Header)}
}

// Header returns the fuzz sink's bounded response metadata.
func (r *boundedFuzzRecorder) Header() http.Header {
	return r.header
}

// WriteHeader records only the first final or informational status.
func (r *boundedFuzzRecorder) WriteHeader(status int) {
	if r.status == 0 || r.status < 200 {
		r.status = status
	}
}

// Write discards response bytes after recording implicit success.
func (r *boundedFuzzRecorder) Write(value []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return io.Discard.Write(value)
}
