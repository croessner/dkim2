package httpjson

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
)

const maxProcessBodyBytes = int64(47_878_316)

type bodyFailure uint8

const (
	bodyFailureTooLarge bodyFailure = iota + 1
	bodyFailureTimeout
	bodyFailureDisconnect
	bodyFailureInvalid
)

type bodyConsumptionContextKey struct{}

type bodyConsumptionState struct {
	unread atomic.Bool
}

// withBoundaryRequestState installs content-free ownership needed across request clones.
func withBoundaryRequestState(
	request *http.Request,
	unread bool,
) *http.Request {
	if request == nil {
		return nil
	}
	state := &bodyConsumptionState{}
	state.unread.Store(unread)
	ctx := context.WithValue(request.Context(), bodyConsumptionContextKey{}, state)
	return request.WithContext(ctx)
}

// boundaryBodyUnread reports whether the socket body still needs early-final containment.
func boundaryBodyUnread(request *http.Request) bool {
	if request == nil {
		return false
	}
	state, _ := request.Context().Value(bodyConsumptionContextKey{}).(*bodyConsumptionState)
	return state != nil && state.unread.Load()
}

// markBoundaryBodyConsumed publishes that body and trailers reached EOF.
func markBoundaryBodyConsumed(request *http.Request) {
	if request == nil {
		return
	}
	state, _ := request.Context().Value(bodyConsumptionContextKey{}).(*bodyConsumptionState)
	if state != nil {
		state.unread.Store(false)
	}
}

// clearBoundaryTrailers clears both active and original server request views.
func clearBoundaryTrailers(request *http.Request, original *http.Request) {
	if request == nil {
		return
	}
	request.Trailer = nil
	if original != nil {
		original.Trailer = nil
	}
}

// readProcessBody receives one bounded process body and discards the trailer channel.
func readProcessBody(
	writer http.ResponseWriter,
	request *http.Request,
	original *http.Request,
) ([]byte, bodyFailure) {
	if request == nil {
		return nil, bodyFailureInvalid
	}
	defer clearBoundaryTrailers(request, original)
	if writer == nil || request.Body == nil {
		return nil, bodyFailureInvalid
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxProcessBodyBytes)
	body, err := io.ReadAll(request.Body)
	clearBoundaryTrailers(request, original)
	if err == nil {
		request.Body = http.NoBody
		request.ContentLength = 0
		if original != nil {
			original.Body = http.NoBody
			original.ContentLength = 0
		}
		markBoundaryBodyConsumed(request)
		return body, 0
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, bodyFailureTooLarge
	}
	if state, ok := transportStateFromContext(request.Context()); ok {
		switch state.ReadTerminal() {
		case transportReadTerminalTimeout:
			return nil, bodyFailureTimeout
		case transportReadTerminalEOF, transportReadTerminalDisconnect, transportReadTerminalOther:
			return nil, bodyFailureDisconnect
		}
	}
	if errors.Is(err, errTransportRead) {
		return nil, bodyFailureDisconnect
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return nil, bodyFailureTimeout
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) {
		return nil, bodyFailureDisconnect
	}
	return nil, bodyFailureInvalid
}
