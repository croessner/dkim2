package httpjson

import (
	"context"
	"encoding/base64"
	"net/http"
)

const localCapabilityHeader = "X-DKIM2-Capability"

type localCapabilityMarker struct{}

// capabilityMatcher is the comparison-only protected capability boundary.
type capabilityMatcher interface {
	Equal([]byte) bool
}

// authenticateLocalCapability validates and removes the local process capability.
func authenticateLocalCapability(
	request *http.Request,
	matcher capabilityMatcher,
) (*http.Request, bool) {
	if request == nil {
		return request, false
	}
	values := request.Header.Values(localCapabilityHeader)
	request.Header.Del(localCapabilityHeader)
	if nilInterfaceValue(matcher) || len(values) != 1 || len(values[0]) != 43 {
		return request, false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
	defer clear(decoded)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != values[0] ||
		!matcher.Equal(decoded) {
		return request, false
	}
	return request.WithContext(context.WithValue(request.Context(), localCapabilityMarker{}, true)), true
}

// localCapabilityAuthenticated reports only the private preflight marker.
func localCapabilityAuthenticated(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	authenticated, ok := ctx.Value(localCapabilityMarker{}).(bool)
	return ok && authenticated
}
