package testclient

import (
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultServerURL = "http://127.0.0.1:8080"
	defaultTimeout   = 10 * time.Second
	minimumTimeout   = 100 * time.Millisecond
	maximumTimeout   = 60 * time.Second
	outputJSONL      = "jsonl"
	schemeHTTP       = "http"
	mediaTypeJSON    = "application/json"
	processPath      = "/v1/process"
	signPath         = "/v1/sign"
	revisePath       = "/v1/revise"
	dsnSignPath      = "/v1/dsn/sign"
	dsnPropagatePath = "/v1/dsn/propagate"
	dsnCommitPath    = "/v1/dsn/propagate/commit"
	cacheNoStore     = "no-store"
	contentNoSniff   = "nosniff"
	connectionClose  = "close"
	healthPath       = "/healthz"
	readinessPath    = "/readyz"
)

// Options owns the validated command-wide authority and resource bounds.
type Options struct {
	ServerURL                  string
	Timeout                    time.Duration
	CapabilityFile             string
	SignCapabilityFile         string
	ReviseCapabilityFile       string
	DSNSignCapabilityFile      string
	DSNPropagateCapabilityFile string
	Output                     string
}

// DefaultOptions returns the closed local-only command defaults.
func DefaultOptions() Options {
	return Options{
		ServerURL: defaultServerURL,
		Timeout:   defaultTimeout,
		Output:    outputJSONL,
	}
}

// Validate checks all command options before protected-file or network access.
func (o Options) Validate(requireCapability bool) error {
	return o.validateRequirements(capabilityRequirements{process: requireCapability})
}

// capabilityRequirements records which protected route credentials one plan needs.
type capabilityRequirements struct {
	process      bool
	sign         bool
	revise       bool
	dsnSign      bool
	dsnPropagate bool
}

// validateRequirements checks operation-specific protected capability paths.
func (o Options) validateRequirements(required capabilityRequirements) error {
	if _, err := ParseServerURL(o.ServerURL); err != nil {
		return NewExitError(ExitUsage)
	}
	if o.Timeout < minimumTimeout || o.Timeout > maximumTimeout {
		return NewExitError(ExitUsage)
	}
	if o.Output != outputJSONL {
		return NewExitError(ExitUsage)
	}
	paths := []string{
		o.CapabilityFile, o.SignCapabilityFile, o.ReviseCapabilityFile,
		o.DSNSignCapabilityFile, o.DSNPropagateCapabilityFile,
	}
	for _, path := range paths {
		if path != "" && !validCapabilityPath(path) {
			return NewExitError(ExitUsage)
		}
	}
	if required.process && o.CapabilityFile == "" ||
		required.sign && o.SignCapabilityFile == "" ||
		required.revise && o.ReviseCapabilityFile == "" ||
		required.dsnSign && o.DSNSignCapabilityFile == "" ||
		required.dsnPropagate && o.DSNPropagateCapabilityFile == "" {
		return NewExitError(ExitUsage)
	}
	for left := range paths {
		if paths[left] == "" {
			continue
		}
		for right := left + 1; right < len(paths); right++ {
			if paths[left] == paths[right] {
				return NewExitError(ExitUsage)
			}
		}
	}
	return nil
}

// ParseServerURL accepts only one canonical loopback HTTP authority.
func ParseServerURL(raw string) (*url.URL, error) {
	if raw == "" || strings.ContainsAny(raw, "\r\n\t ") {
		return nil, NewExitError(ExitUsage)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != schemeHTTP || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.ForceQuery {
		return nil, NewExitError(ExitUsage)
	}
	host := parsed.Hostname()
	portText := parsed.Port()
	if host == "" || portText == "" {
		return nil, NewExitError(ExitUsage)
	}
	if strings.Contains(host, "%") || parsed.Host != net.JoinHostPort(host, portText) {
		return nil, NewExitError(ExitUsage)
	}
	address := net.ParseIP(host)
	if address == nil || (!address.Equal(net.IPv4(127, 0, 0, 1)) && !address.Equal(net.IPv6loopback)) {
		return nil, NewExitError(ExitUsage)
	}
	if address.To4() != nil && host != "127.0.0.1" {
		return nil, NewExitError(ExitUsage)
	}
	if address.To4() == nil && host != "::1" {
		return nil, NewExitError(ExitUsage)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return nil, NewExitError(ExitUsage)
	}
	canonical := schemeHTTP + "://" + net.JoinHostPort(host, portText)
	if raw != canonical || parsed.String() != canonical {
		return nil, NewExitError(ExitUsage)
	}
	return parsed, nil
}

// validCapabilityPath performs bounded lexical checks before descriptor access.
func validCapabilityPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		len(path) <= 4096 && !strings.ContainsRune(path, '\x00')
}
