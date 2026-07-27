// Package endpoint owns canonical local HTTP endpoint validation.
package endpoint

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
)

const httpScheme = "http"

// IsCanonicalLoopbackHTTPURL accepts one exact literal loopback HTTP origin.
func IsCanonicalLoopbackHTTPURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != httpScheme || parsed.Opaque != "" ||
		parsed.User != nil || parsed.Host == "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" ||
		parsed.Host != net.JoinHostPort(parsed.Hostname(), parsed.Port()) {
		return false
	}
	address, addressErr := netip.ParseAddr(parsed.Hostname())
	port, portErr := strconv.Atoi(parsed.Port())
	if addressErr != nil || portErr != nil || !address.IsLoopback() ||
		address.Zone() != "" || address.String() != parsed.Hostname() ||
		address.Is4In6() || port < 1 || port > 65_535 ||
		strconv.Itoa(port) != parsed.Port() {
		return false
	}
	canonical := httpScheme + "://" +
		net.JoinHostPort(address.String(), strconv.Itoa(port))
	return value == canonical && parsed.String() == canonical
}

// IsCanonicalLoopbackAuthority accepts one exact literal loopback host-port.
func IsCanonicalLoopbackAuthority(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || net.JoinHostPort(host, portText) != value {
		return false
	}
	address, addressErr := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	return addressErr == nil && portErr == nil && address.IsLoopback() &&
		address.Zone() == "" && address.String() == host && !address.Is4In6() &&
		port > 0 && port <= 65_535 && strconv.Itoa(port) == portText
}
