// Package endpoint owns canonical local endpoint validation for the adapter.
//
// The adapter admits only literal loopback origins. Hostnames, credentials,
// query strings, fragments, and every non-loopback address are refused so a
// resolver, proxy, or redirect can never move the daemon call or the
// re-injection session to another peer.
package endpoint

import (
	"net"
	"net/netip"
	"net/url"
	"strconv"
)

const (
	httpScheme = "http"
	smtpScheme = "smtp"
)

// IsCanonicalLoopbackHTTPURL accepts one exact literal loopback HTTP origin.
func IsCanonicalLoopbackHTTPURL(value string) bool {
	return isCanonicalLoopbackOrigin(value, httpScheme)
}

// IsCanonicalLoopbackSMTPURL accepts one exact literal loopback SMTP origin.
func IsCanonicalLoopbackSMTPURL(value string) bool {
	return isCanonicalLoopbackOrigin(value, smtpScheme)
}

// isCanonicalLoopbackOrigin proves one scheme-exact literal loopback origin.
func isCanonicalLoopbackOrigin(value, scheme string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != scheme || parsed.Opaque != "" ||
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
	canonical := scheme + "://" + net.JoinHostPort(address.String(), strconv.Itoa(port))
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

// Authority returns the literal host-port of one already validated origin.
func Authority(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	if !IsCanonicalLoopbackAuthority(parsed.Host) {
		return "", false
	}
	return parsed.Host, true
}
