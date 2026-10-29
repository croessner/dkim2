// Package redisgrammar is the single authority for the syntactic rules of the
// Redis-compatible replay backend settings. The daemon configuration loader
// and the replay provider both validate through it, so a configuration that
// loads is always admitted by the provider and the two can never drift.
//
// The package is pure: it performs no I/O, holds no state, and depends only
// on the standard library.
package redisgrammar

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// MaxSentinelAddresses bounds the Sentinel seed list.
	MaxSentinelAddresses = 32
	// MaxClusterAddresses bounds the cluster seed list.
	MaxClusterAddresses = 64
	// MaxAddressBytes bounds one host:port element.
	MaxAddressBytes = 255
	// MaxKeyPrefixBytes bounds the operator key prefix.
	MaxKeyPrefixBytes = 64
	// MaxIdentifierBytes bounds ACL usernames and the Sentinel master name.
	MaxIdentifierBytes = 128
	// MaxClientPEMBytes bounds the client certificate and client key PEM.
	MaxClientPEMBytes = 524_288
	// maxDNSNameBytes bounds one DNS host name.
	maxDNSNameBytes = 253
	// maxDNSLabelBytes bounds one DNS label.
	maxDNSLabelBytes = 63
)

// ValidAddressList accepts 1..maximum distinct canonical addresses.
func ValidAddressList(addresses []string, maximum int) bool {
	if len(addresses) < 1 || len(addresses) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if !ValidAddress(address) {
			return false
		}
		if _, duplicate := seen[address]; duplicate {
			return false
		}
		seen[address] = struct{}{}
	}
	return true
}

// ValidAddress accepts one canonical host:port endpoint: a canonical IP
// literal (IPv6 in brackets) or a lowercase DNS host name, and a canonical
// decimal port in 1..65535. The whole element is at most 255 bytes.
func ValidAddress(value string) bool {
	if value == "" || len(value) > MaxAddressBytes {
		return false
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil || !ValidHost(host) || net.JoinHostPort(host, portText) != value {
		return false
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	return err == nil && port != 0 && strconv.FormatUint(port, 10) == portText
}

// ValidHost accepts one canonical unicast IP literal without zone or one
// lowercase DNS host name whose labels may also carry underscores, as
// container and service-discovery names do. A name whose last label is
// numeric is refused so that a malformed IP literal is never resolved.
func ValidHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.String() == host && address.Zone() == "" && !address.Is4In6() &&
			!address.IsUnspecified() && !address.IsMulticast()
	}
	if host == "" || len(host) > maxDNSNameBytes || strings.HasSuffix(host, ".") ||
		strings.Trim(host[strings.LastIndexByte(host, '.')+1:], "0123456789") == "" {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > maxDNSLabelBytes || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			character := label[index]
			if !lowerLetterOrDigit(character) && character != '-' && character != '_' {
				return false
			}
		}
	}
	return true
}

// ValidServerName accepts the TLS verification identity used for every node:
// localhost, a canonical IP literal without zone, or a lowercase DNS name of
// letters, digits, and inner hyphens. Underscores are refused because they
// never appear in a certificate DNS SAN.
func ValidServerName(value string) bool {
	if value == "localhost" {
		return true
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String() == value && address.Zone() == ""
	}
	if value == "" || len(value) > maxDNSNameBytes {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" || len(label) > maxDNSLabelBytes || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			if !lowerLetterOrDigit(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

// ValidUsername accepts one bounded visible-ASCII ACL user name.
func ValidUsername(value string) bool {
	if value == "" || len(value) > MaxIdentifierBytes {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

// ValidMasterName accepts one bounded Sentinel master name from [A-Za-z0-9._-].
func ValidMasterName(value string) bool {
	if value == "" || len(value) > MaxIdentifierBytes {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if !keyPrefixCharacter(character) || character == ':' {
			return false
		}
	}
	return true
}

// ValidKeyPrefix accepts the empty prefix or up to 64 bytes from
// [A-Za-z0-9._:-]. Hash-tag braces are excluded so the prefix can never pin
// every replay key to one cluster slot.
func ValidKeyPrefix(value string) bool {
	if len(value) > MaxKeyPrefixBytes {
		return false
	}
	for index := range len(value) {
		if !keyPrefixCharacter(value[index]) {
			return false
		}
	}
	return true
}

// keyPrefixCharacter reports the closed key-prefix alphabet.
func keyPrefixCharacter(character byte) bool {
	return lowerLetterOrDigit(character) || character >= 'A' && character <= 'Z' ||
		character == '.' || character == '_' || character == ':' || character == '-'
}

// lowerLetterOrDigit reports the lowercase DNS-label alphabet.
func lowerLetterOrDigit(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}
