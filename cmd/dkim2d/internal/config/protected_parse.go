package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

const (
	maxPasswordBytes        = 1_024
	exactKeyBytes           = 32
	maxCAPEMBytes           = 524_288
	maxCertificateCount     = 128
	maxCertificateDERBytes  = 65_536
	maxCertificateAggregate = 262_144
	certificatePEMType      = "CERTIFICATE"
)

// validatePassword accepts one bounded opaque password without text normalization.
func validatePassword(value []byte) error {
	if len(value) == 0 || len(value) > maxPasswordBytes ||
		bytes.IndexByte(value, 0) >= 0 ||
		bytes.IndexByte(value, '\r') >= 0 ||
		bytes.IndexByte(value, '\n') >= 0 {
		return newError(CodeProtectedContent)
	}
	return nil
}

// validateExactKey accepts one exact nonzero opaque capability or HMAC key.
func validateExactKey(value []byte) error {
	if len(value) != exactKeyBytes {
		return newError(CodeProtectedContent)
	}
	var combined byte
	for _, octet := range value {
		combined |= octet
	}
	if combined == 0 {
		return newError(CodeProtectedContent)
	}
	return nil
}

// parseCertificateRoots validates one strict PEM-only CA trust bundle.
func parseCertificateRoots(data []byte) ([][]byte, error) {
	if len(data) == 0 || len(data) > maxCAPEMBytes {
		return nil, newError(CodeProtectedContent)
	}
	remaining := data
	roots := make([][]byte, 0, 1)
	seen := make(map[[32]byte]struct{})
	totalDER := 0
	for len(remaining) > 0 {
		prefixLength := bytes.Index(remaining, []byte("-----BEGIN "))
		if prefixLength < 0 {
			if !isPEMWhitespace(remaining) {
				return nil, newError(CodeProtectedContent)
			}
			break
		}
		if !isPEMWhitespace(remaining[:prefixLength]) {
			return nil, newError(CodeProtectedContent)
		}
		block, rest := pem.Decode(remaining[prefixLength:])
		if block == nil || block.Type != certificatePEMType || len(block.Headers) != 0 {
			return nil, newError(CodeProtectedContent)
		}
		nextTotal, err := validateCertificateBounds(len(roots), totalDER, len(block.Bytes))
		if err != nil {
			return nil, err
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA ||
			hasCertificateKeyUsage(certificate) &&
				certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, newError(CodeProtectedContent)
		}
		digest := x509Fingerprint(block.Bytes)
		if _, duplicate := seen[digest]; duplicate {
			return nil, newError(CodeProtectedContent)
		}
		seen[digest] = struct{}{}
		roots = append(roots, append([]byte(nil), block.Bytes...))
		totalDER = nextTotal
		remaining = rest
	}
	if len(roots) == 0 {
		return nil, newError(CodeProtectedContent)
	}
	return roots, nil
}

// validateCertificateBounds applies per-root, count, and aggregate DER limits.
func validateCertificateBounds(count, aggregate, next int) (int, error) {
	if next <= 0 || next > maxCertificateDERBytes ||
		count < 0 || count >= maxCertificateCount ||
		aggregate < 0 || aggregate > maxCertificateAggregate-next {
		return 0, newError(CodeProtectedContent)
	}
	return aggregate + next, nil
}

// hasCertificateKeyUsage reports whether the DER explicitly carries OID 2.5.29.15.
func hasCertificateKeyUsage(certificate *x509.Certificate) bool {
	if certificate == nil {
		return false
	}
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal([]int{2, 5, 29, 15}) {
			return true
		}
	}
	return false
}

// isPEMWhitespace accepts only the four ASCII separators allowed by the contract.
func isPEMWhitespace(value []byte) bool {
	for _, octet := range value {
		switch octet {
		case ' ', '\t', '\r', '\n':
		default:
			return false
		}
	}
	return true
}

// x509Fingerprint returns the duplicate-detection digest for one DER certificate.
func x509Fingerprint(der []byte) [32]byte {
	return sha256.Sum256(der)
}
