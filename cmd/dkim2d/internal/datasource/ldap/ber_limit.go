package ldap

import ber "github.com/go-asn1-ber/asn1-ber"

const maximumBERResponseBytes = int64(4 << 20)

// init narrows the process-wide BER decoder before any LDAP reader starts.
func init() {
	if ber.MaxPacketLengthBytes == 0 ||
		ber.MaxPacketLengthBytes > maximumBERResponseBytes {
		ber.MaxPacketLengthBytes = maximumBERResponseBytes
	}
}
