package ldap

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// TestBERLimitRejectsDeclaredOversizeBeforeContentRead proves the global
// daemon LDAP decoder rejects a hostile length header before allocation.
func TestBERLimitRejectsDeclaredOversizeBeforeContentRead(t *testing.T) {
	if ber.MaxPacketLengthBytes != maximumBERResponseBytes {
		t.Fatal("LDAP BER decoder limit drifted")
	}
	header := []byte{0x30, 0x84, 0x00, 0x40, 0x00, 0x01}
	if packet, err := ber.ReadPacket(bytes.NewReader(header)); err == nil || packet != nil {
		t.Fatal("oversized declared LDAP BER packet accepted")
	}
}
