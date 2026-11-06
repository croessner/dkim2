package routeplan

import "testing"

// TestDeliveryStatusPropagationPurposeShape proves the propagation purpose is
// an initial external single-recipient route without a revision binding.
func TestDeliveryStatusPropagationPurposeShape(t *testing.T) {
	if !PurposeDeliveryStatusPropagation.Known() || !PurposeDeliveryStatusPropagation.Initial() || PurposeRevision.Initial() || PurposeNextDomain.Initial() {
		t.Fatal("purpose classification mismatch")
	}
	source, err := NewImmutableSource([]byte("From: a@example.test\r\n\r\nbody\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	reverse := []byte("<>")
	single := [][]byte{[]byte("<previous@example.test>")}
	entry, err := NewEntry(source, PurposeDeliveryStatusPropagation, reverse, single, DisclosureSingle, []byte("propagation-route"), nil)
	if err != nil || entry.purpose != PurposeDeliveryStatusPropagation || entry.routeClass != RouteExternal {
		t.Fatalf("propagation entry error=%v", err)
	}
	if _, err := NewEntry(source, PurposeDeliveryStatusPropagation, reverse, single, DisclosureBccSeparated, []byte("propagation-route"), nil); err == nil {
		t.Fatal("bcc disclosure accepted for propagation")
	}
	if _, err := NewEntry(source, PurposeDeliveryStatusPropagation, reverse, [][]byte{single[0], []byte("<second@example.test>")}, DisclosureAuthorizedGroup, []byte("propagation-route"), nil); err == nil {
		t.Fatal("group disclosure accepted for propagation")
	}
	if _, err := NewEntry(source, PurposeDeliveryStatusPropagation, reverse, single, DisclosureSingle, []byte("propagation-route"), make([]byte, 32)); err == nil {
		t.Fatal("revision binding accepted for propagation")
	}
	if _, err := NewClassifiedEntry(source, PurposeDeliveryStatusPropagation, reverse, single, DisclosureSingle, RouteInControl, []byte("propagation-route"), nil, nil); err == nil {
		t.Fatal("in-control class accepted for propagation")
	}
}
