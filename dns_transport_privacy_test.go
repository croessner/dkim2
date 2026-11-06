package dkim2

import (
	"context"
	"encoding"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

const dnsPrivacyMarker = "DNS-OPAQUE-OWNER-MARKER"

const (
	privacyDefaultFormat  = "%v"
	privacyDetailedFormat = "%+v"
	privacyGoSyntaxFormat = "%#v"
)

type privacyNetTXTResolver struct {
	marker string
}

// LookupTXT returns one deterministic record while retaining a protected test marker.
func (*privacyNetTXTResolver) LookupTXT(context.Context, string) ([]string, error) {
	return []string{testTXTKeyRecord}, nil
}

type privacyTXTTransport struct {
	marker string
	result TXTLookupResult
}

// LookupTXT returns one deterministic result while retaining a protected test marker.
func (t *privacyTXTTransport) LookupTXT(context.Context, string) (TXTLookupResult, error) {
	return t.result, nil
}

type privacyDNSParentContext struct {
	marker string
}

// Deadline reports no parent deadline for the deterministic privacy fixture.
func (privacyDNSParentContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no parent cancellation for the deterministic privacy fixture.
func (privacyDNSParentContext) Done() <-chan struct{} { return nil }

// Err reports no parent cancellation for the deterministic privacy fixture.
func (privacyDNSParentContext) Err() error { return nil }

// Value returns no inherited values for the deterministic privacy fixture.
func (privacyDNSParentContext) Value(any) any { return nil }

// TestPublicTXTValuesPreserveZeroAndDetachedOwnership verifies pointer-backed
// opacity does not alter zero semantics or caller mutation isolation.
func TestPublicTXTValuesPreserveZeroAndDetachedOwnership(t *testing.T) {
	var zeroRecord TXTRecord
	if zeroRecord.Payload() != nil {
		t.Fatal("zero TXT record exposed non-nil payload")
	}
	var zeroResult TXTLookupResult
	if !zeroResult.IsZero() || zeroResult.Status() != "" || zeroResult.RecordCount() != 0 ||
		zeroResult.Records() != nil || zeroResult.Absence() != "" ||
		zeroResult.PositiveTTL() != 0 || zeroResult.NegativeTTL() != 0 ||
		zeroResult.DNSSECStatus() != "" {
		t.Fatal("zero TXT lookup result changed semantics")
	}
	forgedZero := TXTLookupResult{state: &txtLookupResultState{}}
	if !forgedZero.IsZero() {
		t.Fatal("empty internal TXT lookup state was not zero")
	}

	source := []byte(dnsPrivacyMarker)
	result, err := NewFoundTXTLookupResult([][]byte{source}, time.Minute, DNSSECStatusSecure)
	if err != nil {
		t.Fatal("TXT ownership fixture construction failed")
	}
	source[0] ^= 0xff
	first := result.Records()
	second := result.Records()
	first[0].state.payload[0] ^= 0xff
	first = append(first, newTXTRecord([]byte("unrelated")))
	if len(first) != 2 || len(second) != 1 || string(second[0].Payload()) != dnsPrivacyMarker ||
		string(result.Records()[0].Payload()) != dnsPrivacyMarker {
		t.Fatal("TXT lookup result did not retain detached immutable storage")
	}
}

// TestDNSFacadeFormattingDoesNotTraverseProtectedState verifies public DNS
// values and retained dependencies remain opaque through direct and nested fmt use.
func TestDNSFacadeFormattingDoesNotTraverseProtectedState(t *testing.T) {
	record := newTXTRecord([]byte(dnsPrivacyMarker))
	encodedKeyMarker := base64.StdEncoding.EncodeToString([]byte(dnsPrivacyMarker))
	result, err := NewFoundTXTLookupResult(
		[][]byte{[]byte("p=" + encodedKeyMarker)}, time.Minute, DNSSECStatusUnavailable,
	)
	if err != nil {
		t.Fatal("TXT privacy result construction failed")
	}
	netTransport, err := newNetTXTTransport(&privacyNetTXTResolver{marker: dnsPrivacyMarker})
	if err != nil {
		t.Fatal("net TXT privacy transport construction failed")
	}
	provider, err := NewDNSPublicKeyProvider(&privacyTXTTransport{
		marker: dnsPrivacyMarker,
		result: result,
	})
	if err != nil {
		t.Fatal("DNS privacy provider construction failed")
	}

	direct := []struct {
		value    any
		expected string
	}{
		{value: record, expected: txtRecordRedactedText},
		{value: result, expected: txtLookupResultRedactedText},
		{value: *netTransport, expected: netTXTTransportRedactedText},
		{value: *provider, expected: dnsPublicKeyProviderRedactedText},
	}
	for _, test := range direct {
		for _, format := range []string{privacyDefaultFormat, privacyDetailedFormat, privacyGoSyntaxFormat, "%s", "%q", "%x", "%X"} {
			if formatted := fmt.Sprintf(format, test.value); formatted != test.expected {
				t.Fatal("direct DNS facade formatting did not use its constant representation")
			}
		}
	}

	values := []any{
		record, &record, any(record),
		[]TXTRecord{record}, map[string]TXTRecord{"record": record},
		result, &result, any(result),
		[]TXTLookupResult{result}, map[string]TXTLookupResult{"result": result},
		*netTransport, netTransport, any(*netTransport),
		[]NetTXTTransport{*netTransport}, map[string]NetTXTTransport{"transport": *netTransport},
		*provider, provider, any(*provider),
		[]DNSPublicKeyProvider{*provider}, map[string]DNSPublicKeyProvider{"provider": *provider},
	}
	formats := []string{
		"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%O",
		"%b", "%e", "%E", "%f", "%F", "%g", "%G", "%c", "%U", "%t", "%p",
	}
	protected := []string{
		dnsPrivacyMarker,
		encodedKeyMarker,
		hex.EncodeToString([]byte(dnsPrivacyMarker)),
		strings.ToUpper(hex.EncodeToString([]byte(dnsPrivacyMarker))),
	}
	for _, value := range values {
		for _, format := range formats {
			formatted := fmt.Sprintf(format, value)
			for _, marker := range protected {
				if strings.Contains(formatted, marker) {
					t.Fatal("DNS facade formatting leaked protected state")
				}
			}
		}
	}
}

// TestDNSFacadeSerializationFailsClosed verifies protected DNS values cannot
// bypass explicit response mapping through JSON or text serialization.
func TestDNSFacadeSerializationFailsClosed(t *testing.T) {
	record := newTXTRecord([]byte(dnsPrivacyMarker))
	result, err := NewFoundTXTLookupResult(
		[][]byte{[]byte(dnsPrivacyMarker)}, time.Minute, DNSSECStatusUnavailable,
	)
	if err != nil {
		t.Fatal("TXT serialization fixture construction failed")
	}
	netTransport, err := newNetTXTTransport(&privacyNetTXTResolver{marker: dnsPrivacyMarker})
	if err != nil {
		t.Fatal("net TXT serialization fixture construction failed")
	}
	provider, err := NewDNSPublicKeyProvider(&privacyTXTTransport{
		marker: dnsPrivacyMarker,
		result: result,
	})
	if err != nil {
		t.Fatal("DNS provider serialization fixture construction failed")
	}

	for _, value := range []any{
		record, &record, result, &result,
		*netTransport, netTransport, *provider, provider,
	} {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr == nil || len(encoded) != 0 ||
			strings.Contains(marshalErr.Error(), dnsPrivacyMarker) {
			t.Fatal("protected DNS value allowed or leaked through JSON serialization")
		}
		textMarshaler, ok := value.(encoding.TextMarshaler)
		if !ok {
			t.Fatal("protected DNS value omitted fail-closed text serialization")
		}
		encoded, marshalErr = textMarshaler.MarshalText()
		if marshalErr == nil || len(encoded) != 0 ||
			strings.Contains(marshalErr.Error(), dnsPrivacyMarker) {
			t.Fatal("protected DNS value allowed or leaked through text serialization")
		}
	}
}

// TestDNSProviderConfigDependenciesStayOutOfConstructorDiagnostics verifies
// transient clock and parent state is retained only behind the opaque provider.
func TestDNSProviderConfigDependenciesStayOutOfConstructorDiagnostics(t *testing.T) {
	result, err := NewFoundTXTLookupResult(
		[][]byte{[]byte(testTXTKeyRecord)}, time.Minute, DNSSECStatusUnavailable,
	)
	if err != nil {
		t.Fatal("DNS config privacy result construction failed")
	}
	config := DefaultDNSProviderConfig()
	config.Parent = privacyDNSParentContext{marker: dnsPrivacyMarker}
	clockMarker := strings.Clone(dnsPrivacyMarker)
	config.Clock = func() time.Time {
		if clockMarker == "" {
			return time.Time{}
		}
		return time.Unix(100, 0)
	}
	transport := &privacyTXTTransport{marker: dnsPrivacyMarker, result: result}
	provider, err := NewDNSPublicKeyProviderWithConfig(transport, config)
	if err != nil {
		t.Fatal("valid protected DNS config was rejected")
	}
	for _, value := range []any{
		*provider, provider, any(*provider),
		[]DNSPublicKeyProvider{*provider},
		map[string]DNSPublicKeyProvider{"provider": *provider},
	} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%p"} {
			if strings.Contains(fmt.Sprintf(format, value), dnsPrivacyMarker) {
				t.Fatal("configured DNS provider formatting leaked transient dependency state")
			}
		}
	}

	config.Limits.MaxOwnerBytes = 0
	_, err = NewDNSPublicKeyProviderWithConfig(transport, config)
	if err == nil || strings.Contains(err.Error(), dnsPrivacyMarker) {
		t.Fatal("DNS provider constructor error exposed transient dependency state")
	}
}

// TestNetTXTTransportRejectsForgedTypedNilState verifies pointer-backed
// dependency ownership preserves typed-nil rejection after construction.
func TestNetTXTTransportRejectsForgedTypedNilState(t *testing.T) {
	var resolver *privacyNetTXTResolver
	transport := &NetTXTTransport{state: &netTXTTransportState{resolver: resolver}}
	result, err := transport.LookupTXT(context.Background(), "s._domainkey.example.test.")
	if !result.IsZero() || err == nil || ProviderErrorClassOf(err) != "" {
		t.Fatal("forged typed-nil resolver state did not fail closed")
	}
}
