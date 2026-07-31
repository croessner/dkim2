package evidence

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	protectedDefaultFormat = "%v"
	protectedDetailFormat  = "%+v"
	protectedGoFormat      = "%#v"
	protectedStringFormat  = "%s"
	protectedQuotedFormat  = "%q"
)

// TestManifestGrammarRejectsNearMisses proves reserved state is exact.
func TestManifestGrammarRejectsNearMisses(t *testing.T) {
	locator := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, LocatorBytes))
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, nonceBytes))
	valid := []string{
		locator + finalSuffix,
		publicationPrefix + locator + "-" + nonce,
		quarantinePrefix + locator + "-" + nonce,
	}
	for _, name := range valid {
		if _, _, err := parseChildName(name); err != nil {
			t.Fatal("valid manifest name rejected")
		}
	}
	invalid := []string{
		unexpectedManifestName,
		"../" + locator + finalSuffix,
		locator + ".EV1",
		publicationPrefix + locator + "-" + nonce + "=",
		quarantinePrefix + locator + "-" + nonce[:len(nonce)-1],
		publicationPrefix + locator + "_" + nonce,
	}
	for _, name := range invalid {
		if _, _, err := parseChildName(name); err == nil {
			t.Fatal("manifest near-miss accepted")
		}
	}
}

// TestStorePrivacyContract proves generic formatting and serialization cannot
// traverse retained descriptors, keys, clocks, locators, or accounting state.
func TestStorePrivacyContract(t *testing.T) {
	store := &Store{}
	for _, format := range []string{
		protectedDefaultFormat, protectedDetailFormat, protectedGoFormat,
		protectedStringFormat, protectedQuotedFormat,
	} {
		rendered := fmt.Sprintf(format, store)
		if rendered != "exim_evidence_store{redacted}" ||
			strings.Contains(rendered, "descriptor") {
			t.Fatal("store formatting escaped the redacted contract")
		}
	}
	if _, err := json.Marshal(store); err == nil {
		t.Fatal("store JSON serialization succeeded")
	}
	var text encoding.TextMarshaler = store
	if _, err := text.MarshalText(); err == nil {
		t.Fatal("store text serialization succeeded")
	}
}

// FuzzStoreManifest validates bounded exact child-name classification.
func FuzzStoreManifest(f *testing.F) {
	locator := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, LocatorBytes))
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, nonceBytes))
	f.Add(locator + finalSuffix)
	f.Add(publicationPrefix + locator + "-" + nonce)
	f.Add(quarantinePrefix + locator + "-" + nonce)
	f.Add(unexpectedManifestName)
	f.Fuzz(func(t *testing.T, name string) {
		locator, kind, err := parseChildName(name)
		if err == nil {
			if !validLocator(locator) ||
				(kind != manifestFinal && kind != manifestPublication &&
					kind != manifestQuarantine) {
				t.Fatal("manifest parser returned an invalid success")
			}
		}
	})
}
