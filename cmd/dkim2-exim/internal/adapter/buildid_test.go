package adapter

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestBuildIDDerivationFreezesTheNULFraming proves the exact compatibility hash.
func TestBuildIDDerivationFreezesTheNULFraming(t *testing.T) {
	contract := BuildContract{
		EximVersion:                "4.99.5",
		SourceSHA256:               strings.Repeat("1", 64),
		ProbeSHA256:                strings.Repeat("2", 64),
		CSourceSHA256:              strings.Repeat("3", 64),
		TransportFilterPatchSHA256: strings.Repeat("4", 64),
		IPCSchemaSHA256:            strings.Repeat("5", 64),
	}
	value, err := DeriveBuildID(contract)
	if err != nil {
		t.Fatal("valid build contract failed")
	}
	const independent = "00f00b677f9189cfcf0dff3b39301e188768ad5ae83f8df5a45c1ec684e1dfd0"
	if value != independent {
		t.Fatal("build identifier differs from the independent oracle")
	}
	contract.EximVersion += "\x00unexpected"
	if _, err = DeriveBuildID(contract); err == nil {
		t.Fatal("embedded NUL in version accepted")
	}
	for _, invalid := range []string{"4.99.5\ninjected=true", "4.99.5\rnext", "4.99.5 value"} {
		contract.EximVersion = invalid
		if _, err = DeriveBuildID(contract); err == nil {
			t.Fatal("unsafe Exim version accepted")
		}
		if _, err = RenderBuildArtifacts(invalid, independent); err == nil {
			t.Fatal("unsafe Exim version entered a derived artifact")
		}
	}
}

// TestBuildAllowlistIsClosedAndRedacted proves bounded exact admission.
func TestBuildAllowlistIsClosedAndRedacted(t *testing.T) {
	first := strings.Repeat("a", 64)
	allowlist, err := NewBuildAllowlist([]string{first})
	if err != nil || !allowlist.Allows([]byte(first)) ||
		allowlist.Allows([]byte(strings.Repeat("b", 64))) {
		t.Fatal("exact build admission failed")
	}
	if _, err = NewBuildAllowlist([]string{first, first}); err == nil {
		t.Fatal("duplicate build identifier accepted")
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", allowlist, allowlist, allowlist), first) {
		t.Fatal("build identity escaped formatting")
	}
	if _, err = json.Marshal(allowlist); err == nil ||
		func() bool {
			_, textErr := allowlist.MarshalText()
			return textErr == nil
		}() {
		t.Fatal("protected build identity serialized")
	}
	var zero *BuildAllowlist
	if zero.Allows([]byte(first)) {
		t.Fatal("zero allowlist admitted a build")
	}
}

// TestBuildIDFromExactBytesDoesNotNormalize proves every raw input is authoritative.
func TestBuildIDFromExactBytesDoesNotNormalize(t *testing.T) {
	inputs := BuildInputs{
		EximVersion:          "4.99.5",
		Source:               []byte("source\n"),
		ProbeContract:        []byte("probe\n"),
		CSource:              []byte("c-source\n"),
		TransportFilterPatch: []byte("transport-filter-patch\n"),
		IPCSchema:            []byte("schema\n"),
	}
	baseline, err := DeriveBuildIDFromBytes(inputs)
	if err != nil {
		t.Fatal("exact input derivation failed")
	}
	cases := []BuildInputs{inputs, inputs, inputs, inputs, inputs}
	cases[0].Source = []byte("source\r\n")
	cases[1].ProbeContract = []byte("probe\r\n")
	cases[2].CSource = []byte("c-source\r\n")
	cases[3].TransportFilterPatch = []byte("transport-filter-patch\r\n")
	cases[4].IPCSchema = []byte("schema\r\n")
	for index, mutated := range cases {
		value, deriveErr := DeriveBuildIDFromBytes(mutated)
		if deriveErr != nil || value == baseline {
			t.Fatalf("exact-byte input class %d was normalized", index)
		}
	}
	artifacts, err := RenderBuildArtifacts("4.99.5", baseline)
	if err != nil || !strings.Contains(string(artifacts.Header), baseline) ||
		!strings.Contains(string(artifacts.Manifest), baseline) {
		t.Fatal("deterministic build artifacts failed")
	}
}
