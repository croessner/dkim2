// Command buildid emits deterministic Exim compatibility artifacts.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const (
	probeContractPath        = "cmd/dkim2-exim/exim/generated/probe-contract-v1.txt"
	cSourcePath              = "cmd/dkim2-exim/exim/dkim2_local_scan.c"
	transportFilterPatchPath = "cmd/dkim2-exim/packaging/exim/dkim2-transport-filter-return-path.patch"
	ipcSchemaPath            = "cmd/dkim2-exim/internal/ipc/schema-v1.txt"
	headerOutputPath         = "cmd/dkim2-exim/exim/generated/build-id-v1.h"
	manifestOutputPath       = "cmd/dkim2-exim/exim/generated/compatibility-manifest-v1.txt"
)

// main validates the fixed named-input contract and emits only derived outputs.
func main() {
	var eximVersion string
	var headerOutput string
	var manifestOutput string
	var probeContract string
	var sourcePath string
	flag.StringVar(&eximVersion, "exim-version", "", "exact Exim source version")
	flag.StringVar(&sourcePath, "source", "", "exact verified Exim source archive or tree manifest")
	flag.StringVar(&probeContract, "probe-contract", probeContractPath, "source-matched Exim ABI probe contract")
	flag.StringVar(&headerOutput, "header-output", headerOutputPath, "derived C header output")
	flag.StringVar(&manifestOutput, "manifest-output", manifestOutputPath, "derived compatibility manifest output")
	flag.Parse()
	if flag.NArg() != 0 || eximVersion == "" || sourcePath == "" {
		fail(errors.New("invalid build compatibility invocation"))
	}
	if err := emit(eximVersion, sourcePath, probeContract, headerOutput, manifestOutput); err != nil {
		fail(err)
	}
}

// emit hashes the prescribed named files, then writes the derived artifacts.
func emit(eximVersion, sourcePath, probeContract, headerOutput, manifestOutput string) error {
	source, err := readRegular(sourcePath)
	if err != nil {
		return errors.New("unreadable Exim source input")
	}
	probe, err := readRegular(probeContract)
	if err != nil {
		return errors.New("unreadable probe contract")
	}
	cSource, err := readRegular(cSourcePath)
	if err != nil {
		return errors.New("unreadable local-scan source")
	}
	transportFilterPatch, err := readRegular(transportFilterPatchPath)
	if err != nil {
		return errors.New("unreadable transport-filter patch")
	}
	schema, err := readRegular(ipcSchemaPath)
	if err != nil {
		return errors.New("unreadable IPC schema")
	}
	if err := validateRowInputs(eximVersion, source, probe, transportFilterPatch); err != nil {
		return err
	}
	buildID, err := adapter.DeriveBuildIDFromBytes(adapter.BuildInputs{
		EximVersion: eximVersion, Source: source, ProbeContract: probe,
		CSource: cSource, TransportFilterPatch: transportFilterPatch, IPCSchema: schema,
	})
	if err != nil {
		return errors.New("invalid build compatibility input")
	}
	artifacts, err := adapter.RenderBuildArtifacts(eximVersion, buildID)
	if err != nil {
		return errors.New("invalid build compatibility output")
	}
	if err := writeDerived(headerOutput, artifacts.Header); err != nil {
		return errors.New("unable to write build header")
	}
	if err := writeDerived(manifestOutput, artifacts.Manifest); err != nil {
		return errors.New("unable to write build manifest")
	}
	return nil
}

// validateRowInputs binds a source manifest and ABI probe to one exact Exim row.
func validateRowInputs(eximVersion string, source, probe, transportFilterPatch []byte) error {
	sourceFields, err := parseContractFields(source)
	if err != nil {
		return errors.New("invalid Exim source manifest")
	}
	probeFields, err := parseContractFields(probe)
	if err != nil {
		return errors.New("invalid Exim probe contract")
	}
	if sourceFields["format"] != "dkim2-exim-source-manifest-v1" || probeFields["format"] != "dkim2-exim-probe-contract-v1" {
		return errors.New("invalid Exim compatibility formats")
	}
	if sourceFields["exim_version"] != eximVersion || probeFields["exim_version"] != eximVersion {
		return errors.New("mismatched Exim version inputs")
	}
	if !isLowerSHA256(sourceFields["source_sha256"]) || sourceFields["source_sha256"] != probeFields["source_sha256"] {
		return errors.New("mismatched Exim source inputs")
	}
	if !isLowerSHA256(sourceFields["local_scan_header_sha256"]) || sourceFields["local_scan_header_sha256"] != probeFields["local_scan_header_sha256"] {
		return errors.New("mismatched Exim local-scan inputs")
	}
	patchDigest := sha256.Sum256(transportFilterPatch)
	patchSHA256 := hex.EncodeToString(patchDigest[:])
	if !isLowerSHA256(sourceFields["transport_filter_patch_sha256"]) ||
		sourceFields["transport_filter_patch_sha256"] != probeFields["transport_filter_patch_sha256"] ||
		sourceFields["transport_filter_patch_sha256"] != patchSHA256 {
		return errors.New("mismatched Exim transport-filter patch inputs")
	}
	if sourceFields["feature_international_mail"] != "1" || probeFields["feature_international_mail"] != "1" {
		return errors.New("mismatched Exim feature inputs")
	}
	return nil
}

// isLowerSHA256 accepts only a canonical lowercase SHA-256 digest.
func isLowerSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// parseContractFields reads unique non-empty key-value lines without normalization.
func parseContractFields(data []byte) (map[string]string, error) {
	fields := make(map[string]string)
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || key == "" || value == "" || fields[key] != "" {
			return nil, errors.New("invalid contract field")
		}
		fields[key] = value
	}
	return fields, nil
}

// readRegular accepts one regular named build input without normalization.
func readRegular(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.ReadFile(path)
}

// writeDerived writes one deterministic derived artifact with restrictive mode.
func writeDerived(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, fs.FileMode(0o644)); err != nil {
		return err
	}
	return nil
}

// fail prints no protected compatibility input before returning a non-zero status.
func fail(err error) {
	_, _ = fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}
