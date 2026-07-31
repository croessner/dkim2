// Package adapter owns Exim-specific compatibility and action contracts.
package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	buildIDPrefix    = "dkim2-exim-build-v1"
	buildIDHexLength = 64
	maxAllowedBuilds = 16
)

var errBuildContract = errors.New("exim build compatibility failure")

// BuildContract names the non-circular compatibility inputs.
type BuildContract struct {
	EximVersion                string
	SourceSHA256               string
	ProbeSHA256                string
	CSourceSHA256              string
	TransportFilterPatchSHA256 string
	IPCSchemaSHA256            string
}

// BuildInputs carries exact compatibility-source bytes before hashing.
type BuildInputs struct {
	EximVersion          string
	Source               []byte
	ProbeContract        []byte
	CSource              []byte
	TransportFilterPatch []byte
	IPCSchema            []byte
}

// BuildArtifacts carries deterministic outputs that are not hash inputs.
type BuildArtifacts struct {
	Header   []byte
	Manifest []byte
}

// DeriveBuildIDFromBytes hashes the exact named source bytes without normalization.
func DeriveBuildIDFromBytes(inputs BuildInputs) (string, error) {
	if len(inputs.Source) == 0 || len(inputs.ProbeContract) == 0 ||
		len(inputs.CSource) == 0 || len(inputs.TransportFilterPatch) == 0 ||
		len(inputs.IPCSchema) == 0 {
		return "", &BuildError{}
	}
	return DeriveBuildID(BuildContract{
		EximVersion:                inputs.EximVersion,
		SourceSHA256:               digestBytes(inputs.Source),
		ProbeSHA256:                digestBytes(inputs.ProbeContract),
		CSourceSHA256:              digestBytes(inputs.CSource),
		TransportFilterPatchSHA256: digestBytes(inputs.TransportFilterPatch),
		IPCSchemaSHA256:            digestBytes(inputs.IPCSchema),
	})
}

// RenderBuildArtifacts emits non-input header and manifest bytes deterministically.
func RenderBuildArtifacts(eximVersion, buildID string) (BuildArtifacts, error) {
	if !validEximVersion(eximVersion) ||
		!validLowerHexDigest(buildID) {
		return BuildArtifacts{}, &BuildError{}
	}
	header := fmt.Sprintf(
		"#ifndef DKIM2_EXIM_BUILD_ID_V1_H\n"+
			"#define DKIM2_EXIM_BUILD_ID_V1_H\n"+
			"#define DKIM2_EXIM_BUILD_ID_V1 \"%s\"\n"+
			"#endif\n",
		buildID,
	)
	manifest := fmt.Sprintf(
		"format=dkim2-exim-compatibility-v1\nexim_version=%s\nbuild_id=%s\n",
		eximVersion,
		buildID,
	)
	return BuildArtifacts{Header: []byte(header), Manifest: []byte(manifest)}, nil
}

// DeriveBuildID computes the exact version-one compatibility identifier.
func DeriveBuildID(contract BuildContract) (string, error) {
	values := []string{
		buildIDPrefix,
		contract.EximVersion,
		contract.SourceSHA256,
		contract.ProbeSHA256,
		contract.CSourceSHA256,
		contract.TransportFilterPatchSHA256,
		contract.IPCSchemaSHA256,
	}
	if !validEximVersion(contract.EximVersion) {
		return "", &BuildError{}
	}
	for index := 2; index < len(values); index++ {
		if !validLowerHexDigest(values[index]) {
			return "", &BuildError{}
		}
	}
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// BuildAllowlist owns the bounded immutable compatibility set.
type BuildAllowlist struct {
	values map[[sha256.Size]byte]struct{}
}

// NewBuildAllowlist validates and copies one exact compatibility set.
func NewBuildAllowlist(values []string) (*BuildAllowlist, error) {
	if len(values) < 1 || len(values) > maxAllowedBuilds {
		return nil, &BuildError{}
	}
	digests := make([][sha256.Size]byte, len(values))
	seen := make(map[[sha256.Size]byte]struct{}, len(values))
	for index, value := range values {
		if !validLowerHexDigest(value) {
			return nil, &BuildError{}
		}
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			return nil, &BuildError{}
		}
		copy(digests[index][:], decoded)
		if _, exists := seen[digests[index]]; exists {
			return nil, &BuildError{}
		}
		seen[digests[index]] = struct{}{}
	}
	output := &BuildAllowlist{
		values: make(map[[sha256.Size]byte]struct{}, len(digests)),
	}
	for _, digest := range digests {
		output.values[digest] = struct{}{}
	}
	return output, nil
}

// Allows reports whether one complete exact build ID is configured.
func (a *BuildAllowlist) Allows(value []byte) bool {
	if a == nil || len(value) != buildIDHexLength || !validLowerHexDigest(string(value)) {
		return false
	}
	decoded, err := hex.DecodeString(string(value))
	if err != nil || len(decoded) != sha256.Size {
		return false
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	_, ok := a.values[digest]
	return ok
}

// String returns a content-free allowlist diagnostic.
func (BuildAllowlist) String() string { return "exim_build_allowlist{redacted}" }

// GoString returns a content-free Go representation.
func (a BuildAllowlist) GoString() string { return a.String() }

// Format prevents formatting from traversing protected build identities.
func (a BuildAllowlist) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, a.String())
}

// MarshalJSON rejects serialization of protected build identities.
func (BuildAllowlist) MarshalJSON() ([]byte, error) { return nil, &BuildError{} }

// MarshalText rejects textual serialization of protected build identities.
func (BuildAllowlist) MarshalText() ([]byte, error) { return nil, &BuildError{} }

// BuildError identifies a compatibility failure without retaining values.
type BuildError struct{}

// Error returns a content-free failure class.
func (*BuildError) Error() string { return errBuildContract.Error() }

// validLowerHexDigest validates one exact lowercase SHA-256 spelling.
func validLowerHexDigest(value string) bool {
	if len(value) != buildIDHexLength {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') && (current < 'a' || current > 'f') {
			return false
		}
	}
	return true
}

// validEximVersion accepts one line-safe canonical release identifier.
func validEximVersion(value string) bool {
	if value == "" || len(value) > 64 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, current := range value {
		if (current < '0' || current > '9') &&
			(current < 'A' || current > 'Z') &&
			(current < 'a' || current > 'z') &&
			!strings.ContainsRune(".+~:-_", current) {
			return false
		}
	}
	return true
}

// digestBytes returns the lowercase SHA-256 spelling of exact bytes.
func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
