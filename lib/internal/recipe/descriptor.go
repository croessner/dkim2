package recipe

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

const (
	descriptorDomainLabel  = "dkim2-recipe-descriptor-v1"
	descriptorRedactedText = "recipe.Descriptor{redacted}"
)

// ChangeClass identifies one conservative normalized Recipe change dimension.
type ChangeClass string

const (
	// ChangeClassBodyRewrite reports an authenticated body reconstruction recipe.
	ChangeClassBodyRewrite ChangeClass = "body.rewrite"
	// ChangeClassHeaderRewrite reports one or more authenticated header reconstruction recipes.
	ChangeClassHeaderRewrite ChangeClass = "header.rewrite"
)

// Known reports whether the change class belongs to the closed descriptor vocabulary.
func (c ChangeClass) Known() bool {
	return c == ChangeClassBodyRewrite || c == ChangeClassHeaderRewrite
}

// Descriptor stores a privacy-minimized immutable Recipe projection.
type Descriptor struct {
	headerNames   []string
	changeClasses []ChangeClass
	digest        [sha256.Size]byte
	bodyMode      BodyMode
	initialized   bool
}

// Valid reports whether the descriptor is a coherent closed projection.
func (d Descriptor) Valid() bool {
	if !d.initialized || !d.bodyMode.Known() || len(d.headerNames) > 128 ||
		len(d.changeClasses) > 2 {
		return false
	}
	for index, name := range d.headerNames {
		if name == "" || len(name) > 64 || index > 0 && d.headerNames[index-1] >= name {
			return false
		}
	}
	for index, class := range d.changeClasses {
		if !class.Known() || index > 0 && d.changeClasses[index-1] >= class {
			return false
		}
	}
	hasHeaders := len(d.headerNames) > 0
	hasBody := d.bodyMode != BodyModeAbsent
	return slices.Contains(d.changeClasses, ChangeClassHeaderRewrite) == hasHeaders &&
		slices.Contains(d.changeClasses, ChangeClassBodyRewrite) == hasBody &&
		d.digest == descriptorDigest(d.headerNames, d.changeClasses, d.bodyMode)
}

// HasHeaderChanges reports whether h= contains at least one header dimension.
func (d Descriptor) HasHeaderChanges() bool { return d.Valid() && len(d.headerNames) > 0 }

// AffectedHeaders returns sorted unique canonical lower-case header names.
func (d Descriptor) AffectedHeaders() []string {
	if !d.Valid() {
		return nil
	}
	return slices.Clone(d.headerNames)
}

// BodyMode returns the exact Draft-06 body member form.
func (d Descriptor) BodyMode() BodyMode {
	if !d.Valid() {
		return ""
	}
	return d.bodyMode
}

// ChangeClasses returns the sorted closed conservative change dimensions.
func (d Descriptor) ChangeClasses() []ChangeClass {
	if !d.Valid() {
		return nil
	}
	return slices.Clone(d.changeClasses)
}

// ChangeCount returns the number of normalized change dimensions.
func (d Descriptor) ChangeCount() int {
	if !d.Valid() {
		return 0
	}
	return len(d.changeClasses)
}

// AffectedHeaderCount returns the coherence count for AffectedHeaders.
func (d Descriptor) AffectedHeaderCount() int {
	if !d.Valid() {
		return 0
	}
	return len(d.headerNames)
}

// Digest returns the SHA-256 binding of the normalized descriptor.
func (d Descriptor) Digest() [sha256.Size]byte {
	if !d.Valid() {
		return [sha256.Size]byte{}
	}
	return d.digest
}

// String returns a constant representation without message-derived names or counts.
func (Descriptor) String() string { return descriptorRedactedText }

// GoString returns a constant representation without message-derived names or counts.
func (Descriptor) GoString() string { return descriptorRedactedText }

// Format prevents formatting verbs from exposing message-derived descriptor facts.
func (Descriptor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, descriptorRedactedText)
}

// Descriptor returns a privacy-minimized immutable view of this Recipe.
func (r Recipe) Descriptor() Descriptor {
	if !r.Valid() {
		return Descriptor{}
	}
	headerNames := r.HeaderNames()
	slices.Sort(headerNames)
	classes := make([]ChangeClass, 0, 2)
	if len(headerNames) > 0 {
		classes = append(classes, ChangeClassHeaderRewrite)
	}
	if r.bodyMode != BodyModeAbsent {
		classes = append(classes, ChangeClassBodyRewrite)
	}
	slices.Sort(classes)
	descriptor := Descriptor{
		headerNames: headerNames, changeClasses: classes, bodyMode: r.bodyMode,
		initialized: true,
	}
	descriptor.digest = descriptorDigest(headerNames, classes, r.bodyMode)
	return descriptor
}

// UnchangedDescriptor returns the canonical descriptor for an absent Recipe.
func UnchangedDescriptor() Descriptor {
	descriptor := Descriptor{bodyMode: BodyModeAbsent, initialized: true}
	descriptor.digest = descriptorDigest(nil, nil, BodyModeAbsent)
	return descriptor
}

// descriptorDigest hashes one domain-separated deterministic length-prefixed descriptor frame.
func descriptorDigest(headerNames []string, classes []ChangeClass, bodyMode BodyMode) [sha256.Size]byte {
	frame := make([]byte, 0, 128)
	frame = appendDescriptorField(frame, []byte(descriptorDomainLabel))
	frame = appendDescriptorField(frame, []byte(bodyMode))
	frame = appendDescriptorUint64(frame, uint64(len(headerNames)))
	for _, name := range headerNames {
		frame = appendDescriptorField(frame, []byte(name))
	}
	frame = appendDescriptorUint64(frame, uint64(len(classes)))
	for _, class := range classes {
		frame = appendDescriptorField(frame, []byte(class))
	}
	return sha256.Sum256(frame)
}

// appendDescriptorField appends one network-order length-delimited byte field.
func appendDescriptorField(output, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

// appendDescriptorUint64 appends one fixed-width network-order integer field.
func appendDescriptorUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}
