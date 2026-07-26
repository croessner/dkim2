package config

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"
)

const protectedRedactedText = "dkim2d_protected_material"

// descriptorMetadata freezes the descriptor-native fields used for TOCTOU checks.
type descriptorMetadata struct {
	device    uint64
	inode     uint64
	typeBits  uint32
	uid       uint32
	modeBits  uint32
	linkCount uint64
	size      int64
	mtimeSec  int64
	mtimeNsec int64
	ctimeSec  int64
	ctimeNsec int64
}

// descriptorState freezes metadata and descriptor-native access-control state.
type descriptorState struct {
	metadata descriptorMetadata
	access   [32]byte
}

// protectedState owns all startup material through exactly one lifecycle phase.
type protectedState struct {
	mu sync.Mutex

	phase         protectedPhase
	borrowed      bool
	runtimeToken  *runtimeToken
	releasedToken *runtimeToken
	releasedBy    protectedPhase

	snapshot Snapshot

	capability [32]byte
	hmac       [32]byte
	hasHMAC    bool

	applicationPassword []byte
	auditorPassword     []byte
	rootCertificatesDER [][]byte
}

// protectedPhase identifies the single current material owner.
type protectedPhase uint8

const (
	protectedOwnedByPrebootstrap protectedPhase = iota + 1
	protectedPreparedForRuntime
	protectedOwnedByRuntime
	protectedReleased
)

// runtimeToken binds non-owning prepared handles to one exact owner transition.
type runtimeToken struct {
	marker byte
}

// Prebootstrap owns one validated configuration and protected generation before Fx starts.
type Prebootstrap struct {
	state *protectedState
}

// RuntimePreparation is one opaque commit token for a prepared runtime handoff.
type RuntimePreparation struct {
	state *protectedState
	token *runtimeToken
}

// ReplayStartupMaterial lends complete replay inputs only during prepared startup.
type ReplayStartupMaterial struct {
	state *protectedState
	token *runtimeToken
}

// ReplayAuditorMaterial lends the least-authority auditor credential only after commit.
type ReplayAuditorMaterial struct {
	state *protectedState
	token *runtimeToken
}

// ReplayRuntimePreparation binds one startup borrow to its exact post-commit auditor handle.
type ReplayRuntimePreparation struct {
	state *protectedState
	token *runtimeToken
}

// RuntimeMaterial owns one transferred protected generation during daemon runtime.
type RuntimeMaterial struct {
	state *protectedState
	token *runtimeToken
}

// ProcessCapability is a comparison-only opaque local authorization value.
type ProcessCapability struct {
	state *protectedState
	token *runtimeToken
}

// Snapshot returns the immutable typed configuration associated with this generation.
func (p *Prebootstrap) Snapshot() Snapshot {
	if p == nil || p.state == nil {
		return Snapshot{}
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.phase != protectedOwnedByPrebootstrap &&
		p.state.phase != protectedPreparedForRuntime {
		return Snapshot{}
	}
	return p.state.snapshot
}

// PrepareRuntime creates one token-bound set of non-owning startup/runtime handles.
func (p *Prebootstrap) PrepareRuntime() (*RuntimePreparation, error) {
	if p == nil || p.state == nil {
		return nil, newError(CodeProtectedClosed)
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.phase == protectedReleased {
		return nil, newError(CodeProtectedClosed)
	}
	if p.state.phase != protectedOwnedByPrebootstrap || p.state.runtimeToken != nil {
		return nil, newError(CodeProtectedTransferred)
	}
	token := &runtimeToken{marker: 1}
	p.state.runtimeToken = token
	p.state.phase = protectedPreparedForRuntime
	return &RuntimePreparation{state: p.state, token: token}, nil
}

// CommitRuntime atomically transfers ownership after every fallible startup step succeeds.
func (p *Prebootstrap) CommitRuntime(
	preparation *RuntimePreparation,
) (*RuntimeMaterial, error) {
	if p == nil || p.state == nil || preparation == nil ||
		preparation.state == nil || preparation.token == nil {
		return nil, newError(CodeProtectedTransferred)
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state != preparation.state ||
		p.state.phase != protectedPreparedForRuntime ||
		p.state.runtimeToken != preparation.token ||
		p.state.borrowed {
		return nil, newError(CodeProtectedTransferred)
	}
	runtime := &RuntimeMaterial{state: p.state, token: preparation.token}
	p.state.phase = protectedOwnedByRuntime
	return runtime, nil
}

// Close releases material still owned by prebootstrap exactly once.
func (p *Prebootstrap) Close() error {
	if p == nil || p.state == nil {
		return nil
	}
	return p.state.releasePrebootstrap()
}

// StartupReplay returns the non-owning startup-only replay-material handle.
func (p *RuntimePreparation) StartupReplay() ReplayStartupMaterial {
	if p == nil {
		return ReplayStartupMaterial{}
	}
	return ReplayStartupMaterial{state: p.state, token: p.token}
}

// Snapshot returns the same-generation configuration only during preparation.
func (p *RuntimePreparation) Snapshot() Snapshot {
	if p == nil {
		return Snapshot{}
	}
	return ReplayStartupMaterial{state: p.state, token: p.token}.Snapshot()
}

// ReplayAuditor returns the non-owning post-commit auditor-material handle.
func (p *RuntimePreparation) ReplayAuditor() ReplayAuditorMaterial {
	if p == nil {
		return ReplayAuditorMaterial{}
	}
	return ReplayAuditorMaterial{state: p.state, token: p.token}
}

// ProcessCapability returns the non-owning post-commit capability handle.
func (p *RuntimePreparation) ProcessCapability() ProcessCapability {
	if p == nil {
		return ProcessCapability{}
	}
	return ProcessCapability{state: p.state, token: p.token}
}

// ReplayRuntime returns one atomic same-generation replay preparation.
func (p *RuntimePreparation) ReplayRuntime() ReplayRuntimePreparation {
	if p == nil {
		return ReplayRuntimePreparation{}
	}
	return ReplayRuntimePreparation{state: p.state, token: p.token}
}

// Snapshot returns the immutable configuration only while startup is prepared.
func (m ReplayStartupMaterial) Snapshot() Snapshot {
	if m.state == nil || m.token == nil {
		return Snapshot{}
	}
	m.state.mu.Lock()
	defer m.state.mu.Unlock()
	if m.state.phase != protectedPreparedForRuntime ||
		m.state.runtimeToken != m.token {
		return Snapshot{}
	}
	return m.state.snapshot
}

// Snapshot returns the immutable configuration only while replay startup is prepared.
func (m ReplayRuntimePreparation) Snapshot() Snapshot {
	return ReplayStartupMaterial(m).Snapshot()
}

// UseReplayMaterial lends complete callback-scoped material before commit.
func (m ReplayRuntimePreparation) UseReplayMaterial(
	use func(hmac, applicationPassword, auditorPassword []byte, rootsDER [][]byte) error,
) error {
	return ReplayStartupMaterial(m).UseReplayMaterial(use)
}

// ReplayAuditor returns the exact same-generation post-commit auditor handle.
func (m ReplayRuntimePreparation) ReplayAuditor() ReplayAuditorMaterial {
	return ReplayAuditorMaterial(m)
}

// Snapshot returns the immutable typed runtime configuration.
func (r *RuntimeMaterial) Snapshot() Snapshot {
	if r == nil || r.state == nil {
		return Snapshot{}
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.phase != protectedOwnedByRuntime ||
		r.state.runtimeToken != r.token {
		return Snapshot{}
	}
	return r.state.snapshot
}

// UseReplayMaterial lends protected replay inputs only for synchronous startup construction.
func (m ReplayStartupMaterial) UseReplayMaterial(
	use func(hmac, applicationPassword, auditorPassword []byte, rootsDER [][]byte) error,
) (resultErr error) {
	if m.state == nil || m.token == nil || use == nil {
		return newError(CodeProtectedClosed)
	}
	m.state.mu.Lock()
	if m.state.phase != protectedPreparedForRuntime ||
		m.state.runtimeToken != m.token ||
		m.state.borrowed {
		m.state.mu.Unlock()
		return newError(CodeProtectedClosed)
	}
	if !m.state.hasHMAC {
		m.state.mu.Unlock()
		return newError(CodeProtectedContent)
	}
	m.state.borrowed = true
	hmac := append([]byte(nil), m.state.hmac[:]...)
	applicationPassword := append([]byte(nil), m.state.applicationPassword...)
	auditorPassword := append([]byte(nil), m.state.auditorPassword...)
	rootsDER := cloneProtectedRoots(m.state.rootCertificatesDER)
	m.state.mu.Unlock()
	defer func() {
		panicValue := recover()
		clearReplayBorrow(hmac, applicationPassword, auditorPassword, rootsDER)
		m.state.mu.Lock()
		m.state.borrowed = false
		m.state.mu.Unlock()
		if panicValue != nil {
			resultErr = newError(CodeProtectedContent)
		}
	}()
	if err := use(hmac, applicationPassword, auditorPassword, rootsDER); err != nil {
		return newError(CodeProtectedContent)
	}
	return nil
}

// UseReplayAuditorPassword lends only one fresh post-commit auditor credential clone.
func (m ReplayAuditorMaterial) UseReplayAuditorPassword(
	use func(auditorPassword []byte) error,
) (resultErr error) {
	if m.state == nil || m.token == nil || use == nil {
		return newError(CodeProtectedClosed)
	}
	m.state.mu.Lock()
	if m.state.phase != protectedOwnedByRuntime ||
		m.state.runtimeToken != m.token ||
		m.state.borrowed {
		m.state.mu.Unlock()
		return newError(CodeProtectedClosed)
	}
	if len(m.state.auditorPassword) == 0 {
		m.state.mu.Unlock()
		return newError(CodeProtectedContent)
	}
	m.state.borrowed = true
	auditorPassword := append([]byte(nil), m.state.auditorPassword...)
	m.state.mu.Unlock()
	defer func() {
		panicValue := recover()
		clear(auditorPassword)
		m.state.mu.Lock()
		m.state.borrowed = false
		m.state.mu.Unlock()
		if panicValue != nil {
			resultErr = newError(CodeProtectedContent)
		}
	}()
	if err := use(auditorPassword); err != nil {
		return newError(CodeProtectedContent)
	}
	return nil
}

// Close releases runtime-owned material exactly once.
func (r *RuntimeMaterial) Close() error {
	if r == nil || r.state == nil {
		return nil
	}
	return r.state.releaseRuntime(r.token)
}

// Equal performs a length-hiding constant-time comparison against one candidate.
func (c ProcessCapability) Equal(candidate []byte) bool {
	if c.state == nil || c.token == nil {
		return false
	}
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if c.state.phase != protectedOwnedByRuntime ||
		c.state.runtimeToken != c.token {
		return false
	}
	var padded [32]byte
	copy(padded[:], candidate)
	valueEqual := subtle.ConstantTimeCompare(c.state.capability[:], padded[:])
	return len(candidate) == len(padded) && valueEqual == 1
}

// releasePrebootstrap clears material while prebootstrap still owns prepared state.
func (s *protectedState) releasePrebootstrap() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == protectedReleased {
		if s.releasedBy == protectedOwnedByPrebootstrap {
			return nil
		}
		return newError(CodeProtectedTransferred)
	}
	if s.borrowed {
		return newError(CodeProtectedTransferred)
	}
	if s.phase != protectedOwnedByPrebootstrap &&
		s.phase != protectedPreparedForRuntime {
		return newError(CodeProtectedTransferred)
	}
	s.clearProtected(protectedOwnedByPrebootstrap)
	return nil
}

// releaseRuntime clears material through the sole committed runtime owner.
func (s *protectedState) releaseRuntime(token *runtimeToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == protectedReleased {
		if s.releasedBy == protectedOwnedByRuntime &&
			token != nil && s.releasedToken == token {
			return nil
		}
		return newError(CodeProtectedTransferred)
	}
	if s.borrowed || token == nil ||
		s.phase != protectedOwnedByRuntime ||
		s.runtimeToken != token {
		return newError(CodeProtectedTransferred)
	}
	s.clearProtected(protectedOwnedByRuntime)
	return nil
}

// clearProtected zeroizes owned byte backings before dropping all references.
func (s *protectedState) clearProtected(releasedBy protectedPhase) {
	if s.runtimeToken != nil {
		s.runtimeToken.marker = 0
	}
	s.releasedToken = s.runtimeToken
	s.runtimeToken = nil
	s.capability = [32]byte{}
	s.hmac = [32]byte{}
	s.hasHMAC = false
	clear(s.applicationPassword)
	clear(s.auditorPassword)
	for index := range s.rootCertificatesDER {
		clear(s.rootCertificatesDER[index])
		s.rootCertificatesDER[index] = nil
	}
	s.applicationPassword = nil
	s.auditorPassword = nil
	s.rootCertificatesDER = nil
	s.snapshot = Snapshot{}
	s.releasedBy = releasedBy
	s.phase = protectedReleased
}

// cloneProtectedRoots creates a callback-local deep copy of parsed trust roots.
func cloneProtectedRoots(input [][]byte) [][]byte {
	cloned := make([][]byte, len(input))
	for index := range input {
		cloned[index] = append([]byte(nil), input[index]...)
	}
	return cloned
}

// clearReplayBorrow invalidates all callback-local protected byte slices.
func clearReplayBorrow(hmac, applicationPassword, auditorPassword []byte, rootsDER [][]byte) {
	clear(hmac)
	clear(applicationPassword)
	clear(auditorPassword)
	for index := range rootsDER {
		clear(rootsDER[index])
		rootsDER[index] = nil
	}
}

// validateProtectedSeparation rejects equal secrets across distinct roles.
func validateProtectedSeparation(state *protectedState) error {
	if state == nil {
		return newError(CodeInternal)
	}
	if len(state.applicationPassword) > 0 &&
		bytes.Equal(state.applicationPassword, state.auditorPassword) {
		return newError(CodeProtectedContent)
	}
	if state.hasHMAC && bytes.Equal(state.capability[:], state.hmac[:]) {
		return newError(CodeProtectedContent)
	}
	for _, password := range [][]byte{state.applicationPassword, state.auditorPassword} {
		if len(password) == exactKeyBytes &&
			(bytes.Equal(state.capability[:], password) ||
				state.hasHMAC && bytes.Equal(state.hmac[:], password)) {
			return newError(CodeProtectedContent)
		}
	}
	return nil
}

// String returns a constant content-free owner representation.
func (Prebootstrap) String() string { return protectedRedactedText }

// GoString returns a constant content-free owner representation.
func (Prebootstrap) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing protected material.
func (Prebootstrap) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of protected material.
func (Prebootstrap) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of protected material.
func (Prebootstrap) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a constant content-free preparation representation.
func (RuntimePreparation) String() string { return protectedRedactedText }

// GoString returns a constant content-free preparation representation.
func (RuntimePreparation) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing preparation state.
func (RuntimePreparation) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of prepared protected handles.
func (RuntimePreparation) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects text serialization of prepared protected handles.
func (RuntimePreparation) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// String returns a constant content-free startup-replay representation.
func (ReplayStartupMaterial) String() string { return protectedRedactedText }

// GoString returns a constant content-free startup-replay representation.
func (ReplayStartupMaterial) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing startup replay state.
func (ReplayStartupMaterial) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of startup replay material.
func (ReplayStartupMaterial) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects text serialization of startup replay material.
func (ReplayStartupMaterial) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// String returns a constant content-free auditor-material representation.
func (ReplayAuditorMaterial) String() string { return protectedRedactedText }

// GoString returns a constant content-free auditor-material representation.
func (ReplayAuditorMaterial) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing auditor material.
func (ReplayAuditorMaterial) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of auditor material.
func (ReplayAuditorMaterial) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects text serialization of auditor material.
func (ReplayAuditorMaterial) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// String returns a constant content-free replay-preparation representation.
func (ReplayRuntimePreparation) String() string { return protectedRedactedText }

// GoString returns a constant content-free replay-preparation representation.
func (ReplayRuntimePreparation) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing replay preparation state.
func (ReplayRuntimePreparation) Format(state fmt.State, _ rune) {
	writeProtectedRedacted(state)
}

// MarshalJSON rejects serialization of replay preparation state.
func (ReplayRuntimePreparation) MarshalJSON() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// MarshalText rejects text serialization of replay preparation state.
func (ReplayRuntimePreparation) MarshalText() ([]byte, error) {
	return nil, newError(CodeSerialization)
}

// String returns a constant content-free owner representation.
func (RuntimeMaterial) String() string { return protectedRedactedText }

// GoString returns a constant content-free owner representation.
func (RuntimeMaterial) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing protected material.
func (RuntimeMaterial) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of protected material.
func (RuntimeMaterial) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of protected material.
func (RuntimeMaterial) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a constant content-free capability representation.
func (ProcessCapability) String() string { return protectedRedactedText }

// GoString returns a constant content-free capability representation.
func (ProcessCapability) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing capability bytes.
func (ProcessCapability) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of capability bytes.
func (ProcessCapability) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of capability bytes.
func (ProcessCapability) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// writeProtectedRedacted emits only the fixed protected-material marker.
func writeProtectedRedacted(state fmt.State) {
	_, _ = io.WriteString(state, protectedRedactedText)
}

// String returns a constant content-free protected-state representation.
func (*protectedState) String() string { return protectedRedactedText }

// GoString returns a constant content-free protected-state representation.
func (*protectedState) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing protected state.
func (*protectedState) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of protected state.
func (*protectedState) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of protected state.
func (*protectedState) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }
