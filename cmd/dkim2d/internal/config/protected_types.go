package config

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"sync"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
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

	capability        [32]byte
	signCapability    [32]byte
	reviseCapability  [32]byte
	dsnSignCapability [32]byte
	hasSign           bool
	hasRevise         bool
	hasDSNSign        bool
	signingStore      *signingstore.Runtime
	hmac              [32]byte
	hasHMAC           bool

	applicationPassword        []byte
	auditorPassword            []byte
	rootCertificatesDER        [][]byte
	tracingRootCertificatesDER [][]byte
	datasourcePassword         []byte
	datasourceRootsDER         [][]byte
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

// SignCapability is a comparison-only opaque originator authorization value.
type SignCapability struct {
	state *protectedState
	token *runtimeToken
}

// ReviseCapability is a comparison-only opaque revision authorization value.
type ReviseCapability struct {
	state *protectedState
	token *runtimeToken
}

// DSNSignCapability is a comparison-only opaque delivery-status authorization value.
type DSNSignCapability struct {
	state *protectedState
	token *runtimeToken
}

// TracingStartupMaterial lends only the protected OTLP trust roots during startup.
type TracingStartupMaterial struct {
	state *protectedState
	token *runtimeToken
}

// SigningDatasourceMaterial lends network-provider credentials only during startup.
type SigningDatasourceMaterial struct {
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

// SigningDatasource returns the non-owning network-provider startup handle.
func (p *RuntimePreparation) SigningDatasource() SigningDatasourceMaterial {
	if p == nil {
		return SigningDatasourceMaterial{}
	}
	return SigningDatasourceMaterial{state: p.state, token: p.token}
}

// Use lends a fresh password and trust-root clone for synchronous construction.
func (m SigningDatasourceMaterial) Use(
	use func(password []byte, rootsDER [][]byte) error,
) (resultErr error) {
	if m.state == nil || m.token == nil || use == nil {
		return newError(CodeProtectedClosed)
	}
	m.state.mu.Lock()
	if m.state.phase != protectedPreparedForRuntime ||
		m.state.runtimeToken != m.token || m.state.borrowed ||
		len(m.state.datasourcePassword) == 0 || len(m.state.datasourceRootsDER) == 0 {
		m.state.mu.Unlock()
		return newError(CodeProtectedContent)
	}
	m.state.borrowed = true
	password := append([]byte(nil), m.state.datasourcePassword...)
	roots := cloneProtectedRoots(m.state.datasourceRootsDER)
	m.state.mu.Unlock()
	defer func() {
		panicValue := recover()
		clear(password)
		for index := range roots {
			clear(roots[index])
		}
		m.state.mu.Lock()
		m.state.borrowed = false
		m.state.mu.Unlock()
		if panicValue != nil {
			resultErr = newError(CodeProtectedContent)
		}
	}()
	if err := use(password, roots); err != nil {
		return newError(CodeProtectedContent)
	}
	return nil
}

// ProcessCapability returns the non-owning post-commit capability handle.
func (p *RuntimePreparation) ProcessCapability() ProcessCapability {
	if p == nil {
		return ProcessCapability{}
	}
	return ProcessCapability{state: p.state, token: p.token}
}

// SignCapability returns the non-owning post-commit originator capability.
func (p *RuntimePreparation) SignCapability() SignCapability {
	if p == nil {
		return SignCapability{}
	}
	return SignCapability{state: p.state, token: p.token}
}

// ReviseCapability returns the non-owning post-commit revision capability.
func (p *RuntimePreparation) ReviseCapability() ReviseCapability {
	if p == nil {
		return ReviseCapability{}
	}
	return ReviseCapability{state: p.state, token: p.token}
}

// DSNSignCapability returns the non-owning post-commit delivery-status capability.
func (p *RuntimePreparation) DSNSignCapability() DSNSignCapability {
	if p == nil {
		return DSNSignCapability{}
	}
	return DSNSignCapability{state: p.state, token: p.token}
}

// SigningStore returns the same-generation reload runtime only while
// runtime preparation owns the handoff.
func (p *RuntimePreparation) SigningStore() *signingstore.Runtime {
	if p == nil || p.state == nil || p.token == nil {
		return nil
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if p.state.phase != protectedPreparedForRuntime ||
		p.state.runtimeToken != p.token ||
		(!p.state.hasSign && !p.state.hasRevise && !p.state.hasDSNSign) {
		return nil
	}
	return p.state.signingStore
}

// ReplayRuntime returns one atomic same-generation replay preparation.
func (p *RuntimePreparation) ReplayRuntime() ReplayRuntimePreparation {
	if p == nil {
		return ReplayRuntimePreparation{}
	}
	return ReplayRuntimePreparation{state: p.state, token: p.token}
}

// TracingMaterial returns the non-owning startup tracing trust handle.
func (p *RuntimePreparation) TracingMaterial() TracingStartupMaterial {
	if p == nil {
		return TracingStartupMaterial{}
	}
	return TracingStartupMaterial{state: p.state, token: p.token}
}

// UseRoots lends a fresh callback-scoped copy of the tracing trust roots.
func (m TracingStartupMaterial) UseRoots(use func(rootsDER [][]byte) error) (resultErr error) {
	if m.state == nil || m.token == nil || use == nil {
		return newError(CodeProtectedClosed)
	}
	m.state.mu.Lock()
	if m.state.phase != protectedPreparedForRuntime ||
		m.state.runtimeToken != m.token || m.state.borrowed ||
		len(m.state.tracingRootCertificatesDER) == 0 {
		m.state.mu.Unlock()
		return newError(CodeProtectedClosed)
	}
	m.state.borrowed = true
	roots := cloneProtectedRoots(m.state.tracingRootCertificatesDER)
	m.state.mu.Unlock()
	defer func() {
		panicValue := recover()
		for index := range roots {
			clear(roots[index])
			roots[index] = nil
		}
		m.state.mu.Lock()
		m.state.borrowed = false
		m.state.mu.Unlock()
		if panicValue != nil {
			resultErr = newError(CodeProtectedContent)
		}
	}()
	if err := use(roots); err != nil {
		return newError(CodeProtectedContent)
	}
	return nil
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

// Equal performs an exact constant-time originator capability comparison.
func (c SignCapability) Equal(candidate []byte) bool {
	return equalProtectedCapability(c.state, c.token, candidate, protectedSign)
}

// Equal performs an exact constant-time revision capability comparison.
func (c ReviseCapability) Equal(candidate []byte) bool {
	return equalProtectedCapability(c.state, c.token, candidate, protectedRevise)
}

// Equal performs an exact constant-time delivery-status capability comparison.
func (c DSNSignCapability) Equal(candidate []byte) bool {
	return equalProtectedCapability(c.state, c.token, candidate, protectedDSNSign)
}

type protectedCapabilityKind uint8

const (
	protectedSign protectedCapabilityKind = iota + 1
	protectedRevise
	protectedDSNSign
)

// equalProtectedCapability compares one enabled role without revealing length.
func equalProtectedCapability(
	state *protectedState,
	token *runtimeToken,
	candidate []byte,
	kind protectedCapabilityKind,
) bool {
	if state == nil || token == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.phase != protectedOwnedByRuntime ||
		state.runtimeToken != token {
		return false
	}
	var expected *[32]byte
	switch kind {
	case protectedSign:
		if !state.hasSign {
			return false
		}
		expected = &state.signCapability
	case protectedRevise:
		if !state.hasRevise {
			return false
		}
		expected = &state.reviseCapability
	case protectedDSNSign:
		if !state.hasDSNSign {
			return false
		}
		expected = &state.dsnSignCapability
	default:
		return false
	}
	var padded [32]byte
	copy(padded[:], candidate)
	valueEqual := subtle.ConstantTimeCompare(expected[:], padded[:])
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
	s.signCapability = [32]byte{}
	s.reviseCapability = [32]byte{}
	s.dsnSignCapability = [32]byte{}
	s.hasSign = false
	s.hasRevise = false
	s.hasDSNSign = false
	if s.signingStore != nil {
		_ = s.signingStore.Close(context.Background())
		s.signingStore = nil
	}
	s.hmac = [32]byte{}
	s.hasHMAC = false
	clear(s.applicationPassword)
	clear(s.auditorPassword)
	for index := range s.rootCertificatesDER {
		clear(s.rootCertificatesDER[index])
		s.rootCertificatesDER[index] = nil
	}
	clear(s.datasourcePassword)
	for index := range s.datasourceRootsDER {
		clear(s.datasourceRootsDER[index])
		s.datasourceRootsDER[index] = nil
	}
	for index := range s.tracingRootCertificatesDER {
		clear(s.tracingRootCertificatesDER[index])
		s.tracingRootCertificatesDER[index] = nil
	}
	s.applicationPassword = nil
	s.auditorPassword = nil
	s.rootCertificatesDER = nil
	s.datasourcePassword = nil
	s.datasourceRootsDER = nil
	s.tracingRootCertificatesDER = nil
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
//
//nolint:gocyclo // Explicit pairwise secret-separation checks are security invariants.
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
	if state.hasSign && bytes.Equal(state.capability[:], state.signCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasRevise && bytes.Equal(state.capability[:], state.reviseCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasSign && state.hasRevise &&
		bytes.Equal(state.signCapability[:], state.reviseCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasSign && state.hasDSNSign &&
		bytes.Equal(state.signCapability[:], state.dsnSignCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasRevise && state.hasDSNSign &&
		bytes.Equal(state.reviseCapability[:], state.dsnSignCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasDSNSign && bytes.Equal(state.capability[:], state.dsnSignCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasHMAC && state.hasSign &&
		bytes.Equal(state.hmac[:], state.signCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasHMAC && state.hasRevise &&
		bytes.Equal(state.hmac[:], state.reviseCapability[:]) {
		return newError(CodeProtectedContent)
	}
	if state.hasHMAC && state.hasDSNSign &&
		bytes.Equal(state.hmac[:], state.dsnSignCapability[:]) {
		return newError(CodeProtectedContent)
	}
	passwords := [][]byte{
		state.applicationPassword,
		state.auditorPassword,
		state.datasourcePassword,
	}
	for left := range passwords {
		for right := left + 1; right < len(passwords); right++ {
			if len(passwords[left]) > 0 && bytes.Equal(passwords[left], passwords[right]) {
				return newError(CodeProtectedContent)
			}
		}
	}
	for _, password := range passwords {
		if len(password) == exactKeyBytes &&
			(bytes.Equal(state.capability[:], password) ||
				state.hasSign && bytes.Equal(state.signCapability[:], password) ||
				state.hasRevise && bytes.Equal(state.reviseCapability[:], password) ||
				state.hasDSNSign && bytes.Equal(state.dsnSignCapability[:], password) ||
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

// String returns a constant content-free signing-capability representation.
func (SignCapability) String() string { return protectedRedactedText }

// GoString returns a constant content-free signing-capability representation.
func (SignCapability) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing signing capability bytes.
func (SignCapability) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of signing capability bytes.
func (SignCapability) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of signing capability bytes.
func (SignCapability) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a constant content-free revision-capability representation.
func (ReviseCapability) String() string { return protectedRedactedText }

// GoString returns a constant content-free revision-capability representation.
func (ReviseCapability) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing revision capability bytes.
func (ReviseCapability) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of revision capability bytes.
func (ReviseCapability) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects serialization of revision capability bytes.
func (ReviseCapability) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

// String returns a constant content-free delivery-status capability representation.
func (DSNSignCapability) String() string { return protectedRedactedText }

// GoString returns a constant content-free delivery-status capability representation.
func (DSNSignCapability) GoString() string { return protectedRedactedText }

// Format prevents formatting verbs from exposing the delivery-status capability.
func (DSNSignCapability) Format(state fmt.State, _ rune) { writeProtectedRedacted(state) }

// MarshalJSON rejects serialization of the delivery-status capability.
func (DSNSignCapability) MarshalJSON() ([]byte, error) { return nil, newError(CodeSerialization) }

// MarshalText rejects text serialization of the delivery-status capability.
func (DSNSignCapability) MarshalText() ([]byte, error) { return nil, newError(CodeSerialization) }

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
