package milter

// PostfixDSNEvidence is the non-persistent local proof that Postfix's
// bounce(8) path produced the outer DSN.
type PostfixDSNEvidence struct {
	internal bool
}

// Internal reports whether bounce(8) asserted the exact internal origin enum.
func (e PostfixDSNEvidence) Internal() bool { return e.internal }

// Clear erases one detached evidence copy after daemon request mapping.
func (e *PostfixDSNEvidence) Clear() { e.clear() }

// retainedBytes returns the exact evidence payload covered by EOM transport accounting.
func (e PostfixDSNEvidence) retainedBytes() int64 {
	return 0
}

// clone creates an isolated copy without exposing the adapter-owned buffers.
func (e PostfixDSNEvidence) clone() PostfixDSNEvidence {
	return e
}

// clear erases adapter-owned DSN provenance after the synchronous handler call.
func (e *PostfixDSNEvidence) clear() {
	if e == nil {
		return
	}
	e.internal = false
}
