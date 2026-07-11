package keyresolver

// Metadata carries bounded DNS key policy declarations without raw flags.
type Metadata struct {
	testingDeclared        bool
	strictIdentityDeclared bool
	initialized            bool
}

// newMetadata constructs initialized immutable key policy metadata.
func newMetadata(testingDeclared, strictIdentityDeclared bool) Metadata {
	return Metadata{testingDeclared: testingDeclared, strictIdentityDeclared: strictIdentityDeclared, initialized: true}
}

// TestingDeclared reports whether DNS-04 t=y was declared.
func (m Metadata) TestingDeclared() bool { return m.initialized && m.testingDeclared }

// StrictIdentityDeclared reports whether DNS-04 t=s was declared.
func (m Metadata) StrictIdentityDeclared() bool { return m.initialized && m.strictIdentityDeclared }

// StrictIdentityApplicable reports false because active DKIM2 i= is a numeric sequence.
func (m Metadata) StrictIdentityApplicable() bool { return false }

// Valid reports whether metadata was produced by the DNS key record parser.
func (m Metadata) Valid() bool { return m.initialized }
