package draftsection

import "testing"

// TestCitationValidCoversTheClosedDraft08Structure proves every pinned section
// and the active list/range grammars without binding only corrected authorities.
func TestCitationValidCoversTheClosedDraft08Structure(t *testing.T) {
	for section := range sectionOrder {
		for _, prefix := range []string{fullDraft, shortDraft} {
			if !CitationValid(prefix + " Section " + section) {
				t.Fatalf("CitationValid rejected %s Section %s", prefix, section)
			}
		}
	}
	for _, citation := range []string{
		fullDraft + " Sections 3.1 and 9.3",
		fullDraft + " Sections 4, 6.1, and 12.8",
		fullDraft + " Sections 3 through 14",
		fullDraft + " Sections 4 through 9.2",
		shortDraft + " Sections 10 through 14",
		fullDraft + " Sections 13.4 and 16.4",
	} {
		if !CitationValid(citation) {
			t.Fatalf("CitationValid rejected %q", citation)
		}
	}
}

// TestCitationValidRejectsUnknownMalformedAndReverseDraft08Sections freezes the
// fail-closed boundary while leaving authorities for other documents untouched.
func TestCitationValidRejectsUnknownMalformedAndReverseDraft08Sections(t *testing.T) {
	for _, citation := range []string{
		fullDraft + " Section 5.3",
		fullDraft + " Sections 5.5 and 9.6",
		fullDraft + " Section 9.7",
		fullDraft + " Sections 14 through 3",
		fullDraft + " Sections 3 through 3",
		fullDraft + " Section 3 and 9.3",
		fullDraft + " Sections 3.1",
		fullDraft + " Sections 3.1, 3.1",
		fullDraft + " section 3.1",
		shortDraft + " Section 22",
		fullDraft + " Section 13.5",
		fullDraft + " Section 16.5",
		"See " + shortDraft + " Section 5.3",
		"authority: " + fullDraft + " Section 5.3",
	} {
		if CitationValid(citation) {
			t.Fatalf("CitationValid accepted %q", citation)
		}
	}
	if !CitationValid("RFC 5322 Sections 2.2 and 2.3") {
		t.Fatal("CitationValid rejected another document's authority")
	}
}
