package dkim2

import (
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/keyresolver"
	"github.com/croessner/dkim2/internal/replay"
	"github.com/croessner/dkim2/internal/service"
	"github.com/croessner/dkim2/internal/verify"
)

// TestDraftBaselineDeclarationsAgree proves that every independent library
// baseline declaration names the same message draft and the paired DNS draft,
// so a migration cannot leave one owner on an older behavior baseline.
func TestDraftBaselineDeclarationsAgree(t *testing.T) {
	const (
		messageDraft = "draft-ietf-dkim-dkim2-spec-08"
		dnsDraft     = "draft-ietf-dkim-dkim2-dns-02"
	)
	for name, value := range map[string]string{
		"dkim2.DraftIdentifier":   DraftIdentifier,
		"canonical.DraftBaseline": canonical.DraftBaseline,
		"verify.DraftBaseline":    verify.DraftBaseline,
		"replay.DraftIdentifier":  replay.DraftIdentifier,
		"service.DraftIdentifier": service.DraftIdentifier,
	} {
		if value != messageDraft {
			t.Fatalf("%s = %q, want %q", name, value, messageDraft)
		}
	}
	if keyresolver.DNSDraftIdentifier != dnsDraft {
		t.Fatalf("keyresolver.DNSDraftIdentifier = %q, want %q", keyresolver.DNSDraftIdentifier, dnsDraft)
	}
}
