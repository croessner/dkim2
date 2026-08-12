package recipe_test

import (
	"sync"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/recipe"
)

// TestCanonicalHeaderRelevanceAlignsWithDraft04 proves the production seam and complete exclusion surface.
func TestCanonicalHeaderRelevanceAlignsWithDraft04(t *testing.T) {
	relevance := canonical.NewHeaderRelevance()
	var contract recipe.HeaderRelevance = relevance
	if err := contract.Validate(); err != nil {
		t.Fatalf("Validate() failed: error=%t", err != nil)
	}

	for _, name := range []string{
		"received", "return-path", "delivered-to", "dkim-signature",
		"arc-seal", "arc-message-signature", "arc-authentication-results",
		"authentication-results", "x-local", "x-", "message-instance", "dkim2-signature",
	} {
		relevant, err := contract.IsRelevantHeader(name)
		if err != nil || relevant {
			t.Fatalf("excluded draft-04 classification: name=%s relevant=%t error=%t", name, relevant, err != nil)
		}
	}
	for _, name := range []string{"from", "subject", "resent-from", "arcade", "x", "message-id"} {
		relevant, err := contract.IsRelevantHeader(name)
		if err != nil || !relevant {
			t.Fatalf("signed draft-04 classification: name=%s relevant=%t error=%t", name, relevant, err != nil)
		}
	}
	for _, name := range []string{"", "Subject", "bad name", "café"} {
		if _, err := contract.IsRelevantHeader(name); err == nil {
			t.Fatalf("out-of-domain name accepted: bytes=%d", len(name))
		}
	}
	if err := (canonical.HeaderRelevance{}).Validate(); err == nil {
		t.Fatal("zero canonical relevance unexpectedly valid")
	}
}

// TestCanonicalHeaderRelevanceIsConcurrentSafe verifies immutable production classification.
func TestCanonicalHeaderRelevanceIsConcurrentSafe(t *testing.T) {
	relevance := canonical.NewHeaderRelevance()
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			for range 100 {
				if relevant, err := relevance.IsRelevantHeader("subject"); err != nil || !relevant {
					t.Error("signed header classification changed")
					return
				}
				if relevant, err := relevance.IsRelevantHeader("received"); err != nil || relevant {
					t.Error("excluded header classification changed")
					return
				}
			}
		})
	}
	wait.Wait()
}
