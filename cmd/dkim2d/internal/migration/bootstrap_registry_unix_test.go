//go:build unix

package migration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"golang.org/x/sys/unix"
)

// TestFirstGenerationRegistryIsInertAndRuntimeLoadable proves generation one
// is sealed before backend activation and opens through the runtime registry owner.
func TestFirstGenerationRegistryIsInertAndRuntimeLoadable(t *testing.T) {
	_, plan, imported := publicationFixture(t)
	plan.Generation = "1"
	plan.ExpectedCurrent = "0"
	path, err := StageImportedRegistry(plan, imported)
	if err != nil || path != "1/private-manifest.json" {
		t.Fatal("first generation registry was not staged")
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(plan.RegistryRoot, "1"), 0o700) })
	generationFD, err := unix.Open(
		filepath.Join(plan.RegistryRoot, "1"),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		t.Fatal("first generation registry directory was unavailable")
	}
	source, err := signingstore.NewRegistrySource(generationFD, "private-manifest.json")
	closeErr := unix.Close(generationFD)
	if err != nil || closeErr != nil {
		t.Fatal("first generation runtime registry source was unavailable")
	}
	defer func() { _ = source.Close(context.Background()) }()
	registry, err := source.Load(context.Background(), 1)
	if err != nil || registry == nil {
		t.Fatal("first generation registry was not runtime-loadable")
	}
	defer func() { _ = registry.Close(context.Background()) }()
	generation, err := registry.Generation(context.Background())
	if err != nil || generation != 1 || len(registry.Bindings()) != 1 {
		t.Fatal("first generation runtime registry facts drifted")
	}
}
