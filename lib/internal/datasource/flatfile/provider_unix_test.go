//go:build darwin || linux

package flatfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
	"golang.org/x/sys/unix"
)

// TestProviderInitialLoadAndCallerDescriptorIndependence verifies ownership transfer and generation one.
func TestProviderInitialLoadAndCallerDescriptorIndependence(t *testing.T) {
	t.Parallel()

	rootPath, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	provider, err := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
	if err != nil || provider == nil ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("New(valid) nonnil=%t state=%s code=%s",
			provider != nil, flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	if err := root.Close(); err != nil {
		t.Fatal("caller root descriptor close failed")
	}
	result, err := provider.ResolveProfile(context.Background(), mustFlatfileProfileRequest(t))
	if err != nil || !result.Valid() || result.Generation() != 1 {
		t.Fatalf("ResolveProfile(initial) valid=%t generation=%d code=%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err))
	}
	if err := os.WriteFile(
		filepath.Join(rootPath, flatfileProviderName), mustFlatfileDocument(t), 0o600,
	); err != nil {
		t.Fatal("valid reload fixture write failed")
	}
	if err := provider.Reload(context.Background()); err != nil {
		t.Fatalf("Reload(valid) code=%s", datasource.ErrorCodeOf(err))
	}
	result, err = provider.ResolveProfile(context.Background(), mustFlatfileProfileRequest(t))
	if err != nil || !result.Valid() || result.Generation() != 2 {
		t.Fatalf("ResolveProfile(reload) valid=%t generation=%d code=%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err))
	}
	if err := provider.Close(context.Background()); err != nil {
		t.Fatalf("Close() code=%s", datasource.ErrorCodeOf(err))
	}
}

// TestProviderOwnedRootDescriptorIsCLOEXEC verifies the actual atomic descriptor flag.
func TestProviderOwnedRootDescriptorIsCLOEXEC(t *testing.T) {
	t.Parallel()

	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	flags, err := unix.FcntlInt(uintptr(provider.rootFD), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("owned root CLOEXEC set=%t", err == nil && flags&unix.FD_CLOEXEC != 0)
	}
	if err := provider.Close(context.Background()); err != nil {
		t.Fatalf("Close(CLOEXEC provider) code=%s", datasource.ErrorCodeOf(err))
	}
}

// TestProviderSurvivesForcedCallerDescriptorNumberReuse verifies it never reuses the borrowed FD.
func TestProviderSurvivesForcedCallerDescriptorNumberReuse(t *testing.T) {
	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	borrowed := int(root.Fd())
	provider := mustNewFlatfileProvider(t, root)
	defer closeFlatfileTestProvider(t, provider)
	if err := root.Close(); err != nil {
		t.Fatal("borrowed root close failed")
	}
	replacement, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal("replacement descriptor open failed")
	}
	replacementFD := int(replacement.Fd())
	if replacementFD != borrowed {
		if err := unix.Dup2(replacementFD, borrowed); err != nil {
			closeFlatfileTestFile(t, replacement)
			t.Fatal("borrowed descriptor-number reuse failed")
		}
		t.Cleanup(func() { _ = unix.Close(borrowed) })
	}
	defer closeFlatfileTestFile(t, replacement)
	result, resolveErr := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if resolveErr != nil || !result.Valid() || result.Generation() != 1 {
		t.Fatalf("ResolveProfile(after caller FD reuse) valid=%t generation=%d code=%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(resolveErr))
	}
	if err := provider.Reload(context.Background()); err != nil {
		t.Fatalf("Reload(after caller FD reuse) code=%s", datasource.ErrorCodeOf(err))
	}
}

// TestRepeatedCloseCannotCloseAReusedOwnedDescriptorNumber verifies exact-once close safety.
func TestRepeatedCloseCannotCloseAReusedOwnedDescriptorNumber(t *testing.T) {
	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	owned := provider.rootFD
	if err := provider.Close(context.Background()); err != nil {
		t.Fatalf("Close(first) code=%s", datasource.ErrorCodeOf(err))
	}
	replacement, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal("replacement descriptor open failed")
	}
	replacementFD := int(replacement.Fd())
	if replacementFD != owned {
		if err := unix.Dup2(replacementFD, owned); err != nil {
			closeFlatfileTestFile(t, replacement)
			t.Fatal("owned descriptor-number reuse failed")
		}
		t.Cleanup(func() { _ = unix.Close(owned) })
	}
	defer closeFlatfileTestFile(t, replacement)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.Close(cancelled); err != nil {
		t.Fatalf("Close(repeated after reuse) code=%s", datasource.ErrorCodeOf(err))
	}
	if _, err := unix.FcntlInt(uintptr(owned), unix.F_GETFD, 0); err != nil {
		t.Fatal("repeated Close closed the reused descriptor number")
	}
}

// TestProviderReloadDegradesWithoutServingStaleDataAndRecovers verifies atomic lifecycle semantics.
func TestProviderReloadDegradesWithoutServingStaleDataAndRecovers(t *testing.T) {
	t.Parallel()

	rootPath, root, filePath := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	initial, err := provider.ResolvePolicy(context.Background(), mustFlatfilePolicyRequest(t))
	if err != nil || initial.Generation() != 1 {
		t.Fatalf("ResolvePolicy(initial) generation=%d code=%s",
			initial.Generation(), datasource.ErrorCodeOf(err))
	}

	if err := os.WriteFile(filePath, []byte(`{"malformed":true}`), 0o600); err != nil {
		t.Fatal("malformed reload fixture write failed")
	}
	err = provider.Reload(context.Background())
	if datasource.ErrorCodeOf(err) != datasource.ErrorCodeMalformedData ||
		flatfileProviderState(provider) != datasource.ProviderStateDegraded {
		t.Fatalf("Reload(malformed) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	retainedUsage, usageErr := provider.Usage()
	if usageErr != nil || retainedUsage.Records() != 4 {
		t.Fatalf("Usage(degraded) records=%d code=%s",
			retainedUsage.Records(), datasource.ErrorCodeOf(usageErr))
	}
	result, resolveErr := provider.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	if result.Valid() || result.Generation() != 0 ||
		datasource.ErrorCodeOf(resolveErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("ResolvePolicy(degraded) valid=%t generation=%d code=%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(resolveErr))
	}

	if err := os.WriteFile(filePath, mustFlatfileDocument(t), 0o600); err != nil {
		t.Fatal("recovery fixture write failed")
	}
	if err := provider.Reload(context.Background()); err != nil ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("Reload(recovery) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	recovered, err := provider.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	if err != nil || !recovered.Valid() || recovered.Generation() != 2 {
		t.Fatalf("ResolvePolicy(recovery) valid=%t generation=%d code=%s",
			recovered.Valid(), recovered.Generation(), datasource.ErrorCodeOf(err))
	}

	if err := os.Remove(filepath.Join(rootPath, flatfileProviderName)); err != nil {
		t.Fatal("reload fixture removal failed")
	}
	err = provider.Reload(context.Background())
	if datasource.ErrorCodeOf(err) != datasource.ErrorCodeNotFound ||
		flatfileProviderState(provider) != datasource.ProviderStateDegraded {
		t.Fatalf("Reload(missing) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
}

// TestProviderReloadRemainsBoundToTheOpenedRootAfterPathReplacement verifies root capability confinement.
func TestProviderReloadRemainsBoundToTheOpenedRootAfterPathReplacement(t *testing.T) {
	t.Parallel()

	parentPath := t.TempDir()
	rootPath := filepath.Join(parentPath, "root")
	movedPath := filepath.Join(parentPath, "moved")
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal("root directory setup failed")
	}
	if err := os.WriteFile(
		filepath.Join(rootPath, flatfileProviderName), mustFlatfileDocument(t), 0o600,
	); err != nil {
		t.Fatal("root provider fixture setup failed")
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal("root descriptor open failed")
	}
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	if err := os.Rename(rootPath, movedPath); err != nil {
		t.Fatal("root replacement rename failed")
	}
	if err := os.Mkdir(rootPath, 0o700); err != nil {
		t.Fatal("replacement root setup failed")
	}
	if err := os.WriteFile(
		filepath.Join(rootPath, flatfileProviderName), []byte(`{"malformed":true}`), 0o600,
	); err != nil {
		t.Fatal("replacement provider fixture setup failed")
	}
	if err := provider.Reload(context.Background()); err != nil {
		t.Fatalf("Reload(held root) code=%s", datasource.ErrorCodeOf(err))
	}
	result, err := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if err != nil || !result.Valid() || result.Generation() != 2 {
		t.Fatalf("ResolveProfile(held root) valid=%t generation=%d code=%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err))
	}
}

// TestProviderCloseIsIdempotentAndClosesFutureWork verifies closed publication and no retry surface.
func TestProviderCloseIsIdempotentAndClosesFutureWork(t *testing.T) {
	t.Parallel()

	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	if err := provider.Close(context.Background()); err != nil ||
		flatfileProviderState(provider) != datasource.ProviderStateClosed {
		t.Fatalf("Close(first) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	for count := 0; count < 3; count++ {
		if err := provider.Close(context.Background()); err != nil {
			t.Fatalf("Close(idempotent) code=%s", datasource.ErrorCodeOf(err))
		}
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.Close(cancelled); err != nil {
		t.Fatalf("Close(already closed cancelled) code=%s", datasource.ErrorCodeOf(err))
	}
	var nilContext context.Context
	if err := provider.Close(nilContext); err != nil {
		t.Fatalf("Close(already closed nil) code=%s", datasource.ErrorCodeOf(err))
	}
	assertFlatfileProviderClosed(t, provider)
	if err := provider.Reload(context.Background()); datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable {
		t.Fatalf("Reload(closed) code=%s", datasource.ErrorCodeOf(err))
	}
	if usage, err := provider.Usage(); usage.Records() != 0 ||
		datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable {
		t.Fatalf("Usage(closed) records=%d code=%s",
			usage.Records(), datasource.ErrorCodeOf(err))
	}
}

// TestProviderCancelledLifecycleCallsDoNotMutateReadyState verifies context-first slot acquisition.
func TestProviderCancelledLifecycleCallsDoNotMutateReadyState(t *testing.T) {
	t.Parallel()

	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.Reload(cancelled); datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("Reload(cancelled) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	if err := provider.Close(cancelled); datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("Close(cancelled) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	result, err := provider.ResolveProfile(context.Background(), mustFlatfileProfileRequest(t))
	if err != nil || !result.Valid() || result.Generation() != 1 {
		t.Fatalf("ResolveProfile(after cancellation) valid=%t generation=%d code=%s",
			result.Valid(), result.Generation(), datasource.ErrorCodeOf(err))
	}
}

// TestProviderCancellationWhileBlockedOnOccupiedSlotRestoresReadyState verifies live wait cancellation.
func TestProviderCancellationWhileBlockedOnOccupiedSlotRestoresReadyState(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{flatfileReloadOperation, flatfileCloseOperation} {
		_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
		provider := mustNewFlatfileProvider(t, root)
		<-provider.slot
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		result := make(chan error, 1)
		go func() {
			close(started)
			if operation == flatfileReloadOperation {
				result <- provider.Reload(ctx)
			} else {
				result <- provider.Close(ctx)
			}
		}()
		<-started
		for count := 0; count < 10; count++ {
			runtime.Gosched()
		}
		select {
		case <-result:
			t.Fatal("occupied-slot operation returned before cancellation")
		default:
		}
		cancel()
		if err := <-result; datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled {
			t.Fatalf("occupied-slot cancellation code=%s", datasource.ErrorCodeOf(err))
		}
		provider.release()
		if flatfileProviderState(provider) != datasource.ProviderStateReady {
			t.Fatalf("occupied-slot cancellation state=%s", flatfileProviderState(provider))
		}
		if err := provider.Close(context.Background()); err != nil {
			t.Fatalf("Close(after occupied-slot cancellation) code=%s", datasource.ErrorCodeOf(err))
		}
		closeFlatfileTestFile(t, root)
	}
}

// TestProviderFilenameValidationRejectsEveryPlatformEscape verifies one exact safe component.
func TestProviderFilenameValidationRejectsEveryPlatformEscape(t *testing.T) {
	t.Parallel()

	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	invalid := []string{
		"", ".", "..", "/", "\\", "a/b", `a\b`, "\x00", "/absolute",
		`C:relative`, `C:\absolute`, flatfileReservedConsole, "con",
		flatfileReservedNullName, "nul.txt",
		"COM1", "com9.txt", "LPT1", "lpt9.txt", "provider.", "provider ",
		"provider.json.", "provider.json ",
	}
	for _, filename := range invalid {
		provider, err := New(int(root.Fd()), filename, datasource.DefaultLimits())
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInvalidRequest {
			t.Fatalf("New(invalid filename) nonnil=%t code=%s",
				provider != nil, datasource.ErrorCodeOf(err))
		}
	}
}

// TestProviderFilenameLengthAcceptsExactLimitAndRejectsOneOver verifies the fixed component cap.
func TestProviderFilenameLengthAcceptsExactLimitAndRejectsOneOver(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	t.Cleanup(func() {
		_ = os.Chmod(rootPath, 0o700)
		_ = os.Chmod(filepath.Join(rootPath, flatfileProviderName), 0o600)
	})
	exact := strings.Repeat("a", 255)
	if err := os.WriteFile(filepath.Join(rootPath, exact), mustFlatfileDocument(t), 0o600); err != nil {
		t.Fatal("exact filename fixture setup failed")
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal("exact filename root open failed")
	}
	defer closeFlatfileTestFile(t, root)
	provider, err := New(int(root.Fd()), exact, datasource.DefaultLimits())
	if err != nil || provider == nil {
		t.Fatalf("New(exact filename) nonnil=%t code=%s",
			provider != nil, datasource.ErrorCodeOf(err))
	}
	if err := provider.Close(context.Background()); err != nil {
		t.Fatalf("Close(exact filename) code=%s", datasource.ErrorCodeOf(err))
	}
	provider, err = New(
		int(root.Fd()), strings.Repeat("b", 256), datasource.DefaultLimits(),
	)
	if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeLimitExceeded {
		t.Fatalf("New(filename one over) nonnil=%t code=%s",
			provider != nil, datasource.ErrorCodeOf(err))
	}
}

// TestProviderMissingInitialFileReturnsNoProvider verifies absence is not an empty snapshot.
func TestProviderMissingInitialFileReturnsNoProvider(t *testing.T) {
	t.Parallel()

	rootPath := t.TempDir()
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal("root directory open failed")
	}
	defer closeFlatfileTestFile(t, root)
	provider, err := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
	if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeNotFound {
		t.Fatalf("New(missing file) nonnil=%t code=%s",
			provider != nil, datasource.ErrorCodeOf(err))
	}
}

// TestProviderFormattingAndJSONRemainOpaque verifies paths and provider facts never serialize.
func TestProviderFormattingAndJSONRemainOpaque(t *testing.T) {
	t.Parallel()

	const marker = "provider-private-marker"
	document := bytes.ReplaceAll(mustFlatfileDocument(t), []byte("example"), []byte(marker))
	_, root, _ := newFlatfileRoot(t, document, 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		rendered := fmt.Sprintf(format, provider)
		if strings.Contains(rendered, marker) || strings.Contains(rendered, flatfileProviderName) {
			t.Fatal("provider formatting exposed a protected fact")
		}
	}
	encoded, err := json.Marshal(provider)
	if err != nil || strings.Contains(string(encoded), marker) ||
		strings.Contains(string(encoded), flatfileProviderName) {
		t.Fatal("provider JSON exposed a protected fact")
	}
}

// TestProviderConcurrentResolvesRemainGenerationConsistent verifies lock-free read safety.
func TestProviderConcurrentResolvesRemainGenerationConsistent(t *testing.T) {
	t.Parallel()

	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	request := mustFlatfileProfileRequest(t)
	const workers = 48
	const iterations = 40
	var wait sync.WaitGroup
	failures := make(chan struct{}, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for count := 0; count < iterations; count++ {
				result, err := provider.ResolveProfile(
					context.Background(), request,
				)
				if err != nil || !result.Valid() || result.Generation() != 1 {
					failures <- struct{}{}
					return
				}
			}
		}()
	}
	wait.Wait()
	close(failures)
	if _, failed := <-failures; failed {
		t.Fatal("concurrent provider resolve failed")
	}
}

// newFlatfileRoot constructs one root directory and optional provider fixture.
func newFlatfileRoot(
	t *testing.T,
	document []byte,
	mode os.FileMode,
) (string, *os.File, string) {
	t.Helper()
	rootPath := t.TempDir()
	t.Cleanup(func() {
		_ = os.Chmod(rootPath, 0o700)
		_ = os.Chmod(filepath.Join(rootPath, flatfileProviderName), 0o600)
	})
	if err := os.Chmod(rootPath, 0o700); err != nil {
		t.Fatal("root directory mode setup failed")
	}
	filePath := filepath.Join(rootPath, flatfileProviderName)
	if document != nil {
		if err := os.WriteFile(filePath, document, mode); err != nil {
			t.Fatal("provider fixture write failed")
		}
		if err := os.Chmod(filePath, mode); err != nil {
			t.Fatal("provider fixture mode setup failed")
		}
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal("root directory open failed")
	}
	return rootPath, root, filePath
}

// mustNewFlatfileProvider constructs one ready provider from a fixture root.
func mustNewFlatfileProvider(t *testing.T, root *os.File) *Provider {
	t.Helper()
	provider, err := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
	if err != nil || provider == nil ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("New(valid) nonnil=%t state=%s code=%s",
			provider != nil, flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	t.Cleanup(func() {
		if err := provider.Close(context.Background()); err != nil {
			t.Errorf("Close(test cleanup) code=%s", datasource.ErrorCodeOf(err))
		}
	})
	return provider
}

// closeFlatfileTestFile closes one fixture descriptor and reports cleanup failures.
func closeFlatfileTestFile(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil {
		t.Errorf("fixture descriptor close failed: %v", err)
	}
}

// closeFlatfileTestProvider closes one fixture provider and reports cleanup failures.
func closeFlatfileTestProvider(t *testing.T, provider *Provider) {
	t.Helper()
	if err := provider.Close(context.Background()); err != nil {
		t.Errorf("fixture provider close failed: %s", datasource.ErrorCodeOf(err))
	}
}

// assertFlatfileProviderClosed verifies closed resolve result pairs.
func assertFlatfileProviderClosed(t *testing.T, provider *Provider) {
	t.Helper()
	profile, profileErr := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if profile.Valid() || profile.Generation() != 0 ||
		datasource.ErrorCodeOf(profileErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("ResolveProfile(closed) valid=%t generation=%d code=%s",
			profile.Valid(), profile.Generation(), datasource.ErrorCodeOf(profileErr))
	}
	policy, policyErr := provider.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	if policy.Valid() || policy.Generation() != 0 ||
		datasource.ErrorCodeOf(policyErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("ResolvePolicy(closed) valid=%t generation=%d code=%s",
			policy.Valid(), policy.Generation(), datasource.ErrorCodeOf(policyErr))
	}
}

// TestUnixConfinementSourceUsesAtomicDescriptorPrimitives guards the fork/exec race boundary.
func TestUnixConfinementSourceUsesAtomicDescriptorPrimitives(t *testing.T) {
	t.Parallel()

	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal("flatfile source enumeration failed")
	}
	var production strings.Builder
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal("flatfile production source read failed")
		}
		production.Write(content)
	}
	source := production.String()
	for _, required := range []string{
		"F_DUPFD_CLOEXEC", "Openat(", "O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK", "Fstat(",
	} {
		if !strings.Contains(source, required) {
			t.Fatal("flatfile confinement source omitted an atomic primitive")
		}
	}
	for _, forbidden := range []string{"unix.Dup(", "F_SETFD"} {
		if strings.Contains(source, forbidden) {
			t.Fatal("flatfile confinement source contains a forbidden descriptor sequence")
		}
	}
}

// TestProviderRejectsUnsafeRootAndFileObjects covers modes, types, links, symlinks, and FIFOs.
func TestProviderRejectsUnsafeRootAndFileObjects(t *testing.T) {
	t.Parallel()

	t.Run("root modes", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o300, 0o400, 0o722, 0o777} {
			rootPath, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
			if err := os.Chmod(rootPath, mode); err != nil {
				t.Fatal("unsafe root mode setup failed")
			}
			provider, err := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
			closeFlatfileTestFile(t, root)
			if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable {
				t.Fatalf("New(unsafe root) nonnil=%t code=%s",
					provider != nil, datasource.ErrorCodeOf(err))
			}
		}
	})

	t.Run("valid root modes", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o500, 0o700, 0o755, os.ModeSticky | 0o700} {
			rootPath, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
			if err := os.Chmod(rootPath, mode); err != nil {
				t.Fatal("valid root mode setup failed")
			}
			provider := mustNewFlatfileProvider(t, root)
			closeFlatfileTestFile(t, root)
			if err := provider.Close(context.Background()); err != nil {
				t.Fatalf("Close(valid root mode) code=%s", datasource.ErrorCodeOf(err))
			}
		}
	})

	t.Run("file modes", func(t *testing.T) {
		for _, mode := range []os.FileMode{
			0, 0o200, 0o640, 0o660, 0o700,
		} {
			_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), mode)
			provider, err := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
			closeFlatfileTestFile(t, root)
			if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable {
				t.Fatalf("New(unsafe file mode) nonnil=%t code=%s",
					provider != nil, datasource.ErrorCodeOf(err))
			}
		}
	})

	t.Run("valid file modes", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o400, 0o600} {
			_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), mode)
			provider := mustNewFlatfileProvider(t, root)
			closeFlatfileTestFile(t, root)
			if err := provider.Close(context.Background()); err != nil {
				t.Fatalf("Close(valid mode) code=%s", datasource.ErrorCodeOf(err))
			}
		}
	})

	t.Run("hard link", func(t *testing.T) {
		rootPath, root, filePath := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
		defer closeFlatfileTestFile(t, root)
		if err := os.Link(filePath, filepath.Join(rootPath, "second.json")); err != nil {
			t.Fatal("hard-link fixture setup failed")
		}
		provider, err := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable {
			t.Fatalf("New(hard link) nonnil=%t code=%s",
				provider != nil, datasource.ErrorCodeOf(err))
		}
	})

	t.Run("symlink", func(t *testing.T) {
		rootPath := t.TempDir()
		target := filepath.Join(rootPath, "target.json")
		if err := os.WriteFile(target, mustFlatfileDocument(t), 0o600); err != nil {
			t.Fatal("symlink target setup failed")
		}
		if err := os.Symlink("target.json", filepath.Join(rootPath, flatfileProviderName)); err != nil {
			t.Fatal("symlink fixture setup failed")
		}
		root, err := os.Open(rootPath)
		if err != nil {
			t.Fatal("symlink root open failed")
		}
		defer closeFlatfileTestFile(t, root)
		provider, newErr := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
		if provider != nil || datasource.ErrorCodeOf(newErr) != datasource.ErrorCodeUnavailable {
			t.Fatalf("New(symlink) nonnil=%t code=%s",
				provider != nil, datasource.ErrorCodeOf(newErr))
		}
	})

	t.Run("directory", func(t *testing.T) {
		rootPath := t.TempDir()
		if err := os.Mkdir(filepath.Join(rootPath, flatfileProviderName), 0o700); err != nil {
			t.Fatal("directory fixture setup failed")
		}
		root, err := os.Open(rootPath)
		if err != nil {
			t.Fatal("directory root open failed")
		}
		defer closeFlatfileTestFile(t, root)
		provider, newErr := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
		if provider != nil || datasource.ErrorCodeOf(newErr) != datasource.ErrorCodeUnavailable {
			t.Fatalf("New(directory) nonnil=%t code=%s",
				provider != nil, datasource.ErrorCodeOf(newErr))
		}
	})

	t.Run("fifo", func(t *testing.T) {
		rootPath := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(rootPath, flatfileProviderName), 0o600); err != nil {
			t.Fatal("FIFO fixture setup failed")
		}
		root, err := os.Open(rootPath)
		if err != nil {
			t.Fatal("FIFO root open failed")
		}
		defer closeFlatfileTestFile(t, root)
		provider, newErr := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
		if provider != nil || datasource.ErrorCodeOf(newErr) != datasource.ErrorCodeUnavailable {
			t.Fatalf("New(FIFO) nonnil=%t code=%s",
				provider != nil, datasource.ErrorCodeOf(newErr))
		}
	})
}

// TestProviderRejectsUnixSocketFile verifies non-regular socket rejection.
func TestProviderRejectsUnixSocketFile(t *testing.T) {
	t.Parallel()

	rootPath, err := os.MkdirTemp("/tmp", "dkim2-flatfile-socket-")
	if err != nil {
		t.Fatal("socket root setup failed")
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootPath) })
	socketPath := filepath.Join(rootPath, flatfileProviderName)
	listener, err := net.ListenUnix(
		"unix", &net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox policy forbids creating Unix-domain sockets")
	}
	if err != nil {
		t.Fatalf("Unix socket fixture setup failed: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil {
			t.Errorf("Unix socket fixture close failed: %v", closeErr)
		}
	})
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal("socket root open failed")
	}
	defer closeFlatfileTestFile(t, root)
	provider, newErr := New(
		int(root.Fd()), flatfileProviderName, datasource.DefaultLimits(),
	)
	if provider != nil ||
		datasource.ErrorCodeOf(newErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("New(Unix socket) nonnil=%t code=%s",
			provider != nil, datasource.ErrorCodeOf(newErr))
	}
}

// TestProviderRootRequiresDirectoryDescriptor verifies regular-file roots are rejected.
func TestProviderRootRequiresDirectoryDescriptor(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal("root-file fixture setup failed")
	}
	root, err := os.Open(path)
	if err != nil {
		t.Fatal("root-file descriptor open failed")
	}
	defer closeFlatfileTestFile(t, root)
	provider, newErr := New(int(root.Fd()), flatfileProviderName, datasource.DefaultLimits())
	if provider != nil || datasource.ErrorCodeOf(newErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("New(file root) nonnil=%t code=%s",
			provider != nil, datasource.ErrorCodeOf(newErr))
	}
}

// TestProviderLifecycleContextDeadlineIsPreserved verifies deadline identity at serialization.
func TestProviderLifecycleContextDeadlineIsPreserved(t *testing.T) {
	t.Parallel()

	_, root, _ := newFlatfileRoot(t, mustFlatfileDocument(t), 0o600)
	defer closeFlatfileTestFile(t, root)
	provider := mustNewFlatfileProvider(t, root)
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := provider.Reload(expired); datasource.ErrorCodeOf(err) != datasource.ErrorCodeDeadlineExceeded {
		t.Fatalf("Reload(deadline) code=%s", datasource.ErrorCodeOf(err))
	}
	if err := provider.Close(expired); datasource.ErrorCodeOf(err) != datasource.ErrorCodeDeadlineExceeded {
		t.Fatalf("Close(deadline) code=%s", datasource.ErrorCodeOf(err))
	}
}
