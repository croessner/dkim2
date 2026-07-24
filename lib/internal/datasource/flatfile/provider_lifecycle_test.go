package flatfile

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/croessner/dkim2/internal/datasource"
)

// TestInjectedProviderConstructorClosesEveryOwnedDescriptorOnFailure verifies transactional cleanup.
func TestInjectedProviderConstructorClosesEveryOwnedDescriptorOnFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configure  func(*scriptedFilesystem)
		code       datasource.ErrorCode
		rootCloses int
		fileCloses int
	}{
		{
			name: "duplicate failure",
			configure: func(ops *scriptedFilesystem) {
				ops.duplicateDescriptor = -1
				ops.duplicateFailure = operationFailed
			},
			code: datasource.ErrorCodeUnavailable,
		},
		{
			name: "duplicate unsupported",
			configure: func(ops *scriptedFilesystem) {
				ops.duplicateDescriptor = -1
				ops.duplicateFailure = operationUnsupported
			},
			code: datasource.ErrorCodeUnsupportedPlatform,
		},
		{
			name: "root metadata failure",
			configure: func(ops *scriptedFilesystem) {
				ops.rootMetadataFailure = operationFailed
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1,
		},
		{
			name: "root metadata panic",
			configure: func(ops *scriptedFilesystem) {
				ops.rootMetadataPanic = true
			},
			code: datasource.ErrorCodeInternalInvariant, rootCloses: 1,
		},
		{
			name: "root owner mismatch",
			configure: func(ops *scriptedFilesystem) {
				ops.rootMetadata.uid++
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1,
		},
		{
			name: "effective UID panic",
			configure: func(ops *scriptedFilesystem) {
				ops.effectiveUIDPanic = true
			},
			code: datasource.ErrorCodeInternalInvariant, rootCloses: 1,
		},
		{
			name: "missing file",
			configure: func(ops *scriptedFilesystem) {
				ops.openDescriptor = -1
				ops.openFailure = operationNotFound
			},
			code: datasource.ErrorCodeNotFound, rootCloses: 1,
		},
		{
			name: "unsafe file metadata",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadata.links = 2
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "file metadata panic",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadataPanic = true
			},
			code: datasource.ErrorCodeInternalInvariant, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "Unix socket file metadata",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadata.mode = 0140600
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "file owner mismatch",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadata.uid++
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "read failure",
			configure: func(ops *scriptedFilesystem) {
				ops.readFailure = operationFailed
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "read panic",
			configure: func(ops *scriptedFilesystem) {
				ops.readPanic = true
			},
			code: datasource.ErrorCodeInternalInvariant, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "malformed document",
			configure: func(ops *scriptedFilesystem) {
				ops.document = []byte(`{"malformed":true}`)
			},
			code: datasource.ErrorCodeMalformedData, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "file close failure",
			configure: func(ops *scriptedFilesystem) {
				ops.fileCloseFailure = operationFailed
			},
			code: datasource.ErrorCodeUnavailable, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "file close panic",
			configure: func(ops *scriptedFilesystem) {
				ops.fileCloseFailure = operationPanicked
			},
			code: datasource.ErrorCodeInternalInvariant, rootCloses: 1, fileCloses: 1,
		},
		{
			name: "malformed document plus root cleanup panic",
			configure: func(ops *scriptedFilesystem) {
				ops.document = []byte(`{"malformed":true}`)
				ops.rootCloseFailure = operationPanicked
			},
			code: datasource.ErrorCodeInternalInvariant, rootCloses: 1, fileCloses: 1,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			test.configure(ops)
			provider, err := newProvider(
				3, flatfileProviderName, datasource.DefaultLimits(), ops,
			)
			if provider != nil || datasource.ErrorCodeOf(err) != test.code ||
				ops.closeCount(ops.rootFD) != test.rootCloses ||
				ops.totalFileCloses() != test.fileCloses {
				t.Fatalf("newProvider(failure) nonnil=%t code=%s root_closes=%d file_closes=%d",
					provider != nil, datasource.ErrorCodeOf(err),
					ops.closeCount(ops.rootFD), ops.totalFileCloses())
			}
		})
	}
}

// TestInjectedProviderConstructorRejectsNilFilesystemImplementations verifies injected invariants.
func TestInjectedProviderConstructorRejectsNilFilesystemImplementations(t *testing.T) {
	t.Parallel()

	var typedNil *scriptedFilesystem
	for _, ops := range []filesystemOps{nil, typedNil} {
		provider, err := newProvider(
			3, flatfileProviderName, datasource.DefaultLimits(), ops,
		)
		if provider != nil ||
			datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant {
			t.Fatalf("newProvider(nil ops) nonnil=%t code=%s",
				provider != nil, datasource.ErrorCodeOf(err))
		}
	}
}

// TestInjectedProviderReloadFileCloseFailurePublishesDegraded verifies close failure is transactional.
func TestInjectedProviderReloadFileCloseFailurePublishesDegraded(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	ops.setFileCloseFailure(operationFailed)
	err := provider.Reload(context.Background())
	if datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable ||
		flatfileProviderState(provider) != datasource.ProviderStateDegraded {
		t.Fatalf("Reload(file close failure) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	assertInjectedResolveUnavailable(t, provider)
}

// TestInjectedProviderReloadFileClosePanicPublishesDegraded verifies panic containment.
func TestInjectedProviderReloadFileClosePanicPublishesDegraded(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	ops.setFileCloseFailure(operationPanicked)
	err := provider.Reload(context.Background())
	if datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
		flatfileProviderState(provider) != datasource.ProviderStateDegraded {
		t.Fatalf("Reload(file close panic) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	assertInjectedResolveUnavailable(t, provider)
}

// TestInjectedProviderCloseFailureIsPublishedOnceWithoutRetry verifies exact-once root release.
func TestInjectedProviderCloseFailureIsPublishedOnceWithoutRetry(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	ops.setRootCloseFailure(operationFailed)
	err := provider.Close(context.Background())
	if datasource.ErrorCodeOf(err) != datasource.ErrorCodeUnavailable ||
		flatfileProviderState(provider) != datasource.ProviderStateClosed ||
		ops.closeCount(ops.rootFD) != 1 {
		t.Fatalf("Close(failure) state=%s code=%s calls=%d",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err),
			ops.closeCount(ops.rootFD))
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.Close(cancelled); err != nil || ops.closeCount(ops.rootFD) != 1 {
		t.Fatalf("Close(after failure) code=%s calls=%d",
			datasource.ErrorCodeOf(err), ops.closeCount(ops.rootFD))
	}
}

// TestInjectedProviderClosePanicIsPublishedOnceWithoutRetry verifies panic containment.
func TestInjectedProviderClosePanicIsPublishedOnceWithoutRetry(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	ops.setRootCloseFailure(operationPanicked)
	err := provider.Close(context.Background())
	if datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
		flatfileProviderState(provider) != datasource.ProviderStateClosed ||
		ops.closeCount(ops.rootFD) != 1 {
		t.Fatalf("Close(panic) state=%s code=%s calls=%d",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err),
			ops.closeCount(ops.rootFD))
	}
	if err := provider.Close(context.Background()); err != nil ||
		ops.closeCount(ops.rootFD) != 1 {
		t.Fatalf("Close(after panic) code=%s calls=%d",
			datasource.ErrorCodeOf(err), ops.closeCount(ops.rootFD))
	}
}

// TestInjectedReloadLinearizationPreservesBeforeAndAfterResolveSemantics verifies degraded publication.
func TestInjectedReloadLinearizationPreservesBeforeAndAfterResolveSemantics(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	entered, release := ops.blockNextOpen()
	ops.setDocument([]byte(`{"malformed":true}`))
	reloadResult := make(chan error, 1)
	go func() { reloadResult <- provider.Reload(context.Background()) }()
	<-entered
	before, beforeErr := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if beforeErr != nil || !before.Valid() || before.Generation() != 1 {
		t.Fatalf("ResolveProfile(before degraded) valid=%t generation=%d code=%s",
			before.Valid(), before.Generation(), datasource.ErrorCodeOf(beforeErr))
	}
	close(release)
	if err := <-reloadResult; datasource.ErrorCodeOf(err) != datasource.ErrorCodeMalformedData {
		t.Fatalf("Reload(malformed barrier) code=%s", datasource.ErrorCodeOf(err))
	}
	assertInjectedResolveUnavailable(t, provider)
}

// TestInjectedSlotWaitTerminationDoesNotDisturbTheInFlightReload verifies
// cancellation and deadline control flow while lifecycle operations serialize.
func TestInjectedSlotWaitTerminationDoesNotDisturbTheInFlightReload(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{flatfileReloadOperation, flatfileCloseOperation} {
		for _, terminalErr := range []error{context.Canceled, context.DeadlineExceeded} {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			provider := mustNewInjectedProvider(t, ops)
			entered, release := ops.blockNextOpen()
			firstResult := make(chan error, 1)
			go func() { firstResult <- provider.Reload(context.Background()) }()
			<-entered

			ctx := newFlatfileAcquireObservedContext()
			waitResult := make(chan error, 1)
			go func() {
				if operation == flatfileReloadOperation {
					waitResult <- provider.Reload(ctx)
				} else {
					waitResult <- provider.Close(ctx)
				}
			}()
			<-ctx.acquireEntered
			ctx.finish(terminalErr)
			err := <-waitResult
			if !datasource.IsTypedError(err) ||
				datasource.ErrorCodeOf(err) != datasource.ErrorCodeOf(
					datasource.ErrorFromContext(ctx),
				) ||
				!errors.Is(err, terminalErr) ||
				flatfileProviderState(provider) != datasource.ProviderStateReady {
				t.Fatalf("%s(wait terminal) state=%s code=%s",
					operation, flatfileProviderState(provider), datasource.ErrorCodeOf(err))
			}
			close(release)
			if err := <-firstResult; err != nil {
				t.Fatalf("Reload(in flight) code=%s", datasource.ErrorCodeOf(err))
			}
			result, err := provider.ResolveProfile(
				context.Background(), mustFlatfileProfileRequest(t),
			)
			if err != nil || result.Generation() != 2 {
				t.Fatalf("ResolveProfile(after serialized %s) generation=%d code=%s",
					operation, result.Generation(), datasource.ErrorCodeOf(err))
			}
		}
	}
}

// TestInjectedAcquireBothReadyCancellationRestoresTheToken verifies cancellation arbitration.
func TestInjectedAcquireBothReadyCancellationRestoresTheToken(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.acquire(cancelled); datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeCancelled {
		t.Fatalf("acquire(both ready) code=%s", datasource.ErrorCodeOf(err))
	}
	if len(provider.slot) != 1 ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("acquire(both ready) slot=%d state=%s",
			len(provider.slot), flatfileProviderState(provider))
	}
}

// TestInjectedLifecycleRejectsClosedDoneWithNilErrWithoutLosingTheSlot verifies hostile contexts.
func TestInjectedLifecycleRejectsClosedDoneWithNilErrWithoutLosingTheSlot(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{flatfileReloadOperation, flatfileCloseOperation} {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		provider := mustNewInjectedProvider(t, ops)
		ctx := newFlatfileInconsistentContext()
		var err error
		if operation == "reload" {
			err = provider.Reload(ctx)
		} else {
			err = provider.Close(ctx)
		}
		if datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
			flatfileProviderState(provider) != datasource.ProviderStateReady ||
			len(provider.slot) != 1 {
			t.Fatalf("lifecycle(hostile context) state=%s slot=%d code=%s",
				flatfileProviderState(provider), len(provider.slot), datasource.ErrorCodeOf(err))
		}
		if err := provider.Reload(context.Background()); err != nil {
			t.Fatalf("Reload(after hostile context) code=%s", datasource.ErrorCodeOf(err))
		}
	}
}

// TestInjectedDescriptorResultPairsFailClosedWithoutLeakingOrAliasing verifies ownership.
func TestInjectedDescriptorResultPairsFailClosedWithoutLeakingOrAliasing(t *testing.T) {
	t.Parallel()

	t.Run("root metadata plus failure", func(t *testing.T) {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		ops.rootMetadataFailure = operationFailed
		ops.rootMetadataOnFailure = true
		provider, err := newProvider(3, flatfileProviderName, datasource.DefaultLimits(), ops)
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
			ops.closeCount(ops.rootFD) != 1 {
			t.Fatalf("root metadata mixed pair nonnil=%t code=%s closes=%d",
				provider != nil, datasource.ErrorCodeOf(err), ops.closeCount(ops.rootFD))
		}
	})

	t.Run("duplicate valid descriptor plus failure", func(t *testing.T) {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		ops.duplicateFailure = operationFailed
		provider, err := newProvider(3, flatfileProviderName, datasource.DefaultLimits(), ops)
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
			ops.closeCount(ops.rootFD) != 1 {
			t.Fatalf("duplicate mixed pair nonnil=%t code=%s closes=%d",
				provider != nil, datasource.ErrorCodeOf(err), ops.closeCount(ops.rootFD))
		}
	})
	for _, descriptor := range []int{-1, 3} {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		ops.duplicateDescriptor = descriptor
		provider, err := newProvider(3, flatfileProviderName, datasource.DefaultLimits(), ops)
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
			ops.closeCount(3) != 0 {
			t.Fatalf("duplicate invalid success nonnil=%t code=%s borrowed_closes=%d",
				provider != nil, datasource.ErrorCodeOf(err), ops.closeCount(3))
		}
	}

	t.Run("open valid descriptor plus failure", func(t *testing.T) {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		ops.openFailure = operationFailed
		ops.openDescriptor = 250
		provider, err := newProvider(3, flatfileProviderName, datasource.DefaultLimits(), ops)
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
			ops.closeCount(250) != 1 || ops.closeCount(ops.rootFD) != 1 {
			t.Fatalf("open mixed pair nonnil=%t code=%s file_closes=%d root_closes=%d",
				provider != nil, datasource.ErrorCodeOf(err), ops.closeCount(250),
				ops.closeCount(ops.rootFD))
		}
	})
	for _, descriptor := range []int{-1, 100} {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		ops.openDescriptor = descriptor
		provider, err := newProvider(3, flatfileProviderName, datasource.DefaultLimits(), ops)
		if provider != nil || datasource.ErrorCodeOf(err) != datasource.ErrorCodeInternalInvariant ||
			ops.closeCount(ops.rootFD) != 1 || ops.totalFileCloses() != 0 {
			t.Fatalf("open invalid success nonnil=%t code=%s root_closes=%d file_closes=%d",
				provider != nil, datasource.ErrorCodeOf(err), ops.closeCount(ops.rootFD),
				ops.totalFileCloses())
		}
	}
}

// TestInjectedCleanupFailureAppliesOrdinaryAndPanicPrecedence verifies ordinary
// cleanup failures retain the primary while cleanup panics fail as invariants.
func TestInjectedCleanupFailureAppliesOrdinaryAndPanicPrecedence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fileClose operationFailure
		rootClose operationFailure
		code      datasource.ErrorCode
	}{
		{
			name: "file close failure", fileClose: operationFailed,
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "file close panic", fileClose: operationPanicked,
			code: datasource.ErrorCodeInternalInvariant,
		},
		{
			name: "root close failure", rootClose: operationFailed,
			code: datasource.ErrorCodeMalformedData,
		},
		{
			name: "root close panic", rootClose: operationPanicked,
			code: datasource.ErrorCodeInternalInvariant,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ops := newScriptedFilesystem([]byte(`{"malformed":true}`))
			ops.fileCloseFailure = test.fileClose
			ops.rootCloseFailure = test.rootClose
			provider, err := newProvider(3, flatfileProviderName, datasource.DefaultLimits(), ops)
			if provider != nil || datasource.ErrorCodeOf(err) != test.code ||
				ops.closeCount(ops.rootFD) != 1 || ops.totalFileCloses() != 1 {
				t.Fatalf("cleanup classification nonnil=%t code=%s root_closes=%d file_closes=%d",
					provider != nil, datasource.ErrorCodeOf(err),
					ops.closeCount(ops.rootFD), ops.totalFileCloses())
			}
		})
	}
}

// TestInjectedReloadReadsBytesFromTheOpenedDescriptor verifies open-time file identity.
func TestInjectedReloadReadsBytesFromTheOpenedDescriptor(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	entered, release := ops.blockNextOpen()
	result := make(chan error, 1)
	go func() { result <- provider.Reload(context.Background()) }()
	<-entered
	ops.setDocument([]byte(`{"malformed":true}`))
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("Reload(opened descriptor bytes) code=%s", datasource.ErrorCodeOf(err))
	}
	resolved, err := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if err != nil || resolved.Generation() != 2 {
		t.Fatalf("ResolveProfile(opened descriptor bytes) generation=%d code=%s",
			resolved.Generation(), datasource.ErrorCodeOf(err))
	}
	if err := provider.Reload(context.Background()); datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeMalformedData {
		t.Fatalf("Reload(next descriptor bytes) code=%s", datasource.ErrorCodeOf(err))
	}
}

// TestInjectedReleaseDoubleSendPanicsWithoutBlocking verifies invariant misuse is bounded.
func TestInjectedReleaseDoubleSendPanicsWithoutBlocking(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	completed := make(chan bool, 1)
	go func() {
		panicked := false
		defer func() {
			if recover() != nil {
				panicked = true
			}
			completed <- panicked
		}()
		provider.release()
	}()
	select {
	case panicked := <-completed:
		if !panicked {
			t.Fatal("double release did not panic")
		}
	case <-time.After(time.Second):
		t.Fatal("double release blocked")
	}
}

// TestInjectedReloadCancellationAfterAcquisitionPublishesDegraded verifies post-linearization cancellation.
func TestInjectedReloadCancellationAfterAcquisitionPublishesDegraded(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	entered, release := ops.blockNextOpen()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- provider.Reload(ctx) }()
	<-entered
	cancel()
	close(release)
	if err := <-result; datasource.ErrorCodeOf(err) != datasource.ErrorCodeCancelled ||
		flatfileProviderState(provider) != datasource.ProviderStateDegraded {
		t.Fatalf("Reload(post-acquire cancellation) state=%s code=%s",
			flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	assertInjectedResolveUnavailable(t, provider)
}

// TestInjectedCloseCompletesAfterAcquisitionDespiteLaterTermination verifies
// irreversible close success and failures are not masked after linearization.
func TestInjectedCloseCompletesAfterAcquisitionDespiteLaterTermination(t *testing.T) {
	t.Parallel()

	outcomes := []struct {
		name    string
		failure operationFailure
		code    datasource.ErrorCode
	}{
		{name: "success"},
		{
			name: "failure", failure: operationFailed,
			code: datasource.ErrorCodeUnavailable,
		},
		{
			name: "root close panic", failure: operationPanicked,
			code: datasource.ErrorCodeInternalInvariant,
		},
	}
	for _, terminalErr := range []error{context.Canceled, context.DeadlineExceeded} {
		for _, outcome := range outcomes {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			provider := mustNewInjectedProvider(t, ops)
			ops.setRootCloseFailure(outcome.failure)
			entered, release := ops.blockRootClose()
			ctx := newFlatfileReadTransitionContext()
			result := make(chan error, 1)
			go func() { result <- provider.Close(ctx) }()
			<-entered
			ctx.finish(terminalErr)
			close(release)
			err := <-result
			if outcome.code == "" {
				if err != nil {
					t.Fatalf("%s close success returned code=%s",
						outcome.name, datasource.ErrorCodeOf(err))
				}
			} else if !datasource.IsTypedError(err) ||
				datasource.ErrorCodeOf(err) != outcome.code ||
				errors.Is(err, terminalErr) {
				t.Fatalf("%s close failure returned code=%s",
					outcome.name, datasource.ErrorCodeOf(err))
			}
			if flatfileProviderState(provider) != datasource.ProviderStateClosed ||
				ops.closeCount(ops.rootFD) != 1 {
				t.Fatalf("%s close terminal state=%s calls=%d",
					outcome.name, flatfileProviderState(provider),
					ops.closeCount(ops.rootFD))
			}
		}
	}
}

// TestInjectedSuccessfulReloadsIncreaseGenerationExactlyOnce verifies monotonic publication.
func TestInjectedSuccessfulReloadsIncreaseGenerationExactlyOnce(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	for expected := uint64(2); expected <= 4; expected++ {
		if err := provider.Reload(context.Background()); err != nil {
			t.Fatalf("Reload(success) code=%s", datasource.ErrorCodeOf(err))
		}
		result, err := provider.ResolveProfile(
			context.Background(), mustFlatfileProfileRequest(t),
		)
		if err != nil || result.Generation() != expected {
			t.Fatalf("ResolveProfile(generation) got=%d want=%d code=%s",
				result.Generation(), expected, datasource.ErrorCodeOf(err))
		}
	}
}

// TestInjectedReloadRejectsGenerationOverflowWithoutBackendOrStateMutation
// verifies a ready terminal generation is a non-degrading preflight limit.
func TestInjectedReloadRejectsGenerationOverflowWithoutBackendOrStateMutation(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	snapshot, err := DecodeReader(
		math.MaxUint64, bytes.NewReader(mustFlatfileDocument(t)), datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("DecodeReader(max generation) code=%s", datasource.ErrorCodeOf(err))
	}
	provider.publication.Store(&providerSnapshot{
		state: datasource.ProviderStateReady, generation: math.MaxUint64, snapshot: snapshot,
	})
	beforeUsage, usageErr := provider.Usage()
	beforeResult, resolveErr := provider.ResolveProfile(
		context.Background(),
		mustFlatfileProfileRequest(t),
	)
	if usageErr != nil || resolveErr != nil || !beforeResult.Valid() {
		t.Fatal("terminal generation precondition was not ready")
	}
	beforeBackend := ops.backendCounts()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.Reload(cancelled); datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeCancelled {
		t.Fatalf("Reload(cancelled max generation) code=%s", datasource.ErrorCodeOf(err))
	}
	if err := provider.Reload(context.Background()); datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeLimitExceeded {
		t.Fatalf("Reload(max generation) code=%s", datasource.ErrorCodeOf(err))
	}
	published := provider.publication.Load()
	afterUsage, usageErr := provider.Usage()
	afterResult, resolveErr := provider.ResolveProfile(
		context.Background(),
		mustFlatfileProfileRequest(t),
	)
	if published.state != datasource.ProviderStateReady ||
		published.generation != math.MaxUint64 ||
		published.snapshot != snapshot ||
		published.snapshot.generation != math.MaxUint64 ||
		usageErr != nil || afterUsage != beforeUsage ||
		resolveErr != nil || !afterResult.Valid() ||
		afterResult.Generation() != beforeResult.Generation() ||
		ops.backendCounts() != beforeBackend {
		t.Fatalf("Reload(max generation) state=%s generation=%d snapshot_generation=%d",
			published.state, published.generation, published.snapshot.generation)
	}
}

// TestInjectedQueuedReloadRechecksTerminalGenerationAfterAcquisition proves a
// waiter cannot overflow or degrade a generation published while it queued.
func TestInjectedQueuedReloadRechecksTerminalGenerationAfterAcquisition(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	snapshot, err := DecodeReader(
		math.MaxUint64-1,
		bytes.NewReader(mustFlatfileDocument(t)),
		datasource.DefaultLimits(),
	)
	if err != nil {
		t.Fatalf("DecodeReader(pre-terminal generation) code=%s", datasource.ErrorCodeOf(err))
	}
	provider.publication.Store(&providerSnapshot{
		state: datasource.ProviderStateReady, generation: math.MaxUint64 - 1, snapshot: snapshot,
	})
	beforeBackend := ops.backendCounts()

	firstEntered, firstRelease := ops.blockNextOpen()
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- provider.Reload(context.Background())
	}()
	<-firstEntered
	firstOpenCount := ops.backendCounts()[1]

	secondContext := newFlatfileAcquireObservedContext()
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- provider.Reload(secondContext)
	}()
	<-secondContext.acquireEntered

	close(firstRelease)
	if err := <-firstResult; err != nil {
		t.Fatalf("Reload(to terminal generation) code=%s", datasource.ErrorCodeOf(err))
	}
	if err := <-secondResult; datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeLimitExceeded {
		t.Fatalf("Reload(queued at terminal generation) code=%s", datasource.ErrorCodeOf(err))
	}
	expectedBackend := beforeBackend
	expectedBackend[0]++
	expectedBackend[1]++
	expectedBackend[2] += 2
	expectedBackend[3]++
	published := provider.publication.Load()
	if !published.valid() ||
		published.state != datasource.ProviderStateReady ||
		published.generation != math.MaxUint64 ||
		published.snapshot.generation != math.MaxUint64 ||
		ops.backendCounts() != expectedBackend ||
		ops.backendCounts()[1] != firstOpenCount {
		t.Fatal("queued terminal reload mutated state or reached the backend")
	}
}

// TestInjectedQueuedReloadRecoversAfterSerializedFailure proves a queued
// successful load observes degradation and publishes exactly one successor.
func TestInjectedQueuedReloadRecoversAfterSerializedFailure(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	ops.setDocument([]byte(`{"version":`))

	firstEntered, firstRelease := ops.blockNextOpen()
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- provider.Reload(context.Background())
	}()
	<-firstEntered

	ops.setDocument(mustFlatfileDocument(t))
	secondEntered, secondRelease := ops.blockNextOpen()
	secondContext := newFlatfileAcquireObservedContext()
	secondResult := make(chan error, 1)
	go func() {
		secondResult <- provider.Reload(secondContext)
	}()
	<-secondContext.acquireEntered

	close(firstRelease)
	firstErr := <-firstResult
	<-secondEntered
	degradedState := flatfileProviderState(provider)
	degradedProfile, degradedProfileErr := provider.ResolveProfile(
		context.Background(),
		mustFlatfileProfileRequest(t),
	)
	degradedPolicy, degradedPolicyErr := provider.ResolvePolicy(
		context.Background(),
		mustFlatfilePolicyRequest(t),
	)

	close(secondRelease)
	secondErr := <-secondResult
	if datasource.ErrorCodeOf(firstErr) != datasource.ErrorCodeMalformedData {
		t.Fatalf("Reload(serialized failure) code=%s", datasource.ErrorCodeOf(firstErr))
	}
	if degradedState != datasource.ProviderStateDegraded {
		t.Fatal("failed serialized reload did not publish degradation")
	}
	if degradedProfile.Valid() || degradedProfile.Generation() != 0 ||
		datasource.ErrorCodeOf(degradedProfileErr) != datasource.ErrorCodeUnavailable ||
		degradedPolicy.Valid() || degradedPolicy.Generation() != 0 ||
		datasource.ErrorCodeOf(degradedPolicyErr) != datasource.ErrorCodeUnavailable {
		t.Fatal("failed serialized reload exposed a partial degraded result")
	}
	if secondErr != nil {
		t.Fatalf("Reload(serialized recovery) code=%s", datasource.ErrorCodeOf(secondErr))
	}
	result, err := provider.ResolveProfile(
		context.Background(),
		mustFlatfileProfileRequest(t),
	)
	if err != nil ||
		flatfileProviderState(provider) != datasource.ProviderStateReady ||
		result.Generation() != 2 {
		t.Fatalf("Reload(serialized recovery) state=%s generation=%d code=%s",
			flatfileProviderState(provider), result.Generation(), datasource.ErrorCodeOf(err))
	}
}

// TestInjectedReloadCancellationDuringDescriptorReadDegradesWithoutPartial
// publication proves both cancellation classes at the read/decode boundary.
func TestInjectedReloadCancellationDuringDescriptorReadDegradesWithoutPartial(t *testing.T) {
	t.Parallel()

	for _, phase := range []string{"read", "post-decode"} {
		for _, terminalErr := range []error{context.Canceled, context.DeadlineExceeded} {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			provider := mustNewInjectedProvider(t, ops)
			var entered <-chan struct{}
			var release chan<- struct{}
			if phase == "read" {
				entered, release = ops.blockNextRead()
			} else {
				entered, release = ops.blockNextFileClose()
			}
			beforeCloses := ops.totalFileCloses()
			ctx := newFlatfileReadTransitionContext()
			result := make(chan error, 1)
			go func() {
				result <- provider.Reload(ctx)
			}()
			<-entered
			ctx.finish(terminalErr)
			var prematureErr error
			premature := false
			select {
			case prematureErr = <-result:
				premature = true
			default:
			}
			stateWhileBlocked := flatfileProviderState(provider)
			close(release)
			resultErr := prematureErr
			if !premature {
				resultErr = <-result
			}
			if premature {
				t.Fatal("blocked descriptor boundary reported cancellation before returning")
			}
			if stateWhileBlocked != datasource.ProviderStateReady {
				t.Fatal("blocked descriptor boundary published partial state")
			}
			if !errors.Is(resultErr, terminalErr) ||
				flatfileProviderState(provider) != datasource.ProviderStateDegraded ||
				ops.totalFileCloses() != beforeCloses+1 {
				t.Fatalf("Reload(read cancellation) state=%s code=%s closes=%d",
					flatfileProviderState(provider), datasource.ErrorCodeOf(resultErr),
					ops.totalFileCloses())
			}
			assertInjectedResolveUnavailable(t, provider)
		}
	}
}

// TestInjectedReloadReconcilesBoundaryFailureWithTerminalContext proves
// ordinary failures yield to exact context identity while impossible
// capability outcomes and panics retain internal-invariant precedence.
func TestInjectedReloadReconcilesBoundaryFailureWithTerminalContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		configure      func(*scriptedFilesystem)
		block          func(*scriptedFilesystem) (<-chan struct{}, chan<- struct{})
		internal       bool
		fileCloseDelta int
	}{
		{
			name: "open failure",
			configure: func(ops *scriptedFilesystem) {
				ops.openDescriptor = -1
				ops.openFailure = operationFailed
			},
			block:          (*scriptedFilesystem).blockNextOpen,
			fileCloseDelta: 0,
		},
		{
			name: "metadata failure",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadataFailure = operationFailed
			},
			block:          (*scriptedFilesystem).blockNextFileMetadata,
			fileCloseDelta: 1,
		},
		{
			name: "cleanup failure",
			configure: func(ops *scriptedFilesystem) {
				ops.fileCloseFailure = operationFailed
			},
			block:          (*scriptedFilesystem).blockNextFileClose,
			fileCloseDelta: 1,
		},
		{
			name: "terminal descriptor read failure",
			configure: func(ops *scriptedFilesystem) {
				ops.readFailure = operationFailed
			},
			block:          (*scriptedFilesystem).blockNextRead,
			fileCloseDelta: 1,
		},
		{
			name: "malformed document",
			configure: func(ops *scriptedFilesystem) {
				ops.setDocument([]byte(`{"malformed":true}`))
			},
			block:          (*scriptedFilesystem).blockNextFileClose,
			fileCloseDelta: 1,
		},
		{
			name: "read panic",
			configure: func(ops *scriptedFilesystem) {
				ops.readPanic = true
			},
			block:          (*scriptedFilesystem).blockNextRead,
			internal:       true,
			fileCloseDelta: 1,
		},
		{
			name: "metadata panic",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadataPanic = true
			},
			block:          (*scriptedFilesystem).blockNextFileMetadata,
			internal:       true,
			fileCloseDelta: 1,
		},
		{
			name: "cleanup panic",
			configure: func(ops *scriptedFilesystem) {
				ops.fileCloseFailure = operationPanicked
			},
			block:          (*scriptedFilesystem).blockNextFileClose,
			internal:       true,
			fileCloseDelta: 1,
		},
		{
			name: "malformed document plus cleanup panic",
			configure: func(ops *scriptedFilesystem) {
				ops.setDocument([]byte(`{"malformed":true}`))
				ops.fileCloseFailure = operationPanicked
			},
			block:          (*scriptedFilesystem).blockNextFileClose,
			internal:       true,
			fileCloseDelta: 1,
		},
		{
			name: "contradictory open pair",
			configure: func(ops *scriptedFilesystem) {
				ops.openFailure = operationFailed
			},
			block:          (*scriptedFilesystem).blockNextOpen,
			internal:       true,
			fileCloseDelta: 1,
		},
	}
	for _, test := range tests {
		for _, terminalErr := range []error{context.Canceled, context.DeadlineExceeded} {
			runInjectedReloadBoundaryReconciliationCase(
				t,
				test.name,
				test.configure,
				test.block,
				test.internal,
				test.fileCloseDelta,
				terminalErr,
			)
		}
	}
}

// TestInjectedReloadCleanupPanicOverridesPrimaryAndContext proves a panic at
// the transient capability cleanup boundary cannot be hidden by an ordinary
// decode failure or a concurrent terminal context.
func TestInjectedReloadCleanupPanicOverridesPrimaryAndContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		terminalErr error
	}{
		{name: "active"},
		{name: "cancelled", terminalErr: context.Canceled},
		{name: "deadline", terminalErr: context.DeadlineExceeded},
	}
	for _, test := range tests {
		ops := newScriptedFilesystem(mustFlatfileDocument(t))
		provider := mustNewInjectedProvider(t, ops)
		ops.setDocument([]byte(`{"malformed":true}`))
		ops.setFileCloseFailure(operationPanicked)
		entered, release := ops.blockNextFileClose()
		beforeCloses := ops.totalFileCloses()
		ctx := newFlatfileReadTransitionContext()
		result := make(chan error, 1)
		go func() {
			result <- provider.Reload(ctx)
		}()
		<-entered
		if test.terminalErr != nil {
			ctx.finish(test.terminalErr)
		}
		close(release)
		resultErr := <-result
		if !datasource.IsTypedError(resultErr) ||
			datasource.ErrorCodeOf(resultErr) != datasource.ErrorCodeInternalInvariant ||
			errors.Is(resultErr, context.Canceled) ||
			errors.Is(resultErr, context.DeadlineExceeded) ||
			flatfileProviderState(provider) != datasource.ProviderStateDegraded ||
			ops.totalFileCloses() != beforeCloses+1 {
			t.Fatalf("%s cleanup precedence state=%s code=%s closes=%d",
				test.name, flatfileProviderState(provider),
				datasource.ErrorCodeOf(resultErr), ops.totalFileCloses())
		}
		assertInjectedResolveUnavailable(t, provider)
	}
}

// TestInjectedReloadRejectsContradictoryCapabilityPairs proves partial
// metadata and read results fail as internal invariants before terminal
// context reconciliation.
func TestInjectedReloadRejectsContradictoryCapabilityPairs(t *testing.T) {
	t.Parallel()

	boundaries := []struct {
		name      string
		configure func(*scriptedFilesystem)
		block     func(*scriptedFilesystem) (<-chan struct{}, chan<- struct{})
	}{
		{
			name: "file metadata plus failure",
			configure: func(ops *scriptedFilesystem) {
				ops.fileMetadataFailure = operationFailed
				ops.fileMetadataOnFailure = true
			},
			block: (*scriptedFilesystem).blockNextFileMetadata,
		},
		{
			name: "positive read count plus failure",
			configure: func(ops *scriptedFilesystem) {
				ops.readFailure = operationFailed
				ops.readFailureCount = 1
			},
			block: (*scriptedFilesystem).blockNextRead,
		},
	}
	contexts := []struct {
		name        string
		terminalErr error
	}{
		{name: "active"},
		{name: "cancelled", terminalErr: context.Canceled},
		{name: "deadline", terminalErr: context.DeadlineExceeded},
	}
	for _, boundary := range boundaries {
		for _, contextCase := range contexts {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			provider := mustNewInjectedProvider(t, ops)
			boundary.configure(ops)
			entered, release := boundary.block(ops)
			beforeCloses := ops.totalFileCloses()
			ctx := newFlatfileReadTransitionContext()
			result := make(chan error, 1)
			go func() {
				result <- provider.Reload(ctx)
			}()
			<-entered
			if contextCase.terminalErr != nil {
				ctx.finish(contextCase.terminalErr)
			}
			close(release)
			resultErr := <-result
			if !datasource.IsTypedError(resultErr) ||
				datasource.ErrorCodeOf(resultErr) != datasource.ErrorCodeInternalInvariant ||
				errors.Is(resultErr, context.Canceled) ||
				errors.Is(resultErr, context.DeadlineExceeded) ||
				flatfileProviderState(provider) != datasource.ProviderStateDegraded ||
				ops.totalFileCloses() != beforeCloses+1 {
				t.Fatalf("%s/%s state=%s code=%s closes=%d",
					boundary.name, contextCase.name, flatfileProviderState(provider),
					datasource.ErrorCodeOf(resultErr), ops.totalFileCloses())
			}
			assertInjectedResolveUnavailable(t, provider)
		}
	}
}

// runInjectedReloadBoundaryReconciliationCase executes one deterministic
// backend/context cross-product without allowing partial publication.
func runInjectedReloadBoundaryReconciliationCase(
	t *testing.T,
	name string,
	configure func(*scriptedFilesystem),
	block func(*scriptedFilesystem) (<-chan struct{}, chan<- struct{}),
	internal bool,
	fileCloseDelta int,
	terminalErr error,
) {
	t.Helper()
	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	configure(ops)
	entered, release := block(ops)
	beforeCloses := ops.totalFileCloses()
	ctx := newFlatfileReadTransitionContext()
	result := make(chan error, 1)
	go func() {
		result <- provider.Reload(ctx)
	}()
	<-entered
	ctx.finish(terminalErr)
	close(release)
	resultErr := <-result
	if internal {
		if !datasource.IsTypedError(resultErr) ||
			datasource.ErrorCodeOf(resultErr) != datasource.ErrorCodeInternalInvariant ||
			errors.Is(resultErr, terminalErr) {
			t.Fatalf("%s returned code=%s", name, datasource.ErrorCodeOf(resultErr))
		}
	} else if !datasource.IsTypedError(resultErr) ||
		datasource.ErrorCodeOf(resultErr) != datasource.ErrorCodeOf(
			datasource.ErrorFromContext(ctx),
		) ||
		!errors.Is(resultErr, terminalErr) {
		t.Fatalf("%s did not preserve terminal context identity", name)
	}
	if flatfileProviderState(provider) != datasource.ProviderStateDegraded ||
		ops.totalFileCloses() != beforeCloses+fileCloseDelta {
		t.Fatalf("%s state=%s file_closes=%d",
			name, flatfileProviderState(provider), ops.totalFileCloses())
	}
	assertInjectedResolveUnavailable(t, provider)
}

// TestInjectedProviderRejectsCorruptPublicationsAcrossEveryReadSurface verifies fail-closed integrity.
func TestInjectedProviderRejectsCorruptPublicationsAcrossEveryReadSurface(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		corrupt func(*providerSnapshot) *providerSnapshot
	}{
		{name: "nil publication", corrupt: func(*providerSnapshot) *providerSnapshot { return nil }},
		{name: "zero state", corrupt: func(published *providerSnapshot) *providerSnapshot {
			publicationCopy := *published
			publicationCopy.state = 0
			return &publicationCopy
		}},
		{name: "zero generation", corrupt: func(published *providerSnapshot) *providerSnapshot {
			publicationCopy := *published
			publicationCopy.generation = 0
			return &publicationCopy
		}},
		{name: "mismatched generation", corrupt: func(published *providerSnapshot) *providerSnapshot {
			publicationCopy := *published
			publicationCopy.generation++
			return &publicationCopy
		}},
		{name: "nil snapshot", corrupt: func(published *providerSnapshot) *providerSnapshot {
			publicationCopy := *published
			publicationCopy.snapshot = nil
			return &publicationCopy
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			provider := mustNewInjectedProvider(t, ops)
			original := provider.publication.Load()
			provider.publication.Store(test.corrupt(original))
			assertProviderIntegrityFailures(t, provider)
			provider.publication.Store(original)
		})
	}
}

// TestProviderZeroAndNilReceiversRejectStateUsageAndResolve verifies receiver integrity.
func TestProviderZeroAndNilReceiversRejectStateUsageAndResolve(t *testing.T) {
	t.Parallel()

	for _, provider := range []*Provider{nil, &Provider{}} {
		assertProviderIntegrityFailures(t, provider)
	}
}

// TestInjectedProviderRejectsNilTypedNilAndPanickingContexts verifies context trust boundaries.
func TestInjectedProviderRejectsNilTypedNilAndPanickingContexts(t *testing.T) {
	t.Parallel()

	var typedNil *flatfileNilContext
	tests := []struct {
		name string
		ctx  context.Context
		code datasource.ErrorCode
	}{
		{name: "nil", ctx: nil, code: datasource.ErrorCodeInvalidRequest},
		{name: "typed nil", ctx: typedNil, code: datasource.ErrorCodeInvalidRequest},
		{name: "panic", ctx: flatfileProviderPanicContext{}, code: datasource.ErrorCodeInternalInvariant},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			ops := newScriptedFilesystem(mustFlatfileDocument(t))
			provider := mustNewInjectedProvider(t, ops)
			if err := provider.Reload(test.ctx); datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("Reload(context) code=%s", datasource.ErrorCodeOf(err))
			}
			if err := provider.Close(test.ctx); datasource.ErrorCodeOf(err) != test.code {
				t.Fatalf("Close(context) code=%s", datasource.ErrorCodeOf(err))
			}
			profile, profileErr := provider.ResolveProfile(test.ctx, mustFlatfileProfileRequest(t))
			if profile.Valid() || profile.Generation() != 0 ||
				datasource.ErrorCodeOf(profileErr) != test.code {
				t.Fatalf("ResolveProfile(context) valid=%t generation=%d code=%s",
					profile.Valid(), profile.Generation(), datasource.ErrorCodeOf(profileErr))
			}
			policy, policyErr := provider.ResolvePolicy(test.ctx, mustFlatfilePolicyRequest(t))
			if policy.Valid() || policy.Generation() != 0 ||
				datasource.ErrorCodeOf(policyErr) != test.code {
				t.Fatalf("ResolvePolicy(context) valid=%t generation=%d code=%s",
					policy.Valid(), policy.Generation(), datasource.ErrorCodeOf(policyErr))
			}
		})
	}
}

// TestInjectedConcurrentReloadResolveAndCloseHasOneClosedTerminalState provides race coverage.
func TestInjectedConcurrentReloadResolveAndCloseHasOneClosedTerminalState(t *testing.T) {
	t.Parallel()

	ops := newScriptedFilesystem(mustFlatfileDocument(t))
	provider := mustNewInjectedProvider(t, ops)
	request := mustFlatfileProfileRequest(t)
	entered, release := ops.blockNextOpen()
	reloadResult := make(chan error, 1)
	go func() { reloadResult <- provider.Reload(context.Background()) }()
	<-entered

	const readers = 32
	var wait sync.WaitGroup
	for index := 0; index < readers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := provider.ResolveProfile(context.Background(), request)
			if err != nil || !result.Valid() || result.Generation() != 1 {
				t.Error("resolve before concurrent publication failed")
			}
		}()
	}
	wait.Wait()
	closeResult := make(chan error, 1)
	go func() { closeResult <- provider.Close(context.Background()) }()
	close(release)
	if err := <-reloadResult; err != nil {
		t.Fatalf("Reload(concurrent close) code=%s", datasource.ErrorCodeOf(err))
	}
	if err := <-closeResult; err != nil {
		t.Fatalf("Close(concurrent reload) code=%s", datasource.ErrorCodeOf(err))
	}
	if flatfileProviderState(provider) != datasource.ProviderStateClosed {
		t.Fatalf("provider terminal state=%s", flatfileProviderState(provider))
	}
	assertInjectedResolveUnavailable(t, provider)
}

// scriptedFilesystem is one deterministic descriptor and barrier test double.
type scriptedFilesystem struct {
	mu sync.Mutex

	rootFD              int
	duplicateDescriptor int
	nextFD              int
	uid                 uint32
	document            []byte
	offsets             map[int]int
	fdDocuments         map[int][]byte
	closes              map[int]int
	metadataCalls       int
	openCalls           int
	readCalls           int

	duplicateFailure      operationFailure
	rootMetadata          fileMetadata
	rootMetadataFailure   operationFailure
	fileMetadata          fileMetadata
	fileMetadataFailure   operationFailure
	openFailure           operationFailure
	openDescriptor        int
	readFailure           operationFailure
	readFailureCount      int
	rootMetadataPanic     bool
	fileMetadataPanic     bool
	rootMetadataOnFailure bool
	fileMetadataOnFailure bool
	readPanic             bool
	effectiveUIDPanic     bool
	fileCloseFailure      operationFailure
	rootCloseFailure      operationFailure

	openEntered      chan struct{}
	openRelease      chan struct{}
	readEntered      chan struct{}
	readRelease      chan struct{}
	fileCloseEntered chan struct{}
	fileCloseRelease chan struct{}
	metadataEntered  chan struct{}
	metadataRelease  chan struct{}
	closeEntered     chan struct{}
	closeRelease     chan struct{}
}

// newScriptedFilesystem constructs one valid deterministic filesystem.
func newScriptedFilesystem(document []byte) *scriptedFilesystem {
	return &scriptedFilesystem{
		rootFD: 100, duplicateDescriptor: 100, nextFD: 200,
		uid: 1000, document: bytes.Clone(document),
		offsets: make(map[int]int), fdDocuments: make(map[int][]byte),
		closes:       make(map[int]int),
		rootMetadata: fileMetadata{mode: 0040700, uid: 1000, links: 1},
		fileMetadata: fileMetadata{mode: 0100600, uid: 1000, links: 1},
	}
}

// duplicateRoot returns the one owned root descriptor.
func (o *scriptedFilesystem) duplicateRoot(int) (int, operationFailure) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.duplicateDescriptor, o.duplicateFailure
}

// metadata returns root or file confinement facts.
func (o *scriptedFilesystem) metadata(descriptor int) (fileMetadata, operationFailure) {
	o.mu.Lock()
	o.metadataCalls++
	if descriptor == o.rootFD {
		if o.rootMetadataPanic {
			o.mu.Unlock()
			panic("root metadata")
		}
		metadata := o.rootMetadata
		failure := o.rootMetadataFailure
		if failure != operationSucceeded && !o.rootMetadataOnFailure {
			metadata = fileMetadata{}
		}
		o.mu.Unlock()
		return metadata, failure
	}
	entered := o.metadataEntered
	release := o.metadataRelease
	o.metadataEntered = nil
	o.metadataRelease = nil
	metadata := o.fileMetadata
	failure := o.fileMetadataFailure
	if failure != operationSucceeded && !o.fileMetadataOnFailure {
		metadata = fileMetadata{}
	}
	panicAtBoundary := o.fileMetadataPanic
	o.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	if panicAtBoundary {
		panic("file metadata")
	}
	return metadata, failure
}

// openFile returns one new descriptor after an optional deterministic barrier.
func (o *scriptedFilesystem) openFile(int, string) (int, operationFailure) {
	o.mu.Lock()
	o.openCalls++
	entered := o.openEntered
	release := o.openRelease
	o.openEntered = nil
	o.openRelease = nil
	failure := o.openFailure
	o.openFailure = operationSucceeded
	descriptor := o.nextFD
	o.nextFD++
	if o.openDescriptor != 0 {
		descriptor = o.openDescriptor
		o.openDescriptor = 0
	}
	o.offsets[descriptor] = 0
	o.fdDocuments[descriptor] = bytes.Clone(o.document)
	o.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	return descriptor, failure
}

// read copies the current immutable document from one descriptor.
func (o *scriptedFilesystem) read(descriptor int, output []byte) (int, operationFailure) {
	o.mu.Lock()
	entered := o.readEntered
	release := o.readRelease
	o.readEntered = nil
	o.readRelease = nil
	o.readCalls++
	o.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.readPanic {
		panic("read")
	}
	if o.readFailure != operationSucceeded {
		failure := o.readFailure
		count := o.readFailureCount
		o.readFailure = operationSucceeded
		o.readFailureCount = 0
		if count > 0 {
			_ = copy(output, o.fdDocuments[descriptor][:min(count, len(o.fdDocuments[descriptor]))])
		}
		return count, failure
	}
	offset := o.offsets[descriptor]
	document := o.fdDocuments[descriptor]
	if offset >= len(document) {
		return 0, operationSucceeded
	}
	count := copy(output, document[offset:])
	o.offsets[descriptor] += count
	return count, operationSucceeded
}

// close records exactly one invocation and applies configured failures or barriers.
func (o *scriptedFilesystem) close(descriptor int) operationFailure {
	o.mu.Lock()
	o.closes[descriptor]++
	isRoot := descriptor == o.rootFD
	entered := o.closeEntered
	release := o.closeRelease
	if isRoot {
		o.closeEntered = nil
		o.closeRelease = nil
	} else {
		entered = o.fileCloseEntered
		release = o.fileCloseRelease
		o.fileCloseEntered = nil
		o.fileCloseRelease = nil
	}
	failure := o.fileCloseFailure
	if isRoot {
		failure = o.rootCloseFailure
	} else {
		o.fileCloseFailure = operationSucceeded
	}
	o.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	return failure
}

// effectiveUID returns the fixed expected owner or exercises panic containment.
func (o *scriptedFilesystem) effectiveUID() uint32 {
	if o.effectiveUIDPanic {
		panic("effective UID")
	}
	return o.uid
}

// closeCount returns the exact invocation count for one descriptor.
func (o *scriptedFilesystem) closeCount(descriptor int) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.closes[descriptor]
}

// totalFileCloses returns all non-root descriptor close invocations.
func (o *scriptedFilesystem) totalFileCloses() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	total := 0
	for descriptor, count := range o.closes {
		if descriptor != o.rootFD {
			total += count
		}
	}
	return total
}

// backendCounts returns deterministic metadata, open, read, and file-close
// call counts without exposing descriptor values.
func (o *scriptedFilesystem) backendCounts() [4]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	fileCloses := 0
	for descriptor, count := range o.closes {
		if descriptor != o.rootFD {
			fileCloses += count
		}
	}
	return [4]int{o.metadataCalls, o.openCalls, o.readCalls, fileCloses}
}

// setDocument replaces the next load's deterministic bytes.
func (o *scriptedFilesystem) setDocument(document []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.document = bytes.Clone(document)
}

// setFileCloseFailure configures the next non-root close result.
func (o *scriptedFilesystem) setFileCloseFailure(failure operationFailure) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.fileCloseFailure = failure
}

// setRootCloseFailure configures the owned-root close result.
func (o *scriptedFilesystem) setRootCloseFailure(failure operationFailure) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rootCloseFailure = failure
}

// blockNextOpen returns a one-shot open barrier.
func (o *scriptedFilesystem) blockNextOpen() (<-chan struct{}, chan<- struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	o.openEntered = entered
	o.openRelease = release
	return entered, release
}

// blockNextRead returns a one-shot descriptor-read barrier.
func (o *scriptedFilesystem) blockNextRead() (<-chan struct{}, chan<- struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	o.readEntered = entered
	o.readRelease = release
	return entered, release
}

// blockNextFileMetadata returns a one-shot file-metadata barrier.
func (o *scriptedFilesystem) blockNextFileMetadata() (<-chan struct{}, chan<- struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	o.metadataEntered = entered
	o.metadataRelease = release
	return entered, release
}

// blockNextFileClose returns a one-shot loaded-file cleanup barrier.
func (o *scriptedFilesystem) blockNextFileClose() (<-chan struct{}, chan<- struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	o.fileCloseEntered = entered
	o.fileCloseRelease = release
	return entered, release
}

// blockRootClose returns a one-shot owned-root close barrier.
func (o *scriptedFilesystem) blockRootClose() (<-chan struct{}, chan<- struct{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	entered := make(chan struct{})
	release := make(chan struct{})
	o.closeEntered = entered
	o.closeRelease = release
	return entered, release
}

// mustNewInjectedProvider constructs one ready deterministic provider.
func mustNewInjectedProvider(t *testing.T, ops *scriptedFilesystem) *Provider {
	t.Helper()
	provider, err := newProvider(
		3, flatfileProviderName, datasource.DefaultLimits(), ops,
	)
	if err != nil || provider == nil ||
		flatfileProviderState(provider) != datasource.ProviderStateReady {
		t.Fatalf("newProvider(valid) nonnil=%t state=%s code=%s",
			provider != nil, flatfileProviderState(provider), datasource.ErrorCodeOf(err))
	}
	t.Cleanup(func() {
		if err := provider.Close(context.Background()); err != nil {
			t.Errorf("injected provider cleanup failed: %s", datasource.ErrorCodeOf(err))
		}
	})
	return provider
}

// assertInjectedResolveUnavailable verifies degraded or closed providers return no stale result.
func assertInjectedResolveUnavailable(t *testing.T, provider *Provider) {
	t.Helper()
	profile, profileErr := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if profile.Valid() || profile.Generation() != 0 ||
		datasource.ErrorCodeOf(profileErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("ResolveProfile(unavailable) valid=%t generation=%d code=%s",
			profile.Valid(), profile.Generation(), datasource.ErrorCodeOf(profileErr))
	}
	policy, policyErr := provider.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	if policy.Valid() || policy.Generation() != 0 ||
		datasource.ErrorCodeOf(policyErr) != datasource.ErrorCodeUnavailable {
		t.Fatalf("ResolvePolicy(unavailable) valid=%t generation=%d code=%s",
			policy.Valid(), policy.Generation(), datasource.ErrorCodeOf(policyErr))
	}
}

// assertProviderIntegrityFailures verifies every immutable provider read fails internally.
func assertProviderIntegrityFailures(t *testing.T, provider *Provider) {
	t.Helper()
	if _, err := provider.State(); datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeInternalInvariant {
		t.Fatalf("State(corrupt) code=%s", datasource.ErrorCodeOf(err))
	}
	if _, err := provider.Usage(); datasource.ErrorCodeOf(err) !=
		datasource.ErrorCodeInternalInvariant {
		t.Fatalf("Usage(corrupt) code=%s", datasource.ErrorCodeOf(err))
	}
	profile, profileErr := provider.ResolveProfile(
		context.Background(), mustFlatfileProfileRequest(t),
	)
	if profile.Valid() || profile.Generation() != 0 ||
		datasource.ErrorCodeOf(profileErr) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf("ResolveProfile(corrupt) valid=%t generation=%d code=%s",
			profile.Valid(), profile.Generation(), datasource.ErrorCodeOf(profileErr))
	}
	policy, policyErr := provider.ResolvePolicy(
		context.Background(), mustFlatfilePolicyRequest(t),
	)
	if policy.Valid() || policy.Generation() != 0 ||
		datasource.ErrorCodeOf(policyErr) != datasource.ErrorCodeInternalInvariant {
		t.Fatalf("ResolvePolicy(corrupt) valid=%t generation=%d code=%s",
			policy.Valid(), policy.Generation(), datasource.ErrorCodeOf(policyErr))
	}
}

// flatfileInconsistentContext exposes a closed Done channel while Err remains nil.
type flatfileInconsistentContext struct {
	done chan struct{}
}

// newFlatfileInconsistentContext constructs one closed-notification inconsistent context.
func newFlatfileInconsistentContext() flatfileInconsistentContext {
	done := make(chan struct{})
	close(done)
	return flatfileInconsistentContext{done: done}
}

// Deadline reports no deadline.
func (flatfileInconsistentContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done returns the already-closed notification channel.
func (c flatfileInconsistentContext) Done() <-chan struct{} { return c.done }

// Err deliberately contradicts Done for invariant testing.
func (flatfileInconsistentContext) Err() error { return nil }

// Value returns no associated value.
func (flatfileInconsistentContext) Value(any) any { return nil }

// flatfileAcquireObservedContext signals when lifecycle acquisition begins waiting.
type flatfileAcquireObservedContext struct {
	done           chan struct{}
	acquireEntered chan struct{}
	doneCalls      int
	err            error
	mu             sync.Mutex
}

// newFlatfileAcquireObservedContext constructs one active instrumented context.
func newFlatfileAcquireObservedContext() *flatfileAcquireObservedContext {
	return &flatfileAcquireObservedContext{
		done: make(chan struct{}), acquireEntered: make(chan struct{}),
	}
}

// Deadline reports no deadline.
func (*flatfileAcquireObservedContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done exposes cancellation and signals its second lifecycle observation.
func (c *flatfileAcquireObservedContext) Done() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.doneCalls++
	if c.doneCalls == 2 {
		close(c.acquireEntered)
	}
	return c.done
}

// Err reports the exact terminal cause after finish closes the notification channel.
func (c *flatfileAcquireObservedContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Value returns no associated value.
func (*flatfileAcquireObservedContext) Value(any) any { return nil }

// finish publishes one exact terminal acquisition cause.
func (c *flatfileAcquireObservedContext) finish(err error) {
	c.err = err
	close(c.done)
}

// flatfileReadTransitionContext changes to one exact terminal context state.
type flatfileReadTransitionContext struct {
	done chan struct{}
	err  error
}

// newFlatfileReadTransitionContext constructs one active deterministic context.
func newFlatfileReadTransitionContext() *flatfileReadTransitionContext {
	return &flatfileReadTransitionContext{done: make(chan struct{})}
}

// Deadline reports no scheduled wall-clock deadline.
func (*flatfileReadTransitionContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

// Done returns the deterministic transition notification.
func (c *flatfileReadTransitionContext) Done() <-chan struct{} { return c.done }

// Err returns the exact terminal cause only after the transition.
func (c *flatfileReadTransitionContext) Err() error {
	select {
	case <-c.done:
		return c.err
	default:
		return nil
	}
}

// Value returns no associated value.
func (*flatfileReadTransitionContext) Value(any) any { return nil }

// finish publishes one exact terminal cause before notifying observers.
func (c *flatfileReadTransitionContext) finish(err error) {
	c.err = err
	close(c.done)
}

// flatfileProviderPanicContext is a hostile context whose Err method panics.
type flatfileProviderPanicContext struct{}

// Deadline reports no deadline.
func (flatfileProviderPanicContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done reports no cancellation channel.
func (flatfileProviderPanicContext) Done() <-chan struct{} { return nil }

// Err panics across the context trust boundary.
func (flatfileProviderPanicContext) Err() error { panic("hostile context") }

// Value returns no associated value.
func (flatfileProviderPanicContext) Value(any) any { return nil }
