package keyresolver

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestResolverCompliantSlowTransportSaturatesAndCancels verifies the required context-aware transport contract.
func TestResolverCompliantSlowTransportSaturatesAndCancels(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	transport := resolverTransportFunc(func(ctx context.Context, _ string) (LookupResult, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return LookupResult{}, ctx.Err()
	})
	limits := DefaultLimits()
	limits.MaxCacheEntries = 0
	limits.MaxConcurrentLookups = 1
	resolver, err := NewResolver(transport, limits)
	if err != nil {
		t.Fatal("compliant transport resolver construction failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	type resolution struct {
		outcome KeyOutcome
		err     error
	}
	firstDone := make(chan resolution, 1)
	go func() {
		outcome, resolveErr := resolver.Resolve(ctx, testSigningDomain, "first", AlgorithmRSASHA256)
		firstDone <- resolution{outcome: outcome, err: resolveErr}
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("compliant transport did not start")
	}
	second, secondErr := resolver.Resolve(context.Background(), testSigningDomain, "second", AlgorithmRSASHA256)
	if secondErr != nil || second.Status() != KeyOutcomeTemporary {
		t.Fatal("one-over compliant lookup did not saturate immediately")
	}
	cancel()
	var first resolution
	select {
	case first = <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("compliant caller did not return after cancellation")
	}
	if !first.outcome.IsZero() || !errors.Is(first.err, context.Canceled) {
		t.Fatal("compliant transport cancellation did not remain caller control flow")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("compliant transport failed to return after context cancellation")
	}
}

// TestResolverNoncompliantTransportRemainsOneBoundedWorkerUntilReleased proves the injected defect boundary.
func TestResolverNoncompliantTransportRemainsOneBoundedWorkerUntilReleased(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	var releaseOnce sync.Once
	releaseFake := func() { releaseOnce.Do(func() { close(release) }) }
	var startedOnce sync.Once
	var returnedOnce sync.Once
	var active atomic.Int32
	transport := resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		active.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release // Deliberately violates TXTTransport by ignoring context until test teardown.
		active.Add(-1)
		returnedOnce.Do(func() { close(returned) })
		return LookupResult{}, nil
	})
	limits := DefaultLimits()
	limits.MaxCacheEntries = 0
	limits.MaxConcurrentLookups = 1
	resolver, err := NewResolver(transport, limits)
	if err != nil {
		t.Fatal("noncompliant transport resolver construction failed")
	}
	t.Cleanup(func() {
		releaseFake()
		deadline := time.Now().Add(time.Second)
		for {
			resolver.flights.mu.Lock()
			retired := active.Load() == 0 && len(resolver.flights.flights) == 0 && len(resolver.flights.semaphore) == 0
			resolver.flights.mu.Unlock()
			if retired {
				return
			}
			if time.Now().After(deadline) {
				t.Error("noncompliant fake flight did not retire during cleanup")
				return
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	firstDone := make(chan error, 1)
	go func() {
		_, resolveErr := resolver.Resolve(ctx, testSigningDomain, "held", AlgorithmRSASHA256)
		firstDone <- resolveErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("noncompliant fake did not start")
	}
	if outcome, resolveErr := resolver.Resolve(context.Background(), testSigningDomain, "one-over", AlgorithmRSASHA256); resolveErr != nil || outcome.Status() != KeyOutcomeTemporary || active.Load() != 1 {
		t.Fatal("noncompliant transport escaped the single bounded worker")
	}
	cancel()
	select {
	case <-firstDone:
		t.Fatal("last caller detached and orphaned a noncompliant transport worker")
	case <-time.After(25 * time.Millisecond):
	}
	if outcome, resolveErr := resolver.Resolve(context.Background(), testSigningDomain, "still-held", AlgorithmRSASHA256); resolveErr != nil || outcome.Status() != KeyOutcomeTemporary || active.Load() != 1 {
		t.Fatal("held noncompliant worker did not retain bounded saturation")
	}

	releaseFake()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("noncompliant test transport did not release during teardown")
	}
	var firstErr error
	select {
	case firstErr = <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("last caller did not return after noncompliant fake release")
	}
	if !errors.Is(firstErr, context.Canceled) {
		t.Fatal("last caller lost cancellation after worker retirement")
	}
	deadline := time.Now().Add(time.Second)
	for {
		outcome, resolveErr := resolver.Resolve(context.Background(), testSigningDomain, "after-release", AlgorithmRSASHA256)
		if resolveErr == nil && outcome.Status() == KeyOutcomeProviderContract && active.Load() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("flight worker did not retire after explicit fake release")
		}
	}
}

// TestResolverDiagnosticsDiscardDNSToxicMatrix verifies every DNS-derived channel is bounded and forgotten.
func TestResolverDiagnosticsDiscardDNSToxicMatrix(t *testing.T) {
	const marker = "DNS-TOXIC-MARKER"
	limits := DefaultLimits()
	limits.MaxCacheEntries = 4
	transport := resolverTransportFunc(func(context.Context, string) (LookupResult, error) {
		return LookupResult{}, errors.New(marker + "-RAW-ENDPOINT")
	})
	resolver, err := NewResolver(transport, limits)
	if err != nil {
		t.Fatal("privacy resolver construction failed")
	}
	for _, query := range []struct {
		domain, selector string
	}{
		{domain: marker + "/example.test", selector: testSelector},
		{domain: testSigningDomain, selector: marker + "/selector"},
		{domain: testSigningDomain, selector: testSelector},
	} {
		outcome, resolveErr := resolver.Resolve(context.Background(), query.domain, query.selector, AlgorithmRSASHA256)
		assertResolverMarkerAbsent(t, marker, fmt.Sprintf("%v %#v %v", resolveErr, outcome, outcome.Metadata()))
	}

	for _, record := range []string{
		"p=%%%" + marker,
		"p=QQ==; n=" + marker,
		"p=QQ==; retired=" + marker,
		"p=QQ==; t=y:" + marker,
		"p=" + marker,
	} {
		parsed, parseErr := ParseRecord([]byte(record), limits)
		assertResolverMarkerAbsent(t, marker, fmt.Sprintf("%v %#v %v", parseErr, parsed, parsed.Metadata()))
	}

	const cacheMarker = "dns-toxic-cache-key"
	encodedMarker := base64.StdEncoding.EncodeToString([]byte(cacheMarker))
	lookup, lookupErr := NewFoundResult([][]byte{[]byte("p=" + encodedMarker)}, time.Minute, DNSSECStatusUnavailable)
	if lookupErr != nil {
		t.Fatal("cache-key privacy lookup construction failed")
	}
	cacheResolver, constructErr := NewResolver(resolverTransportFunc(func(context.Context, string) (LookupResult, error) { return lookup, nil }), limits)
	if constructErr != nil {
		t.Fatal("cache-key privacy resolver construction failed")
	}
	for range 2 {
		outcome, resolveErr := cacheResolver.Resolve(context.Background(), testSigningDomain, cacheMarker, AlgorithmRSASHA256)
		formatted := fmt.Sprintf("%v %#v %v", resolveErr, outcome, outcome.Metadata())
		assertResolverMarkerAbsent(t, cacheMarker, formatted)
		assertResolverMarkerAbsent(t, encodedMarker, formatted)
	}
}

// assertResolverMarkerAbsent fails without repeating protected diagnostic content.
func assertResolverMarkerAbsent(t *testing.T, marker, text string) {
	t.Helper()
	if strings.Contains(text, marker) {
		t.Fatal("DNS resolver diagnostic leaked protected input")
	}
}
