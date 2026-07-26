package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const readinessPrivateMarker = "READINESS-PRIVATE-MARKER"

type readinessAuthority struct {
	ready atomic.Bool
	panic bool
}

// AuthorityReady returns the configured no-I/O test snapshot.
func (a *readinessAuthority) AuthorityReady() bool {
	if a.panic {
		panic(readinessPrivateMarker)
	}
	return a.ready.Load()
}

// TestReadinessRequiresAuthorityAndEveryLifecycleTransition proves closed publication.
func TestReadinessRequiresAuthorityAndEveryLifecycleTransition(t *testing.T) {
	var typedNil *readinessAuthority
	for _, authority := range []AuthorityReadiness{nil, typedNil} {
		if readiness, err := NewReadiness(authority); readiness != nil ||
			!IsLifecycleError(err) {
			t.Fatal("missing authority did not fail closed")
		}
	}

	authority := &readinessAuthority{}
	readiness, err := NewReadiness(authority)
	if err != nil || readiness.Ready() {
		t.Fatal("new readiness was not closed")
	}
	authority.ready.Store(true)
	if !readiness.publishReady() || !readiness.Ready() {
		t.Fatal("complete live state did not become ready")
	}
	authority.ready.Store(false)
	if readiness.Ready() {
		t.Fatal("authority loss remained ready")
	}
	authority.ready.Store(true)
	if !readiness.withdrawReady() || readiness.Ready() ||
		readiness.publishReady() || !readiness.fatal() {
		t.Fatal("fatal withdrawal was not sticky")
	}
	readiness.beginStopping()
	if readiness.Ready() || !readiness.fatal() {
		t.Fatal("stopping erased fatal history")
	}
}

// TestReadinessPropagatesAuthorityPanicAndProtectsStructure proves outer containment.
func TestReadinessPropagatesAuthorityPanicAndProtectsStructure(t *testing.T) {
	authority := &readinessAuthority{panic: true}
	readiness, err := NewReadiness(authority)
	if err != nil || !readiness.publishReady() {
		t.Fatal("readiness construction or publication failed")
	}
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		readiness.Ready()
	}()
	if !panicked {
		t.Fatal("authority panic did not reach outer containment")
	}
	for _, rendered := range []string{
		fmt.Sprint(readiness),
		fmt.Sprintf("%+v", readiness),
		fmt.Sprintf("%#v", readiness),
	} {
		if rendered != readinessRedacted || strings.Contains(rendered, readinessPrivateMarker) {
			t.Fatal("readiness formatting exposed structure")
		}
	}
	if data, marshalErr := json.Marshal(readiness); data != nil ||
		!IsLifecycleError(marshalErr) {
		t.Fatal("readiness JSON serialization did not fail closed")
	}
}

// TestReadinessFatalWinsConcurrentPublicationAndStopping proves monotone races.
func TestReadinessFatalWinsConcurrentPublicationAndStopping(t *testing.T) {
	const iterations = 1_000
	for range iterations {
		authority := &readinessAuthority{}
		authority.ready.Store(true)
		readiness, err := NewReadiness(authority)
		if err != nil {
			t.Fatal("readiness construction failed")
		}
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Add(3)
		go func() {
			defer group.Done()
			<-start
			readiness.publishReady()
		}()
		go func() {
			defer group.Done()
			<-start
			readiness.withdrawReady()
		}()
		go func() {
			defer group.Done()
			<-start
			readiness.beginStopping()
		}()
		close(start)
		group.Wait()
		if readiness.Ready() || !readiness.fatal() || readiness.publishReady() {
			t.Fatal("concurrent fatal transition was reversible")
		}
	}
}
