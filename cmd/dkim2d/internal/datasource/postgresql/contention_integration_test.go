//go:build datasourceintegration

package postgresql

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestPostgreSQLContentionObserverUsesExactWaitEdge freezes the server-side
// waiter-to-holder predicate and its lock-wait classification.
func TestPostgreSQLContentionObserverUsesExactWaitEdge(t *testing.T) {
	for _, fragment := range []string{
		"wait_event_type = 'Lock'",
		"pg_blocking_pids",
		"pid = $2",
	} {
		if !strings.Contains(queryActivationContentionWaitEdge, fragment) {
			t.Fatal("PostgreSQL contention observer query is incomplete")
		}
	}
}

// TestPostgreSQLContentionObserverRejectsInvalidIdentityAndContext proves the
// integration observer fails closed before issuing an ambiguous query.
func TestPostgreSQLContentionObserverRejectsInvalidIdentityAndContext(t *testing.T) {
	observer := (*ActivationContentionObserver)(nil)
	if _, err := observer.ObserveWaitEdge(context.Background(), 1, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("nil PostgreSQL contention observer was accepted")
	}
	if _, err := observer.ObserveWaitEdge(nil, 1, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("nil PostgreSQL contention context was accepted")
	}
	if _, err := observer.ObserveWaitEdge(context.Background(), 0, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("zero PostgreSQL holder identity was accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.ObserveWaitEdge(canceled, 1, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeUnavailable {
		t.Fatal("canceled PostgreSQL contention observation was accepted")
	}
	if _, err := (*pgxAdministrationTransaction)(nil).IntegrationConnectionID(context.Background()); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("nil PostgreSQL transaction exposed a connection identity")
	}
}
