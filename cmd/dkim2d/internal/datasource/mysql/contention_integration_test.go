//go:build datasourceintegration

package mysql

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
)

// TestMySQLContentionObserverUsesExactWaitEdge freezes the Performance Schema
// process-list and publication-lock predicate.
func TestMySQLContentionObserverUsesExactWaitEdge(t *testing.T) {
	for _, fragment := range []string{
		"performance_schema.data_lock_waits",
		"performance_schema.threads",
		"PROCESSLIST_ID",
		"dkim2_publication_lock",
	} {
		if !strings.Contains(queryMySQLActivationContentionWaitEdge, fragment) {
			t.Fatal("MySQL contention observer query is incomplete")
		}
	}
}

// TestMariaDBContentionObserverUsesExactWaitEdge freezes the InnoDB thread-ID
// and publication-lock predicate.
func TestMariaDBContentionObserverUsesExactWaitEdge(t *testing.T) {
	for _, fragment := range []string{
		"information_schema.INNODB_LOCK_WAITS",
		"information_schema.INNODB_TRX",
		"trx_mysql_thread_id",
		"dkim2_publication_lock",
	} {
		if !strings.Contains(queryMariaDBActivationContentionWaitEdge, fragment) {
			t.Fatal("MariaDB contention observer query is incomplete")
		}
	}
}

// TestMySQLFamilyContentionObserverRejectsInvalidIdentityAndContext proves the
// integration observer fails closed before issuing an ambiguous query.
func TestMySQLFamilyContentionObserverRejectsInvalidIdentityAndContext(t *testing.T) {
	observer := (*ActivationContentionObserver)(nil)
	if _, err := observer.ObserveWaitEdge(context.Background(), 1, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("nil MySQL-family contention observer was accepted")
	}
	if _, err := observer.ObserveWaitEdge(nil, 1, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("nil MySQL-family contention context was accepted")
	}
	if _, err := observer.ObserveWaitEdge(context.Background(), 1, 1); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("equal MySQL-family connection identities were accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.ObserveWaitEdge(canceled, 1, 2); datasourceadmin.CodeOf(err) != datasourceadmin.CodeUnavailable {
		t.Fatal("canceled MySQL-family contention observation was accepted")
	}
	if _, err := (*sqlAdministrationTransaction)(nil).IntegrationConnectionID(context.Background()); datasourceadmin.CodeOf(err) != datasourceadmin.CodeInvalid {
		t.Fatal("nil MySQL-family transaction exposed a connection identity")
	}
}
