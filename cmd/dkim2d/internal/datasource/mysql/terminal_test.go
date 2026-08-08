package mysql

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTerminalMigrationOwnsOnlyFixedCloserAuthority freezes MySQL/MariaDB 005.
func TestTerminalMigrationOwnsOnlyFixedCloserAuthority(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "mysql", "005_campaign_terminal_closure.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{"dkim2_campaign_terminals", "dkim2_v3_record_campaign_terminal", "lock_operation_id", "SQL SECURITY DEFINER"} {
		if !strings.Contains(text, want) {
			t.Fatal("terminal migration missing fixed closer fence")
		}
	}
	if strings.Contains(text, "GRANT DELETE") || strings.Contains(text, "GRANT UPDATE") {
		t.Fatal("terminal migration widened closer authority")
	}
}
