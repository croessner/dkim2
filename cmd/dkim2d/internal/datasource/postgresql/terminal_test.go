package postgresql

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTerminalMigrationOwnsOnlyFixedCloserAuthority freezes the immutable 005 contract.
func TestTerminalMigrationOwnsOnlyFixedCloserAuthority(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "postgresql", "005_campaign_terminal_closure.sql"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, want := range []string{"campaign_terminals", "CREATE ROLE dkim2_closer", "record_campaign_terminal", "lock_operation_id = selected_operation", "GRANT EXECUTE ON PROCEDURE"} {
		if !strings.Contains(text, want) {
			t.Fatal("terminal migration missing fixed closer fence")
		}
	}
	if strings.Contains(text, "GRANT DELETE") || strings.Contains(text, "GRANT UPDATE") {
		t.Fatal("terminal migration widened closer authority")
	}
}
