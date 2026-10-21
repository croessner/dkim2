package postgresql

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
)

// TestAdministrationMetadataScansNullSourceGeneration proves the pgx scan
// destination accepts the SQL NULL source_generation of legacy and v2 rows.
func TestAdministrationMetadataScansNullSourceGeneration(t *testing.T) {
	t.Parallel()
	types := pgtype.NewMap()
	var row MetadataRow
	destinations := row.ScanDestinations()
	if err := types.Scan(pgtype.TextOID, pgtype.TextFormatCode, nil, destinations[5]); err != nil {
		t.Fatal("NULL source_generation rejected the legacy metadata row")
	}
	if row.SourceGeneration != nil {
		t.Fatal("legacy metadata row gained a frozen source")
	}
	if err := types.Scan(pgtype.TextOID, pgtype.TextFormatCode, []byte("7"), destinations[5]); err != nil ||
		row.SourceGeneration == nil || *row.SourceGeneration != "7" {
		t.Fatal("campaign metadata row lost its frozen source")
	}
	current := row.CurrentScanDestinations()
	if err := types.Scan(pgtype.TextOID, pgtype.TextFormatCode, nil, current[5]); err != nil || row.SourceGeneration != nil {
		t.Fatal("NULL source_generation rejected the legacy current pointer")
	}
}
