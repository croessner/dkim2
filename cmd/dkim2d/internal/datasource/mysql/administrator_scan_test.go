package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
)

// legacyMetadataConnector serves fixed v2 metadata rows whose nullable v3
// columns, including source_generation, are SQL NULL, and records staged-root
// source arguments.
type legacyMetadataConnector struct{ boundSource *[]driver.Value }

// Connect returns one in-memory connection serving the fixed rows.
func (c legacyMetadataConnector) Connect(context.Context) (driver.Conn, error) {
	return legacyMetadataConn(c), nil
}

// Driver returns the connector-only driver.
func (legacyMetadataConnector) Driver() driver.Driver { return legacyMetadataDriver{} }

// legacyMetadataDriver rejects DSN-based opening; tests use the connector.
type legacyMetadataDriver struct{}

// Open is unsupported because the fixture has no DSN.
func (legacyMetadataDriver) Open(string) (driver.Conn, error) { return nil, driver.ErrSkip }

// legacyMetadataConn answers the administration metadata projections.
type legacyMetadataConn struct{ boundSource *[]driver.Value }

// Prepare is unsupported; queries use QueryContext directly.
func (legacyMetadataConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }

// Close releases nothing.
func (legacyMetadataConn) Close() error { return nil }

// Begin is unsupported; the fixture serves connection reads only.
func (legacyMetadataConn) Begin() (driver.Tx, error) { return nil, driver.ErrSkip }

// QueryContext returns one legacy row shaped for the requested projection.
func (legacyMetadataConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	// Column names are informational; scans bind by position.
	width := 7
	if query == queryAdminCurrent {
		width = 8
	}
	row := make([]driver.Value, width)
	row[0], row[1], row[2], row[width-1] = "1", "dkim2-datasource-v2", "committed", false
	columns := make([]string, width)
	for index := range columns {
		columns[index] = "c" + strconv.Itoa(index)
	}
	return &legacyMetadataRows{columns: columns, row: row}, nil
}

// ExecContext records the bound source argument of the staged-root call.
func (c legacyMetadataConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if query != queryAdminInsertGeneration || len(args) != 5 || c.boundSource == nil {
		return nil, driver.ErrSkip
	}
	*c.boundSource = append(*c.boundSource, args[3].Value)
	return driver.RowsAffected(1), nil
}

// legacyMetadataRows yields its single row once.
type legacyMetadataRows struct {
	columns []string
	row     []driver.Value
	done    bool
}

// Columns returns the projection column names.
func (r *legacyMetadataRows) Columns() []string { return r.columns }

// Close releases nothing.
func (r *legacyMetadataRows) Close() error { return nil }

// Next copies the single row once and then reports EOF.
func (r *legacyMetadataRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.row)
	return nil
}

// TestAdministrationMetadataScansNullSourceGeneration proves legacy and v2
// metadata rows, whose source_generation is NULL by design, remain readable.
func TestAdministrationMetadataScansNullSourceGeneration(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	database := sql.OpenDB(legacyMetadataConnector{})
	defer func() { _ = database.Close() }()
	connection, err := database.Conn(ctx)
	if err != nil {
		t.Fatal("open fixture connection")
	}
	defer func() { _ = connection.Close() }()
	transaction := &sqlAdministrationTransaction{connection: connection, mode: sqlsnapshot.AdministrationSnapshot}
	current, present, err := transaction.ReadCurrentOptional(ctx, false)
	if err != nil || !present {
		t.Fatal("NULL source_generation rejected the legacy current pointer")
	}
	if current.SourceGeneration != nil || current.OperationID != nil {
		t.Fatal("legacy current pointer gained a v3 binding")
	}
	page, err := transaction.GenerationPage(ctx, "0", 1, false)
	if err != nil || len(page) != 1 {
		t.Fatal("NULL source_generation rejected the legacy generation page")
	}
	if page[0].SourceGeneration != nil {
		t.Fatal("legacy generation gained a frozen source")
	}
}

// TestInsertGenerationCallMatchesSourceBindingRoutine proves the staged-root
// call binds every parameter of the 006 routine, including the frozen source.
func TestInsertGenerationCallMatchesSourceBindingRoutine(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "..", "..", "..", "contrib", "schema", "mysql", "006_campaign_source_binding.sql")
	document, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read MySQL-family source-binding migration")
	}
	text := string(document)
	start := strings.Index(text, "CREATE PROCEDURE dkim2_v3_insert_generation(")
	if start < 0 {
		t.Fatal("source-binding migration omits the staged-root routine")
	}
	end := strings.Index(text[start:], ")\nSQL SECURITY DEFINER")
	if end < 0 {
		t.Fatal("source-binding staged-root routine signature is malformed")
	}
	parameters := strings.Count(text[start:start+end], " IN ")
	if parameters != 5 || strings.Count(queryAdminInsertGeneration, "?") != parameters {
		t.Fatal("staged-root call does not bind every source-binding routine parameter")
	}
}

// TestInsertGenerationBindsNullForSourcelessCandidates proves sourceless v3
// candidates bind SQL NULL instead of an empty decimal string, while campaign
// candidates bind their exact frozen source.
func TestInsertGenerationBindsNullForSourcelessCandidates(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bound := make([]driver.Value, 0, 2)
	database := sql.OpenDB(legacyMetadataConnector{boundSource: &bound})
	defer func() { _ = database.Close() }()
	connection, err := database.Conn(ctx)
	if err != nil {
		t.Fatal("open fixture connection")
	}
	defer func() { _ = connection.Close() }()
	transaction := &sqlAdministrationTransaction{connection: connection, mode: sqlsnapshot.AdministrationStaging, lockRevision: 1}
	operation, source := "aebagbafaydqqcikbmga2dqpca", "1"
	for _, row := range []sqlsnapshot.MetadataRow{
		{Generation: "2", OperationID: &operation, CandidateDigest: make([]byte, 32)},
		{Generation: "2", OperationID: &operation, CandidateDigest: make([]byte, 32), SourceGeneration: &source},
	} {
		if err := transaction.InsertGeneration(ctx, row); err != nil {
			t.Fatal("stage fixture generation root")
		}
	}
	if len(bound) != 2 || bound[0] != nil || bound[1] != "1" {
		t.Fatal("staged-root call bound the wrong frozen source")
	}
}
