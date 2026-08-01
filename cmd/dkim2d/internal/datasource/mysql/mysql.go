// Package mysql implements the verified MySQL and MariaDB datasource adapter.
package mysql

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/provider"
	driver "github.com/go-sql-driver/mysql"
)

const loaderRedacted = "mysql_loader{redacted}"

// Loader is the shared immutable SQL snapshot loader used by this adapter.
type Loader = sqlsnapshot.Loader

// ConnectionConfig owns one verified single-authority MySQL or MariaDB endpoint.
type ConnectionConfig struct {
	Address         string
	ServerName      string
	Database        string
	User            string
	Password        []byte
	RootCAs         *x509.CertPool
	ConnectTimeout  time.Duration
	MaxConnections  int
	IdleConnections int
}

// Validate rejects insecure, indirect, or widened connection settings.
func (c ConnectionConfig) Validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	ip, ipErr := netip.ParseAddr(host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || ipErr != nil || ip.IsUnspecified() || ip.IsMulticast() ||
		portErr != nil || portNumber == 0 || c.ServerName == "" ||
		!validSQLIdentifier(c.Database) || !validSQLIdentifier(c.User) ||
		len(c.Password) == 0 || len(c.Password) > 16<<10 || c.RootCAs == nil ||
		c.ConnectTimeout <= 0 || c.ConnectTimeout > 30*time.Second ||
		c.MaxConnections <= 0 || c.MaxConnections > 4 ||
		c.IdleConnections < 0 || c.IdleConnections > 2 ||
		c.IdleConnections > c.MaxConnections || len(c.Address) > 512 ||
		len(c.ServerName) > 253 {
		return errors.New("invalid mysql connection configuration")
	}
	return nil
}

// String returns a constant protected connection summary.
func (ConnectionConfig) String() string { return loaderRedacted }

// GoString returns a constant protected connection representation.
func (ConnectionConfig) GoString() string { return loaderRedacted }

// Format prevents formatting verbs from exposing connection facts.
func (ConnectionConfig) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, loaderRedacted)
}

// MarshalJSON emits an empty object without connection facts.
func (ConnectionConfig) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// validSQLIdentifier accepts one bounded ASCII database or account identifier.
func validSQLIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			index > 0 && character >= '0' && character <= '9' ||
			index > 0 && character == '_' {
			continue
		}
		return false
	}
	return true
}

// newDriverConfig constructs one environment-independent, verified-TLS driver configuration.
func newDriverConfig(config ConnectionConfig) (*driver.Config, error) {
	if config.Validate() != nil {
		return nil, errors.New("mysql pool unavailable")
	}
	driverConfig := driver.NewConfig()
	driverConfig.User = config.User
	driverConfig.Passwd = string(config.Password)
	driverConfig.Net = "tcp"
	driverConfig.Addr = config.Address
	driverConfig.DBName = config.Database
	driverConfig.Collation = "utf8mb4_bin"
	driverConfig.Loc = time.UTC
	driverConfig.Timeout = config.ConnectTimeout
	driverConfig.ReadTimeout = config.ConnectTimeout
	driverConfig.WriteTimeout = config.ConnectTimeout
	driverConfig.MaxAllowedPacket = 32 << 20
	driverConfig.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: config.ServerName,
		RootCAs:    config.RootCAs,
	}
	driverConfig.TLSConfig = ""
	driverConfig.AllowAllFiles = false
	driverConfig.AllowCleartextPasswords = false
	driverConfig.AllowFallbackToPlaintext = false
	driverConfig.AllowOldPasswords = false
	driverConfig.InterpolateParams = false
	driverConfig.MultiStatements = false
	driverConfig.RejectReadOnly = false
	driverConfig.Params = nil
	return driverConfig, nil
}

// OpenPool constructs a bounded database/sql pool from validated typed fields.
func OpenPool(ctx context.Context, config ConnectionConfig) (sqlsnapshot.Pool, error) {
	database, err := OpenDatabase(ctx, config)
	if err != nil {
		return nil, err
	}
	return &sqlPool{database: database}, nil
}

// OpenDatabase constructs and verifies one bounded database/sql authority.
func OpenDatabase(ctx context.Context, config ConnectionConfig) (*sql.DB, error) {
	if ctx == nil {
		return nil, errors.New("mysql pool unavailable")
	}
	driverConfig, err := newDriverConfig(config)
	if err != nil {
		return nil, errors.New("mysql pool unavailable")
	}
	connector, err := driver.NewConnector(driverConfig)
	if err != nil {
		return nil, errors.New("mysql pool unavailable")
	}
	database := sql.OpenDB(connector)
	database.SetMaxOpenConns(config.MaxConnections)
	database.SetMaxIdleConns(config.IdleConnections)
	database.SetConnMaxLifetime(time.Hour)
	database.SetConnMaxIdleTime(5 * time.Minute)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, errors.New("mysql pool unavailable")
	}
	return database, nil
}

// NewLoader validates one bounded MySQL or MariaDB loader configuration.
func NewLoader(
	pool sqlsnapshot.Pool,
	limits provider.Limits,
	pageSize int,
	maxBytes int,
	maxDeadline time.Duration,
) (*sqlsnapshot.Loader, error) {
	return sqlsnapshot.NewLoader(pool, limits, pageSize, maxBytes, maxDeadline)
}

type sqlPool struct {
	database *sql.DB
}

// Begin starts one explicit read-only repeatable-read transaction.
func (p *sqlPool) Begin(ctx context.Context) (sqlsnapshot.Transaction, error) {
	if p == nil || p.database == nil || ctx == nil {
		return nil, errors.New("mysql transaction unavailable")
	}
	connection, err := p.database.Conn(ctx)
	if err != nil {
		return nil, errors.New("mysql transaction unavailable")
	}
	if _, err := connection.ExecContext(ctx, querySessionIsolation); err != nil {
		_ = connection.Close()
		return nil, errors.New("mysql transaction unavailable")
	}
	if _, err := connection.ExecContext(ctx, querySessionReadOnly); err != nil {
		_ = connection.Close()
		return nil, errors.New("mysql transaction unavailable")
	}
	transaction, err := connection.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelRepeatableRead,
		ReadOnly:  true,
	})
	if err != nil {
		_ = connection.Close()
		return nil, errors.New("mysql transaction unavailable")
	}
	return &sqlTransaction{transaction: transaction, connection: connection}, nil
}

// Close releases all pooled MySQL or MariaDB connections.
func (p *sqlPool) Close() {
	if p != nil && p.database != nil {
		_ = p.database.Close()
	}
}

type sqlTransaction struct {
	transaction *sql.Tx
	connection  *sql.Conn
	generation  string
}

// Isolation proves the effective transaction isolation and read-only state.
func (t *sqlTransaction) Isolation(ctx context.Context) (string, bool, error) {
	if t == nil || t.transaction == nil {
		return "", false, errors.New("mysql isolation unavailable")
	}
	isolation, readOnly, err := readIsolation(ctx, t.transaction, queryIsolation)
	if err != nil {
		var mysqlError *driver.MySQLError
		if !errors.As(err, &mysqlError) || mysqlError.Number != 1193 {
			return "", false, errors.New("mysql isolation unavailable")
		}
		isolation, readOnly, err = readIsolation(ctx, t.transaction, queryLegacyIsolation)
	}
	if err != nil {
		return "", false, errors.New("mysql isolation unavailable")
	}
	return normalizeIsolation(isolation), readOnly != 0, nil
}

// readIsolation reads one fixed modern or legacy server-variable projection.
func readIsolation(ctx context.Context, transaction *sql.Tx, query string) (string, int, error) {
	var isolation string
	var readOnly int
	err := transaction.QueryRowContext(ctx, query).Scan(&isolation, &readOnly)
	return isolation, readOnly, err
}

// normalizeIsolation maps server spellings to the shared closed isolation value.
func normalizeIsolation(value string) string {
	value = strings.ToLower(strings.ReplaceAll(value, "-", " "))
	if value != "repeatable read" {
		return ""
	}
	return value
}

// ReadCurrent reads exactly one current committed metadata row.
func (t *sqlTransaction) ReadCurrent(ctx context.Context) (sqlsnapshot.MetadataRow, error) {
	var row sqlsnapshot.MetadataRow
	if t == nil || t.transaction == nil {
		return row, errors.New("mysql metadata unavailable")
	}
	err := t.transaction.QueryRowContext(ctx, queryCurrent).Scan(
		&row.Generation, &row.SchemaVersion, &row.DatasetState,
	)
	if err != nil {
		return sqlsnapshot.MetadataRow{}, errors.New("mysql metadata unavailable")
	}
	if t.generation == "" {
		t.generation = row.Generation
	}
	return row, nil
}

// HandlePage reads one deterministic handle keyset page.
func (t *sqlTransaction) HandlePage(ctx context.Context, after string, limit int) ([]sqlsnapshot.HandleRow, error) {
	rows, err := t.transaction.QueryContext(ctx, queryHandles, t.generation, after, limit)
	if err != nil {
		return nil, errors.New("mysql page unavailable")
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.HandleRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.HandleRow
		if err := rows.Scan(&row.Generation, &row.HandleID); err != nil {
			return nil, errors.New("mysql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("mysql page unavailable")
	}
	return output, nil
}

// ProfilePage reads one deterministic profile keyset page.
func (t *sqlTransaction) ProfilePage(ctx context.Context, after string, limit int) ([]sqlsnapshot.ProfileRow, error) {
	rows, err := t.transaction.QueryContext(ctx, queryProfiles, t.generation, after, limit)
	if err != nil {
		return nil, errors.New("mysql page unavailable")
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.ProfileRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.ProfileRow
		if err := rows.Scan(
			&row.Generation, &row.ProfileID, &row.Domain, &row.Status,
			&row.NotBeforeUTC, &row.NotAfterUTC,
		); err != nil {
			return nil, errors.New("mysql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("mysql page unavailable")
	}
	return output, nil
}

// CredentialPage reads one deterministic credential keyset page.
func (t *sqlTransaction) CredentialPage(
	ctx context.Context,
	afterProfile string,
	afterAlgorithm string,
	limit int,
) ([]sqlsnapshot.CredentialRow, error) {
	rows, err := t.transaction.QueryContext(
		ctx, queryCredentials, t.generation, afterProfile, afterAlgorithm, limit,
	)
	if err != nil {
		return nil, errors.New("mysql page unavailable")
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.CredentialRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.CredentialRow
		if err := rows.Scan(
			&row.Generation, &row.ProfileID, &row.Algorithm, &row.Selector,
			&row.PublicKeySPKI, &row.HandleID,
		); err != nil {
			return nil, errors.New("mysql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("mysql page unavailable")
	}
	return output, nil
}

// PolicyPage reads one deterministic policy keyset page.
func (t *sqlTransaction) PolicyPage(
	ctx context.Context,
	afterTenant string,
	afterDomain string,
	afterUse string,
	limit int,
) ([]sqlsnapshot.PolicyRow, error) {
	rows, err := t.transaction.QueryContext(
		ctx, queryPolicies, t.generation, afterTenant, afterDomain, afterUse, limit,
	)
	if err != nil {
		return nil, errors.New("mysql page unavailable")
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.PolicyRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.PolicyRow
		if err := rows.Scan(
			&row.Generation, &row.TenantID, &row.Domain, &row.Use,
			&row.ProfileID, &row.Status, &row.Rollout, &row.Compatibility,
			&row.FeedbackRouteID,
		); err != nil {
			return nil, errors.New("mysql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		return nil, errors.New("mysql page unavailable")
	}
	return output, nil
}

// KeyMaterialPage reads one deterministic native-key keyset page.
func (t *sqlTransaction) KeyMaterialPage(ctx context.Context, after string, limit int) ([]sqlsnapshot.KeyMaterialRow, error) {
	rows, err := t.transaction.QueryContext(ctx, queryKeyMaterial, t.generation, after, limit)
	if err != nil {
		return nil, errors.New("mysql page unavailable")
	}
	defer func() { _ = rows.Close() }()
	output := make([]sqlsnapshot.KeyMaterialRow, 0, limit)
	for rows.Next() {
		var row sqlsnapshot.KeyMaterialRow
		if err := rows.Scan(
			&row.Generation, &row.TenantID, &row.Domain, &row.Use,
			&row.HandleID, &row.Algorithm, &row.PublicSPKI, &row.PrivatePKCS8,
		); err != nil {
			sqlsnapshot.ClearKeyMaterialRows(output)
			return nil, errors.New("mysql page unavailable")
		}
		output = append(output, row)
	}
	if rows.Err() != nil {
		sqlsnapshot.ClearKeyMaterialRows(output)
		return nil, errors.New("mysql page unavailable")
	}
	return output, nil
}

// Commit completes the read-only snapshot before local publication.
func (t *sqlTransaction) Commit(_ context.Context) error {
	if t == nil || t.transaction == nil {
		return errors.New("mysql completion unavailable")
	}
	err := t.transaction.Commit()
	t.transaction = nil
	t.closeConnection()
	if err != nil {
		return errors.New("mysql completion unavailable")
	}
	return nil
}

// Rollback closes an incomplete read-only snapshot.
func (t *sqlTransaction) Rollback(_ context.Context) error {
	if t == nil || t.transaction == nil {
		return nil
	}
	err := t.transaction.Rollback()
	t.transaction = nil
	t.closeConnection()
	if err != nil && !errors.Is(err, sql.ErrTxDone) {
		return errors.New("mysql completion unavailable")
	}
	return nil
}

// closeConnection returns the transaction-owned session to the read-only runtime pool.
func (t *sqlTransaction) closeConnection() {
	if t != nil && t.connection != nil {
		_ = t.connection.Close()
		t.connection = nil
	}
}
