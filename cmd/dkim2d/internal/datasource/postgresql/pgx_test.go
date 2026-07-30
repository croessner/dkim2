package postgresql

import (
	"crypto/x509"
	"reflect"
	"testing"
	"time"
)

// TestPoolConfigRejectsLibpqEnvironment proves PG variables cannot redirect
// the typed single-authority configuration or trigger service-file reads.
func TestPoolConfigRejectsLibpqEnvironment(t *testing.T) {
	t.Setenv("PGSERVICE", "hostile")
	t.Setenv("PGSERVICEFILE", "/definitely/not/a/service/file")
	t.Setenv("PGOPTIONS", "-c search_path=hostile")
	t.Setenv("PGTARGETSESSIONATTRS", "read-write")
	config := ConnectionConfig{
		Address: "192.0.2.10:5433", ServerName: "postgres.example.test",
		Database: "dkim2", User: "runtime", Password: []byte("synthetic"),
		RootCAs: x509.NewCertPool(), ConnectTimeout: 5 * time.Second,
		MaxConnections: 2, IdleConnections: 1,
	}
	if poolConfig, err := newPoolConfig(config); err == nil || poolConfig != nil {
		t.Fatal("libpq environment was accepted")
	}
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv("PGOPTIONS", "")
	t.Setenv("PGTARGETSESSIONATTRS", "")
	poolConfig, err := newPoolConfig(config)
	if err != nil {
		t.Fatal("clean typed pool configuration rejected")
	}
	connection := poolConfig.ConnConfig
	if connection.Host != "192.0.2.10" || connection.Port != 5433 ||
		connection.Database != "dkim2" || connection.User != "runtime" ||
		connection.ConnectTimeout != 5*time.Second ||
		len(connection.Fallbacks) != 0 ||
		!reflect.DeepEqual(
			connection.RuntimeParams,
			map[string]string{"application_name": "dkim2d"},
		) {
		t.Fatal("typed pool configuration drifted")
	}
}
