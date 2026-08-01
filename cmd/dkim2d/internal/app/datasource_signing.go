package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	datasourceldap "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/ldap"
	datasourcemysql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/observability"
	"github.com/croessner/dkim2/provider"
)

const datasourceLoadBytes = 16 << 20

type datasourcePool interface {
	Close()
}

type sqlSigningFactory func(
	context.Context,
	config.SQLSigningConfig,
	[]byte,
	*x509.CertPool,
) (datasourceruntime.Loader, datasourcePool, error)

// networkSigningRuntime owns one selected loader, refresh worker, and backend pool.
type networkSigningRuntime struct {
	runtime *datasourceruntime.Runtime
	pool    datasourcePool
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
	metrics *observability.Metrics
	class   string
}

// joinedAuthority requires every configured runtime authority to remain ready.
type joinedAuthority struct {
	replay  AuthorityReadiness
	signing AuthorityReadiness
}

// AuthorityReady reports one no-I/O conjunction of replay and signing authority.
func (a joinedAuthority) AuthorityReady() bool {
	return sampleAuthorityReadiness(a.replay) && sampleAuthorityReadiness(a.signing)
}

// AuthorityReady exposes the joined datasource runtime's no-I/O state.
func (r *networkSigningRuntime) AuthorityReady() bool {
	return r != nil && r.runtime != nil && r.runtime.Ready()
}

// newNetworkSigningRuntime constructs and initially loads one selected provider.
func newNetworkSigningRuntime(
	ctx context.Context,
	preparation *config.RuntimePreparation,
	telemetry *observability.Runtime,
) (*networkSigningRuntime, error) {
	if ctx == nil || preparation == nil {
		return nil, &LifecycleError{}
	}
	snapshot := preparation.Snapshot()
	var output *networkSigningRuntime
	var constructionErr error
	borrowErr := preparation.SigningDatasource().Use(
		func(password []byte, rootsDER [][]byte) error {
			roots, err := datasourceRootPool(rootsDER)
			if err != nil {
				constructionErr = err
				return nil
			}
			switch snapshot.Signing().Backend() {
			case config.SigningLDAP:
				ldapConfig, ok := snapshot.Signing().LDAP()
				if !ok {
					constructionErr = &LifecycleError{}
					return nil
				}
				connector, connectorErr := datasourceldap.NewGoLDAPConnector(
					datasourceldap.ConnectionConfig{
						Address: ldapConfig.Address(), ServerName: ldapConfig.ServerName(),
						BaseDN: ldapConfig.BaseDN(), BindDN: ldapConfig.BindDN(),
						Password: password, RootCAs: roots,
						UseStartTLS: ldapConfig.Transport() == "starttls",
					},
				)
				if connectorErr != nil {
					constructionErr = connectorErr
					return nil
				}
				loader, loaderErr := datasourceldap.NewLoader(
					connector, provider.DefaultLimits(),
					int(ldapConfig.PageSize()), datasourceLoadBytes,
					ldapConfig.LoadDeadline(),
				)
				if loaderErr != nil {
					constructionErr = loaderErr
					return nil
				}
				output, constructionErr = startNetworkSigningRuntime(
					ctx, loader, nil, ldapConfig.LoadDeadline(),
					snapshot.Signing().ReloadInterval(), "ldap", telemetry,
				)
			case config.SigningPostgreSQL:
				postgresqlConfig, ok := snapshot.Signing().PostgreSQL()
				if !ok {
					constructionErr = &LifecycleError{}
					return nil
				}
				output, constructionErr = startSQLSigningRuntime(
					ctx, postgresqlConfig, password, roots,
					snapshot.Signing().ReloadInterval(), "postgresql", telemetry,
					newPostgreSQLSigningComponents,
				)
			case config.SigningMySQL:
				mysqlConfig, ok := snapshot.Signing().MySQL()
				if !ok {
					constructionErr = &LifecycleError{}
					return nil
				}
				output, constructionErr = startSQLSigningRuntime(
					ctx, mysqlConfig, password, roots,
					snapshot.Signing().ReloadInterval(), "mysql", telemetry,
					newMySQLSigningComponents,
				)
			default:
				constructionErr = &LifecycleError{}
			}
			return nil
		},
	)
	if borrowErr != nil || constructionErr != nil || output == nil {
		return nil, &LifecycleError{}
	}
	return output, nil
}

// startSQLSigningRuntime constructs one SQL provider and performs its initial load.
func startSQLSigningRuntime(
	ctx context.Context,
	providerConfig config.SQLSigningConfig,
	password []byte,
	roots *x509.CertPool,
	refreshInterval time.Duration,
	providerClass string,
	telemetry *observability.Runtime,
	factory sqlSigningFactory,
) (*networkSigningRuntime, error) {
	if factory == nil {
		return nil, &LifecycleError{}
	}
	loader, pool, err := factory(ctx, providerConfig, password, roots)
	if err != nil {
		return nil, err
	}
	return startNetworkSigningRuntime(
		ctx, loader, pool, providerConfig.LoadDeadline(), refreshInterval,
		providerClass, telemetry,
	)
}

// newPostgreSQLSigningComponents opens one bounded PostgreSQL loader and pool.
func newPostgreSQLSigningComponents(
	ctx context.Context,
	providerConfig config.SQLSigningConfig,
	password []byte,
	roots *x509.CertPool,
) (datasourceruntime.Loader, datasourcePool, error) {
	pool, err := datasourcepostgresql.OpenPool(ctx, datasourcepostgresql.ConnectionConfig{
		Address: providerConfig.Address(), ServerName: providerConfig.ServerName(),
		Database: providerConfig.Database(), User: providerConfig.User(),
		Password: password, RootCAs: roots,
		ConnectTimeout:  providerConfig.LoadDeadline(),
		MaxConnections:  int32(providerConfig.MaxConnections()),
		IdleConnections: int32(providerConfig.IdleConnections()),
	})
	if err != nil {
		return nil, nil, err
	}
	loader, err := datasourcepostgresql.NewLoader(
		pool, provider.DefaultLimits(), int(providerConfig.PageSize()),
		datasourceLoadBytes, providerConfig.LoadDeadline(),
	)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return loader, pool, nil
}

// newMySQLSigningComponents opens one bounded MySQL-family loader and pool.
func newMySQLSigningComponents(
	ctx context.Context,
	providerConfig config.SQLSigningConfig,
	password []byte,
	roots *x509.CertPool,
) (datasourceruntime.Loader, datasourcePool, error) {
	pool, err := datasourcemysql.OpenPool(ctx, datasourcemysql.ConnectionConfig{
		Address: providerConfig.Address(), ServerName: providerConfig.ServerName(),
		Database: providerConfig.Database(), User: providerConfig.User(),
		Password: password, RootCAs: roots,
		ConnectTimeout:  providerConfig.LoadDeadline(),
		MaxConnections:  int(providerConfig.MaxConnections()),
		IdleConnections: int(providerConfig.IdleConnections()),
	})
	if err != nil {
		return nil, nil, err
	}
	loader, err := datasourcemysql.NewLoader(
		pool, provider.DefaultLimits(), int(providerConfig.PageSize()),
		datasourceLoadBytes, providerConfig.LoadDeadline(),
	)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return loader, pool, nil
}

// startNetworkSigningRuntime performs the complete initial load before starting refresh.
func startNetworkSigningRuntime(
	ctx context.Context,
	loader datasourceruntime.Loader,
	pool datasourcePool,
	loadDeadline time.Duration,
	refreshInterval time.Duration,
	providerClass string,
	telemetry *observability.Runtime,
) (*networkSigningRuntime, error) {
	started := time.Now()
	loadCtx, cancel := context.WithTimeout(ctx, loadDeadline)
	runtime, err := datasourceruntime.New(loadCtx, loader, loadDeadline)
	cancel()
	var metrics *observability.Metrics
	if telemetry != nil {
		metrics = telemetry.Metrics()
	}
	if err != nil || runtime == nil {
		if metrics != nil {
			metrics.DatasourceCompleted(
				providerClass, "datasource_initial_load", "degraded",
				"failure", time.Since(started),
			)
		}
		if pool != nil {
			pool.Close()
		}
		return nil, &LifecycleError{}
	}
	refreshCtx, refreshCancel := context.WithCancel(context.Background())
	output := &networkSigningRuntime{
		runtime: runtime, pool: pool, cancel: refreshCancel, done: make(chan struct{}),
		metrics: metrics, class: providerClass,
	}
	if metrics != nil {
		metrics.DatasourceCompleted(
			providerClass, "datasource_initial_load", "ready",
			"success", time.Since(started),
		)
	}
	go output.runRefresh(refreshCtx, refreshInterval, loadDeadline)
	return output, nil
}

// runRefresh serializes periodic full reload attempts until shutdown.
func (r *networkSigningRuntime) runRefresh(
	ctx context.Context,
	interval time.Duration,
	loadDeadline time.Duration,
) {
	defer close(r.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			started := time.Now()
			loadCtx, cancel := context.WithTimeout(ctx, loadDeadline)
			err := r.runtime.Refresh(loadCtx)
			cancel()
			if r.metrics != nil {
				result := "success"
				if err != nil {
					result = "failure"
				}
				r.metrics.DatasourceCompleted(
					r.class, "datasource_refresh", string(r.runtime.State()),
					result, time.Since(started),
				)
			}
		}
	}
}

// Close stops refresh, joins it, retires snapshots, and closes backend resources.
func (r *networkSigningRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var result error
	r.once.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		select {
		case <-r.done:
		case <-ctx.Done():
			result = &LifecycleError{}
			return
		}
		if r.runtime != nil && r.runtime.Close(ctx) != nil {
			result = &LifecycleError{}
		}
		if r.pool != nil {
			r.pool.Close()
		}
	})
	return result
}

// datasourceRootPool validates and owns callback-scoped trust roots.
func datasourceRootPool(rootsDER [][]byte) (*x509.CertPool, error) {
	if len(rootsDER) == 0 {
		return nil, errors.New("datasource trust unavailable")
	}
	pool := x509.NewCertPool()
	for _, encoded := range rootsDER {
		certificate, err := x509.ParseCertificate(bytes.Clone(encoded))
		if err != nil {
			return nil, errors.New("datasource trust unavailable")
		}
		pool.AddCert(certificate)
	}
	return pool, nil
}
