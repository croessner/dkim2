//go:build datasourceintegration

package parity

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	datasourcemysql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/mysql"
	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/sqlsnapshot"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const (
	integrationOperationOne   = "aebagbafaydqqcikbmga2dqpca"
	integrationOperationTwo   = "aibqibiga4eascqlbqgy3dymc4"
	integrationOperationThree = "aibqibiga4eascqlbqgzav3y4m"
)

// TestDisposableSQLAdministration qualifies the same two exact v3 rotations
// against upgraded PostgreSQL, MySQL, and MariaDB authorities.
func TestDisposableSQLAdministration(t *testing.T) {
	rootCAs := integrationRoots(t)
	tests := []struct {
		name         string
		open         func(context.Context, string) (*sqlsnapshot.Administrator, error)
		openObserver func(context.Context, string) (activationContentionObserver, error)
	}{
		{
			name: "postgresql",
			open: func(ctx context.Context, database string) (*sqlsnapshot.Administrator, error) {
				return integrationPostgreSQLAdministrator(ctx, t, rootCAs, database)
			},
			openObserver: func(ctx context.Context, database string) (activationContentionObserver, error) {
				return integrationPostgreSQLContentionObserver(ctx, t, rootCAs, database)
			},
		},
		{
			name: "mysql",
			open: func(ctx context.Context, database string) (*sqlsnapshot.Administrator, error) {
				return integrationMySQLAdministrator(
					ctx, t, rootCAs, "DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME", database,
				)
			},
			openObserver: func(ctx context.Context, database string) (activationContentionObserver, error) {
				return integrationMySQLContentionObserver(
					ctx, t, rootCAs, "DKIM2_MYSQL_PORT", "DKIM2_MYSQL_SERVER_NAME",
					"DKIM2_MYSQL_OBSERVER_PASSWORD", database, false,
				)
			},
		},
		{
			name: "mariadb",
			open: func(ctx context.Context, database string) (*sqlsnapshot.Administrator, error) {
				return integrationMySQLAdministrator(
					ctx, t, rootCAs, "DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME", database,
				)
			},
			openObserver: func(ctx context.Context, database string) (activationContentionObserver, error) {
				return integrationMySQLContentionObserver(
					ctx, t, rootCAs, "DKIM2_MARIADB_PORT", "DKIM2_MARIADB_SERVER_NAME",
					"DKIM2_MARIADB_OBSERVER_PASSWORD", database, true,
				)
			},
		},
	}
	for _, test := range tests {
		current := test
		t.Run(current.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			administrator, err := current.open(ctx, "dkim2")
			cancel()
			if err != nil {
				t.Fatal("open SQL administrator")
			}
			defer administrator.Close()
			rotateDisposableSQLGeneration(t, administrator, 1, 2, integrationOperationOne)
			rotateDisposableSQLGeneration(t, administrator, 2, 3, integrationOperationTwo)
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			peer, err := current.open(ctx, "dkim2")
			cancel()
			if err != nil {
				t.Fatal("open independent SQL activation contender")
			}
			defer peer.Close()
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			observer, err := current.openObserver(ctx, "dkim2")
			cancel()
			if err != nil {
				t.Fatal("open independent SQL contention observer")
			}
			defer observer.Close()
			raceDisposableSQLActivation(
				t, administrator, peer, observer, 3, 4, integrationOperationThree,
			)
			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			inventory, err := administrator.Inventory(ctx, integrationGenerationLimits())
			cancel()
			if err != nil || inventory.Current != 4 || len(inventory.Generations) != 4 ||
				!inventory.Generations[0].WasActive || !inventory.Generations[1].WasActive ||
				!inventory.Generations[2].WasActive || !inventory.Generations[3].Current {
				t.Fatal("two SQL rotations did not preserve exact history")
			}

			ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
			fresh, err := current.open(ctx, "dkim2_fresh")
			cancel()
			if err != nil {
				t.Fatal("open fresh SQL administrator")
			}
			defer fresh.Close()
			bootstrapDisposableSQLGeneration(t, administrator, fresh, integrationOperationOne)
			rotateDisposableSQLGeneration(t, fresh, 1, 2, integrationOperationTwo)
		})
	}
}

type activationContentionObserver interface {
	ObserveWaitEdge(context.Context, uint64, uint64) (bool, error)
	Close()
}

// raceDisposableSQLActivation proves one same-current contender wins while
// the exact loser remains typed and the committed candidate stays coherent.
func raceDisposableSQLActivation(
	t *testing.T,
	administrator *sqlsnapshot.Administrator,
	peer *sqlsnapshot.Administrator,
	observer activationContentionObserver,
	expected uint64,
	candidateGeneration uint64,
	operationText string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	current, err := administrator.ReadCurrent(ctx, integrationGenerationLimits())
	cancel()
	if err != nil {
		t.Fatal("read race source generation")
	}
	clone, err := current.CloneTo(datasourceadmin.SchemaVersionV3, candidateGeneration)
	_ = current.Close()
	if err != nil {
		t.Fatal("clone race candidate generation")
	}
	content, err := datasourceadmin.NewCandidateContent(clone)
	if err != nil {
		_ = clone.Close()
		t.Fatal("construct race candidate content")
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope(operationText, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("bind race candidate operation")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operation, _ := datasourceadmin.NewOperationBinding(operationText)
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	observation, err := administrator.ObserveAdministrationLock(ctx)
	cancel()
	if err != nil || observation.Claimed() {
		t.Fatal("observe race administration lock")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	lock, err := administrator.Claim(ctx, operation, observation.Revision())
	cancel()
	if err != nil {
		t.Fatal("claim race administration lock")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	staged, err := administrator.Stage(ctx, lock, operation, candidate)
	cancel()
	if err != nil {
		t.Fatal("stage race candidate")
	}
	activation, err := datasourceadmin.NewActivation(
		lock, operation, expected, candidateGeneration,
		candidate.PreparedEvidence(), staged,
	)
	if err != nil {
		t.Fatal("construct race activation")
	}
	contention := sqlsnapshot.NewActivationContentionGate()
	if err := sqlsnapshot.DecorateActivationContention(
		administrator, contention, sqlsnapshot.ActivationContentionHolder,
	); err != nil {
		t.Fatal("decorate activation lock holder")
	}
	if err := sqlsnapshot.DecorateActivationContention(
		peer, contention, sqlsnapshot.ActivationContentionWaiter,
	); err != nil {
		t.Fatal("decorate activation lock waiter")
	}
	defer contention.ReleaseHolder()
	holderResult := make(chan error, 1)
	waiterResult := make(chan error, 1)
	go func() {
		attemptCtx, attemptCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer attemptCancel()
		holderResult <- administrator.Activate(attemptCtx, activation)
	}()
	waitForContentionSignal(t, contention.HolderBeforeMutation(), "holder before mutation")
	holderID := waitForContentionConnectionID(t, contention.HolderConnectionID(), "holder connection identity")
	go func() {
		attemptCtx, attemptCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer attemptCancel()
		waiterResult <- peer.Activate(attemptCtx, activation)
	}()
	waitForContentionSignal(t, contention.WaiterTransactionBegun(), "waiter transaction begun")
	waiterID := waitForContentionConnectionID(t, contention.WaiterConnectionID(), "waiter connection identity")
	waitForContentionSignal(t, contention.WaiterReadLockAttempt(), "waiter read-lock attempt")
	waitForObservedContentionEdge(t, observer, holderID, waiterID)
	contention.ReleaseHolder()
	if holderErr := waitForActivationResult(t, holderResult, "holder"); holderErr != nil {
		t.Fatalf("activation lock holder did not win: %s", datasourceadmin.CodeOf(holderErr))
	}
	if waiterErr := waitForActivationResult(t, waiterResult, "waiter"); datasourceadmin.CodeOf(waiterErr) != datasourceadmin.CodeConflict {
		t.Fatalf("activation lock waiter result = %s, want conflict", datasourceadmin.CodeOf(waiterErr))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	inventory, err := administrator.Inventory(ctx, integrationGenerationLimits())
	cancel()
	if err != nil || inventory.Current != candidateGeneration {
		t.Fatal("race winner did not own exact current")
	}
	old, oldPresent := integrationGenerationInfo(inventory, expected)
	selected, selectedPresent := integrationGenerationInfo(inventory, candidateGeneration)
	if !oldPresent || !old.WasActive || !selectedPresent || !selected.Current ||
		selected.State != datasourceadmin.StateCommitted {
		t.Fatal("race result lost current, digest, or history coherence")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	readback, err := administrator.ReadCurrent(ctx, integrationGenerationLimits())
	cancel()
	if err != nil || readback.Generation() != candidateGeneration {
		if readback != nil {
			_ = readback.Close()
		}
		t.Fatal("race current readback is incoherent")
	}
	_ = readback.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	_, err = administrator.Release(ctx, lock)
	cancel()
	if err != nil {
		t.Fatal("release race administration lock")
	}
}

// waitForContentionConnectionID waits for one exact physical transaction identity.
func waitForContentionConnectionID(t *testing.T, ids <-chan uint64, name string) uint64 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	select {
	case id := <-ids:
		if id == 0 {
			t.Fatalf("contention handshake unavailable: %s", name)
		}
		return id
	case <-ctx.Done():
		t.Fatalf("contention handshake unavailable: %s", name)
		return 0
	}
}

// waitForObservedContentionEdge polls until the server proves the exact edge.
func waitForObservedContentionEdge(
	t *testing.T,
	observer activationContentionObserver,
	holderID uint64,
	waiterID uint64,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		observed, err := observer.ObserveWaitEdge(ctx, holderID, waiterID)
		if err != nil {
			t.Fatalf("server-side contention observation failed: %s", datasourceadmin.CodeOf(err))
		}
		if observed {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal("server-side waiter-to-holder contention edge was not observed")
		}
	}
}

// waitForContentionSignal waits only as a bounded deadlock guard for one exact handshake.
func waitForContentionSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("contention handshake unavailable: %s", name)
	}
}

// waitForActivationResult waits only as a bounded deadlock guard for one contender.
func waitForActivationResult(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatalf("activation contender did not complete: %s", name)
		return ctx.Err()
	}
}

// integrationGenerationInfo returns one exact inventory member.
func integrationGenerationInfo(
	inventory datasourceadmin.Inventory,
	generation uint64,
) (datasourceadmin.GenerationInfo, bool) {
	for _, info := range inventory.Generations {
		if info.Generation == generation {
			return info, true
		}
	}
	return datasourceadmin.GenerationInfo{}, false
}

// rotateDisposableSQLGeneration clones current, stages canonical readback,
// activates once, and releases the exact administration claim.
func rotateDisposableSQLGeneration(
	t *testing.T,
	administrator *sqlsnapshot.Administrator,
	expected uint64,
	candidateGeneration uint64,
	operationText string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	current, err := administrator.ReadCurrent(ctx, integrationGenerationLimits())
	cancel()
	if err != nil {
		t.Fatal("read current SQL generation")
	}
	clone, err := current.CloneTo(datasourceadmin.SchemaVersionV3, candidateGeneration)
	_ = current.Close()
	if err != nil {
		t.Fatal("clone SQL candidate generation")
	}
	content, err := datasourceadmin.NewCandidateContent(clone)
	if err != nil {
		_ = clone.Close()
		t.Fatal("construct SQL candidate content")
	}
	candidate, err := datasourceadmin.NewPublicationEnvelope(operationText, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("bind SQL candidate operation")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	operation, err := datasourceadmin.NewOperationBinding(operationText)
	if err != nil {
		t.Fatal("construct SQL operation")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	observation, err := administrator.ObserveAdministrationLock(ctx)
	cancel()
	if err != nil || observation.Claimed() {
		t.Fatal("observe ownerless SQL administration lock")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	lock, err := administrator.Claim(ctx, operation, observation.Revision())
	cancel()
	if err != nil {
		t.Fatalf("claim SQL administration lock: %s", datasourceadmin.CodeOf(err))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	staged, err := administrator.Stage(ctx, lock, operation, candidate)
	cancel()
	if err != nil {
		t.Fatalf("stage SQL candidate: %s", datasourceadmin.CodeOf(err))
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	replayed, err := administrator.Stage(ctx, lock, operation, candidate)
	cancel()
	if err != nil || !replayed.Digest().Equal(staged.Digest()) {
		t.Fatal("replay exact SQL stage")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	inspected, _, err := administrator.Inspect(
		ctx, operation, candidateGeneration, expected, integrationGenerationLimits(),
	)
	cancel()
	if err != nil || inspected == nil || !inspected.Digest().Equal(candidate.Digest()) {
		if inspected != nil {
			_ = inspected.Close()
		}
		t.Fatal("inspect exact SQL stage")
	}
	_ = inspected.Close()
	activation, err := datasourceadmin.NewActivation(
		lock, operation, expected, candidateGeneration,
		candidate.PreparedEvidence(), staged,
	)
	if err != nil {
		t.Fatal("construct SQL activation")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	err = administrator.Activate(ctx, activation)
	cancel()
	if err != nil {
		t.Fatal("activate SQL candidate")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	next, err := administrator.Release(ctx, lock)
	cancel()
	if err != nil || next != observation.Revision()+1 {
		t.Fatal("release SQL administration lock")
	}
}

// bootstrapDisposableSQLGeneration copies only protected logical rows into a
// separate empty upgraded database and exercises the first-writer path.
func bootstrapDisposableSQLGeneration(
	t *testing.T,
	source *sqlsnapshot.Administrator,
	target *sqlsnapshot.Administrator,
	operationText string,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	current, err := source.ReadCurrent(ctx, integrationGenerationLimits())
	cancel()
	if err != nil {
		t.Fatal("read bootstrap source")
	}
	var candidate *datasourceadmin.PublicationEnvelope
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	err = current.WithRows(ctx, func(rows datasourceadmin.Rows) error {
		snapshot, snapshotErr := datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV3, 1, rows)
		if snapshotErr != nil {
			return snapshotErr
		}
		content, contentErr := datasourceadmin.NewCandidateContent(snapshot)
		if contentErr != nil {
			_ = snapshot.Close()
			return contentErr
		}
		candidate, snapshotErr = datasourceadmin.NewPublicationEnvelope(operationText, content)
		if snapshotErr != nil {
			_ = content.Close()
		}
		return snapshotErr
	})
	cancel()
	_ = current.Close()
	if err != nil || candidate == nil {
		t.Fatal("construct bootstrap SQL candidate")
	}
	defer candidate.Close() //nolint:errcheck // Test cleanup has no recovery action.
	publishDisposableSQLCandidate(t, target, 0, candidate, operationText)
}

// publishDisposableSQLCandidate claims, stages, inspects, activates, and
// releases one already constructed candidate.
func publishDisposableSQLCandidate(
	t *testing.T,
	administrator *sqlsnapshot.Administrator,
	expected uint64,
	candidate *datasourceadmin.PublicationEnvelope,
	operationText string,
) {
	t.Helper()
	operation, err := datasourceadmin.NewOperationBinding(operationText)
	if err != nil {
		t.Fatal("construct bootstrap SQL operation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	observation, err := administrator.ObserveAdministrationLock(ctx)
	cancel()
	if err != nil || observation.Claimed() {
		t.Fatal("observe bootstrap SQL lock")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	lock, err := administrator.Claim(ctx, operation, observation.Revision())
	cancel()
	if err != nil {
		t.Fatal("claim bootstrap SQL lock")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	staged, err := administrator.Stage(ctx, lock, operation, candidate)
	cancel()
	if err != nil {
		t.Fatal("stage bootstrap SQL candidate")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	inspected, _, err := administrator.Inspect(
		ctx, operation, candidate.Generation(), expected, integrationGenerationLimits(),
	)
	cancel()
	if err != nil || inspected == nil || !inspected.Digest().Equal(candidate.Digest()) {
		if inspected != nil {
			_ = inspected.Close()
		}
		t.Fatal("inspect bootstrap SQL candidate")
	}
	_ = inspected.Close()
	activation, err := datasourceadmin.NewActivation(
		lock, operation, expected, candidate.Generation(), candidate.PreparedEvidence(), staged,
	)
	if err != nil {
		t.Fatal("construct bootstrap SQL activation")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	err = administrator.Activate(ctx, activation)
	cancel()
	if err != nil {
		t.Fatal("activate bootstrap SQL candidate")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	_, err = administrator.Release(ctx, lock)
	cancel()
	if err != nil {
		t.Fatal("release bootstrap SQL lock")
	}
}

// integrationPostgreSQLAdministrator opens three exact verified-TLS role pools.
func integrationPostgreSQLAdministrator(
	ctx context.Context,
	t *testing.T,
	rootCAs *x509.CertPool,
	database string,
) (*sqlsnapshot.Administrator, error) {
	t.Helper()
	config := func(user, password string) datasourcepostgresql.ConnectionConfig {
		return datasourcepostgresql.ConnectionConfig{
			Address:    integrationAddress(t, "DKIM2_POSTGRESQL_PORT"),
			ServerName: integrationEnvironment(t, "DKIM2_POSTGRESQL_SERVER_NAME"),
			Database:   database, User: user, Password: []byte(password), RootCAs: rootCAs,
			ConnectTimeout: 5 * time.Second, MaxConnections: 2,
		}
	}
	return datasourcepostgresql.OpenAdministrator(
		ctx,
		config("dkim2_snapshot_login", integrationEnvironment(t, "DKIM2_SQL_SNAPSHOT_PASSWORD")),
		config("dkim2_staging_login", integrationEnvironment(t, "DKIM2_SQL_STAGING_PASSWORD")),
		config("dkim2_activation_login", integrationEnvironment(t, "DKIM2_SQL_ACTIVATION_PASSWORD")),
		provider.DefaultLimits(), integrationGenerationLimits(), 2,
	)
}

// integrationPostgreSQLContentionObserver opens a separate disposable root observer.
func integrationPostgreSQLContentionObserver(
	ctx context.Context,
	t *testing.T,
	rootCAs *x509.CertPool,
	database string,
) (*datasourcepostgresql.ActivationContentionObserver, error) {
	t.Helper()
	return datasourcepostgresql.OpenActivationContentionObserver(ctx, datasourcepostgresql.ConnectionConfig{
		Address:    integrationAddress(t, "DKIM2_POSTGRESQL_PORT"),
		ServerName: integrationEnvironment(t, "DKIM2_POSTGRESQL_SERVER_NAME"),
		Database:   database, User: "postgres",
		Password: integrationPassword(t, "DKIM2_POSTGRESQL_OBSERVER_PASSWORD"),
		RootCAs:  rootCAs, ConnectTimeout: 5 * time.Second, MaxConnections: 1,
	})
}

// integrationMySQLAdministrator opens three exact verified-TLS account pools.
func integrationMySQLAdministrator(
	ctx context.Context,
	t *testing.T,
	rootCAs *x509.CertPool,
	portName string,
	serverName string,
	database string,
) (*sqlsnapshot.Administrator, error) {
	t.Helper()
	config := func(user, password string) datasourcemysql.ConnectionConfig {
		return datasourcemysql.ConnectionConfig{
			Address:    integrationAddress(t, portName),
			ServerName: integrationEnvironment(t, serverName),
			Database:   database, User: user, Password: []byte(password), RootCAs: rootCAs,
			ConnectTimeout: 5 * time.Second, MaxConnections: 2,
		}
	}
	return datasourcemysql.OpenAdministrator(
		ctx,
		config("dkim2_snapshot_login", integrationEnvironment(t, "DKIM2_SQL_SNAPSHOT_PASSWORD")),
		config("dkim2_staging_login", integrationEnvironment(t, "DKIM2_SQL_STAGING_PASSWORD")),
		config("dkim2_activation_login", integrationEnvironment(t, "DKIM2_SQL_ACTIVATION_PASSWORD")),
		provider.DefaultLimits(), integrationGenerationLimits(), 2,
	)
}

// integrationMySQLContentionObserver opens a separate disposable root observer.
func integrationMySQLContentionObserver(
	ctx context.Context,
	t *testing.T,
	rootCAs *x509.CertPool,
	portName string,
	serverName string,
	passwordName string,
	database string,
	mariaDB bool,
) (*datasourcemysql.ActivationContentionObserver, error) {
	t.Helper()
	config := datasourcemysql.ConnectionConfig{
		Address:    integrationAddress(t, portName),
		ServerName: integrationEnvironment(t, serverName),
		Database:   database, User: "root", Password: integrationPassword(t, passwordName),
		RootCAs: rootCAs, ConnectTimeout: 5 * time.Second, MaxConnections: 1,
	}
	if mariaDB {
		return datasourcemysql.OpenMariaDBActivationContentionObserver(ctx, config)
	}
	return datasourcemysql.OpenMySQLActivationContentionObserver(ctx, config)
}

// integrationGenerationLimits returns the fixed disposable administration bounds.
func integrationGenerationLimits() datasourceadmin.GenerationLimits {
	return datasourceadmin.GenerationLimits{
		MaxGenerations: 16, MaxOutstandingCandidates: 2,
		MaxSnapshotRows: 128, MaxSnapshotBytes: 4 << 20,
		BackendDeadline: 15 * time.Second,
	}
}
