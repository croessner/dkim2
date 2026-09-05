//go:build valkeyintegration

package valkey

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	integrationApplicationUser     = "dkim2-integration-application"
	integrationApplicationPassword = "synthetic-application-password-91"
	integrationAuditorUser         = "dkim2-integration-auditor"
	integrationAuditorPassword     = "synthetic-auditor-password-91"
	integrationSaveSchedule        = "3600 1"
)

// TestRealValkeyHarness proves the production parser, audit plan, and provider contract against Valkey 9.1.0.
func TestRealValkeyHarness(t *testing.T) {
	socket := requiredIntegrationSocket(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	attestation := integrationOperatorAttestation(t)
	runRealSecurityAudit(ctx, t, socket, attestation)

	memory := integrationMemoryStore(t)
	exerciseProviderParity(t, memory)
	exercisePropagationParity(t, memory)
	closeIntegrationStore(t, memory)

	store := integrationValkeyStore(t, socket)
	exerciseProviderParity(t, store)
	exercisePropagationParity(t, store)
	closeIntegrationStore(t, store)
}

// requiredIntegrationSocket validates the private harness directory and Unix socket.
func requiredIntegrationSocket(t *testing.T) string {
	t.Helper()
	socket := os.Getenv("DKIM2_VALKEY_SOCKET")
	if socket == "" || !filepath.IsAbs(socket) {
		t.Fatal("mandatory hermetic Valkey socket is absent")
	}
	directoryInfo, err := os.Stat(filepath.Dir(socket))
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatal("hermetic Valkey directory is not private")
	}
	socketInfo, err := os.Stat(socket)
	if err != nil || socketInfo.Mode().Type()&os.ModeSocket == 0 ||
		socketInfo.Mode().Perm() != 0o600 {
		t.Fatal("hermetic Valkey socket is not private")
	}
	return socket
}

// integrationOperatorAttestation constructs the exact synthetic RDB deployment assertion.
func integrationOperatorAttestation(t *testing.T) OperatorAttestation {
	t.Helper()
	input := validOperatorAttestationInput()
	input.values.SaveSchedule = integrationSaveSchedule
	input.values.MinReplicasMaxLagSeconds = 10
	attestation, err := NewOperatorAttestation(input)
	if err != nil {
		t.Fatal("synthetic operator attestation construction failed")
	}
	return attestation
}

// runRealSecurityAudit executes the exact production eleven-command plan over one Unix connection.
func runRealSecurityAudit(
	ctx context.Context,
	t *testing.T,
	socket string,
	attestation OperatorAttestation,
) {
	t.Helper()
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", socket)
	if err != nil {
		t.Fatal("hermetic auditor connection failed")
	}
	wire := &tlsSecurityAuditWire{connection: connection}
	err = runSecurityAudit(
		ctx,
		wire,
		auditCredentials{
			username: integrationAuditorUser,
			password: []byte(integrationAuditorPassword),
		},
		securityAuditPolicyFrom(attestation, integrationApplicationUser),
		auditPhaseConstruction,
	)
	if err != nil {
		t.Fatalf("real eleven-command security audit failed: %s", dkim2.ReplayErrorCodeOf(err))
	}
	if wire.commands != auditCommandCount {
		t.Fatalf("real security audit sent %d commands, want %d", wire.commands, auditCommandCount)
	}
}

// integrationMemoryStore constructs the storage-neutral parity baseline.
func integrationMemoryStore(t *testing.T) dkim2.ManagedReplayStore {
	t.Helper()
	store, err := dkim2.NewReplayMemoryStore(dkim2.ReplayMemoryConfig{
		Clock: dkim2.ReplayClockFunc(time.Now),
	})
	if err != nil {
		t.Fatal("memory parity store construction failed")
	}
	return store
}

// integrationValkeyStore constructs one package-private Unix transport around the production command adapter.
func integrationValkeyStore(t *testing.T, socket string) dkim2.ManagedReplayStore {
	t.Helper()
	option := valkeygo.ClientOption{
		DialCtxFn: func(
			ctx context.Context,
			_ string,
			dialer *net.Dialer,
			_ *tls.Config,
		) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		Dialer: net.Dialer{
			Timeout:   time.Second,
			KeepAlive: time.Second,
		},
		Username:          integrationApplicationUser,
		Password:          integrationApplicationPassword,
		ClientSetInfo:     make([]string, 0),
		InitAddress:       []string{"hermetic-unix-socket"},
		ConnWriteTimeout:  time.Second,
		DisableRetry:      true,
		DisableCache:      true,
		ForceSingleClient: true,
	}
	client, err := valkeygo.NewClient(option)
	if err != nil {
		t.Fatal("hermetic application client construction failed")
	}
	owned := &applicationClientAdapter{client: client}
	return &Store{storeCore: &storeCore{
		client:      valkeyCommandClient{client: owned},
		gate:        newAdmissionGate(1024, 1024),
		ownedClient: owned,
	}}
}

// exerciseProviderParity proves first-seen, replay, non-extension, expiry, and same-key concurrency.
func exerciseProviderParity(t *testing.T, store dkim2.ReplayStore) {
	t.Helper()
	retention, err := dkim2.NewReplayRetention(time.Second)
	if err != nil {
		t.Fatal("integration retention construction failed")
	}
	key := validReplayKey(t)
	requireIntegrationCheck(t, store, key, retention, dkim2.ReplayCheckFirstSeen)
	requireIntegrationCheck(t, store, key, retention, dkim2.ReplayCheckReplayed)
	time.Sleep(650 * time.Millisecond)
	requireIntegrationCheck(t, store, key, retention, dkim2.ReplayCheckReplayed)
	time.Sleep(550 * time.Millisecond)
	requireIntegrationCheck(t, store, key, retention, dkim2.ReplayCheckFirstSeen)

	time.Sleep(1100 * time.Millisecond)
	const callers = 32
	results := make(chan dkim2.ReplayCheck, callers)
	errors := make(chan error, callers)
	var group sync.WaitGroup
	group.Add(callers)
	for range callers {
		go func() {
			defer group.Done()
			check, callErr := store.CheckAndRemember(context.Background(), key, retention)
			results <- check
			errors <- callErr
		}()
	}
	group.Wait()
	close(results)
	close(errors)

	firstSeen := 0
	replayed := 0
	for callErr := range errors {
		if callErr != nil {
			t.Fatalf("same-key parity call failed: %s", dkim2.ReplayErrorCodeOf(callErr))
		}
	}
	for check := range results {
		switch check {
		case dkim2.ReplayCheckFirstSeen:
			firstSeen++
		case dkim2.ReplayCheckReplayed:
			replayed++
		default:
			t.Fatal("same-key parity returned an invalid successful state")
		}
	}
	if firstSeen != 1 || replayed != callers-1 {
		t.Fatalf("same-key parity = %d first-seen, %d replayed", firstSeen, replayed)
	}
}

// exercisePropagationParity proves the two-phase propagation contract on a
// real provider: an absent coordinate is reserved, a live lease is pending, an
// expired lease is re-served exactly once, a commit is monotonic and
// idempotent, a committed coordinate is never re-served, and a coordinate
// that was never reserved cannot be committed.
func exercisePropagationParity(t *testing.T, store dkim2.ReplayStore) {
	t.Helper()
	propagation, ok := store.(dkim2.ReplayPropagationStore)
	if !ok {
		t.Fatal("integration provider does not hold the propagation contract")
	}
	retention, err := dkim2.NewReplayRetention(5 * time.Second)
	if err != nil {
		t.Fatal("propagation retention construction failed")
	}
	lease, err := dkim2.NewReplayLease(time.Second)
	if err != nil {
		t.Fatal("propagation lease construction failed")
	}
	key := validPropagationReplayKey(t)
	requireIntegrationReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationReserved)
	requireIntegrationReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationPending)
	time.Sleep(1100 * time.Millisecond)
	requireIntegrationReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationReserved)
	requireIntegrationReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationPending)
	requireIntegrationCommit(t, propagation, key, dkim2.ReplayPropagationCommitted)
	requireIntegrationCommit(t, propagation, key, dkim2.ReplayPropagationCommitted)
	requireIntegrationReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationAlreadyCommitted)
	time.Sleep(1100 * time.Millisecond)
	requireIntegrationReservation(t, propagation, key, retention, lease, dkim2.ReplayPropagationAlreadyCommitted)
	requireIntegrationCommit(t, propagation, validReplayKey(t), dkim2.ReplayPropagationCommitUnresolved)
}

// requireIntegrationReservation requires one exact successful reservation outcome.
func requireIntegrationReservation(
	t *testing.T,
	store dkim2.ReplayPropagationStore,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
	lease dkim2.ReplayLease,
	want dkim2.ReplayPropagationReservation,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	reservation, err := store.ReservePropagation(ctx, key, retention, lease)
	if err != nil || reservation != want {
		t.Fatalf("ReservePropagation() = %v, %v; want %v", reservation, err, want)
	}
}

// requireIntegrationCommit requires one exact successful commit outcome.
func requireIntegrationCommit(
	t *testing.T,
	store dkim2.ReplayPropagationStore,
	key dkim2.ReplayKey,
	want dkim2.ReplayPropagationCommit,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	commit, err := store.CommitPropagation(ctx, key)
	if err != nil || commit != want {
		t.Fatalf("CommitPropagation() = %v, %v; want %v", commit, err, want)
	}
}

// requireIntegrationCheck requires one exact successful parity outcome.
func requireIntegrationCheck(
	t *testing.T,
	store dkim2.ReplayStore,
	key dkim2.ReplayKey,
	retention dkim2.ReplayRetention,
	want dkim2.ReplayCheck,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	check, err := store.CheckAndRemember(ctx, key, retention)
	if err != nil || check != want {
		t.Fatalf("CheckAndRemember() = %v, %v; want %v", check, err, want)
	}
}

// closeIntegrationStore closes one managed provider under a bounded context.
func closeIntegrationStore(t *testing.T, store dkim2.ManagedReplayStore) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := store.Close(ctx); err != nil {
		t.Fatalf("integration store close failed: %s", dkim2.ReplayErrorCodeOf(err))
	}
}
