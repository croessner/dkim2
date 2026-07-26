package valkey

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

// TestAuditFactoryReceivesOnlyNarrowPasswordFreeAuthority freezes the credential boundary.
func TestAuditFactoryReceivesOnlyNarrowPasswordFreeAuthority(t *testing.T) {
	authorityType := reflect.TypeOf(auditAuthority{})
	wantFields := []string{
		"endpoint",
		"tlsServerName",
		"rootCertificates",
		"dialTimeout",
		"tcpKeepAlive",
	}
	if authorityType.NumField() != len(wantFields) {
		t.Fatalf("audit authority fields=%d want=%d", authorityType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if authorityType.Field(index).Name != want {
			t.Fatalf("audit authority field %d=%q want=%q",
				index, authorityType.Field(index).Name, want)
		}
	}
	for _, forbidden := range []string{
		"username",
		"password",
		"connWriteTimeout",
		"epoch",
		"limits",
	} {
		if _, present := authorityType.FieldByName(forbidden); present {
			t.Fatalf("audit authority exposed %q", forbidden)
		}
	}

	config := validClientConfig(t)
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	var observed auditAuthority
	dependencies.newAuditWire = func(
		_ context.Context,
		authority auditAuthority,
		publish func(auditWire),
	) error {
		observed = authority
		publish(&fakeAuditWire{replies: validAuditReplies()})
		return nil
	}
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		config,
		mustOperatorAttestation(t),
		validAuditorConfig(),
		dependencies,
	)
	if err != nil {
		t.Fatalf("construction with narrow audit authority failed: %v", err)
	}
	if observed.endpoint != config.values.Endpoint ||
		observed.tlsServerName != config.values.TLSServerName ||
		observed.rootCertificates == nil ||
		observed.dialTimeout != config.values.DialTimeout ||
		observed.tcpKeepAlive != config.values.TCPKeepAlive {
		t.Fatal("audit factory received an incomplete authority projection")
	}
	if store.applicationUsername == nil || *store.applicationUsername != config.values.Username {
		t.Fatal("application policy identity was not retained separately")
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestRealAuditWireContextClassification distinguishes caller and owned timeouts.
func TestRealAuditWireContextClassification(t *testing.T) {
	tests := []struct {
		name       string
		readBlock  bool
		parentMode string
		want       dkim2.ReplayErrorCode
	}{
		{name: "owned read timeout", readBlock: true, parentMode: testParentOwned, want: dkim2.ReplayErrorUnavailable},
		{name: "owned write timeout", parentMode: testParentOwned, want: dkim2.ReplayErrorUnavailable},
		{name: "parent read cancel", readBlock: true, parentMode: syntheticCancelledName, want: dkim2.ReplayErrorCancelled},
		{name: "parent write cancel", parentMode: syntheticCancelledName, want: dkim2.ReplayErrorCancelled},
		{name: "parent read deadline", readBlock: true, parentMode: syntheticDeadlineName, want: dkim2.ReplayErrorDeadlineExceeded},
		{name: "parent write deadline", parentMode: syntheticDeadlineName, want: dkim2.ReplayErrorDeadlineExceeded},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			parent := context.Background()
			cancelParent := func() {}
			switch testCase.parentMode {
			case syntheticCancelledName:
				var cancel context.CancelFunc
				parent, cancel = context.WithCancel(context.Background())
				cancelParent = cancel
			case syntheticDeadlineName:
				var cancel context.CancelFunc
				parent, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
				cancelParent = cancel
			}
			defer cancelParent()

			childTimeout := time.Second
			if testCase.parentMode == testParentOwned {
				childTimeout = 50 * time.Millisecond
			}
			child, cancelChild := context.WithTimeout(parent, childTimeout)
			defer cancelChild()

			client, server := net.Pipe()
			defer func() { _ = client.Close() }()
			defer func() { _ = server.Close() }()
			connection := newSignalingAuditConn(client)
			wire := &classifiedAuditWire{wire: &tlsSecurityAuditWire{connection: connection}}

			if testCase.readBlock {
				go func() {
					buffer := make([]byte, 1024)
					_, _ = server.Read(buffer)
					<-child.Done()
					_ = server.Close()
				}()
			} else {
				go func() {
					<-child.Done()
					_ = server.Close()
				}()
			}

			result := make(chan error, 1)
			go func() {
				_, err := wire.roundTrip(child, auditRequest{command: auditCommandRole})
				result <- err
			}()
			if testCase.readBlock {
				<-connection.readStarted
			} else {
				<-connection.writeStarted
			}
			if testCase.parentMode == syntheticCancelledName {
				cancelParent()
			}

			wireErr := <-result
			err := boundedAuditResult(parent, context.Background(), wire, wireErr)
			if dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("code=%q want=%q", dkim2.ReplayErrorCodeOf(err), testCase.want)
			}
		})
	}
}

// TestProductionFactoryOrdersAuditCleanupBeforeApplicationConstruction proves unattested stores cannot exist.
func TestProductionFactoryOrdersAuditCleanupBeforeApplicationConstruction(t *testing.T) {
	var eventsMu sync.Mutex
	var events []string
	appendEvent := func(event string) {
		eventsMu.Lock()
		events = append(events, event)
		eventsMu.Unlock()
	}
	wire := &orderingAuditWire{
		fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
		onClose:       func() { appendEvent("audit_closed") },
	}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		validClientConfig(t),
		mustOperatorAttestation(t),
		validAuditorConfig(),
		productionDependencies{
			clock: fixedSecurityClock{now: time.Unix(10_000, 0)},
			newAuditWire: func(
				_ context.Context,
				_ auditAuthority,
				publish func(auditWire),
			) error {
				appendEvent("audit_created")
				publish(wire)
				return nil
			},
			newApplication: func(
				option valkeygo.ClientOption,
				publish func(ownedApplicationClient),
			) error {
				appendEvent("application_created")
				if option.ForceSingleClient != true || option.TLSConfig == nil {
					t.Fatal("application factory received an unsafe option")
				}
				publish(client)
				return nil
			},
		},
	)
	if err != nil || store == nil {
		t.Fatalf("production construction failed: %v events=%v", err, events)
	}
	eventsMu.Lock()
	defer eventsMu.Unlock()
	want := []string{"audit_created", "audit_closed", "application_created"}
	if len(events) != len(want) {
		t.Fatalf("events=%v", events)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events=%v", events)
		}
	}
}

// TestProductionFactoryHonorsEveryAcquisitionBarrier proves cancellation creates no later ownership.
func TestProductionFactoryHonorsEveryAcquisitionBarrier(t *testing.T) {
	t.Run("after local validation", func(t *testing.T) {
		ctx := &nthCancellationContext{cancelAt: 2}
		var auditCalls atomic.Int32
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			context.Context,
			auditAuthority,
			func(auditWire),
		) error {
			auditCalls.Add(1)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
			auditCalls.Load() != 0 {
			t.Fatalf("store=%v code=%q audit calls=%d",
				store, dkim2.ReplayErrorCodeOf(err), auditCalls.Load())
		}
	})

	t.Run("after audit cleanup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		var applicationCalls atomic.Int32
		wire := &orderingAuditWire{
			fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
			onClose:       cancel,
		}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(wire)
			return nil
		}
		dependencies.newApplication = func(
			valkeygo.ClientOption,
			func(ownedApplicationClient),
		) error {
			applicationCalls.Add(1)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
			applicationCalls.Load() != 0 {
			t.Fatalf("store=%v code=%q application calls=%d",
				store, dkim2.ReplayErrorCodeOf(err), applicationCalls.Load())
		}
	})
}

// TestAuditAcquisitionReceivesTheGlobalDeadline proves the budget starts before dialing.
func TestAuditAcquisitionReceivesTheGlobalDeadline(t *testing.T) {
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	var remaining time.Duration
	dependencies.newAuditWire = func(
		ctx context.Context,
		_ auditAuthority,
		publish func(auditWire),
	) error {
		deadline, present := ctx.Deadline()
		if !present {
			t.Fatal("audit acquisition had no global deadline")
		}
		remaining = time.Until(deadline)
		publish(&fakeAuditWire{replies: validAuditReplies()})
		return nil
	}
	store := mustProductionStore(t, dependencies)
	if remaining <= 0 || remaining > auditGlobalTimeout ||
		remaining < auditGlobalTimeout-time.Second {
		t.Fatalf("acquisition budget=%s", remaining)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestOwnedGlobalDeadlineExpiresDuringAcquisition proves dialing consumes the same budget.
func TestOwnedGlobalDeadlineExpiresDuringAcquisition(t *testing.T) {
	validated, err := validateClientConfig(validClientConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer validated.clearPassword()
	factory := func(
		ctx context.Context,
		_ auditAuthority,
		_ func(auditWire),
	) error {
		<-ctx.Done()
		return ctx.Err()
	}
	completed, err := acquireAndRunSecurityAuditWithBudget(
		context.Background(),
		factory,
		validated.auditAuthority(),
		validAuditCredentials(),
		validSecurityAuditPolicy(),
		auditPhaseConstruction,
		fixedSecurityClock{now: time.Unix(10_000, 0)},
		time.Millisecond,
	)
	if !completed.IsZero() ||
		dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("completed=%v code=%q", completed, dkim2.ReplayErrorCodeOf(err))
	}
}

// TestProductionAuditErrorClassification preserves bounded wire failures through construction and runtime recovery.
func TestProductionAuditErrorClassification(t *testing.T) {
	tests := []struct {
		name     string
		newWire  func() auditWire
		want     dkim2.ReplayErrorCode
		recovery recoveryClass
	}{
		{
			name: "malformed frame",
			newWire: func() auditWire {
				return &decoderFailureAuditWire{encoded: []byte("$5\r\nabc\r\n")}
			},
			want:     dkim2.ReplayErrorInconsistent,
			recovery: recoveryRestart,
		},
		{
			name: "round trip invariant",
			newWire: func() auditWire {
				return &classifiedFailureAuditWire{
					err: dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
				}
			},
			want:     dkim2.ReplayErrorInternalInvariant,
			recovery: recoveryRestart,
		},
		{
			name: "transport unavailable",
			newWire: func() auditWire {
				return &classifiedFailureAuditWire{
					err: dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
				}
			},
			want:     dkim2.ReplayErrorUnavailable,
			recovery: recoveryRevalidation,
		},
		{
			name: "impossible raw wire error",
			newWire: func() auditWire {
				return &classifiedFailureAuditWire{err: errors.New("synthetic impossible wire error")}
			},
			want:     dkim2.ReplayErrorInternalInvariant,
			recovery: recoveryRestart,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name+"/construction", func(t *testing.T) {
			wire := testCase.newWire()
			dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
				mode: valkeygo.ClientModeStandalone,
			})
			dependencies.newAuditWire = publishingAuditFactory(wire, nil)
			store, err := newProductionStoreWithDependencies(
				context.Background(),
				validClientConfig(t),
				mustOperatorAttestation(t),
				validAuditorConfig(),
				dependencies,
			)
			if store != nil || dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("store=%v code=%q want=%q",
					store, dkim2.ReplayErrorCodeOf(err), testCase.want)
			}
			if auditWireCloseCalls(wire) != 1 {
				t.Fatalf("close calls=%d", auditWireCloseCalls(wire))
			}
		})

		t.Run(testCase.name+"/runtime", func(t *testing.T) {
			client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			store := mustProductionStore(t, validProductionDependencies(t, client))
			wire := testCase.newWire()
			store.auditWireFactory = publishingAuditFactory(wire, nil)
			err := store.Revalidate(context.Background(), validAuditorConfig())
			if dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("code=%q want=%q", dkim2.ReplayErrorCodeOf(err), testCase.want)
			}
			if store.strongestRecovery() != testCase.recovery ||
				store.State() != dkim2.ReplayStoreDegraded {
				t.Fatalf("recovery=%d state=%q", store.strongestRecovery(), store.State())
			}
			if auditWireCloseCalls(wire) != 1 {
				t.Fatalf("close calls=%d", auditWireCloseCalls(wire))
			}
			if err := store.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestProductionAuditCallerAndOwnedDeadlinePrecedence freezes control-flow ordering.
func TestProductionAuditCallerAndOwnedDeadlinePrecedence(t *testing.T) {
	t.Run("round trip invariant precedes caller", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		wire := &classifiedFailureAuditWire{
			err:         dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
			onRoundTrip: cancel,
		}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = publishingAuditFactory(wire, nil)
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
			t.Fatalf("store=%v code=%q", store, dkim2.ReplayErrorCodeOf(err))
		}
	})

	t.Run("round trip invariant precedes owned global expiry", func(t *testing.T) {
		validated, err := validateClientConfig(validClientConfig(t))
		if err != nil {
			t.Fatal(err)
		}
		defer validated.clearPassword()
		wire := &deadlineAuditWire{}
		completed, err := acquireAndRunSecurityAuditWithBudget(
			context.Background(),
			publishingAuditFactory(wire, nil),
			validated.auditAuthority(),
			validAuditCredentials(),
			validSecurityAuditPolicy(),
			auditPhaseConstruction,
			fixedSecurityClock{now: time.Unix(10_000, 0)},
			time.Millisecond,
		)
		if !completed.IsZero() ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
			t.Fatalf("completed=%v code=%q", completed, dkim2.ReplayErrorCodeOf(err))
		}
	})
}

// TestProductionAuditCloseBarrierPrecedence freezes terminal state observed during cleanup.
func TestProductionAuditCloseBarrierPrecedence(t *testing.T) {
	tests := []struct {
		name       string
		primary    string
		wantCaller dkim2.ReplayErrorCode
		wantGlobal dkim2.ReplayErrorCode
	}{
		{
			name:       "internal invariant",
			primary:    testPrimaryInternal,
			wantCaller: dkim2.ReplayErrorInternalInvariant,
			wantGlobal: dkim2.ReplayErrorInternalInvariant,
		},
		{
			name:       testPrimaryMalformed,
			primary:    testPrimaryMalformed,
			wantCaller: dkim2.ReplayErrorCancelled,
			wantGlobal: dkim2.ReplayErrorUnavailable,
		},
		{
			name:       "policy mismatch",
			primary:    testPrimaryMismatch,
			wantCaller: dkim2.ReplayErrorCancelled,
			wantGlobal: dkim2.ReplayErrorUnavailable,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name+"/caller", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			wire := newAuditCloseBarrierWire(testCase.primary, cancel, false)
			dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
				mode: valkeygo.ClientModeStandalone,
			})
			dependencies.newAuditWire = publishingAuditFactory(wire, nil)
			store, err := newProductionStoreWithDependencies(
				ctx,
				validClientConfig(t),
				mustOperatorAttestation(t),
				validAuditorConfig(),
				dependencies,
			)
			if store != nil || dkim2.ReplayErrorCodeOf(err) != testCase.wantCaller {
				t.Fatalf("store=%v code=%q want=%q",
					store, dkim2.ReplayErrorCodeOf(err), testCase.wantCaller)
			}
		})

		t.Run(testCase.name+"/global", func(t *testing.T) {
			validated, err := validateClientConfig(validClientConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			defer validated.clearPassword()
			var wire auditWire
			factory := func(
				ctx context.Context,
				_ auditAuthority,
				publish func(auditWire),
			) error {
				wire = newAuditCloseBarrierWire(testCase.primary, func() {
					<-ctx.Done()
				}, false)
				publish(wire)
				return nil
			}
			completed, err := acquireAndRunSecurityAuditWithBudget(
				context.Background(),
				factory,
				validated.auditAuthority(),
				validAuditCredentials(),
				validSecurityAuditPolicy(),
				auditPhaseConstruction,
				fixedSecurityClock{now: time.Unix(10_000, 0)},
				time.Millisecond,
			)
			if !completed.IsZero() ||
				dkim2.ReplayErrorCodeOf(err) != testCase.wantGlobal {
				t.Fatalf("completed=%v code=%q want=%q",
					completed, dkim2.ReplayErrorCodeOf(err), testCase.wantGlobal)
			}
		})
	}
}

// TestProductionAuditClosePanicDominatesEveryPrimaryClass freezes cleanup capability failure.
func TestProductionAuditClosePanicDominatesEveryPrimaryClass(t *testing.T) {
	for _, primary := range []string{
		"success",
		testPrimaryTransport,
		testPrimaryMismatch,
		testPrimaryMalformed,
		testPrimaryInternal,
	} {
		t.Run(primary, func(t *testing.T) {
			validated, err := validateClientConfig(validClientConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			defer validated.clearPassword()
			completed, err := acquireAndRunSecurityAuditWithBudget(
				context.Background(),
				publishingAuditFactory(newAuditCloseBarrierWire(primary, nil, true), nil),
				validated.auditAuthority(),
				validAuditCredentials(),
				validSecurityAuditPolicy(),
				auditPhaseConstruction,
				fixedSecurityClock{now: time.Unix(10_000, 0)},
				time.Second,
			)
			if !completed.IsZero() ||
				dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
				t.Fatalf("completed=%v code=%q", completed, dkim2.ReplayErrorCodeOf(err))
			}
		})
	}
}

// TestBoundedFactoryErrorClassification freezes the closed acquisition error seam.
func TestBoundedFactoryErrorClassification(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want dkim2.ReplayErrorCode
	}{
		{
			name: "caller first",
			ctx:  cancelledContext,
			err:  dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
			want: dkim2.ReplayErrorCancelled,
		},
		{
			name: "typed internal invariant",
			ctx:  context.Background(),
			err:  dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
			want: dkim2.ReplayErrorInternalInvariant,
		},
		{
			name: "typed unavailable",
			ctx:  context.Background(),
			err:  dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
			want: dkim2.ReplayErrorUnavailable,
		},
		{
			name: "ordinary raw acquisition failure",
			ctx:  context.Background(),
			err:  errors.New("synthetic ordinary acquisition failure"),
			want: dkim2.ReplayErrorUnavailable,
		},
		{
			name: "impossible typed class",
			ctx:  context.Background(),
			err:  dkim2.NewReplayError(dkim2.ReplayErrorInconsistent),
			want: dkim2.ReplayErrorInternalInvariant,
		},
		{
			name: "nil failure",
			ctx:  context.Background(),
			err:  nil,
			want: dkim2.ReplayErrorInternalInvariant,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := dkim2.ReplayErrorCodeOf(boundedFactoryError(testCase.ctx, testCase.err)); got != testCase.want {
				t.Fatalf("code=%q want=%q", got, testCase.want)
			}
		})
	}
}

// TestProductionFactoryPreservesPrimaryAndCleanupPrecedence proves partial ownership fails closed.
func TestProductionFactoryPreservesPrimaryAndCleanupPrecedence(t *testing.T) {
	t.Run("audit typed internal without partial wire", func(t *testing.T) {
		var applicationCalls atomic.Int32
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			context.Context,
			auditAuthority,
			func(auditWire),
		) error {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		dependencies.newApplication = func(
			valkeygo.ClientOption,
			func(ownedApplicationClient),
		) error {
			applicationCalls.Add(1)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			applicationCalls.Load() != 0 {
			t.Fatalf("store=%v code=%q application=%d",
				store, dkim2.ReplayErrorCodeOf(err), applicationCalls.Load())
		}
	})

	t.Run("application typed internal without partial client", func(t *testing.T) {
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newApplication = func(
			valkeygo.ClientOption,
			func(ownedApplicationClient),
		) error {
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
			t.Fatalf("store=%v code=%q", store, dkim2.ReplayErrorCodeOf(err))
		}
	})

	t.Run("audit typed internal survives ordinary close error", func(t *testing.T) {
		wire := &classifiedFailureAuditWire{closeErr: errors.New("synthetic close failure")}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = publishingAuditFactory(
			wire,
			dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
		)
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			wire.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), wire.closeCalls.Load())
		}
	})

	t.Run("audit caller survives ordinary close error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		wire := &classifiedFailureAuditWire{closeErr: errors.New("synthetic close failure")}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(wire)
			cancel()
			return errors.New("synthetic acquisition failure")
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
			wire.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), wire.closeCalls.Load())
		}
	})

	t.Run("audit cleanup panic dominates caller", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		wire := &classifiedFailureAuditWire{closePanic: true}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(wire)
			cancel()
			return errors.New("synthetic acquisition failure")
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			wire.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), wire.closeCalls.Load())
		}
	})

	t.Run("application typed internal survives cleanup", func(t *testing.T) {
		client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		dependencies := validProductionDependencies(t, client)
		dependencies.newApplication = func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(client)
			return dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})

	t.Run("application caller survives cleanup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		dependencies := validProductionDependencies(t, client)
		dependencies.newApplication = func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(client)
			cancel()
			return errors.New("synthetic acquisition failure")
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})
}

// TestFactoriesCleanOwnershipPublishedBeforePanic proves callback-time acquisition cannot leak.
func TestFactoriesCleanOwnershipPublishedBeforePanic(t *testing.T) {
	t.Run("audit wire", func(t *testing.T) {
		wire := &fakeAuditWire{}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(wire)
			panic("synthetic factory panic")
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		_, _, closeCalls := wire.snapshot()
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			closeCalls != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), closeCalls)
		}
	})

	t.Run("application client", func(t *testing.T) {
		client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		dependencies := validProductionDependencies(t, client)
		dependencies.newApplication = func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(client)
			panic("synthetic factory panic")
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})
}

// TestFactoriesCleanEveryDuplicatePublication proves hostile seams cannot leak ownership.
func TestFactoriesCleanEveryDuplicatePublication(t *testing.T) {
	t.Run("audit wires", func(t *testing.T) {
		first := &fakeAuditWire{}
		second := &fakeAuditWire{closePanic: true}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(first)
			publish(second)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		_, _, firstClose := first.snapshot()
		_, _, secondClose := second.snapshot()
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			firstClose != 1 || secondClose != 1 {
			t.Fatalf("store=%v code=%q closes=%d/%d",
				store, dkim2.ReplayErrorCodeOf(err), firstClose, secondClose)
		}
	})

	t.Run("application clients", func(t *testing.T) {
		first := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		second := &fakeOwnedApplicationClient{
			mode:       valkeygo.ClientModeStandalone,
			closePanic: true,
		}
		dependencies := validProductionDependencies(t, first)
		dependencies.newApplication = func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(first)
			publish(second)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			first.closeCalls.Load() != 1 || second.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q closes=%d/%d",
				store, dkim2.ReplayErrorCodeOf(err),
				first.closeCalls.Load(), second.closeCalls.Load())
		}
	})

	t.Run("same audit wire", func(t *testing.T) {
		wire := &fakeAuditWire{}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(wire)
			publish(wire)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		_, _, closeCalls := wire.snapshot()
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			closeCalls != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), closeCalls)
		}
	})

	t.Run("same application client", func(t *testing.T) {
		client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		dependencies := validProductionDependencies(t, client)
		dependencies.newApplication = func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(client)
			publish(client)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})
}

// TestFactoryNilSuccessIsMisconfigured proves invalid injected dependencies fail closed.
func TestFactoryNilSuccessIsMisconfigured(t *testing.T) {
	dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
		mode: valkeygo.ClientModeStandalone,
	})
	dependencies.newApplication = func(
		_ valkeygo.ClientOption,
		publish func(ownedApplicationClient),
	) error {
		var client *fakeOwnedApplicationClient
		publish(client)
		return nil
	}
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		validClientConfig(t),
		mustOperatorAttestation(t),
		validAuditorConfig(),
		dependencies,
	)
	if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
		t.Fatalf("store=%v code=%q", store, dkim2.ReplayErrorCodeOf(err))
	}
}

// TestFactoriesRejectAmbiguousValueOwnershipHandles proves identity is unambiguous.
func TestFactoriesRejectAmbiguousValueOwnershipHandles(t *testing.T) {
	t.Run("audit wire value", func(t *testing.T) {
		var closeCalls atomic.Int32
		wire := comparableAuditWire{closeCalls: &closeCalls}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newAuditWire = func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(wire)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), closeCalls.Load())
		}
	})

	t.Run("application client value", func(t *testing.T) {
		var closeCalls atomic.Int32
		client := comparableOwnedApplicationClient{closeCalls: &closeCalls}
		dependencies := validProductionDependencies(t, &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
		})
		dependencies.newApplication = func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(client)
			return nil
		}
		store, err := newProductionStoreWithDependencies(
			context.Background(),
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), closeCalls.Load())
		}
	})
}

// TestProductionFactoryCleansEveryPartialApplicationClient covers error, mode, context, and panic paths.
func TestProductionFactoryCleansEveryPartialApplicationClient(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*fakeOwnedApplicationClient, *context.CancelFunc)
		factoryErr error
		want       dkim2.ReplayErrorCode
	}{
		{name: "client plus error", factoryErr: errors.New("synthetic factory"), want: dkim2.ReplayErrorUnavailable},
		{name: "wrong mode", configure: func(client *fakeOwnedApplicationClient, _ *context.CancelFunc) {
			client.mode = valkeygo.ClientModeCluster
		}, want: dkim2.ReplayErrorMisconfigured},
		{name: "mode panic", configure: func(client *fakeOwnedApplicationClient, _ *context.CancelFunc) {
			client.modePanic = true
		}, want: dkim2.ReplayErrorInternalInvariant},
		{name: "post-return cancellation", configure: func(_ *fakeOwnedApplicationClient, cancel *context.CancelFunc) {
			(*cancel)()
		}, want: dkim2.ReplayErrorCancelled},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			dependencies := validProductionDependencies(t, client)
			dependencies.newApplication = func(
				_ valkeygo.ClientOption,
				publish func(ownedApplicationClient),
			) error {
				if testCase.configure != nil {
					testCase.configure(client, &cancel)
				}
				publish(client)
				return testCase.factoryErr
			}
			store, err := newProductionStoreWithDependencies(
				ctx,
				validClientConfig(t),
				mustOperatorAttestation(t),
				validAuditorConfig(),
				dependencies,
			)
			if store != nil || dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("store=%v code=%q", store, dkim2.ReplayErrorCodeOf(err))
			}
			if client.closeCalls.Load() != 1 {
				t.Fatalf("close calls=%d", client.closeCalls.Load())
			}
		})
	}
}

// TestProductionFactoryRechecksCallerAfterModeAndClock proves final construction barriers.
func TestProductionFactoryRechecksCallerAfterModeAndClock(t *testing.T) {
	t.Run("cancellation during mode", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := &fakeOwnedApplicationClient{
			mode:     valkeygo.ClientModeStandalone,
			modeHook: cancel,
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			validProductionDependencies(t, client),
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})

	t.Run("deadline during mode", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		client := &fakeOwnedApplicationClient{
			mode: valkeygo.ClientModeStandalone,
			modeHook: func() {
				<-ctx.Done()
			},
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			validProductionDependencies(t, client),
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorDeadlineExceeded ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})

	t.Run("cancellation during final clock sample", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		dependencies := validProductionDependencies(t, client)
		dependencies.clock = &hookSecurityClock{
			now: time.Unix(10_000, 0),
			hook: func(call int32) {
				if call == 2 {
					cancel()
				}
			},
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})

	t.Run("deadline during final clock sample", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
		dependencies := validProductionDependencies(t, client)
		dependencies.clock = &hookSecurityClock{
			now: time.Unix(10_000, 0),
			hook: func(call int32) {
				if call == 2 {
					<-ctx.Done()
				}
			},
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorDeadlineExceeded ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})
}

// TestProductionFactoryFinalBarrierPreservesInternalCleanupPrecedence freezes dominance.
func TestProductionFactoryFinalBarrierPreservesInternalCleanupPrecedence(t *testing.T) {
	t.Run("mode panic dominates cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := &fakeOwnedApplicationClient{
			modePanic: true,
			modeHook:  cancel,
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			validProductionDependencies(t, client),
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})

	t.Run("cleanup panic dominates final cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client := &fakeOwnedApplicationClient{
			mode:       valkeygo.ClientModeStandalone,
			closePanic: true,
		}
		dependencies := validProductionDependencies(t, client)
		dependencies.clock = &hookSecurityClock{
			now: time.Unix(10_000, 0),
			hook: func(call int32) {
				if call == 2 {
					cancel()
				}
			},
		}
		store, err := newProductionStoreWithDependencies(
			ctx,
			validClientConfig(t),
			mustOperatorAttestation(t),
			validAuditorConfig(),
			dependencies,
		)
		if store != nil ||
			dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant ||
			client.closeCalls.Load() != 1 {
			t.Fatalf("store=%v code=%q close=%d",
				store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
		}
	})
}

// TestProductionFactoryCleanupPanicDominatesPrimaryFailure freezes cleanup precedence.
func TestProductionFactoryCleanupPanicDominatesPrimaryFailure(t *testing.T) {
	client := &fakeOwnedApplicationClient{
		mode:       valkeygo.ClientModeStandalone,
		closePanic: true,
	}
	dependencies := validProductionDependencies(t, client)
	dependencies.newApplication = func(
		_ valkeygo.ClientOption,
		publish func(ownedApplicationClient),
	) error {
		publish(client)
		return errors.New("synthetic primary")
	}
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		validClientConfig(t),
		mustOperatorAttestation(t),
		validAuditorConfig(),
		dependencies,
	)
	if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("store=%v code=%q", store, dkim2.ReplayErrorCodeOf(err))
	}
}

// TestEvidenceStaleBeforeAdmissionDispatchesNoSET proves exact fail-closed freshness order.
func TestEvidenceStaleBeforeAdmissionDispatchesNoSET(t *testing.T) {
	clock := &mutableSecurityClock{now: time.Unix(10_000, 0)}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	commandClient := &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
	}
	store.client = commandClient
	clock.set(time.Unix(10_000, 0).Add(securityEvidenceValidity))
	if _, err := store.CheckAndRemember(
		context.Background(),
		validReplayKey(t),
		dkim2.DefaultReplayRetention(),
	); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("stale code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if builds, dispatches := commandClient.counts(); builds != 0 || dispatches != 0 {
		t.Fatalf("stale evidence command counts = (%d,%d), want zero", builds, dispatches)
	}
	if store.strongestRecovery() != recoveryRevalidation {
		t.Fatal("stale evidence did not publish revalidation fact")
	}
}

// TestStaleEvidencePrecedesCommandCapacity proves security before backend admission.
func TestStaleEvidencePrecedesCommandCapacity(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &mutableSecurityClock{now: start}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	store.gate = newAdmissionGate(1, 1)
	finish, err := store.gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer finish()
	commandClient := &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
	}
	store.client = commandClient
	clock.set(start.Add(securityEvidenceValidity))

	if _, err = store.CheckAndRemember(
		context.Background(),
		validReplayKey(t),
		dkim2.DefaultReplayRetention(),
	); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("stale command-capacity code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if builds, dispatches := commandClient.counts(); builds != 0 || dispatches != 0 {
		t.Fatalf("stale command-capacity counts = (%d,%d), want zero", builds, dispatches)
	}
}

// TestClosedStorePrecedesInvalidRequest proves terminal lifecycle ordering.
func TestClosedStorePrecedesInvalidRequest(t *testing.T) {
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store := mustProductionStore(t, validProductionDependencies(t, client))
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CheckAndRemember(
		context.Background(),
		dkim2.ReplayKey{},
		dkim2.ReplayRetention{},
	); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatalf("closed invalid-request code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.CheckAndRemember(
		cancelled,
		dkim2.ReplayKey{},
		dkim2.ReplayRetention{},
	); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("closed cancelled code=%q", dkim2.ReplayErrorCodeOf(err))
	}
}

// TestEvidenceExpiringDuringAdmissionWaitDispatchesNoSET proves exact post-wait freshness.
func TestEvidenceExpiringDuringAdmissionWaitDispatchesNoSET(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &mutableSecurityClock{now: start}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	store.gate = newAdmissionGate(1, 1)
	blockingFinish, err := store.gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	commandClient := &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
	}
	store.client = commandClient
	result := make(chan error, 1)
	go func() {
		_, checkErr := store.CheckAndRemember(
			context.Background(),
			validReplayKey(t),
			dkim2.DefaultReplayRetention(),
		)
		result <- checkErr
	}()
	deadline := time.Now().Add(time.Second)
	for store.gate.waiters.Load() != 1 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if store.gate.waiters.Load() != 1 {
		t.Fatal("check did not reach the bounded admission wait")
	}
	clock.set(start.Add(securityEvidenceValidity))
	blockingFinish()
	if resultErr := <-result; dkim2.ReplayErrorCodeOf(resultErr) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("code=%q", dkim2.ReplayErrorCodeOf(resultErr))
	}
	if _, dispatches := commandClient.counts(); dispatches != 0 ||
		store.strongestRecovery() != recoveryRevalidation {
		t.Fatalf("dispatches=%d recovery=%d", dispatches, store.strongestRecovery())
	}
}

// TestConstructionAnchorsEvidenceToAuditCompletion proves client setup cannot extend trust.
func TestConstructionAnchorsEvidenceToAuditCompletion(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &mutableSecurityClock{now: start}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	dependencies.newApplication = func(
		_ valkeygo.ClientOption,
		publish func(ownedApplicationClient),
	) error {
		publish(client)
		clock.set(start.Add(securityEvidenceValidity))
		return nil
	}
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		validClientConfig(t),
		mustOperatorAttestation(t),
		validAuditorConfig(),
		dependencies,
	)
	if store != nil || dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable ||
		client.closeCalls.Load() != 1 {
		t.Fatalf("store=%v code=%q close=%d",
			store, dkim2.ReplayErrorCodeOf(err), client.closeCalls.Load())
	}
}

// TestRevalidateRechecksCallerAtFinalClockBoundary prevents terminal evidence publication.
func TestRevalidateRechecksCallerAtFinalClockBoundary(t *testing.T) {
	tests := []struct {
		name      string
		newCaller func() (context.Context, context.CancelFunc)
		hook      func(context.Context, context.CancelFunc)
		want      dkim2.ReplayErrorCode
	}{
		{
			name: "cancellation",
			newCaller: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			hook: func(_ context.Context, cancel context.CancelFunc) {
				cancel()
			},
			want: dkim2.ReplayErrorCancelled,
		},
		{
			name: "deadline",
			newCaller: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 250*time.Millisecond)
			},
			hook: func(ctx context.Context, _ context.CancelFunc) {
				<-ctx.Done()
			},
			want: dkim2.ReplayErrorDeadlineExceeded,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			store := mustProductionStore(t, validProductionDependencies(t, client))
			initialDeadline := store.evidence.deadlineSnapshot()
			ctx, cancel := testCase.newCaller()
			defer cancel()
			store.clock = newSerializedSecurityClock(&hookSecurityClock{
				now: time.Unix(10_060, 0),
				hook: func(call int32) {
					if call == 2 {
						testCase.hook(ctx, cancel)
					}
				},
			})
			err := store.Revalidate(ctx, validAuditorConfig())
			if dkim2.ReplayErrorCodeOf(err) != testCase.want {
				t.Fatalf("code=%q want=%q", dkim2.ReplayErrorCodeOf(err), testCase.want)
			}
			if store.evidence.deadlineSnapshot() != initialDeadline ||
				store.State() != dkim2.ReplayStoreReady ||
				store.facts.load() != 0 {
				t.Fatalf("deadline=%v state=%q facts=%d",
					store.evidence.deadlineSnapshot(), store.State(), store.facts.load())
			}
			if err := store.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestRevalidateFinalClockPreservesClosePrecedence prevents evidence publication while closing.
func TestRevalidateFinalClockPreservesClosePrecedence(t *testing.T) {
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store := mustProductionStore(t, validProductionDependencies(t, client))
	initialDeadline := store.evidence.deadlineSnapshot()
	closeResult := make(chan error, 1)
	store.clock = newSerializedSecurityClock(&hookSecurityClock{
		now: time.Unix(10_060, 0),
		hook: func(call int32) {
			if call != 2 {
				return
			}
			go func() {
				closeResult <- store.Close(context.Background())
			}()
			deadline := time.Now().Add(time.Second)
			for store.State() != dkim2.ReplayStoreClosing && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if store.State() != dkim2.ReplayStoreClosing {
				t.Fatal("close did not publish terminal state at final clock barrier")
			}
		},
	})
	if err := store.Revalidate(context.Background(), validAuditorConfig()); err != nil {
		t.Fatal(err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
	if store.evidence.deadlineSnapshot() != initialDeadline ||
		store.State() != dkim2.ReplayStoreClosed ||
		client.closeCalls.Load() != 1 {
		t.Fatalf("deadline=%v state=%q close=%d",
			store.evidence.deadlineSnapshot(), store.State(), client.closeCalls.Load())
	}
}

// TestRevalidateBlockingCallerCheckDoesNotHoldLifecycleLock keeps capabilities outside gate.mu.
func TestRevalidateBlockingCallerCheckDoesNotHoldLifecycleLock(t *testing.T) {
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store := mustProductionStore(t, validProductionDependencies(t, client))
	ctx := newArmableBlockingContext(context.Background())
	store.clock = newSerializedSecurityClock(&hookSecurityClock{
		now: time.Unix(10_060, 0),
		hook: func(call int32) {
			if call == 2 {
				ctx.arm()
			}
		},
	})
	revalidation := make(chan error, 1)
	go func() {
		revalidation <- store.Revalidate(ctx, validAuditorConfig())
	}()
	<-ctx.started

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- store.Close(context.Background())
	}()
	deadline := time.Now().Add(time.Second)
	for store.State() != dkim2.ReplayStoreClosing && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if store.State() != dkim2.ReplayStoreClosing {
		t.Fatal("blocking caller Err held the lifecycle lock")
	}
	close(ctx.release)
	if err := <-revalidation; err != nil {
		t.Fatal(err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
	if store.State() != dkim2.ReplayStoreClosed || client.closeCalls.Load() != 1 {
		t.Fatalf("state=%q close=%d", store.State(), client.closeCalls.Load())
	}
}

// TestRevalidationCompletionDuringCloseDiscardsEvidence proves terminal publication wins.
func TestRevalidationCompletionDuringCloseDiscardsEvidence(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &mutableSecurityClock{now: start}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	store.publishFailure(recoveryRevalidation)
	originalDeadline := store.evidence.deadlineSnapshot()
	blocking := &blockingAuditWire{
		fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	store.auditWireFactory = func(
		_ context.Context,
		_ auditAuthority,
		publish func(auditWire),
	) error {
		publish(blocking)
		return nil
	}
	revalidation := make(chan error, 1)
	go func() {
		revalidation <- store.Revalidate(context.Background(), validAuditorConfig())
	}()
	<-blocking.started
	closing := make(chan error, 1)
	go func() {
		closing <- store.Close(context.Background())
	}()
	deadline := time.Now().Add(time.Second)
	for store.State() != dkim2.ReplayStoreClosing && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if store.State() != dkim2.ReplayStoreClosing {
		t.Fatal("close did not publish terminal precedence")
	}
	clock.set(start.Add(time.Minute))
	close(blocking.release)
	if err := <-revalidation; err != nil {
		t.Fatalf("revalidation during close: %v", err)
	}
	if err := <-closing; err != nil {
		t.Fatalf("close: %v", err)
	}
	if store.evidence.deadlineSnapshot() != originalDeadline ||
		!store.facts.has(recoveryRevalidation) {
		t.Fatal("closing revalidation published refreshed evidence")
	}
}

// TestRevalidationKeepsNewerDriftFact proves conditional recovery publication.
func TestRevalidationKeepsNewerDriftFact(t *testing.T) {
	clock := newSelectiveBlockingClock(4)
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	store.publishFailure(recoveryRevalidation)
	revalidation := make(chan error, 1)
	go func() {
		revalidation <- store.Revalidate(context.Background(), validAuditorConfig())
	}()
	<-clock.started
	store.publishFailure(recoveryRevalidation)
	close(clock.release)
	if err := <-revalidation; err != nil {
		t.Fatal(err)
	}
	if !store.facts.has(recoveryRevalidation) {
		t.Fatal("revalidation cleared a newer drift fact")
	}
}

// TestRevalidationClearsConcurrentStaleEvidence proves freshness has no lost-heal race.
func TestRevalidationClearsConcurrentStaleEvidence(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &mutableSecurityClock{now: start}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	blocking := &blockingAuditWire{
		fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	store.auditWireFactory = func(
		_ context.Context,
		_ auditAuthority,
		publish func(auditWire),
	) error {
		publish(blocking)
		return nil
	}
	clock.set(start.Add(securityEvidenceValidity))
	revalidation := make(chan error, 1)
	go func() {
		revalidation <- store.Revalidate(context.Background(), validAuditorConfig())
	}()
	<-blocking.started
	store.client = &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
	}
	if _, err := store.CheckAndRemember(
		context.Background(),
		validReplayKey(t),
		dkim2.DefaultReplayRetention(),
	); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("stale check code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	close(blocking.release)
	if err := <-revalidation; err != nil {
		t.Fatal(err)
	}
	if store.State() != dkim2.ReplayStoreReady ||
		store.facts.load()&recoveryStaleEvidenceBit != 0 {
		t.Fatal("successful revalidation did not heal concurrent stale evidence")
	}
}

// TestRevalidationExpiredAuditEvidenceRemainsRevalidationClearable covers delayed publication.
func TestRevalidationExpiredAuditEvidenceRemainsRevalidationClearable(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &sequenceSecurityClock{values: []time.Time{
		start,
		start,
		start.Add(time.Minute),
		start.Add(time.Minute).Add(securityEvidenceValidity),
		start.Add(7 * time.Minute),
		start.Add(7 * time.Minute),
	}}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)

	err := store.Revalidate(context.Background(), validAuditorConfig())
	if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorUnavailable {
		t.Fatalf("expired audit code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if store.strongestRecovery() != recoveryRevalidation ||
		store.State() != dkim2.ReplayStoreDegraded {
		t.Fatalf("recovery=%d state=%q", store.strongestRecovery(), store.State())
	}

	if err := store.Revalidate(context.Background(), validAuditorConfig()); err != nil {
		t.Fatalf("later live audit did not heal stale evidence: %v", err)
	}
	if store.strongestRecovery() != recoveryNone ||
		store.State() != dkim2.ReplayStoreReady {
		t.Fatalf("healed recovery=%d state=%q", store.strongestRecovery(), store.State())
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestRevalidationAuditCompletionRollbackIsRestartSticky covers every clock sample.
func TestRevalidationAuditCompletionRollbackIsRestartSticky(t *testing.T) {
	start := time.Unix(10_000, 0)
	clock := &sequenceSecurityClock{values: []time.Time{
		start,
		start,
		start.Add(-time.Nanosecond),
	}}
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	initialDeadline := store.evidence.deadlineSnapshot()

	err := store.Revalidate(context.Background(), validAuditorConfig())
	if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("rollback code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if store.strongestRecovery() != recoveryRestart ||
		store.State() != dkim2.ReplayStoreDegraded ||
		store.evidence.deadlineSnapshot() != initialDeadline {
		t.Fatalf("recovery=%d state=%q", store.strongestRecovery(), store.State())
	}
	if clock.calls != len(clock.values) {
		t.Fatalf("clock calls=%d want=%d", clock.calls, len(clock.values))
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestBlockedRevalidationClockDoesNotBlockContextAwareClose proves lock isolation.
func TestBlockedRevalidationClockDoesNotBlockContextAwareClose(t *testing.T) {
	clock := newSelectiveBlockingClock(4)
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)
	revalidation := make(chan error, 1)
	go func() {
		revalidation <- store.Revalidate(context.Background(), validAuditorConfig())
	}()
	<-clock.started
	ctx, cancel := context.WithCancel(context.Background())
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- store.Close(ctx)
	}()
	deadline := time.Now().Add(time.Second)
	for store.State() != dkim2.ReplayStoreClosing && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if store.State() != dkim2.ReplayStoreClosing {
		t.Fatal("close could not publish closing while the clock was blocked")
	}
	cancel()
	if err := <-closeResult; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
		t.Fatalf("close code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	close(clock.release)
	if err := <-revalidation; err != nil {
		t.Fatal(err)
	}
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestCheckPausedBeforeAdmissionCannotRaceClosedClientOwnership proves drain ordering.
func TestCheckPausedBeforeAdmissionCannotRaceClosedClientOwnership(t *testing.T) {
	clock := newSelectiveBlockingClock(3)
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	dependencies.clock = clock
	store := mustProductionStore(t, dependencies)

	checkResult := make(chan error, 1)
	go func() {
		_, err := store.CheckAndRemember(
			context.Background(),
			validReplayKey(t),
			dkim2.DefaultReplayRetention(),
		)
		checkResult <- err
	}()
	<-clock.started
	if err := store.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(clock.release)
	if err := <-checkResult; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatalf("check code=%q want=%q", dkim2.ReplayErrorCodeOf(err), dkim2.ReplayErrorClosed)
	}
	if store.State() != dkim2.ReplayStoreClosed ||
		store.client != nil ||
		store.ownedClient != nil ||
		client.closeCalls.Load() != 1 {
		t.Fatalf("state=%q close=%d", store.State(), client.closeCalls.Load())
	}
}

// TestRevalidateIsExclusiveAndClearsOnlyRevalidationFact covers managed recovery.
func TestRevalidateIsExclusiveAndClearsOnlyRevalidationFact(t *testing.T) {
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	dependencies := validProductionDependencies(t, client)
	store := mustProductionStore(t, dependencies)
	store.publishFailure(recoveryRevalidation)
	store.publishFailure(recoveryRestart)

	blocking := &blockingAuditWire{
		fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	store.auditWireFactory = func(
		_ context.Context,
		_ auditAuthority,
		publish func(auditWire),
	) error {
		publish(blocking)
		return nil
	}
	result := make(chan error, 1)
	go func() { result <- store.Revalidate(context.Background(), validAuditorConfig()) }()
	<-blocking.started
	if err := store.Revalidate(context.Background(), validAuditorConfig()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded {
		t.Fatalf("concurrent code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	close(blocking.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if store.facts.has(recoveryRevalidation) || !store.facts.has(recoveryRestart) ||
		store.State() != dkim2.ReplayStoreDegraded {
		t.Fatal("revalidation cleared the wrong recovery facts")
	}
}

// TestRevalidationTokenRefusalLeavesPublishedStateUnchanged covers both states.
func TestRevalidationTokenRefusalLeavesPublishedStateUnchanged(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(map[bool]string{false: testStateReady, true: testStateDegraded}[degraded], func(t *testing.T) {
			client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			store := mustProductionStore(t, validProductionDependencies(t, client))
			if degraded {
				store.publishFailure(recoveryRestart)
			}
			initialState := store.State()
			blocking := &blockingAuditWire{
				fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
				started:       make(chan struct{}),
				release:       make(chan struct{}),
			}
			store.auditWireFactory = func(
				_ context.Context,
				_ auditAuthority,
				publish func(auditWire),
			) error {
				publish(blocking)
				return nil
			}
			first := make(chan error, 1)
			go func() {
				first <- store.Revalidate(context.Background(), validAuditorConfig())
			}()
			<-blocking.started
			err := store.Revalidate(context.Background(), validAuditorConfig())
			if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded ||
				store.State() != initialState {
				t.Fatalf("code=%q state=%q want=%q",
					dkim2.ReplayErrorCodeOf(err), store.State(), initialState)
			}
			close(blocking.release)
			if err := <-first; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestCheckAdmissionCapRefusalLeavesPublishedStateUnchanged covers both states.
func TestCheckAdmissionCapRefusalLeavesPublishedStateUnchanged(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(map[bool]string{false: testStateReady, true: testStateDegraded}[degraded], func(t *testing.T) {
			client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			store := mustProductionStore(t, validProductionDependencies(t, client))
			store.gate = newAdmissionGate(1, 1)
			if degraded {
				store.publishFailure(recoveryRestart)
			}
			initialState := store.State()
			commandSlot, err := store.gate.admit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			store.client = &fakeCommandClient{
				command: fakeCommand{},
				result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
			}
			waitContext, cancelWait := context.WithCancel(context.Background())
			first := make(chan error, 1)
			go func() {
				_, checkErr := store.CheckAndRemember(
					waitContext,
					validReplayKey(t),
					dkim2.DefaultReplayRetention(),
				)
				first <- checkErr
			}()
			waitAtomicCount(t, &store.gate.waiters, 1)
			_, err = store.CheckAndRemember(
				context.Background(),
				validReplayKey(t),
				dkim2.DefaultReplayRetention(),
			)
			if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded ||
				store.State() != initialState {
				t.Fatalf("code=%q state=%q want=%q",
					dkim2.ReplayErrorCodeOf(err), store.State(), initialState)
			}
			cancelWait()
			if err := <-first; dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorCancelled {
				t.Fatalf("waiting code=%q", dkim2.ReplayErrorCodeOf(err))
			}
			commandSlot()
		})
	}
}

// TestZeroCheckWaitersLeavesPublishedStateUnchanged covers ready and degraded.
func TestZeroCheckWaitersLeavesPublishedStateUnchanged(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		t.Run(map[bool]string{false: testStateReady, true: testStateDegraded}[degraded], func(t *testing.T) {
			client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			store := mustProductionStore(t, validProductionDependencies(t, client))
			store.gate = newAdmissionGate(1, 0)
			if degraded {
				store.publishFailure(recoveryRestart)
			}
			initialState := store.State()
			commandSlot, err := store.gate.admit(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer commandSlot()
			store.client = &fakeCommandClient{
				command: fakeCommand{},
				result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
			}
			_, err = store.CheckAndRemember(
				context.Background(),
				validReplayKey(t),
				dkim2.DefaultReplayRetention(),
			)
			if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorLimitExceeded ||
				store.State() != initialState || store.gate.waiters.Load() != 0 {
				t.Fatalf("code=%q state=%q waiters=%d",
					dkim2.ReplayErrorCodeOf(err), store.State(), store.gate.waiters.Load())
			}
		})
	}
}

// TestRevalidateSharesDrainButNotCommandSlots proves lifecycle-only admission.
func TestRevalidateSharesDrainButNotCommandSlots(t *testing.T) {
	client := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store := mustProductionStore(t, validProductionDependencies(t, client))
	store.gate = newAdmissionGate(1, 1)
	commandSlot, err := store.gate.admit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	blocking := &blockingAuditWire{
		fakeAuditWire: fakeAuditWire{replies: validAuditReplies()},
		started:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	store.auditWireFactory = func(
		_ context.Context,
		_ auditAuthority,
		publish func(auditWire),
	) error {
		publish(blocking)
		return nil
	}
	revalidation := make(chan error, 1)
	go func() {
		revalidation <- store.Revalidate(context.Background(), validAuditorConfig())
	}()
	select {
	case <-blocking.started:
	case <-time.After(time.Second):
		t.Fatal("revalidation consumed the occupied command slot")
	}
	commandSlot()
	store.client = &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
	}
	if check, err := store.CheckAndRemember(
		context.Background(),
		validReplayKey(t),
		dkim2.DefaultReplayRetention(),
	); err != nil || check != dkim2.ReplayCheckFirstSeen {
		t.Fatalf("check=%q code=%q", check, dkim2.ReplayErrorCodeOf(err))
	}
	close(blocking.release)
	if err := <-revalidation; err != nil {
		t.Fatal(err)
	}
}

// TestStoreCloseIsIdempotentAndTerminalDespiteClientPanic proves owned close behavior.
func TestStoreCloseIsIdempotentAndTerminalDespiteClientPanic(t *testing.T) {
	client := &fakeOwnedApplicationClient{
		mode:       valkeygo.ClientModeStandalone,
		closePanic: true,
	}
	store := mustProductionStore(t, validProductionDependencies(t, client))
	if err := store.Close(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("close code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if store.State() != dkim2.ReplayStoreClosed || client.closeCalls.Load() != 1 {
		t.Fatalf("state=%q close=%d", store.State(), client.closeCalls.Load())
	}
	if !nilInterface(store.ownedClient) || !nilInterface(store.client) {
		t.Fatal("closed store retained concrete client handles after cleanup panic")
	}
	if err := store.Close(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
		t.Fatalf("idempotent close code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if client.closeCalls.Load() != 1 ||
		!nilInterface(store.ownedClient) ||
		!nilInterface(store.client) {
		t.Fatalf(
			"repeated close=%d owned_nil=%t command_nil=%t",
			client.closeCalls.Load(),
			nilInterface(store.ownedClient),
			nilInterface(store.client),
		)
	}
}

// TestStoreCloseDrainsAdmittedCommand proves admitted work completes before ownership closes.
func TestStoreCloseDrainsAdmittedCommand(t *testing.T) {
	owned := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
	store := mustProductionStore(t, validProductionDependencies(t, owned))
	builderStarted := make(chan struct{})
	releaseBuilder := make(chan struct{})
	var startOnce sync.Once
	commandClient := &fakeCommandClient{
		command: fakeCommand{},
		result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
		onBuild: func() {
			startOnce.Do(func() { close(builderStarted) })
			<-releaseBuilder
		},
	}
	store.client = commandClient
	checkResult := make(chan error, 1)
	go func() {
		_, err := store.CheckAndRemember(
			context.Background(),
			validReplayKey(t),
			dkim2.DefaultReplayRetention(),
		)
		checkResult <- err
	}()
	<-builderStarted
	closeResult := make(chan error, 1)
	go func() {
		closeResult <- store.Close(context.Background())
	}()
	deadline := time.Now().Add(time.Second)
	for store.State() != dkim2.ReplayStoreClosing && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if store.State() != dkim2.ReplayStoreClosing || owned.closeCalls.Load() != 0 {
		t.Fatalf("state=%q close=%d", store.State(), owned.closeCalls.Load())
	}
	close(releaseBuilder)
	if err := <-checkResult; err != nil {
		t.Fatalf("admitted check code=%q", dkim2.ReplayErrorCodeOf(err))
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
	if owned.closeCalls.Load() != 1 {
		t.Fatalf("close=%d", owned.closeCalls.Load())
	}
	if !nilInterface(store.ownedClient) || !nilInterface(store.client) {
		t.Fatal("closed store retained concrete client handles after successful cleanup")
	}
	if _, dispatches := commandClient.counts(); dispatches != 1 {
		t.Fatalf("dispatches=%d", dispatches)
	}
}

// TestStoreCloseContainsHostileDoneCapability proves retryable closing after a caller panic.
func TestStoreCloseContainsHostileDoneCapability(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		terminal error
		errPanic bool
	}{
		{name: "no terminal state"},
		{name: syntheticCancelledName, terminal: context.Canceled},
		{name: syntheticDeadlineName, terminal: context.DeadlineExceeded},
		{name: "hostile err", errPanic: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			owned := &fakeOwnedApplicationClient{mode: valkeygo.ClientModeStandalone}
			store := mustProductionStore(t, validProductionDependencies(t, owned))
			builderStarted := make(chan struct{})
			releaseBuilder := make(chan struct{})
			var startOnce sync.Once
			store.client = &fakeCommandClient{
				command: fakeCommand{},
				result:  resultFromMessage(t, cachedMessage(t, '+', "OK")),
				onBuild: func() {
					startOnce.Do(func() { close(builderStarted) })
					<-releaseBuilder
				},
			}
			checkResult := make(chan error, 1)
			go func() {
				_, err := store.CheckAndRemember(
					context.Background(),
					validReplayKey(t),
					dkim2.DefaultReplayRetention(),
				)
				checkResult <- err
			}()
			<-builderStarted

			err := store.Close(&panicDoneContext{
				terminal: testCase.terminal,
				errPanic: testCase.errPanic,
			})
			if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorInternalInvariant {
				t.Fatalf("hostile close code=%q", dkim2.ReplayErrorCodeOf(err))
			}
			if store.State() != dkim2.ReplayStoreClosing || owned.closeCalls.Load() != 0 {
				t.Fatalf("state=%q close=%d", store.State(), owned.closeCalls.Load())
			}

			close(releaseBuilder)
			if err := <-checkResult; err != nil {
				t.Fatalf("admitted check code=%q", dkim2.ReplayErrorCodeOf(err))
			}
			if err := store.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if store.State() != dkim2.ReplayStoreClosed || owned.closeCalls.Load() != 1 {
				t.Fatalf("state=%q close=%d", store.State(), owned.closeCalls.Load())
			}
		})
	}
}

type fixedSecurityClock struct {
	now time.Time
}

// Now returns one fixed deterministic evidence time.
func (c fixedSecurityClock) Now() time.Time { return c.now }

type panicDoneContext struct {
	terminal error
	errPanic bool
	armed    atomic.Bool
}

// Deadline reports no deadline for the hostile close fixture.
func (*panicDoneContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done panics at the exact asynchronous capability boundary.
func (c *panicDoneContext) Done() <-chan struct{} {
	c.armed.Store(true)
	panic("synthetic context done panic")
}

// Err injects the configured terminal or hostile state only after Done is called.
func (c *panicDoneContext) Err() error {
	if !c.armed.Load() {
		return nil
	}
	if c.errPanic {
		panic("synthetic context err panic")
	}
	return c.terminal
}

// Value exposes no values for the hostile close fixture.
func (*panicDoneContext) Value(any) any { return nil }

type mutableSecurityClock struct {
	mu  sync.Mutex
	now time.Time
}

type sequenceSecurityClock struct {
	mu     sync.Mutex
	values []time.Time
	calls  int
}

type hookSecurityClock struct {
	now   time.Time
	calls atomic.Int32
	hook  func(int32)
}

type signalingAuditConn struct {
	net.Conn
	readStarted  chan struct{}
	writeStarted chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
}

// newSignalingAuditConn wraps one real connection with I/O entry signals.
func newSignalingAuditConn(connection net.Conn) *signalingAuditConn {
	return &signalingAuditConn{
		Conn:         connection,
		readStarted:  make(chan struct{}),
		writeStarted: make(chan struct{}),
	}
}

// Read signals entry before delegating one potentially blocked read.
func (c *signalingAuditConn) Read(destination []byte) (int, error) {
	c.readOnce.Do(func() { close(c.readStarted) })
	return c.Conn.Read(destination)
}

// Write signals entry before delegating one potentially blocked write.
func (c *signalingAuditConn) Write(value []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })
	return c.Conn.Write(value)
}

type armableBlockingContext struct {
	parent  context.Context
	armed   atomic.Bool
	blocked atomic.Bool
	started chan struct{}
	release chan struct{}
}

// newArmableBlockingContext constructs one hostile Err barrier.
func newArmableBlockingContext(parent context.Context) *armableBlockingContext {
	return &armableBlockingContext{
		parent:  parent,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

// arm makes the next Err call block exactly once.
func (c *armableBlockingContext) arm() {
	c.armed.Store(true)
}

// Deadline delegates the caller deadline.
func (c *armableBlockingContext) Deadline() (time.Time, bool) {
	return c.parent.Deadline()
}

// Done delegates caller terminal notification.
func (c *armableBlockingContext) Done() <-chan struct{} {
	return c.parent.Done()
}

// Err blocks one armed observation and otherwise delegates caller state.
func (c *armableBlockingContext) Err() error {
	if c.armed.Load() && c.blocked.CompareAndSwap(false, true) {
		close(c.started)
		<-c.release
	}
	return c.parent.Err()
}

// Value delegates caller values.
func (c *armableBlockingContext) Value(key any) any {
	return c.parent.Value(key)
}

type nthCancellationContext struct {
	calls    atomic.Int32
	cancelAt int32
}

type selectiveBlockingClock struct {
	start   time.Time
	blockAt int32
	calls   atomic.Int32
	started chan struct{}
	release chan struct{}
}

// newSelectiveBlockingClock constructs one monotonic clock with one blocked call.
func newSelectiveBlockingClock(blockAt int32) *selectiveBlockingClock {
	return &selectiveBlockingClock{
		start:   time.Unix(10_000, 0),
		blockAt: blockAt,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
}

// Now returns monotonic samples while blocking one selected caller only.
func (c *selectiveBlockingClock) Now() time.Time {
	call := c.calls.Add(1)
	if call == c.blockAt {
		close(c.started)
		<-c.release
	}
	return c.start
}

// Deadline reports no caller deadline for deterministic barrier testing.
func (*nthCancellationContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Done returns no channel because cancellation is exposed synchronously through Err.
func (*nthCancellationContext) Done() <-chan struct{} { return nil }

// Err publishes cancellation at one exact preflight observation.
func (c *nthCancellationContext) Err() error {
	if c.calls.Add(1) >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

// Value exposes no context values.
func (*nthCancellationContext) Value(any) any { return nil }

// Now returns one synchronized deterministic evidence time.
func (c *mutableSecurityClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Now returns the next deterministic security-time sample.
func (c *sequenceSecurityClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls >= len(c.values) {
		return time.Time{}
	}
	value := c.values[c.calls]
	c.calls++
	return value
}

// Now invokes one deterministic call-indexed barrier before returning time.
func (c *hookSecurityClock) Now() time.Time {
	call := c.calls.Add(1)
	if c.hook != nil {
		c.hook(call)
	}
	return c.now
}

// set replaces one synchronized deterministic evidence time.
func (c *mutableSecurityClock) set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

// deadlineSnapshot returns one synchronized evidence deadline for race tests.
func (e *evidenceState) deadlineSnapshot() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.deadline
}

type fakeOwnedApplicationClient struct {
	mode       valkeygo.ClientMode
	modePanic  bool
	modeHook   func()
	closePanic bool
	closeCalls atomic.Int32
}

type comparableOwnedApplicationClient struct {
	closeCalls *atomic.Int32
}

// B returns a zero command builder for the rejected ownership fixture.
func (comparableOwnedApplicationClient) B() valkeygo.Builder { return valkeygo.Builder{} }

// Do returns a zero result for the rejected ownership fixture.
func (comparableOwnedApplicationClient) Do(
	context.Context,
	valkeygo.Completed,
) valkeygo.ValkeyResult {
	return valkeygo.ValkeyResult{}
}

// Mode returns standalone for the rejected ownership fixture.
func (comparableOwnedApplicationClient) Mode() valkeygo.ClientMode {
	return valkeygo.ClientModeStandalone
}

// Close records cleanup of the rejected ownership fixture.
func (c comparableOwnedApplicationClient) Close() { c.closeCalls.Add(1) }

// B returns one concrete command builder.
func (*fakeOwnedApplicationClient) B() valkeygo.Builder { return valkeygo.Builder{} }

// Do returns a zero result; managed tests replace the command seam before dispatch.
func (*fakeOwnedApplicationClient) Do(context.Context, valkeygo.Completed) valkeygo.ValkeyResult {
	return valkeygo.ValkeyResult{}
}

// Mode returns or panics at the exact mode proof boundary.
func (c *fakeOwnedApplicationClient) Mode() valkeygo.ClientMode {
	if c.modeHook != nil {
		c.modeHook()
	}
	if c.modePanic {
		panic("synthetic mode panic")
	}
	return c.mode
}

// Close records or panics at the owned cleanup boundary.
func (c *fakeOwnedApplicationClient) Close() {
	c.closeCalls.Add(1)
	if c.closePanic {
		panic("synthetic close panic")
	}
}

type orderingAuditWire struct {
	fakeAuditWire
	onClose func()
}

type comparableAuditWire struct {
	closeCalls *atomic.Int32
}

// roundTrip is unreachable for the rejected ownership fixture.
func (comparableAuditWire) roundTrip(context.Context, auditRequest) (resp2Value, error) {
	return resp2Value{}, errors.New("unreachable")
}

// Close records cleanup of the rejected ownership fixture.
func (w comparableAuditWire) Close() error {
	w.closeCalls.Add(1)
	return nil
}

// Close records cleanup ordering before delegating fake cleanup.
func (w *orderingAuditWire) Close() error {
	if w.onClose != nil {
		w.onClose()
	}
	return w.fakeAuditWire.Close()
}

type blockingAuditWire struct {
	fakeAuditWire
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

// roundTrip blocks command one for exclusive revalidation tests.
func (w *blockingAuditWire) roundTrip(ctx context.Context, request auditRequest) (resp2Value, error) {
	w.once.Do(func() {
		close(w.started)
		<-w.release
	})
	return w.fakeAuditWire.roundTrip(ctx, request)
}

// classifiedFailureAuditWire returns one exact injected round-trip class.
type classifiedFailureAuditWire struct {
	value       resp2Value
	err         error
	onRoundTrip func()
	onClose     func()
	closeErr    error
	closePanic  bool
	closeCalls  atomic.Int32
}

// roundTrip returns one injected failure without a reply.
func (w *classifiedFailureAuditWire) roundTrip(
	context.Context,
	auditRequest,
) (resp2Value, error) {
	if w.onRoundTrip != nil {
		w.onRoundTrip()
	}
	return w.value, w.err
}

// Close records cleanup and injects its exact bounded behavior.
func (w *classifiedFailureAuditWire) Close() error {
	w.closeCalls.Add(1)
	if w.onClose != nil {
		w.onClose()
	}
	if w.closePanic {
		panic("synthetic close panic")
	}
	return w.closeErr
}

// decoderFailureAuditWire exercises the private bounded RESP2 decoder.
type decoderFailureAuditWire struct {
	encoded    []byte
	onClose    func()
	closePanic bool
	closeCalls atomic.Int32
}

// roundTrip decodes one injected malformed frame through the production decoder.
func (w *decoderFailureAuditWire) roundTrip(
	context.Context,
	auditRequest,
) (resp2Value, error) {
	decoder := newRESP2Decoder(bytes.NewReader(w.encoded))
	defer decoder.clear()
	return decoder.decode()
}

// Close records exact cleanup.
func (w *decoderFailureAuditWire) Close() error {
	w.closeCalls.Add(1)
	if w.onClose != nil {
		w.onClose()
	}
	if w.closePanic {
		panic("synthetic close panic")
	}
	return nil
}

// deadlineAuditWire waits for the owned command/global deadline.
type deadlineAuditWire struct {
	closeCalls atomic.Int32
}

// roundTrip returns an impossible failure concurrent with owned expiry.
func (*deadlineAuditWire) roundTrip(ctx context.Context, _ auditRequest) (resp2Value, error) {
	<-ctx.Done()
	return resp2Value{}, dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant)
}

// Close records exact cleanup.
func (w *deadlineAuditWire) Close() error {
	w.closeCalls.Add(1)
	return nil
}

// publishingAuditFactory publishes one wire and returns one injected acquisition result.
func publishingAuditFactory(wire auditWire, result error) auditWireFactory {
	return func(
		_ context.Context,
		_ auditAuthority,
		publish func(auditWire),
	) error {
		publish(wire)
		return result
	}
}

// auditWireCloseCalls reads one bounded fixture's cleanup count.
func auditWireCloseCalls(wire auditWire) int32 {
	switch typed := wire.(type) {
	case *classifiedFailureAuditWire:
		return typed.closeCalls.Load()
	case *decoderFailureAuditWire:
		return typed.closeCalls.Load()
	case *deadlineAuditWire:
		return typed.closeCalls.Load()
	default:
		return -1
	}
}

// newAuditCloseBarrierWire constructs one exact primary result with cleanup hooks.
func newAuditCloseBarrierWire(primary string, onClose func(), closePanic bool) auditWire {
	switch primary {
	case "success":
		return &orderingAuditWire{
			fakeAuditWire: fakeAuditWire{
				replies:    validAuditReplies(),
				closePanic: closePanic,
			},
			onClose: onClose,
		}
	case testPrimaryTransport:
		return &classifiedFailureAuditWire{
			err:        dkim2.NewReplayError(dkim2.ReplayErrorUnavailable),
			onClose:    onClose,
			closePanic: closePanic,
		}
	case testPrimaryMismatch:
		return &classifiedFailureAuditWire{
			value:      errorAuditValue("NOPERM bounded denial"),
			onClose:    onClose,
			closePanic: closePanic,
		}
	case testPrimaryMalformed:
		return &decoderFailureAuditWire{
			encoded:    []byte("$5\r\nabc\r\n"),
			onClose:    onClose,
			closePanic: closePanic,
		}
	case testPrimaryInternal:
		return &classifiedFailureAuditWire{
			err:        dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
			onClose:    onClose,
			closePanic: closePanic,
		}
	default:
		return &classifiedFailureAuditWire{
			err: dkim2.NewReplayError(dkim2.ReplayErrorInternalInvariant),
		}
	}
}

// validAuditorConfig returns one bounded credentials-only fixture.
func validAuditorConfig() AuditorConfig {
	return NewAuditorConfig(syntheticAuditUsername, []byte(syntheticAuditPassword))
}

// mustOperatorAttestation constructs one exact trusted policy fixture.
func mustOperatorAttestation(t *testing.T) OperatorAttestation {
	t.Helper()
	input := validOperatorAttestationInput()
	input.values.SaveSchedule = "60 1"
	value, err := NewOperatorAttestation(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// validProductionDependencies returns fresh deterministic constructor seams.
func validProductionDependencies(
	t *testing.T,
	client ownedApplicationClient,
) productionDependencies {
	t.Helper()
	return productionDependencies{
		clock: fixedSecurityClock{now: time.Unix(10_000, 0)},
		newAuditWire: func(
			_ context.Context,
			_ auditAuthority,
			publish func(auditWire),
		) error {
			publish(&fakeAuditWire{replies: validAuditReplies()})
			return nil
		},
		newApplication: func(
			_ valkeygo.ClientOption,
			publish func(ownedApplicationClient),
		) error {
			publish(client)
			return nil
		},
	}
}

// mustProductionStore constructs one complete test production store.
func mustProductionStore(t *testing.T, dependencies productionDependencies) *Store {
	t.Helper()
	store, err := newProductionStoreWithDependencies(
		context.Background(),
		validClientConfig(t),
		mustOperatorAttestation(t),
		validAuditorConfig(),
		dependencies,
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}
