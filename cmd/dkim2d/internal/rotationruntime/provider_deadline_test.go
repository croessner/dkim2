package rotationruntime

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
)

type deadlineBackendProbe struct {
	campaignBackend
	remaining time.Duration
}

type deadlinePurgeProbe struct{ remaining []time.Duration }

func (p *deadlinePurgeProbe) Purge(ctx context.Context, _ rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return rotationadmin.PurgeExecutionResult{}, nil
}

func (p *deadlinePurgeProbe) Reconcile(ctx context.Context, _ rotationadmin.PurgeCommand) (rotationadmin.PurgeExecutionResult, error) {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return rotationadmin.PurgeExecutionResult{}, nil
}

type deadlineTerminalProbe struct{ remaining []time.Duration }

type deadlineTerminalRecoveryProbe struct{ remaining []time.Duration }

func (*deadlineTerminalRecoveryProbe) RecordTerminal(context.Context, datasourceadmin.TerminalRecord) error {
	return nil
}

func (p *deadlineTerminalRecoveryProbe) ReadTerminal(ctx context.Context, _ datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return datasourceadmin.TerminalRecord{}, false, nil
}

func (p *deadlineTerminalProbe) RecordTerminal(ctx context.Context, _ datasourceadmin.TerminalRecord) error {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return nil
}

func (p *deadlineTerminalProbe) ReadTerminal(ctx context.Context, _ datasourceadmin.OperationBinding) (datasourceadmin.TerminalRecord, bool, error) {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return datasourceadmin.TerminalRecord{}, false, nil
}

type deadlineRecoveryProbe struct{ remaining []time.Duration }

type slowRecoveryProbe struct {
	steps int
	delay time.Duration
}

func (p *slowRecoveryProbe) RetentionCurrent(ctx context.Context) (uint64, error) {
	for range p.steps {
		timer := time.NewTimer(p.delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return 0, ctx.Err()
		}
	}
	return 1, nil
}

func (*slowRecoveryProbe) RetentionPage(context.Context, uint64, uint32) ([]datasourceadmin.RetentionGeneration, error) {
	return nil, nil
}

func (p *deadlineRecoveryProbe) RetentionCurrent(ctx context.Context) (uint64, error) {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return 1, nil
}

func (p *deadlineRecoveryProbe) RetentionPage(ctx context.Context, _ uint64, _ uint32) ([]datasourceadmin.RetentionGeneration, error) {
	p.remaining = append(p.remaining, remainingDeadline(ctx))
	return nil, nil
}

func (p *deadlineBackendProbe) Inventory(ctx context.Context, _ datasourceadmin.GenerationLimits) (datasourceadmin.Inventory, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return datasourceadmin.Inventory{}, errUnavailable
	}
	p.remaining = time.Until(deadline)
	return datasourceadmin.Inventory{}, nil
}

func TestProviderBoundaryCapsLongCampaignDeadline(t *testing.T) {
	outer, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	probe := &deadlineBackendProbe{}
	backend := &deadlineCampaignBackend{backend: probe, maximum: 2 * time.Minute}
	if _, err := backend.Inventory(outer, datasourceadmin.GenerationLimits{}); err != nil {
		t.Fatalf("inventory through bounded provider: %v", err)
	}
	if probe.remaining <= 0 || probe.remaining > 2*time.Minute {
		t.Fatalf("provider deadline = %s, want (0, 2m]", probe.remaining)
	}
	if remaining := time.Until(mustDeadline(outer, t)); remaining < 23*time.Hour {
		t.Fatalf("outer campaign deadline was shortened: %s", remaining)
	}
}

func TestProviderBoundaryPreservesShorterCampaignDeadline(t *testing.T) {
	outer, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	probe := &deadlineBackendProbe{}
	backend := &deadlineCampaignBackend{backend: probe, maximum: 2 * time.Minute}
	if _, err := backend.Inventory(outer, datasourceadmin.GenerationLimits{}); err != nil {
		t.Fatalf("inventory through bounded provider: %v", err)
	}
	if probe.remaining <= 0 || probe.remaining > 30*time.Second {
		t.Fatalf("provider deadline = %s, want (0, 30s]", probe.remaining)
	}
}

func TestProviderBoundaryCapsPurgeTerminalAndRecovery(t *testing.T) {
	outer, cancel := context.WithTimeout(context.Background(), 24*time.Hour)
	defer cancel()
	const maximum = 2 * time.Minute
	purgeProbe := &deadlinePurgeProbe{}
	purge := &deadlinePurgeExecutor{executor: purgeProbe, maximum: maximum}
	_, _ = purge.Purge(outer, rotationadmin.PurgeCommand{})
	_, _ = purge.Reconcile(outer, rotationadmin.PurgeCommand{})
	terminalProbe := &deadlineTerminalProbe{}
	terminal := &deadlineTerminalRecorder{recorder: terminalProbe, maximum: maximum}
	_ = terminal.RecordTerminal(outer, datasourceadmin.TerminalRecord{})
	_, _, _ = terminal.ReadTerminal(outer, datasourceadmin.OperationBinding{})
	recoveryProbe := &deadlineRecoveryProbe{}
	recovery := &deadlineRetentionRecoveryReader{reader: recoveryProbe, maximum: maximum}
	_, _ = recovery.RetentionCurrent(outer)
	_, _ = recovery.RetentionPage(outer, 0, 1)
	for _, remaining := range append(purgeProbe.remaining, terminalProbe.remaining...) {
		if remaining <= 0 || remaining > maximum {
			t.Fatalf("provider deadline = %s, want (0, 2m]", remaining)
		}
	}
	if len(recoveryProbe.remaining) != 2 || recoveryProbe.remaining[0] < 23*time.Hour ||
		recoveryProbe.remaining[1] <= 0 || recoveryProbe.remaining[1] > maximum {
		t.Fatalf("recovery deadlines = %v, want campaign-wide current and bounded page", recoveryProbe.remaining)
	}
}

func TestRetentionRecoveryCanSpanMultipleProviderDeadlines(t *testing.T) {
	outer, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const maximum = 20 * time.Millisecond
	probe := &slowRecoveryProbe{steps: 3, delay: 15 * time.Millisecond}
	recovery := &deadlineRetentionRecoveryReader{reader: probe, maximum: maximum}
	if current, err := recovery.RetentionCurrent(outer); err != nil || current != 1 {
		t.Fatalf("multi-step recovery: current=%d err=%v", current, err)
	}
}

func TestRetentionRecoveryBoundsEachTerminalRead(t *testing.T) {
	operation, err := datasourceadmin.NewOperationBinding("aebagbafaydqqcikbmga2dqpca")
	if err != nil {
		t.Fatal(err)
	}
	view := datasourceadmin.RetentionInventory{Version: "deadline-recovery-v1", Current: 2, Generations: []datasourceadmin.RetentionGeneration{{
		Generation: 2, Operation: operation, SourceGeneration: 1, Schema: datasourceadmin.SchemaVersionV3,
	}}}
	outer, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	const maximum = 20 * time.Millisecond
	terminalProbe := &deadlineTerminalRecoveryProbe{}
	terminal := &deadlineTerminalRecorder{recorder: terminalProbe, maximum: maximum}
	reader := newRetentionRecoveryAdapter(&retentionRecoverySequence{views: []datasourceadmin.RetentionInventory{view}}, terminal, datasourceadmin.DefaultRetentionRecoveryLimits())
	if _, err := datasourceadmin.ReadRetentionRecoveryInventory(outer, reader, datasourceadmin.DefaultRetentionRecoveryLimits()); err != nil {
		t.Fatalf("retention recovery: %v", err)
	}
	if len(terminalProbe.remaining) != 2 {
		t.Fatalf("terminal reads = %d, want 2", len(terminalProbe.remaining))
	}
	for _, remaining := range terminalProbe.remaining {
		if remaining <= 0 || remaining > maximum {
			t.Fatalf("terminal deadline = %s, want (0, %s]", remaining, maximum)
		}
	}
}

func TestProviderBoundaryPropagatesParentCancellation(t *testing.T) {
	outer, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := providerContext(outer, 2*time.Minute); err == nil {
		t.Fatal("cancelled parent accepted")
	}
}

func mustDeadline(ctx context.Context, t *testing.T) time.Time {
	t.Helper()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context has no deadline")
	}
	return deadline
}

func remainingDeadline(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return time.Until(deadline)
}
