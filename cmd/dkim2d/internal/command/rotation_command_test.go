package command

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationruntime"
)

const (
	rotationTestConfig  = "/tmp/rotation-config.yaml"
	rotationTestJournal = "/tmp/rotation-journal.json"
	rotationTestPlan    = "/tmp/rotation-purge-plan.json"
)

// TestRotationCommandTreeHasNoAdditionalSurface freezes the closed campaign command vocabulary.
func TestRotationCommandTreeHasNoAdditionalSurface(t *testing.T) {
	deps := domainTestDependencies(t)
	deps.rotation = func(context.Context, rotationruntime.Request) ([]byte, error) { return []byte("result=success\n"), nil }
	root, err := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal("rotation command tree construction failed")
	}
	datasource, _, err := root.Find([]string{datasourceCommandName})
	if err != nil {
		t.Fatal("datasource command unavailable")
	}
	rotation, _, err := datasource.Find([]string{rotationCommandName})
	if err != nil || !slices.Equal(commandNames(rotation), []string{domainAbortCommandName, rotationDNSExportName, rotationEmergencyName, rotationPurgeName, domainReconcileName, rotationRunCommandName, domainStatusCommandName}) {
		t.Fatal("rotation command vocabulary drifted")
	}
	purge, _, err := rotation.Find([]string{rotationPurgeName})
	if err != nil || !slices.Equal(commandNames(purge), []string{rotationPurgeApplyName, rotationPurgePlanName}) {
		t.Fatal("rotation purge vocabulary drifted")
	}
}

// TestRotationNormalRequiresAutomaticAndExplicitApplyForMutation proves normal rotation is not a hidden default mutation.
func TestRotationNormalRequiresAutomaticAndExplicitApplyForMutation(t *testing.T) {
	base := []string{datasourceCommandName, rotationCommandName, rotationRunCommandName, "--config", rotationTestConfig, "--journal", rotationTestJournal}
	for _, test := range []struct {
		name      string
		tail      []string
		wantCalls int
		wantExit  int
	}{
		{"automatic_dry_run", []string{"--automatic"}, 1, 0},
		{"automatic_apply", []string{"--automatic", "--apply"}, 1, 0},
		{"no_automatic", nil, 0, 2},
		{"apply_without_automatic", []string{"--apply"}, 0, 2},
		{"conflicting_dry_run_apply", []string{"--automatic", "--dry-run", "--apply"}, 0, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			calls := 0
			deps := domainTestDependencies(t)
			deps.rotation = func(_ context.Context, request rotationruntime.Request) ([]byte, error) {
				calls++
				if !request.Automatic {
					t.Fatal("normal command did not preserve automatic intent")
				}
				if request.Command != rotationruntime.CommandRun {
					t.Fatal("normal command drifted")
				}
				if request.Apply && request.DryRun {
					return []byte("result=failure\n"), errCommandRuntime
				}
				return []byte("result=success\n"), nil
			}
			exit := executeWithDependencies(append(base, test.tail...), &stdout, &stderr, deps)
			if exit != test.wantExit || calls != test.wantCalls {
				t.Fatalf("exit=%d calls=%d", exit, calls)
			}
		})
	}
}

// TestRotationEmergencyAndPurgeApplyRequireOneExactBareApplyToken proves destructive paths reject aliases and values.
func TestRotationEmergencyAndPurgeApplyRequireOneExactBareApplyToken(t *testing.T) {
	tests := [][]string{
		{datasourceCommandName, rotationCommandName, rotationEmergencyName, "--config", rotationTestConfig, "--journal", rotationTestJournal, "--tenant", "t", "--domain", "d", "--use", "u", "--profile", "p", "--reason", "incident"},
		{datasourceCommandName, rotationCommandName, rotationPurgeName, rotationPurgeApplyName, "--config", rotationTestConfig, "--journal", rotationTestJournal, "--plan", rotationTestPlan},
		{datasourceCommandName, rotationCommandName, domainAbortCommandName, "--config", rotationTestConfig, "--journal", rotationTestJournal},
	}
	for _, base := range tests {
		for _, tail := range [][]string{nil, {"--apply=false"}, {"--apply=true"}, {"--apply", "--apply"}, {"--apply"}} {
			var stdout, stderr bytes.Buffer
			calls := 0
			deps := domainTestDependencies(t)
			deps.rotation = func(context.Context, rotationruntime.Request) ([]byte, error) {
				calls++
				return []byte("result=success\n"), nil
			}
			exit := executeWithDependencies(append(base, tail...), &stdout, &stderr, deps)
			wantCall := len(tail) == 1 && tail[0] == "--apply"
			if (exit == 0) != wantCall || (calls == 1) != wantCall {
				t.Fatalf("tail=%v exit=%d calls=%d", tail, exit, calls)
			}
		}
	}
}
