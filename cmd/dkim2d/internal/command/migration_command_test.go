package command

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
)

const migrationTestConfigPath = "/tmp/migration.yaml"

// TestDatasourceDryRunUsesOnlyOfflineDependency proves daemon construction is absent.
func TestDatasourceDryRunUsesOnlyOfflineDependency(t *testing.T) {
	var stdout, stderr bytes.Buffer
	loadCalls, buildCalls, dryRunCalls := 0, 0, 0
	exit := executeWithDependencies(
		[]string{
			datasourceCommandName, bootstrapCommandName,
			testConfigFlag, migrationTestConfigPath, "--machine",
		},
		&stdout,
		&stderr,
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				loadCalls++
				return nil, errCommandRuntime
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				buildCalls++
				return nil, errCommandRuntime
			},
			withTimeout: context.WithTimeout,
			dryRun: func(
				context.Context,
				string,
				bool,
				string,
			) ([]byte, error) {
				dryRunCalls++
				return []byte("{\"result\":\"success\"}\n"), nil
			},
		},
	)
	if exit != 0 || dryRunCalls != 1 || loadCalls != 0 || buildCalls != 0 ||
		stdout.String() != "{\"result\":\"success\"}\n" || stderr.Len() != 0 {
		t.Fatal("offline dry run crossed daemon bootstrap")
	}
}

// TestDatasourceCommandRejectsDisablingSafeMode proves no accidental apply path.
func TestDatasourceCommandRejectsDisablingSafeMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := executeWithDependencies(
		[]string{
			datasourceCommandName, bootstrapCommandName,
			testConfigFlag, migrationTestConfigPath, "--dry-run=false",
		},
		&stdout,
		&stderr,
		commandDependencies{
			load: func(string, config.FlagValues) (bootstrapOwner, error) {
				return nil, errCommandRuntime
			},
			build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
				return nil, errCommandRuntime
			},
			withTimeout: context.WithTimeout,
			dryRun: func(
				context.Context,
				string,
				bool,
				string,
			) ([]byte, error) {
				t.Fatal("disabled dry run reached runner")
				return nil, nil
			},
		},
	)
	if exit != 1 || stdout.Len() != 0 ||
		stderr.String() != commandRuntimeDiagnostic {
		t.Fatal("unsafe migration mode was not rejected")
	}
}

// TestDatasourceApplyAndRollbackUseOnlyOfflineMutationDependencies proves
// privileged migration commands never assemble the daemon.
func TestDatasourceApplyAndRollbackUseOnlyOfflineMutationDependencies(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		deps func(*int) commandDependencies
	}{
		{
			name: "apply",
			args: []string{datasourceCommandName, bootstrapCommandName, testConfigFlag, migrationTestConfigPath, applyToken},
			deps: func(calls *int) commandDependencies {
				return commandDependencies{apply: func(
					context.Context, string, bool, string,
				) ([]byte, error) {
					*calls++
					return []byte("mode=apply result=success\n"), nil
				}}
			},
		},
		{
			name: rollbackCommandName,
			args: []string{datasourceCommandName, rollbackCommandName, testConfigFlag, migrationTestConfigPath, "--generation", "3"},
			deps: func(calls *int) commandDependencies {
				return commandDependencies{rollback: func(
					_ context.Context, _ string, generation string, _ bool, _ string,
				) ([]byte, error) {
					if generation != "3" {
						t.Fatal("rollback generation drifted")
					}
					*calls++
					return []byte("mode=rollback result=success\n"), nil
				}}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			calls := 0
			deps := test.deps(&calls)
			deps.load = func(string, config.FlagValues) (bootstrapOwner, error) {
				t.Fatal("offline mutation reached daemon loader")
				return nil, nil
			}
			deps.build = func(bootstrapOwner, time.Duration) (managedApplication, error) {
				t.Fatal("offline mutation reached daemon builder")
				return nil, nil
			}
			deps.withTimeout = context.WithTimeout
			exit := executeWithDependencies(test.args, &stdout, &stderr, deps)
			if exit != 0 || calls != 1 || stdout.Len() == 0 || stderr.Len() != 0 {
				t.Fatal("offline mutation command failed")
			}
		})
	}
}
