package command

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
	"github.com/spf13/cobra"
)

const (
	domainTestConfigPath    = "/tmp/domain-admin.yaml"
	domainTestIntentPath    = "/tmp/domain-intent.yaml"
	domainTestOperationPath = "/tmp/domain-operation.json"
	domainTestDNSPath       = "/tmp/domain-dns.txt"
	domainTestIntentFlag    = "--intent"
	domainTestOperationFlag = "--operation"
	domainTestOutputFlag    = "--output"
)

// domainTestDependencies returns daemon seams that fail if an offline command crosses them.
func domainTestDependencies(t *testing.T) commandDependencies {
	t.Helper()
	return commandDependencies{
		load: func(string, config.FlagValues) (bootstrapOwner, error) {
			t.Fatal("offline domain command reached daemon loader")
			return nil, nil
		},
		build: func(bootstrapOwner, time.Duration) (managedApplication, error) {
			t.Fatal("offline domain command reached daemon builder")
			return nil, nil
		},
		withTimeout: context.WithTimeout,
	}
}

// commandNames returns one sorted immediate child-command vocabulary.
func commandNames(command interface{ Commands() []*cobra.Command }) []string {
	children := command.Commands()
	names := make([]string, 0, len(children))
	for _, child := range children {
		if !child.Hidden {
			names = append(names, child.Name())
		}
	}
	sort.Strings(names)
	return names
}

// TestDomainCommandTreeHasNoAdditionalSurface freezes every immediate administrative child.
func TestDomainCommandTreeHasNoAdditionalSurface(t *testing.T) {
	deps := domainTestDependencies(t)
	deps.domain = func(context.Context, domainadmin.CommandRequest) ([]byte, error) {
		return []byte("result=success\n"), nil
	}
	root, err := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{}, deps)
	if err != nil {
		t.Fatal("domain command tree construction failed")
	}
	datasource, _, err := root.Find([]string{datasourceCommandName})
	if err != nil {
		t.Fatal("datasource command unavailable")
	}
	domain, _, err := datasource.Find([]string{domainCommandName})
	if err != nil || !slices.Equal(commandNames(domain), []string{domainAbortCommandName, domainActivateCommandName, domainDNSCommandName, domainPlanCommandName, domainPrepareCommandName, domainProveCommandName, domainReconcileName, domainStatusCommandName}) {
		t.Fatal("domain command vocabulary drifted")
	}
	dns, _, err := domain.Find([]string{domainDNSCommandName})
	if err != nil || !slices.Equal(commandNames(dns), []string{domainDNSExportName}) {
		t.Fatal("DNS command vocabulary drifted")
	}
}

// TestDomainCommandShapeFreezesExactOfflineTree proves the public command names cannot drift.
func TestDomainCommandShapeFreezesExactOfflineTree(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command domainadmin.Command
	}{
		{domainPlanCommandName, []string{domainCommandName, domainPlanCommandName, testConfigFlag, domainTestConfigPath, domainTestIntentFlag, domainTestIntentPath, domainTestOperationFlag, domainTestOperationPath}, domainadmin.CommandPlan},
		{domainPrepareCommandName, []string{domainCommandName, domainPrepareCommandName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath}, domainadmin.CommandPrepare},
		{"dns-export", []string{domainCommandName, domainDNSCommandName, domainDNSExportName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath, domainTestOutputFlag, domainTestDNSPath}, domainadmin.CommandDNSExport},
		{domainProveCommandName, []string{domainCommandName, domainProveCommandName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath}, domainadmin.CommandProve},
		{domainStatusCommandName, []string{domainCommandName, domainStatusCommandName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath}, domainadmin.CommandStatus},
		{domainReconcileName, []string{domainCommandName, domainReconcileName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath}, domainadmin.CommandReconcile},
		{domainAbortCommandName, []string{domainCommandName, domainAbortCommandName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath}, domainadmin.CommandAbort},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			deps := domainTestDependencies(t)
			calls := 0
			deps.domain = func(_ context.Context, request domainadmin.CommandRequest) ([]byte, error) {
				calls++
				if request.Command != test.command || request.Apply {
					t.Fatal("Cobra changed the domain command semantics")
				}
				return []byte("result=success\n"), nil
			}
			exit := executeWithDependencies(append([]string{datasourceCommandName}, test.args...), &stdout, &stderr, deps)
			if exit != 0 || calls != 1 || stdout.String() != "result=success\n" || stderr.Len() != 0 {
				t.Fatal("exact offline domain command did not reach its sole semantic owner")
			}
		})
	}
}

// TestDomainActivationRequiresExactApply proves no default, false value, or alias authorizes activation.
func TestDomainActivationRequiresExactApply(t *testing.T) {
	base := []string{datasourceCommandName, domainCommandName, domainActivateCommandName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath}
	for _, test := range []struct {
		name string
		tail []string
		want int
	}{
		{"missing", nil, 2},
		{"explicit-false", []string{applyToken + "=false"}, 2},
		{"explicit-true", []string{applyToken + "=true"}, 2},
		{"alternate", []string{"--force"}, 2},
		{"short", []string{"-a"}, 2},
		{"combined", []string{applyToken, applyToken + "=true"}, 2},
		{"after-terminator", []string{"--", applyToken}, 2},
		{"exact", []string{applyToken}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			deps := domainTestDependencies(t)
			calls := 0
			deps.domain = func(_ context.Context, request domainadmin.CommandRequest) ([]byte, error) {
				calls++
				if request.Command != domainadmin.CommandActivate || !request.Apply {
					t.Fatal("activation reached semantics without exact apply authorization")
				}
				return []byte("result=success\n"), nil
			}
			exit := executeWithDependencies(append(base, test.tail...), &stdout, &stderr, deps)
			if exit != test.want {
				t.Fatalf("activation exit=%d, want %d", exit, test.want)
			}
			if test.want == 0 && calls != 1 {
				t.Fatal("exact apply did not reach activation")
			}
			if test.want != 0 && calls != 0 {
				t.Fatal("unsafe activation reached semantic runner")
			}
		})
	}
}

// TestDomainCommandRejectsVerify freezes the absence of a false runtime-verification claim.
func TestDomainCommandRejectsVerify(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := domainTestDependencies(t)
	deps.domain = func(context.Context, domainadmin.CommandRequest) ([]byte, error) {
		t.Fatal("unsupported verify command reached semantic runner")
		return nil, nil
	}
	exit := executeWithDependencies(
		[]string{datasourceCommandName, domainCommandName, "verify", testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath},
		&stdout,
		&stderr,
		deps,
	)
	if exit != 2 || stdout.Len() != 0 || stderr.String() != commandShapeDiagnostic+commandUsage {
		t.Fatal("verify was not rejected as a command-shape error")
	}
}

// TestDomainCommandWritesBoundedFailureReportAndKeepsNonzeroExit freezes operator failure UX.
func TestDomainCommandWritesBoundedFailureReportAndKeepsNonzeroExit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	deps := domainTestDependencies(t)
	deps.domain = func(context.Context, domainadmin.CommandRequest) ([]byte, error) {
		return []byte("{\"schema\":\"dkim2-domain-report-v1\",\"result\":\"failure\",\"failure\":\"conflict\"}\n"), errCommandRuntime
	}
	exit := executeWithDependencies(
		[]string{datasourceCommandName, domainCommandName, domainPrepareCommandName, testConfigFlag, domainTestConfigPath, domainTestOperationFlag, domainTestOperationPath},
		&stdout, &stderr, deps,
	)
	if exit != 1 || !bytes.Contains(stdout.Bytes(), []byte("\"failure\":\"conflict\"")) ||
		stderr.String() != commandRuntimeDiagnostic {
		t.Fatal("bounded workflow failure report lost nonzero runtime exit")
	}
}
