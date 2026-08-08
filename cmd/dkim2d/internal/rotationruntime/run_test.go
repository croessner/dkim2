package rotationruntime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/rotationadmin"
)

type coordinatorFake struct{ calls int }

// Run records only that the thin adapter reached its sole coordinator owner.
func (f *coordinatorFake) Run(_ context.Context, request Request, configuration *rotationadmin.Config) (rotationadmin.CommandReport, error) {
	f.calls++
	if request.Command != CommandRun || !request.Automatic || configuration.Backend() != backendLDAP {
		return rotationadmin.CommandReport{}, errUnavailable
	}
	return rotationadmin.CommandReport{Command: "run", Mode: "normal", State: rotationadmin.StatePrepared, Backend: backendLDAP, WorkCount: 4, RecordCount: 8, BatchCount: 2, ResultClass: "success"}, nil
}

// TestRunFileInvokesOnlyTheCoordinator proves the command adapter does not own a parallel campaign flow.
func TestRunFileInvokesOnlyTheCoordinator(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("protect test directory")
	}
	secrets := make([]string, 5)
	for index := range secrets {
		secrets[index] = filepath.Join(directory, "role-"+string(rune('a'+index)))
		if err := os.WriteFile(secrets[index], []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(directory, "rotation.yaml")
	document := "version: dkim2-rotation-admin-v1\nauthority_id: aaaaaaaaaaaaaaaaaaaaaaaaae\nbackend: ldap\ndeadline: 30s\nlimits:\n  max_work_items: 16\n  max_dns_batch_records: 4\n  max_dns_batches: 4\nroles:\n  snapshot:\n    name: snapshot\n    secret_file: " + secrets[0] + "\n  staging:\n    name: staging\n    secret_file: " + secrets[1] + "\n  activation:\n    name: activation\n    secret_file: " + secrets[2] + "\n  purge:\n    name: purge\n    secret_file: " + secrets[3] + "\n  closer:\n    name: closer\n    secret_file: " + secrets[4] + "\n"
	if err := os.WriteFile(configPath, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	fake := &coordinatorFake{}
	encoded, err := RunFile(context.Background(), Request{Command: CommandRun, Config: configPath, Journal: filepath.Join(directory, "journal"), Automatic: true, DryRun: true, Machine: true}, fake)
	if err != nil || fake.calls != 1 || len(encoded) == 0 {
		t.Fatal("real coordinator was not invoked exactly once")
	}
}

// TestRequestRejectsEmergencyAndPurgeAmbiguity freezes no-implicit-destructive-input behavior.
func TestRequestRejectsEmergencyAndPurgeAmbiguity(t *testing.T) {
	base := Request{Config: "/tmp/config", Journal: "/tmp/journal"}
	if (Request{Command: CommandEmergency, Config: base.Config, Journal: base.Journal, Apply: true, Emergency: rotationadmin.BindingSelector{Tenant: "t", Domain: "d", Use: "u", Profile: "p"}}).Validate() == nil {
		t.Fatal("emergency without reason accepted")
	}
	if (Request{Command: CommandPurgeApply, Config: base.Config, Journal: base.Journal, Plan: "/tmp/plan", Apply: true, DryRun: true}).Validate() == nil {
		t.Fatal("purge apply with dry-run accepted")
	}
}
