//nolint:goconst // Independent policy negatives intentionally repeat exact Compose values.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateDemoRejectsEveryAdditionalPublication freezes the loopback-only override.
func TestValidateDemoRejectsEveryAdditionalPublication(t *testing.T) {
	defaultProject := testProject(t.TempDir())
	demoProject := testProject(t.TempDir())
	demoProject.Services["postfix"] = withPorts(demoProject.Services["postfix"], []composePort{{
		Mode: "ingress", HostIP: "127.0.0.1", Target: 25,
		Published: "2525", Protocol: "tcp",
	}})
	if err := validateDemo(defaultProject, demoProject); err != nil {
		t.Fatal(err)
	}
	tests := []composePort{
		{Mode: "ingress", HostIP: "0.0.0.0", Target: 25, Published: "2525", Protocol: "tcp"},
		{Mode: "ingress", HostIP: "::1", Target: 25, Published: "2525", Protocol: "tcp"},
		{Mode: "ingress", HostIP: "127.0.0.1", Target: 8080, Published: "8080", Protocol: "tcp"},
	}
	for _, hostile := range tests {
		candidate := testProject(t.TempDir())
		candidate.Services["postfix"] = withPorts(candidate.Services["postfix"], []composePort{hostile})
		if err := validateDemo(defaultProject, candidate); err == nil {
			t.Fatalf("publication %+v was accepted", hostile)
		}
	}
}

// TestLoadProjectRejectsUnknownDuplicateAndOversizedEvidence freezes rendered-input bounds.
func TestLoadProjectRejectsUnknownDuplicateAndOversizedEvidence(t *testing.T) {
	inputs := [][]byte{
		[]byte(`{"name":"first","name":"second"}`),
		[]byte(`{"name":"x","networks":{},"services":{},"volumes":{},"unknown":true}`),
		[]byte(strings.Repeat("x", maximumComposeBytes+1)),
	}
	for index, input := range inputs {
		path := filepath.Join(t.TempDir(), "input.json")
		if err := os.WriteFile(path, input, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadProject(path); err == nil {
			t.Fatalf("hostile input %d was accepted", index)
		}
	}
}

// TestValidatePostfixRejectsRouteConflation freezes operation-separated sockets.
func TestValidatePostfixRejectsRouteConflation(t *testing.T) {
	root := t.TempDir()
	base := filepath.Join(root, "deployments", "postfix-compose", "postfix")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	mainCF := expectedMainCF
	masterCF := expectedMasterCF
	if err := os.WriteFile(filepath.Join(base, "main.cf"), []byte(mainCF), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "master.cf"), []byte(masterCF), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePostfix(root); err != nil {
		t.Fatal(err)
	}
	hostile := strings.Replace(masterCF, "transit/milter.sock", "inbound/milter.sock", 1)
	if err := os.WriteFile(filepath.Join(base, "master.cf"), []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePostfix(root); err == nil {
		t.Fatal("route capability conflation was accepted")
	}
}

// TestProjectRoundTripDocumentsTheClosedProjection verifies stable JSON field shapes.
func TestProjectRoundTripDocumentsTheClosedProjection(t *testing.T) {
	project := testProject(t.TempDir())
	content, err := json.Marshal(project)
	if err != nil {
		t.Fatal(err)
	}
	var decoded composeProject
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Name != project.Name {
		t.Fatal("project identity changed")
	}
}

// TestValidProductImageRejectsMutableAndUntrustedReferences freezes image authority.
func TestValidProductImageRejectsMutableAndUntrustedReferences(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, valid := range []string{
		"dkim2d:local",
		"ghcr.io/croessner/dkim2d@sha256:" + digest,
	} {
		if !validProductImage(valid, "dkim2d") {
			t.Fatalf("valid image %q was rejected", valid)
		}
	}
	for _, hostile := range []string{
		"dkim2d:latest",
		"registry.example/dkim2d@sha256:" + digest,
		"ghcr.io/croessner/dkim2d:release",
		"ghcr.io/croessner/dkim2d@sha256:" + strings.Repeat("A", 64),
	} {
		if validProductImage(hostile, "dkim2d") {
			t.Fatalf("hostile image %q was accepted", hostile)
		}
	}
}

// TestValidateRouteRejectsCrossRouteMountNetworkAndDependencyDrift freezes isolation.
func TestValidateRouteRejectsCrossRouteMountNetworkAndDependencyDrift(t *testing.T) {
	root := t.TempDir()
	valid := validRouteProject(root)
	if err := validateRoute(valid, "inbound", root); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*composeProject)
	}{
		{
			name: "cross route socket",
			mutate: func(project *composeProject) {
				service := project.Services["milter-inbound"]
				service.Volumes[0].Source = filepath.Join(
					root, "deployments", "postfix-compose", "state", "sockets", "transit",
				)
				project.Services["milter-inbound"] = service
			},
		},
		{
			name: "extra mount",
			mutate: func(project *composeProject) {
				service := project.Services["daemon-inbound"]
				service.Volumes = append(service.Volumes, composeMount{
					Type: "bind", Source: "/host", Target: "/host",
				})
				project.Services["daemon-inbound"] = service
			},
		},
		{
			name: "extra network",
			mutate: func(project *composeProject) {
				service := project.Services["daemon-inbound"]
				service.Networks["mail"] = nil
				project.Services["daemon-inbound"] = service
			},
		},
		{
			name: "dependency weakened",
			mutate: func(project *composeProject) {
				service := project.Services["milter-inbound"]
				service.DependsOn["daemon-inbound"] = composeDependency{
					Condition: "service_started", Required: true,
				}
				project.Services["milter-inbound"] = service
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			project := validRouteProject(root)
			test.mutate(&project)
			if err := validateRoute(project, "inbound", root); err == nil {
				t.Fatal("hostile route drift was accepted")
			}
		})
	}
}

// TestValidatePostfixServiceRejectsMountAndNetworkDrift freezes queue and socket ownership.
func TestValidatePostfixServiceRejectsMountAndNetworkDrift(t *testing.T) {
	root := t.TempDir()
	valid := validPostfixService(root)
	if err := validatePostfixService(valid, root); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*composeService)
	}{
		{
			name: "writable socket",
			mutate: func(service *composeService) {
				service.Volumes[2].ReadOnly = false
			},
		},
		{
			name: "cross route alias",
			mutate: func(service *composeService) {
				service.Volumes[3].Source = service.Volumes[2].Source
			},
		},
		{
			name: "extra protected mount",
			mutate: func(service *composeService) {
				service.Volumes = append(service.Volumes, composeMount{
					Type: "bind", Source: "/protected", Target: "/protected", ReadOnly: true,
				})
			},
		},
		{
			name: "extra network",
			mutate: func(service *composeService) {
				service.Networks["daemon-control"] = nil
			},
		},
		{
			name: "dependency weakened",
			mutate: func(service *composeService) {
				service.DependsOn["milter-transit"] = composeDependency{
					Condition: "service_started", Required: true,
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := validPostfixService(root)
			test.mutate(&service)
			if err := validatePostfixService(service, root); err == nil {
				t.Fatal("hostile Postfix drift was accepted")
			}
		})
	}
}

// testProject returns one minimal project sufficient for demo comparison tests.
func testProject(_ string) composeProject {
	service := composeService{
		CapDrop:         []string{"ALL"},
		CPUs:            1,
		MemoryLimit:     "1",
		PidsLimit:       1,
		ReadOnly:        true,
		Restart:         "no",
		SecurityOptions: []string{"no-new-privileges:true"},
		StopGracePeriod: "1s",
		Ulimits:         map[string]composeUlimit{"nofile": {Soft: 1024, Hard: 1024}},
	}
	return composeProject{
		Name: "dkim2-postfix",
		Networks: map[string]composeNetwork{
			"daemon-control": {Internal: true},
			"mail":           {Internal: true},
		},
		Services: map[string]composeService{
			"daemon-inbound": service, "daemon-originator": service, "daemon-transit": service,
			"milter-inbound": service, "milter-originator": service, "milter-transit": service,
			"postfix": service,
		},
		Volumes: map[string]composeVolume{
			"postfix-config": {},
			"postfix-queue":  {},
		},
	}
}

// withPorts returns a copied service with the selected publication.
func withPorts(service composeService, ports []composePort) composeService {
	service.Ports = ports
	return service
}

// validRouteProject returns one exact inbound route for validator tests.
func validRouteProject(root string) composeProject {
	arguments := map[string]string{
		"CREATED": "1970-01-01T00:00:00Z", "DIRTY": "clean",
		"REVISION": strings.Repeat("0", 40), "SOURCE_DATE_EPOCH": "0",
		"VERSION": "0.0.0-dev",
	}
	base := filepath.Join(root, "deployments", "postfix-compose")
	tmpfs := []string{
		"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000",
	}
	return composeProject{Services: map[string]composeService{
		"daemon-inbound": {
			Build: &composeBuild{
				Context: root, Dockerfile: "build/container/Dockerfile",
				Arguments: arguments, Target: "dkim2d",
			},
			Command: []string{"serve", "--config", "/etc/dkim2d/config.yaml"},
			Image:   "dkim2d:local", User: "2000:2000",
			Networks: map[string]any{"daemon-control": nil},
			Healthcheck: composeHealthcheck{
				Test:     []string{"CMD", "/usr/local/bin/dkim2d", "probe"},
				Interval: "10s", Timeout: "3s", Retries: 6, StartPeriod: "5s",
			},
			PidsLimit: 64, MemoryLimit: "268435456", CPUs: 1,
			StopGracePeriod: "15s", Tmpfs: tmpfs,
			Volumes: []composeMount{
				{
					Type: "bind", Source: filepath.Join(base, "state", "daemon", "inbound"),
					Target: "/var/lib/dkim2d", ReadOnly: true,
				},
				{
					Type: "bind", Source: filepath.Join(base, "config", "dkim2d-inbound.yaml"),
					Target: "/etc/dkim2d/config.yaml", ReadOnly: true,
				},
			},
		},
		"milter-inbound": {
			Build: &composeBuild{
				Context: root, Dockerfile: "build/container/Dockerfile",
				Arguments: arguments, Target: "dkim2-milter",
			},
			Command: []string{"serve", "--config", "/etc/dkim2-milter/inbound.yaml"},
			Image:   "dkim2-milter:local", User: "2000:103",
			NetworkMode: "service:daemon-inbound",
			DependsOn: map[string]composeDependency{
				"daemon-inbound": {Condition: "service_healthy", Required: true},
			},
			Healthcheck: composeHealthcheck{
				Test: []string{
					"CMD", "/usr/local/bin/dkim2-milter", "probe",
					"--config", "/etc/dkim2-milter/inbound.yaml",
				},
				Interval: "10s", Timeout: "2s", Retries: 6, StartPeriod: "5s",
			},
			PidsLimit: 64, MemoryLimit: "268435456", CPUs: 1,
			StopGracePeriod: "15s", Tmpfs: tmpfs,
			Volumes: []composeMount{
				{
					Type: "bind", Source: filepath.Join(base, "state", "sockets", "inbound"),
					Target: "/run/dkim2",
				},
				{
					Type: "bind", Source: filepath.Join(base, "state", "milter", "inbound"),
					Target: "/etc/dkim2-milter", ReadOnly: true,
				},
			},
		},
	}}
}

// validPostfixService returns one exact Postfix service for validator tests.
func validPostfixService(root string) composeService {
	base := filepath.Join(root, "deployments", "postfix-compose")
	return composeService{
		CapAdd: []string{
			"CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE",
			"SETGID", "SETUID", "SYS_CHROOT",
		},
		GroupAdd: []string{"103"},
		Image:    "chrroessner/postfix:3.11.6-r2@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c",
		Networks: map[string]any{"mail": nil},
		DependsOn: map[string]composeDependency{
			"milter-inbound":    {Condition: "service_healthy", Required: true},
			"milter-originator": {Condition: "service_healthy", Required: true},
			"milter-transit":    {Condition: "service_healthy", Required: true},
		},
		Healthcheck: composeHealthcheck{
			Test:     []string{"CMD", "/usr/local/bin/docker-healthcheck.sh"},
			Interval: "10s", Timeout: "3s", Retries: 6, StartPeriod: "10s",
		},
		PidsLimit: 128, MemoryLimit: "536870912", CPUs: 1.5,
		StopGracePeriod: "30s",
		Tmpfs: []string{
			"/run:rw,nosuid,nodev,size=32m,mode=0755",
			"/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
			"/var/lib/postfix:rw,nosuid,nodev,size=32m,mode=0755",
		},
		Volumes: []composeMount{
			{Type: "volume", Source: "postfix-config", Target: "/etc/postfix"},
			{Type: "volume", Source: "postfix-queue", Target: "/var/spool/postfix"},
			{
				Type: "bind", Source: filepath.Join(base, "state", "sockets", "inbound"),
				Target: "/run/dkim2/inbound", ReadOnly: true,
			},
			{
				Type: "bind", Source: filepath.Join(base, "state", "sockets", "originator"),
				Target: "/run/dkim2/originator", ReadOnly: true,
			},
			{
				Type: "bind", Source: filepath.Join(base, "state", "sockets", "transit"),
				Target: "/run/dkim2/transit", ReadOnly: true,
			},
			{
				Type: "bind", Source: filepath.Join(base, "postfix", "main.cf"),
				Target: "/etc/postfix/custom-config/main.cf", ReadOnly: true,
			},
			{
				Type: "bind", Source: filepath.Join(base, "postfix", "master.cf"),
				Target: "/etc/postfix/custom-config/master.cf", ReadOnly: true,
			},
		},
	}
}
