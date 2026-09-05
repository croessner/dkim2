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
	writePostfixFixtures(t, base)
	if err := validatePostfix(root); err != nil {
		t.Fatal(err)
	}
	hostile := strings.Replace(expectedMasterCF, "transit/milter.sock", "inbound/milter.sock", 1)
	if err := os.WriteFile(filepath.Join(base, "master.cf"), []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePostfix(root); err == nil {
		t.Fatal("route capability conflation was accepted")
	}
}

// TestValidatePostfixFreezesPropagationOverlayConfiguration proves the
// propagation main.cf and master.cf are frozen exactly, so a parser-level
// defect in either file cannot ship unnoticed again.
func TestValidatePostfixFreezesPropagationOverlayConfiguration(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		file    string
		content string
	}{
		{
			name: "flat inline table", file: "propagation-main.cf",
			content: strings.Replace(expectedPropagationMainCF, "inline:{ {bounces@operator.test = OK} }", "inline:{ bounces@operator.test = OK }", 1),
		},
		{
			name: "unauthorized return path", file: "propagation-main.cf",
			content: strings.Replace(expectedPropagationMainCF, "    check_recipient_access inline:{ {bounces@operator.test = OK} },\n", "", 1),
		},
		{
			name: "multi-recipient transport", file: "propagation-main.cf",
			content: strings.Replace(expectedPropagationMainCF, "dsn_propagator_destination_recipient_limit = 1", "dsn_propagator_destination_recipient_limit = 2", 1),
		},
		{
			name: "unknown backoff parameter", file: "propagation-main.cf",
			content: strings.Replace(expectedPropagationMainCF, "maximal_backoff_time", "maximum_backoff_time", 1),
		},
		{
			name: "milter on reinjection listener", file: "propagation-master.cf",
			content: strings.Replace(expectedPropagationMasterCF, "  -o smtpd_milters=\n  -o non_smtpd_milters=\n", "  -o smtpd_milters=unix:/run/dkim2/inbound/milter.sock\n  -o non_smtpd_milters=\n", 1),
		},
		{
			name: "missing transport", file: "propagation-master.cf",
			content: strings.Replace(expectedPropagationMasterCF, "dsn_propagator unix  -       -       n       -       -       lmtp\n", "", 1),
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "deployments", "postfix-compose", "postfix")
			if err := os.MkdirAll(base, 0o700); err != nil {
				t.Fatal(err)
			}
			writePostfixFixtures(t, base)
			if err := validatePostfix(root); err != nil {
				t.Fatal(err)
			}
			if testCase.content == expectedPropagationMainCF || testCase.content == expectedPropagationMasterCF {
				t.Fatal("mutation did not change the frozen configuration")
			}
			if err := os.WriteFile(filepath.Join(base, testCase.file), []byte(testCase.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validatePostfix(root); err == nil {
				t.Fatal("propagation configuration drift was accepted")
			}
		})
	}
}

// writePostfixFixtures writes the four frozen Postfix files below base.
func writePostfixFixtures(t *testing.T, base string) {
	t.Helper()
	for name, content := range map[string]string{
		"main.cf": expectedMainCF, "master.cf": expectedMasterCF,
		"propagation-main.cf": expectedPropagationMainCF, "propagation-master.cf": expectedPropagationMasterCF,
	} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestValidatePropagationRejectsTopologyDrift freezes the propagation overlay:
// the adapter and Postfix must share the propagation daemon's namespace, the
// base services must stay untouched, and no mount may reach protected state.
func TestValidatePropagationRejectsTopologyDrift(t *testing.T) {
	root := t.TempDir()
	defaultProject := validRouteProject(root)
	defaultProject.Services["postfix"] = validPostfixService(root)
	defaultProject.Networks = map[string]composeNetwork{"daemon-control": {Internal: true}, "mail": {Internal: true}}
	defaultProject.Volumes = map[string]composeVolume{"postfix-config": {}, "postfix-queue": {}}
	if err := validatePropagation(defaultProject, validPropagationProject(root, defaultProject), root); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(root, "deployments", "postfix-compose")
	tests := []struct {
		name   string
		mutate func(*composeProject)
	}{
		{name: "postfix keeps the mail network", mutate: func(project *composeProject) {
			service := project.Services["postfix"]
			service.Networks = map[string]any{"mail": nil}
			project.Services["postfix"] = service
		}},
		{name: "postfix outside the propagation namespace", mutate: func(project *composeProject) {
			service := project.Services["postfix"]
			service.NetworkMode = ""
			project.Services["postfix"] = service
		}},
		{name: "postfix without the propagation socket", mutate: func(project *composeProject) {
			service := project.Services["postfix"]
			service.Volumes = service.Volumes[:7]
			project.Services["postfix"] = service
		}},
		{name: "postfix mounts propagator configuration", mutate: func(project *composeProject) {
			service := project.Services["postfix"]
			service.Volumes = append(service.Volumes, composeMount{
				Type: "bind", Source: filepath.Join(base, "state", "propagator"), Target: "/mnt", ReadOnly: true,
			})
			project.Services["postfix"] = service
		}},
		{name: "postfix uses base main.cf", mutate: func(project *composeProject) {
			service := project.Services["postfix"]
			service.Volumes[5].Source = filepath.Join(base, "postfix", "main.cf")
			project.Services["postfix"] = service
		}},
		{name: "adapter on its own network", mutate: func(project *composeProject) {
			service := project.Services["dsn-propagator"]
			service.NetworkMode = ""
			service.Networks = map[string]any{"mail": nil}
			project.Services["dsn-propagator"] = service
		}},
		{name: "adapter without health dependency", mutate: func(project *composeProject) {
			service := project.Services["dsn-propagator"]
			service.DependsOn = nil
			project.Services["dsn-propagator"] = service
		}},
		{name: "adapter mounts daemon state", mutate: func(project *composeProject) {
			service := project.Services["dsn-propagator"]
			service.Volumes[1].Source = filepath.Join(base, "state", "daemon", "propagation")
			project.Services["dsn-propagator"] = service
		}},
		{name: "adapter published port", mutate: func(project *composeProject) {
			service := project.Services["dsn-propagator"]
			service.Ports = []composePort{{Mode: "ingress", HostIP: "127.0.0.1", Target: 24, Published: "24", Protocol: "tcp"}}
			project.Services["dsn-propagator"] = service
		}},
		{name: "adapter mutable image", mutate: func(project *composeProject) {
			service := project.Services["dsn-propagator"]
			service.Image = "untrusted.example/dkim2-dsn-propagator:mutable"
			project.Services["dsn-propagator"] = service
		}},
		{name: "daemon off the control network", mutate: func(project *composeProject) {
			service := project.Services["daemon-propagation"]
			service.Networks = map[string]any{"mail": nil}
			project.Services["daemon-propagation"] = service
		}},
		{name: "daemon reuses a route configuration", mutate: func(project *composeProject) {
			service := project.Services["daemon-propagation"]
			service.Volumes[1].Source = filepath.Join(base, "config", "dkim2d-inbound.yaml")
			project.Services["daemon-propagation"] = service
		}},
		{name: "base route changed", mutate: func(project *composeProject) {
			service := project.Services["milter-inbound"]
			service.NetworkMode = "service:daemon-propagation"
			project.Services["milter-inbound"] = service
		}},
		{name: "extra service", mutate: func(project *composeProject) {
			project.Services["debug"] = composeService{}
		}},
		{name: "network drift", mutate: func(project *composeProject) {
			project.Networks["mail"] = composeNetwork{Internal: false}
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			project := validPropagationProject(root, defaultProject)
			testCase.mutate(&project)
			if err := validatePropagation(defaultProject, project, root); err == nil {
				t.Fatal("propagation topology drift was accepted")
			}
		})
	}
}

// validPropagationProject returns one exact propagation overlay rendering of
// the supplied default project for validator tests.
func validPropagationProject(root string, defaultProject composeProject) composeProject {
	arguments := map[string]string{
		"CREATED": "1970-01-01T00:00:00Z", "DIRTY": "clean",
		"REVISION": strings.Repeat("0", 40), "SOURCE_DATE_EPOCH": "0",
		"VERSION": "0.0.0-dev",
	}
	base := filepath.Join(root, "deployments", "postfix-compose")
	project := composeProject{
		Name:     defaultProject.Name,
		Networks: map[string]composeNetwork{},
		Volumes:  map[string]composeVolume{},
		Services: map[string]composeService{},
	}
	for name, network := range defaultProject.Networks {
		project.Networks[name] = network
	}
	for name, volume := range defaultProject.Volumes {
		project.Volumes[name] = volume
	}
	for name, service := range defaultProject.Services {
		project.Services[name] = service
	}
	postfix := defaultProject.Services["postfix"]
	postfix.NetworkMode = "service:daemon-propagation"
	postfix.Networks = nil
	postfix.DependsOn = map[string]composeDependency{
		"daemon-propagation": {Condition: "service_started", Required: true, Restart: true},
		"dsn-propagator":     {Condition: "service_healthy", Required: true},
		"milter-inbound":     {Condition: "service_healthy", Required: true},
		"milter-originator":  {Condition: "service_healthy", Required: true},
		"milter-transit":     {Condition: "service_healthy", Required: true},
	}
	postfix.Volumes = append([]composeMount(nil), defaultProject.Services["postfix"].Volumes[:5]...)
	postfix.Volumes = append(postfix.Volumes,
		composeMount{Type: "bind", Source: filepath.Join(base, "postfix", "propagation-main.cf"), Target: "/etc/postfix/custom-config/main.cf", ReadOnly: true},
		composeMount{Type: "bind", Source: filepath.Join(base, "postfix", "propagation-master.cf"), Target: "/etc/postfix/custom-config/master.cf", ReadOnly: true},
		composeMount{Type: "bind", Source: filepath.Join(base, "state", "sockets", "propagation"), Target: "/run/dkim2/propagation", ReadOnly: true},
	)
	project.Services["postfix"] = postfix
	project.Services["daemon-propagation"] = composeService{
		Build: &composeBuild{
			Context: root, Dockerfile: "build/container/Dockerfile",
			Arguments: arguments, Target: "dkim2d",
		},
		Command: []string{"serve", "--config", "/etc/dkim2d/config.yaml"},
		Image:   "dkim2d:local", User: "2000:2000",
		Networks: map[string]any{"daemon-control": nil, "mail": nil},
		Healthcheck: composeHealthcheck{
			Test:     []string{"CMD", "/usr/local/bin/dkim2d", "probe"},
			Interval: "10s", Timeout: "3s", Retries: 6, StartPeriod: "5s",
		},
		CapDrop: []string{"ALL"}, SecurityOptions: []string{"no-new-privileges:true"},
		ReadOnly: true, Restart: "no",
		Ulimits:   map[string]composeUlimit{"nofile": {Soft: 1024, Hard: 1024}},
		PidsLimit: 64, MemoryLimit: "268435456", CPUs: 1,
		StopGracePeriod: "15s",
		Tmpfs:           []string{"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000"},
		Volumes: []composeMount{
			{Type: "bind", Source: filepath.Join(base, "state", "daemon", "propagation"), Target: "/var/lib/dkim2d", ReadOnly: true},
			{Type: "bind", Source: filepath.Join(base, "config", "dkim2d-propagation.yaml"), Target: "/etc/dkim2d/config.yaml", ReadOnly: true},
		},
	}
	project.Services["dsn-propagator"] = composeService{
		Build: &composeBuild{
			Context: root, Dockerfile: "build/container/Dockerfile",
			Arguments: arguments, Target: "dkim2-dsn-propagator",
		},
		Command: []string{"serve", "--config", "/etc/dkim2-dsn-propagator/config.yaml"},
		Image:   "dkim2-dsn-propagator:local", User: "2000:103",
		NetworkMode: "service:daemon-propagation",
		DependsOn: map[string]composeDependency{
			"daemon-propagation": {Condition: "service_healthy", Required: true},
		},
		Healthcheck: composeHealthcheck{
			Test: []string{
				"CMD", "/usr/local/bin/dkim2-dsn-propagator", "probe",
				"--config", "/etc/dkim2-dsn-propagator/config.yaml",
			},
			Interval: "10s", Timeout: "2s", Retries: 6, StartPeriod: "5s",
		},
		CapDrop: []string{"ALL"}, SecurityOptions: []string{"no-new-privileges:true"},
		ReadOnly: true, Restart: "no",
		Ulimits:   map[string]composeUlimit{"nofile": {Soft: 1024, Hard: 1024}},
		PidsLimit: 64, MemoryLimit: "268435456", CPUs: 1,
		StopGracePeriod: "15s",
		Tmpfs:           []string{"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=103"},
		Volumes: []composeMount{
			{Type: "bind", Source: filepath.Join(base, "state", "sockets", "propagation"), Target: "/run/dkim2/propagation"},
			{Type: "bind", Source: filepath.Join(base, "state", "propagator"), Target: "/etc/dkim2-dsn-propagator", ReadOnly: true},
		},
	}
	return project
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
