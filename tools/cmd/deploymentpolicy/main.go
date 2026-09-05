// Command deploymentpolicy validates the rendered DKIM2 Postfix Compose boundary.
//
//nolint:goconst // Closed policy assertions keep expected Compose literals at each boundary.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/croessner/dkim2/tools/internal/artifactpath"
	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const (
	maximumComposeBytes = 4 << 20
	maximumConfigBytes  = 1 << 20
)

var errPolicy = errors.New("deployment_policy")

type composeProject struct {
	Name     string                    `json:"name"`
	Networks map[string]composeNetwork `json:"networks"`
	Services map[string]composeService `json:"services"`
	Volumes  map[string]composeVolume  `json:"volumes"`
}

type composeNetwork struct {
	Name     string         `json:"name"`
	IPAM     map[string]any `json:"ipam"`
	Internal bool           `json:"internal"`
}

type composeVolume struct {
	Name string `json:"name"`
}

type composeService struct {
	Build           *composeBuild                `json:"build"`
	CapAdd          []string                     `json:"cap_add"`
	CapDrop         []string                     `json:"cap_drop"`
	Command         []string                     `json:"command"`
	CPUs            float64                      `json:"cpus"`
	DependsOn       map[string]composeDependency `json:"depends_on"`
	Entrypoint      any                          `json:"entrypoint"`
	GroupAdd        []string                     `json:"group_add"`
	Healthcheck     composeHealthcheck           `json:"healthcheck"`
	Image           string                       `json:"image"`
	MemoryLimit     string                       `json:"mem_limit"`
	NetworkMode     string                       `json:"network_mode"`
	Networks        map[string]any               `json:"networks"`
	PidsLimit       int                          `json:"pids_limit"`
	Ports           []composePort                `json:"ports"`
	ReadOnly        bool                         `json:"read_only"`
	Restart         string                       `json:"restart"`
	SecurityOptions []string                     `json:"security_opt"`
	StopGracePeriod string                       `json:"stop_grace_period"`
	Tmpfs           []string                     `json:"tmpfs"`
	Ulimits         map[string]composeUlimit     `json:"ulimits"`
	User            string                       `json:"user"`
	Volumes         []composeMount               `json:"volumes"`
}

type composeBuild struct {
	Context    string            `json:"context"`
	Dockerfile string            `json:"dockerfile"`
	Arguments  map[string]string `json:"args"`
	Target     string            `json:"target"`
}

type composeDependency struct {
	Condition string `json:"condition"`
	Required  bool   `json:"required"`
	// Restart is rendered for a network-namespace provider: the dependent is
	// restarted when the provider is, which is what sharing the namespace requires.
	Restart bool `json:"restart"`
}

type composeHealthcheck struct {
	Test        []string `json:"test"`
	Interval    string   `json:"interval"`
	Timeout     string   `json:"timeout"`
	Retries     int      `json:"retries"`
	StartPeriod string   `json:"start_period"`
}

type composePort struct {
	Mode      string `json:"mode"`
	HostIP    string `json:"host_ip"`
	Target    int    `json:"target"`
	Published string `json:"published"`
	Protocol  string `json:"protocol"`
}

type composeUlimit struct {
	Soft int `json:"soft"`
	Hard int `json:"hard"`
}

type composeMount struct {
	Type     string         `json:"type"`
	Source   string         `json:"source"`
	Target   string         `json:"target"`
	ReadOnly bool           `json:"read_only"`
	Volume   map[string]any `json:"volume"`
}

const expectedMainCF = `compatibility_level = 3.11
myhostname = mx.operator.test
mydomain = operator.test
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost
relay_domains =
relayhost =
smtpd_relay_restrictions = permit_mynetworks, reject_unauth_destination
smtpd_milters = unix:/run/dkim2/inbound/milter.sock
non_smtpd_milters = unix:/run/dkim2/originator/milter.sock
milter_protocol = 6
milter_default_action = tempfail
milter_connect_timeout = 2s
milter_command_timeout = 5s
milter_content_timeout = 5s
maillog_file = /dev/stdout
`

const expectedMasterCF = `smtp      inet  n       -       n       -       -       smtpd
127.0.0.1:2526 inet n   -       n       -       -       smtpd
  -o smtpd_milters=unix:/run/dkim2/transit/milter.sock
  -o non_smtpd_milters=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
`

// expectedPropagationMainCF is the frozen Postfix main.cf of the propagation
// overlay: the base configuration plus the reserved return-path permit, the
// one-recipient LMTP transport, and a minimum retry interval above the
// daemon's propagation lease.
const expectedPropagationMainCF = `compatibility_level = 3.11
myhostname = mx.operator.test
mydomain = operator.test
myorigin = $mydomain
inet_interfaces = all
inet_protocols = ipv4
mydestination = $myhostname, localhost.$mydomain, localhost
relay_domains =
relayhost =
smtpd_relay_restrictions = permit_mynetworks,
    check_recipient_access inline:{ {bounces@operator.test = OK} },
    reject_unauth_destination
smtpd_milters = unix:/run/dkim2/inbound/milter.sock
non_smtpd_milters = unix:/run/dkim2/originator/milter.sock
milter_protocol = 6
milter_default_action = tempfail
milter_connect_timeout = 2s
milter_command_timeout = 5s
milter_content_timeout = 5s
maillog_file = /dev/stdout
transport_maps = inline:{ {bounces@operator.test = dsn_propagator:unix:/run/dkim2/propagation/lmtp.sock} }
dsn_propagator_destination_recipient_limit = 1
dsn_propagator_destination_concurrency_limit = 10
minimal_backoff_time = 600s
maximal_backoff_time = 4000s
`

// expectedPropagationMasterCF is the frozen Postfix master.cf of the
// propagation overlay: the base services plus the LMTP transport and the
// Milter-free loopback re-injection listener.
const expectedPropagationMasterCF = `smtp      inet  n       -       n       -       -       smtpd
127.0.0.1:2526 inet n   -       n       -       -       smtpd
  -o smtpd_milters=unix:/run/dkim2/transit/milter.sock
  -o non_smtpd_milters=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
pickup    unix  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      unix  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
relay     unix  -       -       n       -       -       smtp
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
postlog   unix-dgram n  -       n       -       1       postlogd
dsn_propagator unix  -       -       n       -       -       lmtp
  -o syslog_name=postfix/dsn-propagator
  -o lmtp_lhlo_name=$myhostname
127.0.0.1:10025 inet n       -       n       -       -       smtpd
  -o syslog_name=postfix/dkim2-reinjection
  -o smtpd_milters=
  -o non_smtpd_milters=
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject_unauth_destination
  -o content_filter=
  -o receive_override_options=no_address_mappings
`

// main validates one default, one explicit demo, and one propagation
// overlay rendering.
func main() {
	var defaultPath string
	var demoPath string
	var propagationPath string
	var root string
	flag.StringVar(&defaultPath, "default", "", "default Compose JSON rendering")
	flag.StringVar(&demoPath, "demo", "", "demo Compose JSON rendering")
	flag.StringVar(&propagationPath, "propagation", "", "propagation overlay Compose JSON rendering")
	flag.StringVar(&root, "root", "", "repository root")
	flag.Parse()
	if flag.NArg() != 0 || defaultPath == "" || demoPath == "" || propagationPath == "" || root == "" {
		fmt.Fprintln(os.Stderr, "usage: deploymentpolicy -default <json> -demo <json> -propagation <json> -root <root>")
		os.Exit(2)
	}
	if err := run(defaultPath, demoPath, propagationPath, root); err != nil {
		fmt.Fprintln(os.Stderr, "deployment policy violation")
		os.Exit(1)
	}
	fmt.Println("deployment policy passed")
}

// run validates every rendered topology and checked Postfix configuration.
func run(defaultPath, demoPath, propagationPath, root string) error {
	defaultProject, err := loadProject(defaultPath)
	if err != nil {
		return err
	}
	demoProject, err := loadProject(demoPath)
	if err != nil {
		return err
	}
	propagationProject, err := loadProject(propagationPath)
	if err != nil {
		return err
	}
	if err := validateDefault(defaultProject, root); err != nil {
		return err
	}
	if err := validateDemo(defaultProject, demoProject); err != nil {
		return err
	}
	if err := validatePropagation(defaultProject, propagationProject, root); err != nil {
		return err
	}
	return validatePostfix(root)
}

// loadProject reads one bounded duplicate-free Compose JSON rendering.
func loadProject(name string) (composeProject, error) {
	content, err := readRegular(name, maximumComposeBytes)
	if err != nil {
		return composeProject{}, err
	}
	if err := strictjson.Validate(content, 16, 50000); err != nil {
		return composeProject{}, errPolicy
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return composeProject{}, errPolicy
	}
	allowed := []string{"name", "networks", "services", "volumes", "x-daemon", "x-milter", "x-product-security"}
	for key := range raw {
		if !slices.Contains(allowed, key) {
			return composeProject{}, errPolicy
		}
	}
	var project composeProject
	closed, err := json.Marshal(map[string]json.RawMessage{
		"name": raw["name"], "networks": raw["networks"],
		"services": raw["services"], "volumes": raw["volumes"],
	})
	if err != nil || strictjson.Decode(closed, &project, 16, 50000) != nil {
		return composeProject{}, errPolicy
	}
	return project, nil
}

// validateDefault freezes the no-publication and least-authority topology.
func validateDefault(project composeProject, root string) error {
	required := []string{
		"daemon-inbound", "daemon-originator", "daemon-transit",
		"milter-inbound", "milter-originator", "milter-transit", "postfix",
	}
	if project.Name != "dkim2-postfix" ||
		!exactKeys(project.Services, required) ||
		!exactKeys(project.Networks, []string{"daemon-control", "mail"}) ||
		!reflect.DeepEqual(project.Networks["daemon-control"], composeNetwork{
			Name: "dkim2-postfix_daemon-control", IPAM: map[string]any{}, Internal: true,
		}) ||
		!reflect.DeepEqual(project.Networks["mail"], composeNetwork{
			Name: "dkim2-postfix_mail", IPAM: map[string]any{}, Internal: true,
		}) ||
		!reflect.DeepEqual(project.Volumes, map[string]composeVolume{
			"postfix-config": {Name: "dkim2-postfix_postfix-config"},
			"postfix-queue":  {Name: "dkim2-postfix_postfix-queue"},
		}) {
		return errPolicy
	}
	for _, name := range required {
		service := project.Services[name]
		productReadOnly := name == "postfix" || service.ReadOnly
		if len(service.Ports) != 0 || !productReadOnly ||
			!reflect.DeepEqual(service.CapDrop, []string{"ALL"}) ||
			!reflect.DeepEqual(service.SecurityOptions, []string{"no-new-privileges:true"}) ||
			service.PidsLimit < 1 || service.MemoryLimit == "" || service.CPUs <= 0 ||
			service.Restart != "no" || service.StopGracePeriod == "" ||
			service.Entrypoint != nil {
			return errPolicy
		}
		nofile, ok := service.Ulimits["nofile"]
		if !ok || nofile.Soft < 1024 || nofile.Hard != nofile.Soft {
			return errPolicy
		}
	}
	for _, route := range []string{"inbound", "originator", "transit"} {
		if err := validateRoute(project, route, root); err != nil {
			return err
		}
	}
	return validatePostfixService(project.Services["postfix"], root)
}

// validateRoute checks one separate daemon/Milter capability path.
//
//nolint:gocyclo // The closed route matrix stays linear so every field is visibly audited.
func validateRoute(project composeProject, route, root string) error {
	daemon := project.Services["daemon-"+route]
	milter := project.Services["milter-"+route]
	expectedBuildArgs := map[string]string{
		"CREATED": "1970-01-01T00:00:00Z", "DIRTY": "clean",
		"REVISION": strings.Repeat("0", 40), "SOURCE_DATE_EPOCH": "0",
		"VERSION": "0.0.0-dev",
	}
	if daemon.User != "2000:2000" || milter.User != "2000:103" ||
		!validBuild(daemon.Build, root, "dkim2d", expectedBuildArgs) ||
		!validBuild(milter.Build, root, "dkim2-milter", expectedBuildArgs) ||
		!validProductImage(daemon.Image, "dkim2d") ||
		!validProductImage(milter.Image, "dkim2-milter") ||
		!reflect.DeepEqual(daemon.Command, []string{"serve", "--config", "/etc/dkim2d/config.yaml"}) ||
		!reflect.DeepEqual(milter.Command, []string{
			"serve", "--config", "/etc/dkim2-milter/" + route + ".yaml",
		}) ||
		daemon.NetworkMode != "" || len(daemon.Networks) != 1 ||
		!exactKeys(daemon.Networks, []string{"daemon-control"}) ||
		milter.NetworkMode != "service:daemon-"+route || len(milter.Networks) != 0 ||
		!reflect.DeepEqual(milter.DependsOn, map[string]composeDependency{
			"daemon-" + route: {Condition: "service_healthy", Required: true},
		}) ||
		len(daemon.CapAdd) != 0 || len(milter.CapAdd) != 0 ||
		daemon.PidsLimit != 64 || milter.PidsLimit != 64 ||
		daemon.MemoryLimit != "268435456" || milter.MemoryLimit != "268435456" ||
		daemon.CPUs != 1 || milter.CPUs != 1 ||
		daemon.StopGracePeriod != "15s" || milter.StopGracePeriod != "15s" ||
		len(daemon.GroupAdd) != 0 || len(milter.GroupAdd) != 0 ||
		len(daemon.DependsOn) != 0 ||
		!reflect.DeepEqual(daemon.Healthcheck, composeHealthcheck{
			Test:     []string{"CMD", "/usr/local/bin/dkim2d", "probe"},
			Interval: "10s", Timeout: "3s", Retries: 6, StartPeriod: "5s",
		}) ||
		!reflect.DeepEqual(milter.Healthcheck, composeHealthcheck{
			Test: []string{
				"CMD", "/usr/local/bin/dkim2-milter", "probe",
				"--config", "/etc/dkim2-milter/" + route + ".yaml",
			},
			Interval: "10s", Timeout: "2s", Retries: 6, StartPeriod: "5s",
		}) ||
		!reflect.DeepEqual(daemon.Tmpfs, []string{
			"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000",
		}) ||
		!reflect.DeepEqual(milter.Tmpfs, []string{
			"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000",
		}) {
		return errPolicy
	}
	expectedDaemonConfig := filepath.Join(root, "deployments", "postfix-compose", "config", "dkim2d-"+route+".yaml")
	expectedDaemonState := filepath.Join(root, "deployments", "postfix-compose", "state", "daemon", route)
	expectedMilterState := filepath.Join(root, "deployments", "postfix-compose", "state", "milter", route)
	if len(daemon.Volumes) != 2 || len(milter.Volumes) != 2 ||
		!hasMount(daemon.Volumes, "bind", expectedDaemonConfig, "/etc/dkim2d/config.yaml", true) ||
		!hasMount(daemon.Volumes, "bind", expectedDaemonState, "/var/lib/dkim2d", true) ||
		!hasMount(milter.Volumes, "bind", expectedMilterState, "/etc/dkim2-milter", true) ||
		!hasMount(milter.Volumes, "bind",
			filepath.Join(root, "deployments", "postfix-compose", "state", "sockets", route),
			"/run/dkim2", false) {
		return errPolicy
	}
	return nil
}

// validatePostfixService checks queue, socket, image, and capability ownership.
func validatePostfixService(service composeService, root string) error {
	if service.User != "" || service.ReadOnly ||
		service.Image != "chrroessner/postfix:3.11.6-r2@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c" ||
		!reflect.DeepEqual(service.CapAdd, []string{
			"CHOWN", "DAC_OVERRIDE", "FOWNER", "NET_BIND_SERVICE",
			"SETGID", "SETUID", "SYS_CHROOT",
		}) ||
		!reflect.DeepEqual(service.GroupAdd, []string{"103"}) ||
		len(service.Networks) != 1 || !exactKeys(service.Networks, []string{"mail"}) ||
		service.NetworkMode != "" || service.Build != nil || len(service.Command) != 0 ||
		!reflect.DeepEqual(service.Healthcheck, composeHealthcheck{
			Test:     []string{"CMD", "/usr/local/bin/docker-healthcheck.sh"},
			Interval: "10s", Timeout: "3s", Retries: 6, StartPeriod: "10s",
		}) ||
		!reflect.DeepEqual(service.Tmpfs, []string{
			"/run:rw,nosuid,nodev,size=32m,mode=0755",
			"/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777",
			"/var/lib/postfix:rw,nosuid,nodev,size=32m,mode=0755",
		}) ||
		!reflect.DeepEqual(service.DependsOn, map[string]composeDependency{
			"milter-inbound":    {Condition: "service_healthy", Required: true},
			"milter-originator": {Condition: "service_healthy", Required: true},
			"milter-transit":    {Condition: "service_healthy", Required: true},
		}) ||
		service.PidsLimit != 128 || service.MemoryLimit != "536870912" ||
		service.CPUs != 1.5 || service.StopGracePeriod != "30s" {
		return errPolicy
	}
	base := filepath.Join(root, "deployments", "postfix-compose")
	if len(service.Volumes) != 7 ||
		!hasMount(service.Volumes, "volume", "postfix-config", "/etc/postfix", false) ||
		!hasMount(service.Volumes, "volume", "postfix-queue", "/var/spool/postfix", false) ||
		!hasMount(service.Volumes, "bind", filepath.Join(base, "state", "sockets", "inbound"), "/run/dkim2/inbound", true) ||
		!hasMount(service.Volumes, "bind", filepath.Join(base, "state", "sockets", "originator"), "/run/dkim2/originator", true) ||
		!hasMount(service.Volumes, "bind", filepath.Join(base, "state", "sockets", "transit"), "/run/dkim2/transit", true) ||
		!hasMount(service.Volumes, "bind", filepath.Join(base, "postfix", "main.cf"), "/etc/postfix/custom-config/main.cf", true) ||
		!hasMount(service.Volumes, "bind", filepath.Join(base, "postfix", "master.cf"), "/etc/postfix/custom-config/master.cf", true) {
		return errPolicy
	}
	for _, mount := range service.Volumes {
		if strings.Contains(mount.Source, "daemon/") ||
			strings.Contains(mount.Source, "milter/") ||
			strings.Contains(mount.Source, "docker.sock") {
			return errPolicy
		}
	}
	return nil
}

// validateDemo permits only the explicit loopback SMTP publication.
func validateDemo(defaultProject, demoProject composeProject) error {
	if !reflect.DeepEqual(defaultProject.Networks, demoProject.Networks) ||
		!reflect.DeepEqual(defaultProject.Volumes, demoProject.Volumes) ||
		!exactKeys(defaultProject.Services, keys(demoProject.Services)) {
		return errPolicy
	}
	for name, service := range defaultProject.Services {
		demoService := demoProject.Services[name]
		if name == "postfix" {
			service.Ports = []composePort{{
				Mode: "ingress", HostIP: "127.0.0.1", Target: 25,
				Published: "2525", Protocol: "tcp",
			}}
		}
		if !reflect.DeepEqual(service, demoService) {
			return errPolicy
		}
	}
	return nil
}

// validatePropagation freezes the propagation overlay: the base topology is
// unchanged apart from Postfix sharing the propagation daemon's network
// namespace, one additional daemon on both networks, and the LMTP adapter
// confined to that namespace, the propagation socket, and its own protected
// configuration.
//
//nolint:gocyclo // The closed overlay matrix stays linear so every field is visibly audited.
func validatePropagation(defaultProject, propagationProject composeProject, root string) error {
	base := filepath.Join(root, "deployments", "postfix-compose")
	if !reflect.DeepEqual(defaultProject.Networks, propagationProject.Networks) ||
		!reflect.DeepEqual(defaultProject.Volumes, propagationProject.Volumes) ||
		!exactKeys(propagationProject.Services, append(keys(defaultProject.Services),
			"daemon-propagation", "dsn-propagator")) {
		return errPolicy
	}
	for name, service := range defaultProject.Services {
		overlay := propagationProject.Services[name]
		if name != "postfix" {
			if !reflect.DeepEqual(service, overlay) {
				return errPolicy
			}
			continue
		}
		service.NetworkMode = "service:daemon-propagation"
		service.Networks = nil
		service.DependsOn = map[string]composeDependency{
			"daemon-propagation": {Condition: "service_started", Required: true, Restart: true},
			"dsn-propagator":     {Condition: "service_healthy", Required: true},
			"milter-inbound":     {Condition: "service_healthy", Required: true},
			"milter-originator":  {Condition: "service_healthy", Required: true},
			"milter-transit":     {Condition: "service_healthy", Required: true},
		}
		service.Volumes = nil
		expectedOverlayVolumes := overlay
		expectedOverlayVolumes.Volumes = nil
		if !reflect.DeepEqual(service, expectedOverlayVolumes) ||
			len(overlay.Volumes) != 8 ||
			!hasMount(overlay.Volumes, "volume", "postfix-config", "/etc/postfix", false) ||
			!hasMount(overlay.Volumes, "volume", "postfix-queue", "/var/spool/postfix", false) ||
			!hasMount(overlay.Volumes, "bind", filepath.Join(base, "state", "sockets", "inbound"), "/run/dkim2/inbound", true) ||
			!hasMount(overlay.Volumes, "bind", filepath.Join(base, "state", "sockets", "originator"), "/run/dkim2/originator", true) ||
			!hasMount(overlay.Volumes, "bind", filepath.Join(base, "state", "sockets", "transit"), "/run/dkim2/transit", true) ||
			!hasMount(overlay.Volumes, "bind", filepath.Join(base, "state", "sockets", "propagation"), "/run/dkim2/propagation", true) ||
			!hasMount(overlay.Volumes, "bind", filepath.Join(base, "postfix", "propagation-main.cf"), "/etc/postfix/custom-config/main.cf", true) ||
			!hasMount(overlay.Volumes, "bind", filepath.Join(base, "postfix", "propagation-master.cf"), "/etc/postfix/custom-config/master.cf", true) {
			return errPolicy
		}
		for _, mount := range overlay.Volumes {
			if strings.Contains(mount.Source, "daemon/") ||
				strings.Contains(mount.Source, "milter/") ||
				strings.Contains(mount.Source, "propagator/") ||
				strings.Contains(mount.Source, "docker.sock") {
				return errPolicy
			}
		}
	}
	daemon := propagationProject.Services["daemon-propagation"]
	adapter := propagationProject.Services["dsn-propagator"]
	expectedBuildArgs := map[string]string{
		"CREATED": "1970-01-01T00:00:00Z", "DIRTY": "clean",
		"REVISION": strings.Repeat("0", 40), "SOURCE_DATE_EPOCH": "0",
		"VERSION": "0.0.0-dev",
	}
	for _, service := range []composeService{daemon, adapter} {
		if len(service.Ports) != 0 || !service.ReadOnly ||
			!reflect.DeepEqual(service.CapDrop, []string{"ALL"}) ||
			!reflect.DeepEqual(service.SecurityOptions, []string{"no-new-privileges:true"}) ||
			len(service.CapAdd) != 0 || len(service.GroupAdd) != 0 ||
			service.PidsLimit != 64 || service.MemoryLimit != "268435456" || service.CPUs != 1 ||
			service.Restart != "no" || service.StopGracePeriod != "15s" ||
			service.Entrypoint != nil ||
			!reflect.DeepEqual(service.Ulimits, map[string]composeUlimit{"nofile": {Soft: 1024, Hard: 1024}}) {
			return errPolicy
		}
	}
	if daemon.User != "2000:2000" || adapter.User != "2000:103" ||
		!validBuild(daemon.Build, root, "dkim2d", expectedBuildArgs) ||
		!validBuild(adapter.Build, root, "dkim2-dsn-propagator", expectedBuildArgs) ||
		!validProductImage(daemon.Image, "dkim2d") ||
		!validProductImage(adapter.Image, "dkim2-dsn-propagator") ||
		!reflect.DeepEqual(daemon.Command, []string{"serve", "--config", "/etc/dkim2d/config.yaml"}) ||
		!reflect.DeepEqual(adapter.Command, []string{
			"serve", "--config", "/etc/dkim2-dsn-propagator/config.yaml",
		}) ||
		daemon.NetworkMode != "" || !exactKeys(daemon.Networks, []string{"daemon-control", "mail"}) ||
		adapter.NetworkMode != "service:daemon-propagation" || len(adapter.Networks) != 0 ||
		len(daemon.DependsOn) != 0 ||
		!reflect.DeepEqual(adapter.DependsOn, map[string]composeDependency{
			"daemon-propagation": {Condition: "service_healthy", Required: true},
		}) ||
		!reflect.DeepEqual(daemon.Healthcheck, composeHealthcheck{
			Test:     []string{"CMD", "/usr/local/bin/dkim2d", "probe"},
			Interval: "10s", Timeout: "3s", Retries: 6, StartPeriod: "5s",
		}) ||
		!reflect.DeepEqual(adapter.Healthcheck, composeHealthcheck{
			Test: []string{
				"CMD", "/usr/local/bin/dkim2-dsn-propagator", "probe",
				"--config", "/etc/dkim2-dsn-propagator/config.yaml",
			},
			Interval: "10s", Timeout: "2s", Retries: 6, StartPeriod: "5s",
		}) ||
		!reflect.DeepEqual(daemon.Tmpfs, []string{
			"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=2000",
		}) ||
		!reflect.DeepEqual(adapter.Tmpfs, []string{
			"/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=2000,gid=103",
		}) {
		return errPolicy
	}
	if len(daemon.Volumes) != 2 || len(adapter.Volumes) != 2 ||
		!hasMount(daemon.Volumes, "bind", filepath.Join(base, "config", "dkim2d-propagation.yaml"), "/etc/dkim2d/config.yaml", true) ||
		!hasMount(daemon.Volumes, "bind", filepath.Join(base, "state", "daemon", "propagation"), "/var/lib/dkim2d", true) ||
		!hasMount(adapter.Volumes, "bind", filepath.Join(base, "state", "propagator"), "/etc/dkim2-dsn-propagator", true) ||
		!hasMount(adapter.Volumes, "bind", filepath.Join(base, "state", "sockets", "propagation"), "/run/dkim2/propagation", false) {
		return errPolicy
	}
	return nil
}

// validatePostfix freezes Milter routes, callback policy, reserved
// identities, and the propagation overlay's Postfix configuration.
func validatePostfix(root string) error {
	for _, expected := range []struct {
		path    string
		content string
	}{
		{path: "deployments/postfix-compose/postfix/main.cf", content: expectedMainCF},
		{path: "deployments/postfix-compose/postfix/master.cf", content: expectedMasterCF},
		{path: "deployments/postfix-compose/postfix/propagation-main.cf", content: expectedPropagationMainCF},
		{path: "deployments/postfix-compose/postfix/propagation-master.cf", content: expectedPropagationMasterCF},
	} {
		content, err := artifactpath.ReadFile(root, expected.path, maximumConfigBytes)
		if err != nil {
			return err
		}
		if string(content) != expected.content {
			return errPolicy
		}
	}
	return nil
}

// readRegular reads one descriptor-confined stable regular file.
func readRegular(name string, limit int64) ([]byte, error) {
	absolute, err := filepath.Abs(name)
	if err != nil {
		return nil, errPolicy
	}
	return artifactpath.ReadFile(filepath.Dir(absolute), filepath.Base(absolute), limit)
}

// validBuild freezes one exact local product build contract.
func validBuild(
	build *composeBuild,
	root string,
	target string,
	arguments map[string]string,
) bool {
	return build != nil &&
		build.Context == root &&
		build.Dockerfile == "build/container/Dockerfile" &&
		build.Target == target &&
		reflect.DeepEqual(build.Arguments, arguments)
}

// validProductImage admits an exact local build name or protected GHCR digest.
func validProductImage(image, product string) bool {
	if image == product+":local" {
		return true
	}
	prefix := "ghcr.io/croessner/" + product + "@sha256:"
	if !strings.HasPrefix(image, prefix) || len(image) != len(prefix)+64 {
		return false
	}
	for _, character := range image[len(prefix):] {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// exactKeys reports whether a map has exactly the expected keys.
func exactKeys[T any](values map[string]T, expected []string) bool {
	actual := keys(values)
	slices.Sort(actual)
	copyExpected := slices.Clone(expected)
	slices.Sort(copyExpected)
	return slices.Equal(actual, copyExpected)
}

// keys returns one map's keys.
func keys[T any](values map[string]T) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	return result
}

// hasMount reports whether one exact mount exists.
func hasMount(mounts []composeMount, kind, source, target string, readOnly bool) bool {
	for _, mount := range mounts {
		if mount.Type == kind && mount.Source == source &&
			mount.Target == target && mount.ReadOnly == readOnly {
			return true
		}
	}
	return false
}
