package conformance

import (
	"errors"
	"slices"
	"sort"
)

const (
	postfixFragmentSchema = "dkim2.postfix-qualification-fragment.v1"
	postfixProfile        = "postfix"
)

// PostfixQualificationReport is the strict real-Postfix qualification evidence.
type PostfixQualificationReport struct {
	Schema                  string                              `json:"schema"`
	MessageDraft            string                              `json:"message_draft"`
	DNSDraft                string                              `json:"dns_draft"`
	BaseRevision            string                              `json:"base_revision"`
	CandidateSnapshotSHA256 string                              `json:"candidate_snapshot_sha256"`
	ManifestSHA256          string                              `json:"manifest_sha256"`
	Profile                 string                              `json:"profile"`
	Platform                string                              `json:"platform"`
	ProducerSHA256          string                              `json:"producer_sha256"`
	State                   string                              `json:"state"`
	ImageIdentities         map[string]string                   `json:"image_identities"`
	RuntimeIdentity         PostfixQualificationRuntimeIdentity `json:"runtime_identity"`
	Fragments               []PostfixQualificationFragment      `json:"fragments"`
	Topology                PostfixQualificationTopology        `json:"topology"`
	Cleanup                 string                              `json:"cleanup"`
}

// PostfixQualificationRuntimeIdentity binds the tested Postfix and executable set.
type PostfixQualificationRuntimeIdentity struct {
	Schema         string            `json:"schema"`
	PostfixVersion string            `json:"postfix_version"`
	Executables    map[string]string `json:"executables"`
}

// PostfixQualificationFragment records one closed qualification case group.
type PostfixQualificationFragment struct {
	Schema string   `json:"schema"`
	State  string   `json:"state"`
	Cases  []string `json:"cases"`
}

// PostfixQualificationTopology records the security-relevant adapter wiring.
type PostfixQualificationTopology struct {
	ComposeHostPorts     int    `json:"compose_host_ports"`
	DaemonHTTP           string `json:"daemon_http"`
	MilterTransport      string `json:"milter_transport"`
	PostfixProtocol      int    `json:"postfix_protocol"`
	PostfixDefaultAction string `json:"postfix_default_action"`
	MilterConnectTimeout string `json:"milter_connect_timeout"`
	MilterCommandTimeout string `json:"milter_command_timeout"`
	MilterContentTimeout string `json:"milter_content_timeout"`
}

// ValidatePostfixQualificationReport enforces exact provenance, runtime, topology, cases, and cleanup.
func ValidatePostfixQualificationReport(
	report PostfixQualificationReport,
	manifestDigest, revision, snapshotDigest, producerDigest string,
) error {
	if err := validatePostfixReportBinding(
		report,
		manifestDigest,
		revision,
		snapshotDigest,
		producerDigest,
	); err != nil {
		return err
	}
	if err := validatePostfixRuntimeIdentity(report); err != nil {
		return err
	}
	if err := validatePostfixTopology(report.Topology); err != nil {
		return err
	}
	return validatePostfixFragments(report.Fragments)
}

// validatePostfixReportBinding checks report provenance and immutable images.
func validatePostfixReportBinding(
	report PostfixQualificationReport,
	manifestDigest, revision, snapshotDigest, producerDigest string,
) error {
	if report.Schema != "dkim2.postfix-qualification-report.v1" ||
		report.MessageDraft != MessageDraft ||
		report.DNSDraft != DNSDraft ||
		report.BaseRevision != revision ||
		report.CandidateSnapshotSHA256 != snapshotDigest ||
		report.ManifestSHA256 != manifestDigest ||
		report.Profile != postfixProfile ||
		report.Platform != platformLinux ||
		report.ProducerSHA256 != producerDigest ||
		report.State != statePass ||
		report.Cleanup != "project_scoped_pass" {
		return errors.New("runner_identity")
	}
	if len(report.ImageIdentities) != 3 ||
		report.ImageIdentities["debian"] != "debian@sha256:4e401d95de7083948053197a9c3913343cd06b706bf15eb6a0c3ccd26f436a0e" ||
		report.ImageIdentities["golang"] != "golang@sha256:ae5a2316d12f3e78fd99177dad452e6ad4f240af2d71d57b480c3477f250fec6" ||
		report.ImageIdentities["postfix"] != "chrroessner/postfix@sha256:d4b349ce665ba291444e55862ac842e3d4e612596520a9ba65a7b9bf00f9aa3c" {
		return errors.New("runner_identity")
	}
	return nil
}

// validatePostfixRuntimeIdentity checks the exact runtime and executable set.
func validatePostfixRuntimeIdentity(report PostfixQualificationReport) error {
	if report.RuntimeIdentity.Schema != "dkim2.postfix-qualification-identity.v1" ||
		report.RuntimeIdentity.PostfixVersion != "3.11.6" ||
		len(report.RuntimeIdentity.Executables) != 3 {
		return errors.New("runner_identity")
	}
	for _, name := range []string{"dkim2-milter", "dkim2d", "qualify"} {
		if !isSHA256(report.RuntimeIdentity.Executables[name]) {
			return errors.New("runner_identity")
		}
	}
	return nil
}

// validatePostfixTopology checks the bounded adapter and Postfix wiring facts.
func validatePostfixTopology(topology PostfixQualificationTopology) error {
	if topology.ComposeHostPorts != 0 ||
		topology.DaemonHTTP != "canonical_loopback_only" ||
		topology.MilterTransport != "owned_unix_sockets_only" ||
		topology.PostfixProtocol != 6 ||
		topology.PostfixDefaultAction != "tempfail" ||
		topology.MilterConnectTimeout != "2s" ||
		topology.MilterCommandTimeout != "5s" ||
		topology.MilterContentTimeout != "5s" {
		return errors.New("runner_identity")
	}
	return nil
}

// validatePostfixFragments checks ordered fragment shape and exact case closure.
func validatePostfixFragments(fragments []PostfixQualificationFragment) error {
	var cases []string
	for _, fragment := range fragments {
		if fragment.Schema != postfixFragmentSchema ||
			fragment.State != statePass ||
			!slices.IsSorted(fragment.Cases) {
			return errors.New("runner_failure")
		}
		cases = append(cases, fragment.Cases...)
	}
	sort.Strings(cases)
	expected := []string{
		"daemon_loopback_topology",
		"daemon_unavailable_fixed_tempfail",
		"inbound_cryptographic_pass",
		"injected_null_sender_has_no_dsn_evidence",
		"local_sendmail_signing",
		"non_smtp_milter_unavailable_tempfail",
		"postfix_bounce_dsn_evidence_signing",
		"postfix_normal_cleanup_dsn_routing",
		"postfix_received_visibility",
		"smtp_milter_unavailable_tempfail",
		"smtp_origin_signing",
	}
	if !slices.Equal(cases, expected) {
		return errors.New("runner_missing_case")
	}
	return nil
}
