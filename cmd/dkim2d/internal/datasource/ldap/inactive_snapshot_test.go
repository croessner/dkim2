package ldap

import (
	"context"
	"testing"
	"time"

	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/datasourceadmin"
	"github.com/croessner/dkim2/provider"
)

const (
	inactiveCampaignHandleID  = "inactive-handle"
	inactiveCampaignProfileID = "inactive-profile"
	inactiveCampaignDomain    = "inactive.test"
)

// TestInactiveCampaignLoadsCompleteRuntime exercises v3 digest verification,
// private-key registry construction, and runtime readiness with an inactive
// sibling. Only the active profile may be projected into signing authority.
func TestInactiveCampaignLoadsCompleteRuntime(t *testing.T) {
	records := inactiveCampaignRecords(t)
	defer clearEntries(records.KeyMaterial)
	client := &fakeClient{
		records: records, positions: make(map[RecordClass]int),
		pages: map[RecordClass][]Page{
			RecordClassHandle:      {{Entries: records.Handles, Bytes: 128}},
			RecordClassProfile:     {{Entries: records.Profiles, Bytes: 128}},
			RecordClassCredential:  {{Entries: records.Credentials, Bytes: 512}},
			RecordClassPolicy:      {{Entries: records.Policies, Bytes: 256}},
			RecordClassKeyMaterial: {{Entries: records.KeyMaterial, Bytes: 512}},
		},
	}
	loader, err := NewLoader(fakeConnector{client: client}, provider.DefaultLimits(), 2, 1<<20, 5*time.Second)
	if err != nil {
		t.Fatal("construct inactive campaign loader")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	runtime, err := datasourceruntime.New(ctx, loader, 5*time.Second)
	if err != nil || !runtime.Ready() {
		t.Fatal("complete inactive campaign prevented runtime readiness")
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	lease, err := runtime.Acquire(t.Context())
	if err != nil {
		t.Fatal("acquire immutable campaign generation")
	}
	t.Cleanup(func() { _ = lease.Close() })
	active, err := lease.ResolvePolicy(t.Context(), "tenant", testDomain, provider.ProfileUseOriginator, time.Now().UTC())
	if err != nil || !active.Valid() {
		t.Fatal("active campaign profile could not authorize signing")
	}
	inactive, err := lease.ResolvePolicy(t.Context(), "tenant", inactiveCampaignDomain, provider.ProfileUseOrdinaryTransit, time.Now().UTC())
	if provider.ErrorCodeOf(err) != provider.ErrorCodeInactive || inactive.Valid() {
		t.Fatal("inactive campaign profile authorized signing")
	}
}

// TestInactiveCampaignCommitmentCannotHideChanges ensures inactive public and
// private content remains covered by the current/root commitment fence.
func TestInactiveCampaignCommitmentCannotHideChanges(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DatasetRecords)
	}{
		{name: "policy rollout", mutate: func(records *DatasetRecords) {
			records.Policies[1].Attributes[attrRollout] = [][]byte{[]byte("observe")}
		}},
		{name: "selector", mutate: func(records *DatasetRecords) {
			records.Credentials[1].Attributes[attrSelector] = [][]byte{[]byte("changed-selector")}
		}},
		{name: "private key", mutate: func(records *DatasetRecords) { records.KeyMaterial[1].Attributes[attrPrivatePKCS8][0][0] ^= 0xff }},
		{name: "missing key", mutate: func(records *DatasetRecords) {
			clearEntries(records.KeyMaterial[1:])
			records.KeyMaterial = records.KeyMaterial[:1]
		}},
		{name: "source fence", mutate: func(records *DatasetRecords) { records.Root.Attributes[attrSourceGeneration] = [][]byte{[]byte("2")} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			records := inactiveCampaignRecords(t)
			defer func() { clearEntries(records.KeyMaterial) }()
			test.mutate(&records)
			if dataset, err := MapDataset(records, provider.DefaultLimits()); provider.ErrorCodeOf(err) != provider.ErrorCodeMalformedData || dataset != nil {
				t.Fatal("changed inactive campaign passed immutable commitment validation")
			}
		})
	}
}

// inactiveCampaignRecords encodes independent active and disabled native keys
// through the production v3 campaign and LDAP mapping owners.
func inactiveCampaignRecords(t *testing.T) DatasetRecords {
	t.Helper()
	active, inactive := minimalRecords(t), minimalRecords(t)
	defer clearEntries(active.KeyMaterial)
	defer clearEntries(inactive.KeyMaterial)
	rows, err := mapAdministrativeRows(active, 1)
	if err != nil {
		t.Fatal("map active campaign rows")
	}
	defer clearAdministrativeRows(&rows)
	additional, err := mapAdministrativeRows(inactive, 1)
	if err != nil {
		t.Fatal("map inactive campaign rows")
	}
	defer clearAdministrativeRows(&additional)
	additional.Handles[0].ID = inactiveCampaignHandleID
	additional.Profiles[0].ID, additional.Profiles[0].Domain, additional.Profiles[0].Status = inactiveCampaignProfileID, inactiveCampaignDomain, "disabled"
	additional.Credentials[0].ProfileID, additional.Credentials[0].HandleID, additional.Credentials[0].Selector = inactiveCampaignProfileID, inactiveCampaignHandleID, "inactive-selector"
	additional.Policies[0].ProfileID, additional.Policies[0].Domain, additional.Policies[0].Use = inactiveCampaignProfileID, inactiveCampaignDomain, "ordinary_transit"
	additional.Policies[0].Status, additional.Policies[0].Rollout = "disabled", "off"
	additional.KeyMaterial[0].HandleID, additional.KeyMaterial[0].Domain, additional.KeyMaterial[0].Use = inactiveCampaignHandleID, inactiveCampaignDomain, "ordinary_transit"
	rows.Handles = append(rows.Handles, additional.Handles...)
	rows.Profiles = append(rows.Profiles, additional.Profiles...)
	rows.Credentials = append(rows.Credentials, additional.Credentials...)
	rows.Policies = append(rows.Policies, additional.Policies...)
	rows.KeyMaterial = append(rows.KeyMaterial, additional.KeyMaterial...)
	snapshot, err := datasourceadmin.NewSnapshot(datasourceadmin.SchemaVersionV3, 2, rows)
	if err != nil {
		t.Fatal("construct mixed campaign snapshot")
	}
	content, err := datasourceadmin.NewCandidateContent(snapshot)
	if err != nil {
		_ = snapshot.Close()
		t.Fatal("construct mixed campaign content")
	}
	candidate, err := datasourceadmin.NewCampaignPublicationEnvelope("aebagbafaydqqcikbmga2dqpca", 1, content)
	if err != nil {
		_ = content.Close()
		t.Fatal("construct mixed campaign envelope")
	}
	defer func() { _ = candidate.Close() }()
	records := ldapRecordsForCampaignCandidate(t, candidate)
	records.Root.Attributes[attrDatasetState] = [][]byte{[]byte("committed")}
	metadata, err := mapGenerationMetadata(records.Root)
	if err != nil {
		t.Fatal("map committed campaign metadata")
	}
	records.Current = currentEntry(metadata)
	return records
}
