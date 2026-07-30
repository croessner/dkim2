package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/croessner/dkim2/provider"
)

var inventoryAttributes = []string{
	legacyObjectClass,
	legacySelector,
	legacyDomain,
	legacyAssociatedDomain,
	legacyKeyType,
	legacyActive,
	"DKIMIdentity",
	"createTimestamp",
	"modifyTimestamp",
}

// RawEntry contains only explicitly requested bounded legacy attributes.
type RawEntry struct {
	Attributes map[string][][]byte
}

// InventoryClient performs one bounded read-only legacy search.
type InventoryClient interface {
	Search(context.Context, []string, int, int) ([]RawEntry, error)
}

// Inventory validates one complete legacy snapshot without requesting keys.
func Inventory(
	ctx context.Context,
	client InventoryClient,
	limits Limits,
) ([]LegacyRecord, InventoryCounts, error) {
	if ctx == nil || client == nil || limits.Records == 0 ||
		limits.ResponseBytes == 0 {
		return nil, InventoryCounts{}, errors.New("legacy inventory unavailable")
	}
	if slices.Contains(inventoryAttributes, legacyKey) {
		return nil, InventoryCounts{}, errors.New("legacy inventory unavailable")
	}
	entries, err := client.Search(
		ctx, append([]string(nil), inventoryAttributes...),
		int(limits.Records)+1, int(limits.ResponseBytes),
	)
	if err != nil || len(entries) > int(limits.Records) {
		return nil, InventoryCounts{}, errors.New("legacy inventory unavailable")
	}
	records := make([]LegacyRecord, 0, len(entries))
	counts := InventoryCounts{Records: uint32(len(entries))}
	selectors := make(map[string]struct{}, len(entries))
	activeDomainAlgorithms := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		record, mapErr := mapLegacyEntry(entry)
		if mapErr != nil {
			return nil, InventoryCounts{}, errors.New("legacy inventory malformed")
		}
		if _, duplicate := selectors[record.selector]; duplicate {
			return nil, InventoryCounts{}, errors.New("legacy inventory malformed")
		}
		selectors[record.selector] = struct{}{}
		if record.active {
			key := record.domain + "\x00" + string(record.algorithm)
			if _, duplicate := activeDomainAlgorithms[key]; duplicate {
				return nil, InventoryCounts{}, errors.New("legacy inventory malformed")
			}
			activeDomainAlgorithms[key] = struct{}{}
			counts.Active++
		} else {
			counts.Inactive++
			counts.SkippedInactiveHistory++
		}
		switch record.algorithm {
		case AlgorithmRSA:
			counts.RSA++
		case AlgorithmEd25519:
			counts.Ed25519++
		}
		if record.ignoredIdentity {
			counts.IgnoredIdentityFields++
		}
		if record.ignoredCreated {
			counts.IgnoredTimestampFields++
		}
		if record.ignoredModified {
			counts.IgnoredTimestampFields++
		}
		records = append(records, record)
	}
	return records, counts, nil
}

// ValidatePlan reconciles exact active source records with explicit mappings.
func ValidatePlan(
	records []LegacyRecord,
	plan Plan,
	counts *InventoryCounts,
) error {
	if counts == nil || validatePlan(plan) != nil {
		return errors.New("migration plan invalid")
	}
	active := make(map[string]LegacyRecord, len(records))
	for _, record := range records {
		if record.active {
			active[record.domain+"\x00"+record.selector] = record
		}
	}
	if len(active) != len(plan.Mappings) {
		return errors.New("migration plan invalid")
	}
	for _, mapping := range plan.Mappings {
		key := mapping.Domain + "\x00" + mapping.Selector
		if _, exists := active[key]; !exists {
			return errors.New("migration plan invalid")
		}
		delete(active, key)
		counts.ValidatedPlanMappings++
	}
	if len(active) != 0 {
		return errors.New("migration plan invalid")
	}
	return nil
}

// DryRun performs inventory and plan validation without acquiring write authority.
func DryRun(
	ctx context.Context,
	config Config,
	client InventoryClient,
	toolVersion string,
) (Report, error) {
	report := Report{
		Schema:      migrationReportSchema,
		ToolVersion: toolVersion, Target: config.Plan.Target,
		Mode: "dry_run", Result: migrationResultFailure, FailureClass: "internal",
		Inventory: PhaseState{Attempted: true},
	}
	records, counts, err := Inventory(ctx, client, config.Limits)
	if err != nil {
		report.FailureClass = "inventory"
		return report, errors.New("migration dry run failed")
	}
	report.Inventory.Completed = true
	report.Counts = counts
	report.Plan.Attempted = true
	if err := ValidatePlan(records, config.Plan, &report.Counts); err != nil {
		report.FailureClass = "plan"
		return report, errors.New("migration dry run failed")
	}
	report.Plan.Completed = true
	report.Result = migrationResultSuccess
	report.FailureClass = migrationFailureNone
	return report, nil
}

// EncodeMachineReport returns strict bounded deterministic JSON.
func EncodeMachineReport(report Report, maximum uint32) ([]byte, error) {
	if maximum == 0 || maximum > maxConfigBytes {
		return nil, errors.New("migration report unavailable")
	}
	document, err := json.Marshal(report)
	if err != nil || len(document) > int(maximum) {
		return nil, errors.New("migration report unavailable")
	}
	return append(document, '\n'), nil
}

// EncodeHumanReport returns one bounded nonidentity summary.
func EncodeHumanReport(report Report, maximum uint32) ([]byte, error) {
	document := []byte(fmt.Sprintf(
		"mode=%s result=%s target=%s records=%d active=%d inactive=%d mappings=%d\n",
		report.Mode, report.Result, report.Target, report.Counts.Records,
		report.Counts.Active, report.Counts.Inactive,
		report.Counts.ValidatedPlanMappings,
	))
	if maximum == 0 || len(document) > int(maximum) {
		return nil, errors.New("migration report unavailable")
	}
	return document, nil
}

// mapLegacyEntry validates one exact OpenDKIM record without key material.
func mapLegacyEntry(entry RawEntry) (LegacyRecord, error) {
	allowed := append([]string(nil), inventoryAttributes...)
	for name := range entry.Attributes {
		if !slices.Contains(allowed, name) || name == legacyKey {
			return LegacyRecord{}, errors.New("legacy entry malformed")
		}
	}
	required := []string{
		legacyObjectClass, legacySelector, legacyDomain, legacyAssociatedDomain,
		legacyKeyType, legacyActive,
	}
	values := make(map[string]string, len(entry.Attributes))
	for _, name := range required {
		raw := entry.Attributes[name]
		if name == legacyObjectClass {
			found := false
			for _, value := range raw {
				if string(value) == "DKIM" {
					found = true
				}
			}
			if !found {
				return LegacyRecord{}, errors.New("legacy entry malformed")
			}
			continue
		}
		if len(raw) != 1 || len(raw[0]) == 0 || len(raw[0]) > 4096 {
			return LegacyRecord{}, errors.New("legacy entry malformed")
		}
		values[name] = string(raw[0])
	}
	for _, name := range []string{"DKIMIdentity", "createTimestamp", "modifyTimestamp"} {
		if raw, exists := entry.Attributes[name]; exists && len(raw) != 1 {
			return LegacyRecord{}, errors.New("legacy entry malformed")
		}
	}
	sourceSelector := values[legacySelector]
	canonicalSelector := strings.ToLower(sourceSelector)
	active := false
	switch values[legacyActive] {
	case "TRUE":
		active = true
	case "FALSE":
	default:
		return LegacyRecord{}, errors.New("legacy entry malformed")
	}
	if values[legacyDomain] == "*" && !active {
		values[legacyDomain] = values[legacyAssociatedDomain]
	}
	if values[legacyDomain] != values[legacyAssociatedDomain] ||
		values[legacyDomain] != strings.ToLower(values[legacyDomain]) {
		return LegacyRecord{}, errors.New("legacy entry malformed")
	}
	var algorithm Algorithm
	var providerAlgorithm provider.Algorithm
	switch values[legacyKeyType] {
	case "rsa":
		algorithm = AlgorithmRSA
		providerAlgorithm = provider.AlgorithmRSASHA256
	case "ed25519":
		algorithm = AlgorithmEd25519
		providerAlgorithm = provider.AlgorithmEd25519SHA256
	default:
		return LegacyRecord{}, errors.New("legacy entry malformed")
	}
	if provider.ValidateDomainSelector(
		values[legacyDomain], canonicalSelector, providerAlgorithm,
	) != nil {
		return LegacyRecord{}, errors.New("legacy entry malformed")
	}
	return LegacyRecord{
		selector: canonicalSelector, sourceSelector: sourceSelector,
		domain: values[legacyDomain], associated: values[legacyAssociatedDomain],
		algorithm:       algorithm,
		active:          active,
		ignoredIdentity: len(entry.Attributes["DKIMIdentity"]) == 1,
		ignoredCreated:  len(entry.Attributes["createTimestamp"]) == 1,
		ignoredModified: len(entry.Attributes["modifyTimestamp"]) == 1,
	}, nil
}

// String returns a constant protected raw-entry summary.
func (RawEntry) String() string { return redacted }

// GoString returns a constant protected raw-entry representation.
func (RawEntry) GoString() string { return redacted }

// Format prevents formatting verbs from exposing raw LDAP attributes.
func (RawEntry) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON emits an empty object without LDAP attributes.
func (RawEntry) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// reportContainsProtectedMarker supports bounded privacy regression tests.
func reportContainsProtectedMarker(report []byte, marker []byte) bool {
	return bytes.Contains(report, marker)
}
