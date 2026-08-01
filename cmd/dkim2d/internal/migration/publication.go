package migration

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	datasourcepostgresql "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/postgresql"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

// PublicationCandidate owns one complete provider-neutral public generation.
type PublicationCandidate struct {
	generation uint64
	rows       datasourcepostgresql.DatasetRows
}

// Generation returns the exact immutable candidate generation.
func (c PublicationCandidate) Generation() uint64 { return c.generation }

// String returns a constant protected publication-candidate summary.
func (PublicationCandidate) String() string { return redacted }

// GoString returns a constant protected publication-candidate representation.
func (PublicationCandidate) GoString() string { return redacted }

// Format prevents formatting verbs from exposing publication facts.
func (PublicationCandidate) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, redacted)
}

// MarshalJSON emits an empty object without protected publication facts.
func (PublicationCandidate) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Publisher atomically fences and activates one complete backend generation.
// Current returns zero only after proving that no current pointer or generation exists.
type Publisher interface {
	Current(context.Context) (uint64, error)
	Publish(context.Context, uint64, PublicationCandidate) error
}

// BuildPublicationCandidate validates one complete public dataset projection.
func BuildPublicationCandidate(
	plan Plan,
	imported []*ImportedCredential,
) (PublicationCandidate, error) {
	generation, err := parseGeneration(plan.Generation)
	if err != nil || len(imported) != len(plan.Mappings) || len(imported) == 0 {
		return PublicationCandidate{}, errors.New("migration candidate unavailable")
	}
	generationText := plan.Generation
	rows := datasourcepostgresql.DatasetRows{
		Current: datasourcepostgresql.MetadataRow{
			Generation: generationText, SchemaVersion: migrationSchemaVersion,
			DatasetState: datasourceStateCommitted,
		},
		Final: datasourcepostgresql.MetadataRow{
			Generation: generationText, SchemaVersion: migrationSchemaVersion,
			DatasetState: datasourceStateCommitted,
		},
	}
	profileIndex := make(map[string]int, len(imported))
	policyIndex := make(map[string]struct{}, len(imported))
	for index, credential := range imported {
		if credential == nil || credential.key == nil ||
			credential.mapping != plan.Mappings[index] {
			return PublicationCandidate{}, errors.New("migration candidate unavailable")
		}
		mapping := credential.mapping
		publicSPKI := credential.key.PublicSPKIDER()
		privatePKCS8 := credential.key.NativePKCS8DER()
		if len(publicSPKI) == 0 || len(privatePKCS8) == 0 {
			clear(publicSPKI)
			clear(privatePKCS8)
			return PublicationCandidate{}, errors.New("migration candidate unavailable")
		}
		algorithm := string(provider.AlgorithmRSASHA256)
		if credential.key.Algorithm() == "ed25519-sha256" {
			algorithm = string(provider.AlgorithmEd25519SHA256)
		} else if credential.key.Algorithm() != "rsa-sha256" {
			clear(publicSPKI)
			clear(privatePKCS8)
			return PublicationCandidate{}, errors.New("migration candidate unavailable")
		}
		rows.Handles = append(rows.Handles, datasourcepostgresql.HandleRow{
			Generation: generationText, HandleID: mapping.HandleID,
		})
		rows.Credentials = append(rows.Credentials, datasourcepostgresql.CredentialRow{
			Generation: generationText, ProfileID: mapping.ProfileID,
			Algorithm: algorithm, Selector: mapping.Selector,
			PublicKeySPKI: publicSPKI, HandleID: mapping.HandleID,
		})
		rows.KeyMaterial = append(rows.KeyMaterial, datasourcepostgresql.KeyMaterialRow{
			Generation: generationText, TenantID: mapping.TenantID,
			Domain: mapping.Domain, Use: mapping.ProfileUse,
			HandleID: mapping.HandleID, Algorithm: algorithm,
			PublicSPKI:   append([]byte(nil), publicSPKI...),
			PrivatePKCS8: privatePKCS8,
		})
		if profilePosition, exists := profileIndex[mapping.ProfileID]; exists {
			profile := rows.Profiles[profilePosition]
			if profile.Domain != mapping.Domain ||
				textPointerValue(profile.NotBeforeUTC) != mapping.NotBefore ||
				textPointerValue(profile.NotAfterUTC) != mapping.NotAfter {
				return PublicationCandidate{}, errors.New("migration candidate unavailable")
			}
		} else {
			var notBefore, notAfter *string
			if mapping.NotBefore != "" {
				before, after := mapping.NotBefore, mapping.NotAfter
				notBefore, notAfter = &before, &after
			}
			profileIndex[mapping.ProfileID] = len(rows.Profiles)
			rows.Profiles = append(rows.Profiles, datasourcepostgresql.ProfileRow{
				Generation: generationText, ProfileID: mapping.ProfileID,
				Domain: mapping.Domain, Status: "active",
				NotBeforeUTC: notBefore, NotAfterUTC: notAfter,
			})
		}
		policyKey := mapping.TenantID + "\x00" + mapping.Domain + "\x00" + mapping.ProfileUse
		if _, duplicate := policyIndex[policyKey]; !duplicate {
			policyIndex[policyKey] = struct{}{}
			var feedback *string
			if mapping.FeedbackRouteID != "" {
				value := mapping.FeedbackRouteID
				feedback = &value
			}
			rows.Policies = append(rows.Policies, datasourcepostgresql.PolicyRow{
				Generation: generationText, TenantID: mapping.TenantID,
				Domain: mapping.Domain, Use: mapping.ProfileUse,
				ProfileID: mapping.ProfileID, Status: "active",
				Rollout: mapping.Rollout, Compatibility: mapping.Compatibility,
				FeedbackRouteID: feedback,
			})
		}
	}
	dataset, err := datasourcepostgresql.MapDataset(rows, provider.DefaultLimits())
	if err != nil || dataset == nil || !dataset.Valid() ||
		dataset.Generation() != generation {
		clearCandidateRows(&rows)
		return PublicationCandidate{}, errors.New("migration candidate unavailable")
	}
	materials, err := datasourcepostgresql.MapNativeKeyMaterial(rows.KeyMaterial, generation)
	if err != nil {
		clearCandidateRows(&rows)
		return PublicationCandidate{}, errors.New("migration candidate unavailable")
	}
	defer closePublicationMaterials(materials)
	registry, err := signingstore.OpenNativeRegistry(generation, materials)
	if err != nil {
		clearCandidateRows(&rows)
		return PublicationCandidate{}, errors.New("migration candidate unavailable")
	}
	defer func() { _ = registry.Close(context.Background()) }()
	resolver, err := dataset.NewSigningResolver(registry.Bindings(), time.Now().UTC())
	if err != nil || resolver == nil {
		clearCandidateRows(&rows)
		return PublicationCandidate{}, errors.New("migration candidate unavailable")
	}
	_ = resolver.Close(context.Background())
	return PublicationCandidate{generation: generation, rows: rows}, nil
}

// Apply publishes one proven generation pair or returns no success claim.
func Apply(
	ctx context.Context,
	records []LegacyRecord,
	plan Plan,
	imported []*ImportedCredential,
	publisher Publisher,
	toolVersion string,
) (Report, error) {
	report := newPublicationReport(plan.Target, "apply", toolVersion)
	if ctx == nil || publisher == nil ||
		ValidatePlan(records, plan, &report.Counts) != nil {
		return failedPublicationReport(report, "invalid_request")
	}
	report.Inventory = PhaseState{Attempted: true, Completed: true}
	report.Plan = PhaseState{Attempted: true, Completed: true}
	report.KeyValidation = PhaseState{Attempted: true, Completed: len(imported) > 0}
	report.DNSProof = report.KeyValidation
	candidate, err := BuildPublicationCandidate(plan, imported)
	if err != nil {
		return failedPublicationReport(report, "malformed_data")
	}
	defer clearCandidateRows(&candidate.rows)
	expected, err := parseExpectedCurrent(plan.ExpectedCurrent)
	if err != nil {
		return failedPublicationReport(report, "invalid_request")
	}
	current, err := publisher.Current(ctx)
	if err != nil || current != expected {
		return failedPublicationReport(report, "conflict")
	}
	report.KeyMaterialStage = PhaseState{Attempted: true, Completed: true}
	report.DatasetStage.Attempted = true
	report.Publication.Attempted = true
	if err := publisher.Publish(ctx, expected, candidate); err != nil {
		return failedPublicationReport(report, "unavailable")
	}
	report.DatasetStage.Completed = true
	report.Publication.Completed = true
	report.Result = migrationResultSuccess
	report.FailureClass = migrationFailureNone
	return report, nil
}

// Rollback republishes prior logical content only under a higher generation.
func Rollback(
	ctx context.Context,
	records []LegacyRecord,
	plan Plan,
	imported []*ImportedCredential,
	publisher Publisher,
	toolVersion string,
) (Report, error) {
	report, err := Apply(ctx, records, plan, imported, publisher, toolVersion)
	report.Mode = "rollback"
	return report, err
}

// newPublicationReport constructs one closed secret-safe mutation report.
func newPublicationReport(target Target, mode string, toolVersion string) Report {
	return Report{
		Schema: migrationReportSchema, ToolVersion: toolVersion,
		Target: target, Mode: mode, Result: migrationResultFailure, FailureClass: "internal",
	}
}

// failedPublicationReport returns one bounded failed report and content-free error.
func failedPublicationReport(report Report, class string) (Report, error) {
	report.Result = migrationResultFailure
	report.FailureClass = class
	return report, errors.New("migration publication failed")
}

// textPointerValue returns the empty sentinel or exact pointed-to value.
func textPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// clearCandidateRows clears detached public-key bytes retained by a candidate.
func clearCandidateRows(rows *datasourcepostgresql.DatasetRows) {
	if rows == nil {
		return
	}
	for index := range rows.Credentials {
		clear(rows.Credentials[index].PublicKeySPKI)
		rows.Credentials[index].PublicKeySPKI = nil
	}
	for index := range rows.KeyMaterial {
		clear(rows.KeyMaterial[index].PublicSPKI)
		clear(rows.KeyMaterial[index].PrivatePKCS8)
		rows.KeyMaterial[index].PublicSPKI = nil
		rows.KeyMaterial[index].PrivatePKCS8 = nil
	}
}

// closePublicationMaterials clears one native publication validation set.
func closePublicationMaterials(materials []*signingstore.NativeKeyMaterial) {
	for _, material := range materials {
		_ = material.Close()
	}
}
