package testclient

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const validHealthFixture = `{"schema":"dkim2ctl.fixture.v1","draft":"draft-ietf-dkim-dkim2-spec-06","fixture":"fixture-a","cases":[{"case":"case-a","kind":"health","expect":{"http_status":200,"health_status":"alive"}}]}`

// TestCheckedFixtureExamplesRemainStrictAndGloballyUnique validates durable examples together.
func TestCheckedFixtureExamplesRemainStrictAndGloballyUnique(t *testing.T) {
	t.Parallel()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture test source unavailable")
	}
	root := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(source))), "testdata", "fixtures",
		"draft-ietf-dkim-dkim2-spec-06")
	paths := []string{
		filepath.Join(root, "health.json"),
		filepath.Join(root, "process-report.json"),
		filepath.Join(root, "process-negative.json"),
		filepath.Join(root, "process.json"),
		filepath.Join(root, "revise.json"),
		filepath.Join(root, "route-negative.json"),
		filepath.Join(root, "sign.json"),
	}
	plan, err := LoadExecutionPlan(paths)
	if err != nil || len(plan.cases) != 21 ||
		!plan.requiresCapability || !plan.requiresSignCapability ||
		!plan.requiresReviseCapability {
		t.Fatal("checked fixture examples are invalid")
	}
}

// TestDecodeFixtureAcceptsExactClosedDocument proves the offline happy path.
func TestDecodeFixtureAcceptsExactClosedDocument(t *testing.T) {
	t.Parallel()
	document, decodedBytes, err := decodeFixture([]byte(validHealthFixture))
	if err != nil || decodedBytes != 0 || document.Fixture != "fixture-a" ||
		len(document.Cases) != 1 {
		t.Fatal("valid fixture rejected")
	}
}

// TestDecodeFixtureRejectsHostileJSON freezes strict syntax and member policy.
func TestDecodeFixtureRejectsHostileJSON(t *testing.T) {
	t.Parallel()
	for _, data := range []string{
		"",
		"\ufeff" + validHealthFixture,
		validHealthFixture + "{}",
		strings.Replace(validHealthFixture, `"schema":`, `"unknown":1,"schema":`, 1),
		strings.Replace(validHealthFixture, `"schema":`, `"schema":"dkim2ctl.fixture.v1","schema":`, 1),
		strings.Replace(validHealthFixture, `"fixture-a"`, `"UPPER"`, 1),
		strings.Replace(validHealthFixture, `"health"`, `"other"`, 1),
	} {
		if _, _, err := decodeFixture([]byte(data)); ExitClassOf(err) != ExitFixture {
			t.Fatal("hostile fixture accepted")
		}
	}
}

// TestFixtureRejectsImpossibleStatusProjection proves status fixtures cannot
// redefine the generated typed health or readiness contract.
func TestFixtureRejectsImpossibleStatusProjection(t *testing.T) {
	t.Parallel()
	hostile := strings.Replace(validHealthFixture, `"http_status":200`, `"http_status":500`, 1)
	if _, _, err := decodeFixture([]byte(hostile)); ExitClassOf(err) != ExitFixture {
		t.Fatal("impossible health projection accepted")
	}
}

// TestDecodeFixtureRejectsExcessiveDepth proves the literal nesting limit.
func TestDecodeFixtureRejectsExcessiveDepth(t *testing.T) {
	t.Parallel()
	data := strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17)
	if _, _, err := decodeFixture([]byte(data)); ExitClassOf(err) != ExitFixture {
		t.Fatal("excessive JSON depth accepted")
	}
}

// TestLoadExecutionPlanOrdersPathsAndCasesDeterministically freezes plan order.
func TestLoadExecutionPlanOrdersPathsAndCasesDeterministically(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	second := strings.ReplaceAll(validHealthFixture, "fixture-a", "fixture-b")
	second = strings.ReplaceAll(second, "case-a", "case-z")
	first := strings.Replace(validHealthFixture,
		`{"case":"case-a","kind":"health","expect":{"http_status":200,"health_status":"alive"}}`,
		`{"case":"case-b","kind":"health","expect":{"http_status":200,"health_status":"alive"}},{"case":"case-a","kind":"health","expect":{"http_status":200,"health_status":"alive"}}`,
		1,
	)
	firstPath := filepath.Join(directory, "a.json")
	secondPath := filepath.Join(directory, "b.json")
	if err := os.WriteFile(firstPath, []byte(first), 0o600); err != nil {
		t.Fatal("write first fixture")
	}
	if err := os.WriteFile(secondPath, []byte(second), 0o600); err != nil {
		t.Fatal("write second fixture")
	}
	plan, err := LoadExecutionPlan([]string{secondPath, firstPath})
	if err != nil {
		t.Fatal("valid fixture plan rejected")
	}
	got := make([]string, 0, len(plan.cases))
	for _, planned := range plan.cases {
		got = append(got, planned.fixture+"/"+planned.value.Case)
	}
	if strings.Join(got, ",") != "fixture-a/case-a,fixture-a/case-b,fixture-b/case-z" {
		t.Fatal("fixture plan is not deterministic")
	}
}

// TestLoadExecutionPlanRejectsSymlinkAndGlobalDuplicates freezes path and ID policy.
func TestLoadExecutionPlanRejectsSymlinkAndGlobalDuplicates(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(path, []byte(validHealthFixture), 0o600); err != nil {
		t.Fatal("write fixture")
	}
	link := filepath.Join(directory, "fixture-link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal("create fixture symlink")
	}
	if _, err := LoadExecutionPlan([]string{link}); ExitClassOf(err) != ExitFixture {
		t.Fatal("fixture symlink accepted")
	}
	duplicate := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicate, []byte(validHealthFixture), 0o600); err != nil {
		t.Fatal("write duplicate fixture")
	}
	if _, err := LoadExecutionPlan([]string{path, duplicate}); ExitClassOf(err) != ExitFixture {
		t.Fatal("duplicate fixture identifier accepted")
	}
}

// TestStableOutputOrderAndNullPolicy locks the exact JSONL record shape.
func TestStableOutputOrderAndNullPolicy(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	if err := writeRecord(&output, ResultRecord{
		Schema: outputSchema, Draft: draftVersion, Outcome: outcomeMatch,
	}); err != nil {
		t.Fatal("record write failed")
	}
	const expected = `{"schema":"dkim2ctl.result.v1","draft":"draft-ietf-dkim-dkim2-spec-06","fixture":null,"case":null,"operation":null,"outcome":"match","http_status":null,"error_class":null,"duration_bucket":null,"disposition":null,"verification_state":null,"authentication_state":null,"policy_verdict":null,"replay_class":null}` + "\n"
	if output.String() != expected {
		t.Fatal("stable JSONL shape changed")
	}
}

// TestExecutedRecordContainsClosedDurationBucket proves executed JSONL carries
// one bounded bucket without an exact duration.
func TestExecutedRecordContainsClosedDurationBucket(t *testing.T) {
	t.Parallel()
	record := ResultRecord{
		Schema: outputSchema, Draft: draftVersion, Outcome: outcomeMatch,
	}
	bucket := DurationBucket(250 * time.Millisecond)
	record.DurationBucket = &bucket
	var output bytes.Buffer
	if err := writeRecord(&output, record); err != nil {
		t.Fatal("write duration record")
	}
	var decoded ResultRecord
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil ||
		decoded.DurationBucket == nil || !validDurationBucket(*decoded.DurationBucket) {
		t.Fatal("executed record lost its closed duration bucket")
	}
}

// TestValidateWritesOnlyIdentifiers proves offline output is content-free.
func TestValidateWritesOnlyIdentifiers(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "marker-private-path.json")
	if err := os.WriteFile(path, []byte(validHealthFixture), 0o600); err != nil {
		t.Fatal("write fixture")
	}
	var output bytes.Buffer
	application := NewApplication(&output)
	if err := application.Validate(DefaultOptions(), []string{path}); err != nil {
		t.Fatal("offline validation failed")
	}
	if strings.Contains(output.String(), "marker-private-path") {
		t.Fatal("fixture path leaked to output")
	}
}
