package conformance

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	maxVectorBytes          = 24 << 20
	operationVerify         = "verify"
	operationMilter         = "milter"
	operationSign           = "sign"
	operationRevise         = "revise"
	operationOpenAPI        = "openapi"
	operationPolicy         = "policy"
	operationDNS            = "dns_record"
	operationReplay         = "replay"
	operationRecipeApply    = "recipe_apply"
	operationRecipeGenerate = "recipe_generate"
	noMutationState         = "no_mutation"
	codePermerror           = "permerror"
	codeTemperror           = "temperror"
	codeFirstSeen           = "first_seen"
	stateAccept             = "accept"
	statePassUpper          = "PASS"
	dispositionContinue     = "continue"
)

// Case is the strict common portable vector envelope.
type Case struct {
	Schema         string                   `json:"schema"`
	CaseID         string                   `json:"case_id"`
	MessageDraft   string                   `json:"message_draft"`
	DNSDraft       string                   `json:"dns_draft"`
	Class          string                   `json:"class"`
	Authority      []string                 `json:"authority"`
	Provenance     string                   `json:"provenance"`
	Verify         *MailOperation           `json:"verify,omitempty"`
	Sign           *MailOperation           `json:"sign,omitempty"`
	Revise         *MailOperation           `json:"revise,omitempty"`
	RecipeApply    *RecipeApplyOperation    `json:"recipe_apply,omitempty"`
	RecipeGenerate *RecipeGenerateOperation `json:"recipe_generate,omitempty"`
	DNSRecord      *DNSOperation            `json:"dns_record,omitempty"`
	Policy         *PolicyOperation         `json:"policy,omitempty"`
	Replay         *ReplayOperation         `json:"replay,omitempty"`
	OpenAPI        *MailOperation           `json:"openapi,omitempty"`
	Milter         *MailOperation           `json:"milter,omitempty"`
}

// MailOperation contains exact RFC 5322 and SMTP input plus typed expectations.
type MailOperation struct {
	Input    MailInput `json:"input"`
	Expected Expected  `json:"expected"`
}

// MailInput keeps message and envelope bytes separate and Base64 encoded.
type MailInput struct {
	MessageB64      string   `json:"message_b64"`
	ReversePathB64  string   `json:"reverse_path_b64"`
	ForwardPathsB64 []string `json:"forward_paths_b64"`
}

// RecipeApplyOperation contains exact recipe/current inputs and reconstruction result.
type RecipeApplyOperation struct {
	RecipeB64  string   `json:"recipe_b64"`
	CurrentB64 string   `json:"current_message_b64"`
	Expected   Expected `json:"expected"`
}

// RecipeGenerateOperation contains exact before/after inputs and generated result.
type RecipeGenerateOperation struct {
	BeforeB64  string   `json:"before_message_b64"`
	AfterB64   string   `json:"after_message_b64"`
	BodyPolicy string   `json:"body_policy"`
	Expected   Expected `json:"expected"`
}

// DNSOperation contains one exact record and algorithm selection.
type DNSOperation struct {
	RecordB64 string   `json:"record_b64"`
	Algorithm string   `json:"algorithm"`
	Expected  Expected `json:"expected"`
}

// PolicyOperation contains closed verification and policy modes.
type PolicyOperation struct {
	VerificationState string   `json:"verification_state"`
	Mode              string   `json:"mode"`
	Expected          Expected `json:"expected"`
}

// ReplayOperation contains one privacy-safe identity and deterministic clock.
type ReplayOperation struct {
	IdentityB64 string   `json:"identity_b64"`
	ClockUnix   int64    `json:"clock_unix"`
	Expected    Expected `json:"expected"`
}

// Expected is the closed portable result vocabulary.
type Expected struct {
	Code        string `json:"code"`
	State       string `json:"state"`
	Digest      string `json:"digest,omitempty"`
	Disposition string `json:"disposition,omitempty"`
}

// ValidateCaseBytes decodes and validates one strict portable case.
func ValidateCaseBytes(input []byte) (Case, error) {
	var fixture Case
	if err := DecodeStrictJSON(input, maxVectorBytes, &fixture); err != nil {
		return Case{}, err
	}
	if fixture.Schema != "dkim2.conformance-case.v1" ||
		fixture.MessageDraft != MessageDraft || fixture.DNSDraft != DNSDraft ||
		!caseIDPattern.MatchString(fixture.CaseID) || !knownClasses[fixture.Class] ||
		len(fixture.Authority) == 0 || len(fixture.Authority) > 16 ||
		!knownProvenance(fixture.Provenance) {
		return Case{}, errors.New("fixture_invalid")
	}
	for _, authority := range fixture.Authority {
		if len(authority) == 0 || len(authority) > 160 ||
			strings.ContainsAny(authority, "\r\n\x00") {
			return Case{}, errors.New("fixture_invalid")
		}
	}
	operations := 0
	for _, operation := range []struct {
		name  string
		value *MailOperation
	}{
		{name: operationVerify, value: fixture.Verify},
		{name: operationSign, value: fixture.Sign},
		{name: operationRevise, value: fixture.Revise},
		{name: operationOpenAPI, value: fixture.OpenAPI},
		{name: operationMilter, value: fixture.Milter},
	} {
		if operation.value != nil {
			operations++
			if err := operation.value.validate(operation.name); err != nil {
				return Case{}, err
			}
		}
	}
	if fixture.RecipeApply != nil {
		operations++
		if err := fixture.RecipeApply.validate(); err != nil {
			return Case{}, err
		}
	}
	if fixture.RecipeGenerate != nil {
		operations++
		if err := fixture.RecipeGenerate.validate(); err != nil {
			return Case{}, err
		}
	}
	if fixture.DNSRecord != nil {
		operations++
		if err := fixture.DNSRecord.validate(); err != nil {
			return Case{}, err
		}
	}
	if fixture.Policy != nil {
		operations++
		if err := fixture.Policy.validate(); err != nil {
			return Case{}, err
		}
	}
	if fixture.Replay != nil {
		operations++
		if err := fixture.Replay.validate(); err != nil {
			return Case{}, err
		}
	}
	if operations != 1 {
		return Case{}, errors.New("fixture_invalid")
	}
	return fixture, nil
}

// ValidateSchemaClosure proves that every object and array schema is bounded and closed.
func ValidateSchemaClosure(root string) error {
	paths := []string{
		"testdata/conformance/schemas/manifest.schema.json",
		"testdata/conformance/schemas/case.schema.json",
		"testdata/conformance/schemas/report.schema.json",
		"testdata/conformance/exim/fixture.schema.json",
		"testdata/conformance/exim/result.schema.json",
	}
	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		return errors.New("schema_root")
	}
	defer func() { _ = rootHandle.Close() }()
	for _, path := range paths {
		input, readErr := readConfinedFile(rootHandle, path, maxManifestBytes)
		if readErr != nil {
			return readErr
		}
		var schema any
		if decodeErr := DecodeStrictJSON(input, maxManifestBytes, &schema); decodeErr != nil {
			return decodeErr
		}
		if closeErr := validateSchemaNode(schema); closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// validateSchemaNode recursively rejects open objects and unbounded arrays.
func validateSchemaNode(node any) error {
	switch value := node.(type) {
	case map[string]any:
		if value["type"] == "object" {
			if closed, ok := value["additionalProperties"].(bool); !ok || closed {
				return errors.New("schema_open_object")
			}
		}
		if value["type"] == "array" {
			if value["items"] == nil || value["maxItems"] == nil {
				return errors.New("schema_unbounded_array")
			}
		}
		for _, child := range value {
			if err := validateSchemaNode(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := validateSchemaNode(child); err != nil {
				return err
			}
		}
	}
	return nil
}

// validate checks exact mail and envelope Base64 before allocation.
func (o MailOperation) validate(operation string) error {
	if _, err := decodePadded(o.Input.MessageB64, maxVectorBytes); err != nil {
		return err
	}
	if _, err := decodePadded(o.Input.ReversePathB64, 1<<20); err != nil {
		return err
	}
	if len(o.Input.ForwardPathsB64) > 1024 {
		return errors.New("fixture_invalid")
	}
	for _, value := range o.Input.ForwardPathsB64 {
		if _, err := decodePadded(value, 1<<20); err != nil {
			return err
		}
	}
	return o.Expected.validate(operation)
}

// validate checks exact recipe application inputs.
func (o RecipeApplyOperation) validate() error {
	if _, err := decodePadded(o.RecipeB64, maxVectorBytes); err != nil {
		return err
	}
	if _, err := decodePadded(o.CurrentB64, maxVectorBytes); err != nil {
		return err
	}
	return o.Expected.validate(operationRecipeApply)
}

// validate checks exact recipe generation inputs.
func (o RecipeGenerateOperation) validate() error {
	if _, err := decodePadded(o.BeforeB64, maxVectorBytes); err != nil {
		return err
	}
	if _, err := decodePadded(o.AfterB64, maxVectorBytes); err != nil {
		return err
	}
	if o.BodyPolicy != "available" && o.BodyPolicy != "unavailable" {
		return errors.New("fixture_invalid")
	}
	return o.Expected.validate(operationRecipeGenerate)
}

// validate checks exact DNS record inputs.
func (o DNSOperation) validate() error {
	if _, err := decodePadded(o.RecordB64, 1<<20); err != nil {
		return err
	}
	if o.Algorithm != "rsa-sha256" && o.Algorithm != "ed25519-sha256" {
		return errors.New("fixture_invalid")
	}
	return o.Expected.validate(operationDNS)
}

// validate checks closed policy inputs.
func (o PolicyOperation) validate() error {
	if !stringSet("PASS", "FAIL", "PERMERROR", "TEMPERROR")[o.VerificationState] ||
		!stringSet("strict", "permissive", "testing")[o.Mode] {
		return errors.New("fixture_invalid")
	}
	return o.Expected.validate(operationPolicy)
}

// validate checks one privacy-safe replay identity and clock.
func (o ReplayOperation) validate() error {
	if _, err := decodePadded(o.IdentityB64, 1<<20); err != nil {
		return err
	}
	if o.ClockUnix < 0 {
		return errors.New("fixture_invalid")
	}
	return o.Expected.validate(operationReplay)
}

// validate enforces operation-specific result correlations.
func (e Expected) validate(operation string) error {
	if e.Digest != "" && !isSHA256(e.Digest) ||
		e.Disposition != "" && !stringSet(
			"continue", "accept", "reject", "tempfail", "no_mutation",
		)[e.Disposition] {
		return errors.New("fixture_invalid")
	}
	allowed := map[string]map[string]string{
		operationVerify:         {statePass: statePassUpper, stateFail: "FAIL", codePermerror: "PERMERROR", codeTemperror: "TEMPERROR"},
		operationSign:           {statePass: "signed", stateFail: noMutationState, codePermerror: noMutationState, codeTemperror: noMutationState},
		operationRevise:         {statePass: "revised", stateFail: noMutationState, codePermerror: noMutationState, codeTemperror: noMutationState},
		operationOpenAPI:        {statePass: "contract_match", stateFail: "contract_reject"},
		operationMilter:         {statePass: stateAccept, stateFail: "reject", codeTemperror: "tempfail"},
		operationRecipeApply:    {statePass: "applied", codePermerror: "rejected"},
		operationRecipeGenerate: {statePass: "generated", codePermerror: "rejected"},
		operationDNS:            {statePass: "found", codePermerror: "invalid", codeTemperror: "temporary"},
		operationPolicy:         {statePass: e.Disposition},
		operationReplay:         {codeFirstSeen: codeFirstSeen, "replayed": "replayed", "disabled": "disabled", "indeterminate": "indeterminate"},
	}
	state, ok := allowed[operation][e.Code]
	returnIf := !ok || state != e.State
	if operation == operationPolicy {
		returnIf = e.Code != statePass || !stringSet("accept", "reject", "continue", "tempfail")[e.State] ||
			e.Disposition != e.State
	}
	if returnIf {
		return errors.New("fixture_invalid")
	}
	hasDigest := e.Digest != ""
	switch operation {
	case operationVerify:
		returnIf = e.Disposition != "" || hasDigest != (e.Code == statePass)
	case operationSign, operationRevise:
		if e.Code == statePass {
			returnIf = !hasDigest || e.Disposition != dispositionContinue
		} else {
			returnIf = hasDigest || e.Disposition != noMutationState
		}
	case operationOpenAPI:
		returnIf = hasDigest || e.Disposition != noMutationState
	case operationMilter:
		returnIf = hasDigest || e.Disposition != e.State
	case operationRecipeApply, operationRecipeGenerate:
		returnIf = e.Disposition != "" || hasDigest != (e.Code == statePass)
	case operationDNS, operationReplay:
		returnIf = hasDigest || e.Disposition != ""
	case operationPolicy:
		returnIf = hasDigest || e.Disposition != e.State
	}
	if returnIf {
		return errors.New("fixture_invalid")
	}
	return nil
}

// decodePadded bounds and strictly decodes RFC 4648 padded Base64.
func decodePadded(value string, decodedLimit int64) ([]byte, error) {
	if int64(base64.StdEncoding.DecodedLen(len(value))) > decodedLimit {
		return nil, errors.New("fixture_invalid")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil {
		return nil, errors.New("fixture_invalid")
	}
	return decoded, nil
}

// knownProvenance reports whether value is one reviewed expected-value source.
func knownProvenance(value string) bool {
	return stringSet(
		"draft_example", "rfc_example", "independent_oracle",
		"cross_primitive", "manual_derivation", "regression_reproducer",
	)[value]
}

// ValidateDeferredEximResult rejects any checked-in executed Exim evidence.
func ValidateDeferredEximResult(input []byte) error {
	var result struct {
		Schema   string         `json:"schema"`
		CaseID   string         `json:"case_id"`
		State    string         `json:"state"`
		Evidence map[string]any `json:"evidence"`
	}
	if err := DecodeStrictJSON(input, maxManifestBytes, &result); err != nil {
		return err
	}
	if result.Schema != "dkim2.exim-adapter-result.v1" ||
		!caseIDPattern.MatchString(result.CaseID) || result.State != "deferred" ||
		len(result.Evidence) != 0 {
		return errors.New("exim_not_deferred")
	}
	return nil
}

// ValidateDeferredEximFixture validates one adapter-neutral future fixture.
func ValidateDeferredEximFixture(input []byte) error {
	var fixture struct {
		Schema       string `json:"schema"`
		CaseID       string `json:"case_id"`
		MessageDraft string `json:"message_draft"`
		DNSDraft     string `json:"dns_draft"`
		Class        string `json:"class"`
		Path         string `json:"path"`
		Operation    string `json:"operation"`
		MessageB64   string `json:"message_b64"`
		SMTP         struct {
			ReversePathB64  string   `json:"reverse_path_b64"`
			ForwardPathsB64 []string `json:"forward_paths_b64"`
		} `json:"smtp"`
		Expected struct {
			EximOutcome string `json:"exim_outcome"`
			Operation   string `json:"operation"`
			Fidelity    string `json:"fidelity"`
		} `json:"expected"`
		EvidenceState string `json:"evidence_state"`
	}
	if err := DecodeStrictJSON(input, maxVectorBytes, &fixture); err != nil {
		return err
	}
	if fixture.Schema != "dkim2.exim-adapter-fixture.v1" ||
		!caseIDPattern.MatchString(fixture.CaseID) ||
		fixture.MessageDraft != MessageDraft || fixture.DNSDraft != DNSDraft ||
		fixture.Class != classAdapter || fixture.EvidenceState != stateDeferred ||
		!stringSet("local_scan", "transport_filter")[fixture.Path] ||
		!stringSet("process", "sign", "revise")[fixture.Operation] ||
		fixture.Expected.Operation != fixture.Operation ||
		!stringSet("accept", "reject", "tempfail")[fixture.Expected.EximOutcome] ||
		fixture.Expected.Fidelity != "exim_"+fixture.Path {
		return errors.New("exim_fixture_invalid")
	}
	if _, err := decodePadded(fixture.MessageB64, maxVectorBytes); err != nil {
		return err
	}
	if _, err := decodePadded(fixture.SMTP.ReversePathB64, 1<<20); err != nil {
		return err
	}
	if len(fixture.SMTP.ForwardPathsB64) > 1024 {
		return errors.New("exim_fixture_invalid")
	}
	for _, path := range fixture.SMTP.ForwardPathsB64 {
		if _, err := decodePadded(path, 1<<20); err != nil {
			return err
		}
	}
	return nil
}

// LoadPortableCase reads one already manifest-verified case through a confined root.
func LoadPortableCase(root *os.Root, path string) (Case, error) {
	input, err := readConfinedFile(root, filepath.ToSlash(path), maxVectorBytes)
	if err != nil {
		return Case{}, err
	}
	return ValidateCaseBytes(input)
}
