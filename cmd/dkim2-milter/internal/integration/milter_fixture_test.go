//go:build linux || darwin

package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/daemon/generated"
	generatedfixture "github.com/croessner/dkim2/cmd/dkim2-milter/internal/integration/generated"
)

const (
	milterFixtureLimit       = 1 << 20
	milterCaseLimit          = 32
	milterEventLimit         = 64
	fixtureModeInbound       = "inbound"
	fixtureCommandHeader     = "header"
	fixtureCommandEndHeaders = "end_headers"
	fixtureCommandEndMessage = "end_message"
)

var milterFixtureIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type milterFixtureSet struct {
	Schema       string              `json:"schema"`
	MessageDraft string              `json:"message_draft"`
	DNSDraft     string              `json:"dns_draft"`
	Fidelity     string              `json:"fidelity"`
	Cases        []milterFixtureCase `json:"cases"`
}

type milterFixtureCase struct {
	ID                    string                 `json:"id"`
	Mode                  string                 `json:"mode"`
	Operation             string                 `json:"operation"`
	AuthenticationResults bool                   `json:"authentication_results"`
	Events                []milterFixtureEvent   `json:"events"`
	ExpectedRequest       milterExpectedRequest  `json:"expected_request"`
	ExpectedActions       []milterExpectedAction `json:"expected_actions"`
	Terminal              string                 `json:"terminal"`
}

type milterFixtureEvent struct {
	Command       string `json:"command"`
	PayloadBase64 string `json:"payload_base64"`
}

type milterExpectedRequest struct {
	RawBase64      string   `json:"raw_base64"`
	MailFromBase64 string   `json:"mail_from_base64"`
	RcptToBase64   []string `json:"rcpt_to_base64"`
}

type milterExpectedAction struct {
	Command string `json:"command"`
	Index   uint32 `json:"index"`
	Name    string `json:"name"`
	Value   string `json:"value"`
}

// TestExecutableStrictMilterFixtureMatrix drives versioned data through the real public socket.
func TestExecutableStrictMilterFixtureMatrix(t *testing.T) {
	fixtures := loadMilterFixtureSet(t, milterFixturePath(t))
	for _, fixtureCase := range fixtures.Cases {
		testCase := fixtureCase
		t.Run(testCase.ID, func(t *testing.T) {
			runMilterFixtureCase(t, testCase)
		})
	}
}

// TestStrictMilterFixtureLoaderRejectsClosedContractViolations proves offline closure.
func TestStrictMilterFixtureLoaderRejectsClosedContractViolations(t *testing.T) {
	path := milterFixturePath(t)
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutations := [][]byte{
		bytes.Replace(input, []byte(`"schema":`), []byte(`"unknown":0,"schema":`), 1),
		bytes.Replace(input, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1),
		bytes.Replace(input, []byte(`"milter_reconstructed_crlf"`), []byte(`"original_rfc5322"`), 1),
		bytes.Replace(input, []byte(`"draft-ietf-dkim-dkim2-spec-05"`), []byte(`"draft-ietf-dkim-dkim2-spec-04"`), 1),
		bytes.Replace(input, []byte(`"payload_base64": ""`), []byte(`"payload_base64": "***"`), 1),
		append(bytes.Clone(input), []byte("\n{}")...),
	}
	for index, mutation := range mutations {
		t.Run(fmt.Sprintf("mutation-%d", index), func(t *testing.T) {
			if _, err := decodeMilterFixtureSet(mutation); err == nil {
				t.Fatal("decodeMilterFixtureSet() accepted a closed-contract mutation")
			}
		})
	}
	oversize := bytes.Repeat([]byte{' '}, milterFixtureLimit+1)
	if _, err := decodeMilterFixtureSet(oversize); err == nil {
		t.Fatal("decodeMilterFixtureSet() accepted oversized input")
	}
}

// FuzzMilterFixtureDecoding exercises bounded strict fixture decoding.
func FuzzMilterFixtureDecoding(f *testing.F) {
	input, err := os.ReadFile(milterFixturePathForWorkingDirectory())
	if err == nil {
		f.Add(input)
	}
	f.Add([]byte(`{"schema":"dkim2.milter-fixtures.v1"}`))
	f.Fuzz(func(_ *testing.T, value []byte) {
		if len(value) > milterFixtureLimit+1 {
			value = value[:milterFixtureLimit+1]
		}
		_, _ = decodeMilterFixtureSet(value)
	})
}

// runMilterFixtureCase composes a generated daemon oracle with the executable adapter.
func runMilterFixtureCase(t *testing.T, fixtureCase milterFixtureCase) {
	t.Helper()
	service := &generatedDaemonService{}
	switch fixtureCase.Operation {
	case "process":
		service.process = func(body generatedfixture.ProcessRequest) generatedfixture.ProcessResponse {
			assertFixtureRequestProjection(
				t, fixtureCase, body.ApiVersion, body.Draft, body.Message, body.Smtp,
			)
			response := validFixtureProcessResponse()
			if fixtureCase.AuthenticationResults {
				response.Actions = generatedfixture.ActionPlan{{
					Name:  generatedfixture.AuthenticationResults,
					Type:  generatedfixture.AddHeader,
					Value: "mx.example.test; dkim2=pass",
				}}
			}
			return response
		}
	case "sign":
		service.sign = func(body generatedfixture.SignRequest) generatedfixture.OperationResponse {
			assertFixtureRequestProjection(
				t, fixtureCase, body.ApiVersion, body.Draft, body.Message, body.Smtp,
			)
			assertFixtureSigningContext(t, body.Context)
			return fixtureOperationResponse(
				"sign",
				generated.ActionPlan{
					{
						Name:  generated.MessageInstance,
						Type:  generated.AddHeader,
						Value: "v=2; i=fixture",
					},
					{
						Name:  generated.DKIM2Signature,
						Type:  generated.AddHeader,
						Value: "v=2; s=fixture",
					},
				},
			)
		}
	case "revise":
		service.revise = func(body generatedfixture.ReviseRequest) generatedfixture.OperationResponse {
			assertFixtureRequestProjection(
				t, fixtureCase, body.ApiVersion, body.Draft, body.Message, body.Smtp,
			)
			assertFixtureSigningContext(t, body.Context)
			return fixtureOperationResponse("revise", generated.ActionPlan{{
				Name:  generated.DKIM2Signature,
				Type:  generated.AddHeader,
				Value: "v=2; s=revision",
			}})
		}
	default:
		t.Fatal("fixture operation escaped validation")
	}
	daemonFixture := newGeneratedDaemonFixture(t, service)
	extraConfiguration := ""
	if fixtureCase.AuthenticationResults {
		extraConfiguration = `
authentication_results:
  enabled: true
  authserv_id: mx.example.test
`
	}
	process := startExecutable(
		t, daemonFixture.endpoint, fixtureCase.Mode, "tempfail", 2*time.Second,
		extraConfiguration,
	)
	peer := dialPublicPeer(t, process.socket)
	defer peer.close()
	peer.negotiate(t)
	var terminalFrames []adapterFrame
	for _, event := range fixtureCase.Events {
		payload, err := base64.StdEncoding.DecodeString(event.PayloadBase64)
		if err != nil {
			t.Fatal("validated fixture contained invalid Base64")
		}
		command := milterFixtureCommand(event.Command)
		if event.Command == fixtureCommandEndMessage {
			peer.send(t, command, payload)
			terminalFrames = receiveMilterFixtureFrames(t, peer, len(fixtureCase.ExpectedActions)+1)
			continue
		}
		peer.callback(t, command, payload)
		clear(payload)
	}
	assertMilterFixtureFrames(t, terminalFrames, fixtureCase)
	peer.send(t, peerQuit, nil)
	process.stop(t)
	assertPrivateOutputAbsent(t, process.log)
}

// receiveMilterFixtureFrames receives an exact, prevalidated action-plan length.
func receiveMilterFixtureFrames(
	t *testing.T,
	peer *protocolPeer,
	count int,
) []adapterFrame {
	t.Helper()
	frames := make([]adapterFrame, count)
	for index := range frames {
		frames[index] = peer.receive(t)
	}
	return frames
}

// assertMilterFixtureFrames compares independently decoded action frames in order.
func assertMilterFixtureFrames(
	t *testing.T,
	frames []adapterFrame,
	fixtureCase milterFixtureCase,
) {
	t.Helper()
	if len(frames) != len(fixtureCase.ExpectedActions)+1 {
		t.Fatalf("action-frame count = %d", len(frames))
	}
	for index, expected := range fixtureCase.ExpectedActions {
		actual := frames[index]
		wantCommand := milterFixtureActionCommand(expected.Command)
		if actual.command != wantCommand {
			t.Fatalf("action %d command = %q, want %q", index, actual.command, wantCommand)
		}
		payload := actual.payload
		gotIndex := uint32(0)
		if wantCommand == 'i' || wantCommand == 'm' {
			if len(payload) < 4 {
				t.Fatalf("action %d lacked index", index)
			}
			gotIndex = binary.BigEndian.Uint32(payload[:4])
			payload = payload[4:]
		}
		name, value, ok := splitHeaderAction(payload)
		if !ok || gotIndex != expected.Index ||
			name != expected.Name || value != expected.Value {
			t.Fatalf("action %d differed from independent fixture expectation", index)
		}
	}
	terminal := frames[len(frames)-1]
	if fixtureCase.Terminal != "accept" ||
		terminal.command != adapterAccept ||
		len(terminal.payload) != 0 {
		t.Fatal("terminal outcome differed from fixture")
	}
}

// assertFixtureRequestProjection compares generated DTO bytes with fixture authority.
func assertFixtureRequestProjection(
	t *testing.T,
	fixtureCase milterFixtureCase,
	api generatedfixture.APIVersion,
	draft generatedfixture.DraftVersion,
	message generatedfixture.MessageInput,
	smtp generatedfixture.SMTPInput,
) {
	t.Helper()
	if api != generatedfixture.V1 ||
		draft != generatedfixture.DraftIetfDkimDkim2Spec05 ||
		message.Fidelity == nil ||
		*message.Fidelity != generatedfixture.MilterReconstructedCrlf {
		t.Fatal("generated request identity or fidelity differed from fixture")
	}
	rawEncoded := protectedFixtureBytes(t, message.RawRfc5322Base64)
	defer clear(rawEncoded)
	raw, err := base64.StdEncoding.DecodeString(string(rawEncoded))
	if err != nil {
		t.Fatal("generated message contained invalid Base64")
	}
	defer clear(raw)
	mailFrom := protectedFixtureBytes(t, smtp.MailFrom)
	defer clear(mailFrom)
	wantRaw := decodeFixtureBase64(t, fixtureCase.ExpectedRequest.RawBase64)
	defer clear(wantRaw)
	wantMailFrom := decodeFixtureBase64(t, fixtureCase.ExpectedRequest.MailFromBase64)
	defer clear(wantMailFrom)
	if !bytes.Equal(raw, wantRaw) || !bytes.Equal(mailFrom, wantMailFrom) ||
		len(smtp.RcptTo) != len(fixtureCase.ExpectedRequest.RcptToBase64) {
		t.Fatal("generated message or envelope projection differed from independent fixture")
	}
	for index := range smtp.RcptTo {
		actual := protectedFixtureBytes(t, smtp.RcptTo[index])
		expected := decodeFixtureBase64(t, fixtureCase.ExpectedRequest.RcptToBase64[index])
		equal := bytes.Equal(actual, expected)
		clear(actual)
		clear(expected)
		if !equal {
			t.Fatal("generated recipient projection differed from independent fixture")
		}
	}
}

// protectedFixtureBytes extracts one generated protected string.
func protectedFixtureBytes(
	t *testing.T,
	value interface{ Bytes() ([]byte, error) },
) []byte {
	t.Helper()
	encoded, err := value.Bytes()
	if err != nil {
		t.Fatal("generated protected value was unavailable")
	}
	return encoded
}

// decodeFixtureBase64 decodes one fixture-owned exact byte string.
func decodeFixtureBase64(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatal("validated fixture contained invalid Base64")
	}
	return decoded
}

// loadMilterFixtureSet reads one bounded regular fixture file.
func loadMilterFixtureSet(t *testing.T, path string) milterFixtureSet {
	t.Helper()
	pathStateBefore, err := os.Lstat(path)
	if err != nil || !pathStateBefore.Mode().IsRegular() ||
		pathStateBefore.Mode()&os.ModeSymlink != 0 {
		t.Fatal("milter fixture path was not one regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	descriptorStateBefore, err := file.Stat()
	if err != nil || !os.SameFile(pathStateBefore, descriptorStateBefore) ||
		!descriptorStateBefore.Mode().IsRegular() {
		t.Fatal("milter fixture changed before descriptor acquisition")
	}
	input, err := io.ReadAll(io.LimitReader(file, milterFixtureLimit+1))
	if err != nil {
		t.Fatal(err)
	}
	descriptorStateAfter, descriptorErr := file.Stat()
	pathStateAfter, pathErr := os.Lstat(path)
	if descriptorErr != nil || pathErr != nil ||
		!os.SameFile(descriptorStateBefore, descriptorStateAfter) ||
		!os.SameFile(descriptorStateAfter, pathStateAfter) ||
		descriptorStateBefore.Size() != descriptorStateAfter.Size() ||
		descriptorStateBefore.Mode() != descriptorStateAfter.Mode() ||
		descriptorStateAfter.Size() != int64(len(input)) {
		t.Fatal("milter fixture changed during bounded descriptor read")
	}
	fixtures, err := decodeMilterFixtureSet(input)
	if err != nil {
		t.Fatalf("fixture decoding failed: %v", err)
	}
	return fixtures
}

// decodeMilterFixtureSet enforces the closed fixture syntax and semantic bounds.
func decodeMilterFixtureSet(input []byte) (milterFixtureSet, error) {
	if len(input) == 0 || len(input) > milterFixtureLimit {
		return milterFixtureSet{}, errors.New("fixture_size")
	}
	if err := validateMilterFixtureJSONMembers(input); err != nil {
		return milterFixtureSet{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var fixtures milterFixtureSet
	if err := decoder.Decode(&fixtures); err != nil {
		return milterFixtureSet{}, errors.New("fixture_json")
	}
	if err := requireMilterFixtureEOF(decoder); err != nil {
		return milterFixtureSet{}, err
	}
	if err := validateMilterFixtureSet(fixtures); err != nil {
		return milterFixtureSet{}, err
	}
	return fixtures, nil
}

// validateMilterFixtureSet enforces exact identities, enums, ordering, and byte limits.
func validateMilterFixtureSet(fixtures milterFixtureSet) error {
	if fixtures.Schema != "dkim2.milter-fixtures.v1" ||
		fixtures.MessageDraft != "draft-ietf-dkim-dkim2-spec-05" ||
		fixtures.DNSDraft != "draft-chuang-dkim2-dns-04" ||
		fixtures.Fidelity != "milter_reconstructed_crlf" ||
		len(fixtures.Cases) == 0 || len(fixtures.Cases) > milterCaseLimit {
		return errors.New("fixture_identity")
	}
	ids := make(map[string]struct{}, len(fixtures.Cases))
	for _, fixtureCase := range fixtures.Cases {
		if err := validateMilterFixtureCase(fixtureCase); err != nil {
			return err
		}
		if _, duplicate := ids[fixtureCase.ID]; duplicate {
			return errors.New("fixture_duplicate")
		}
		ids[fixtureCase.ID] = struct{}{}
	}
	return nil
}

// validateMilterFixtureCase enforces one closed operation and callback sequence.
func validateMilterFixtureCase(fixtureCase milterFixtureCase) error {
	operationForMode := map[string]string{
		fixtureModeInbound: "process", "originator": "sign", "ordinary_transit": "revise",
	}
	if !milterFixtureIDPattern.MatchString(fixtureCase.ID) ||
		operationForMode[fixtureCase.Mode] != fixtureCase.Operation ||
		fixtureCase.Terminal != "accept" ||
		len(fixtureCase.Events) < 6 || len(fixtureCase.Events) > milterEventLimit ||
		len(fixtureCase.ExpectedActions) > 3 ||
		fixtureCase.AuthenticationResults && fixtureCase.Mode != fixtureModeInbound {
		return errors.New("fixture_case")
	}
	if err := validateMilterFixtureEventOrder(fixtureCase.Events); err != nil {
		return err
	}
	if fixtureCase.Events[len(fixtureCase.Events)-1].Command != fixtureCommandEndMessage {
		return errors.New("fixture_event_order")
	}
	for _, event := range fixtureCase.Events {
		if milterFixtureCommand(event.Command) == 0 {
			return errors.New("fixture_event")
		}
		payload, err := base64.StdEncoding.Strict().DecodeString(event.PayloadBase64)
		if err != nil || len(payload) > 65535 {
			return errors.New("fixture_base64")
		}
		clear(payload)
	}
	for _, value := range append(
		[]string{
			fixtureCase.ExpectedRequest.RawBase64,
			fixtureCase.ExpectedRequest.MailFromBase64,
		},
		fixtureCase.ExpectedRequest.RcptToBase64...,
	) {
		decoded, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(decoded) > 1<<20 {
			return errors.New("fixture_base64")
		}
		clear(decoded)
	}
	for _, action := range fixtureCase.ExpectedActions {
		if milterFixtureActionCommand(action.Command) == 0 ||
			action.Name == "" || strings.ContainsAny(action.Name+action.Value, "\r\n\x00") {
			return errors.New("fixture_action")
		}
		if action.Command == "add_header" && action.Index != 0 {
			return errors.New("fixture_action")
		}
	}
	return nil
}

// validateMilterFixtureEventOrder enforces the complete callback-sequence FSM.
func validateMilterFixtureEventOrder(events []milterFixtureEvent) error {
	const (
		stateConnect = iota + 1
		stateHelo
		stateMail
		stateRecipient
		stateHeaders
		stateBody
		stateDone
	)
	state := stateConnect
	recipients := 0
	for _, event := range events {
		switch state {
		case stateConnect:
			if event.Command != "connect" {
				return errors.New("fixture_event_order")
			}
			state = stateHelo
		case stateHelo:
			if event.Command != "helo" {
				return errors.New("fixture_event_order")
			}
			state = stateMail
		case stateMail:
			if event.Command != "mail" {
				return errors.New("fixture_event_order")
			}
			state = stateRecipient
		case stateRecipient:
			switch event.Command {
			case "recipient":
				recipients++
			case fixtureCommandHeader:
				if recipients == 0 {
					return errors.New("fixture_event_order")
				}
				state = stateHeaders
			case fixtureCommandEndHeaders:
				if recipients == 0 {
					return errors.New("fixture_event_order")
				}
				state = stateBody
			default:
				return errors.New("fixture_event_order")
			}
		case stateHeaders:
			switch event.Command {
			case fixtureCommandHeader:
			case fixtureCommandEndHeaders:
				state = stateBody
			default:
				return errors.New("fixture_event_order")
			}
		case stateBody:
			switch event.Command {
			case "body":
			case fixtureCommandEndMessage:
				state = stateDone
			default:
				return errors.New("fixture_event_order")
			}
		case stateDone:
			return errors.New("fixture_event_order")
		}
	}
	if state != stateDone {
		return errors.New("fixture_event_order")
	}
	return nil
}

// milterFixtureCommand maps the closed event vocabulary without production parsing.
func milterFixtureCommand(value string) byte {
	return map[string]byte{
		"connect": peerConnect, "helo": peerHelo, "mail": peerMail,
		"recipient": peerRecipient, fixtureCommandHeader: peerHeader,
		fixtureCommandEndHeaders: peerEOH, "body": peerBody, fixtureCommandEndMessage: peerEOM,
	}[value]
}

// milterFixtureActionCommand maps the closed expected response vocabulary.
func milterFixtureActionCommand(value string) byte {
	return map[string]byte{
		"add_header": 'h', "insert_header": 'i', "change_header": 'm',
	}[value]
}

// validateMilterFixtureJSONMembers rejects duplicate members at every depth.
func validateMilterFixtureJSONMembers(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := walkMilterFixtureJSON(decoder, 0); err != nil {
		return err
	}
	return requireMilterFixtureEOF(decoder)
}

// walkMilterFixtureJSON consumes one bounded JSON value with duplicate detection.
func walkMilterFixtureJSON(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("fixture_depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return errors.New("fixture_json")
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, tokenErr := decoder.Token()
			name, valid := nameToken.(string)
			if tokenErr != nil || !valid {
				return errors.New("fixture_json")
			}
			if _, duplicate := seen[name]; duplicate {
				return errors.New("fixture_duplicate_member")
			}
			seen[name] = struct{}{}
			if err := walkMilterFixtureJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim('}') {
			return errors.New("fixture_json")
		}
	case '[':
		count := 0
		for decoder.More() {
			count++
			if count > 4096 {
				return errors.New("fixture_count")
			}
			if err := walkMilterFixtureJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		end, endErr := decoder.Token()
		if endErr != nil || end != json.Delim(']') {
			return errors.New("fixture_json")
		}
	default:
		return errors.New("fixture_json")
	}
	return nil
}

// requireMilterFixtureEOF rejects trailing JSON values and malformed suffixes.
func requireMilterFixtureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("fixture_trailing")
	}
	return nil
}

// milterFixturePath resolves the durable fixture relative to the package.
func milterFixturePath(t *testing.T) string {
	t.Helper()
	return milterFixturePathForWorkingDirectory()
}

// milterFixturePathForWorkingDirectory returns the repository-relative fixture path.
func milterFixturePathForWorkingDirectory() string {
	return filepath.Clean(
		"../../../../testdata/conformance/milter/" +
			"draft-ietf-dkim-dkim2-spec-05/portable-fixtures.json",
	)
}
