package signing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	signingGoldenEdAlgorithm = "ed25519-sha256"
	signingGoldenNextDomain  = "next.example"
)

type signingGoldenCorpus struct {
	Draft      string                   `json:"draft"`
	Instances  []signingInstanceGolden  `json:"message_instances"`
	Signatures []signingSignatureGolden `json:"signature_fields"`
	Insertions []signingInsertionGolden `json:"insertions"`
}

type signingInstanceGolden struct {
	Name           string `json:"name"`
	Number         uint64 `json:"number"`
	Recipe         string `json:"recipe"`
	FieldSHA256    string `json:"field_sha256"`
	CanonicalBytes string `json:"section_9_6_sha256"`
}

type signingSignatureGolden struct {
	Name           string   `json:"name"`
	Form           string   `json:"form"`
	Sequence       uint64   `json:"sequence"`
	InstanceNumber uint64   `json:"instance_number"`
	Domain         string   `json:"domain"`
	NextDomain     string   `json:"next_domain"`
	Algorithms     []string `json:"algorithms"`
	Flags          []string `json:"flags"`
	RecipientCount int      `json:"recipient_count"`
	UnsignedSHA256 string   `json:"unsigned_sha256"`
	CompleteSHA256 string   `json:"complete_sha256"`
}

type signingInsertionGolden struct {
	Name           string `json:"name"`
	HeaderOnly     bool   `json:"header_only"`
	OutputSHA256   string `json:"output_sha256"`
	InheritedBytes string `json:"inherited_bytes"`
}

// TestDraft05SigningGoldenVectors verifies byte-exact generated fields and insertion artifacts.
func TestDraft05SigningGoldenVectors(t *testing.T) {
	corpus := readSigningGoldenCorpus(t)
	if corpus.Draft != "draft-ietf-dkim-dkim2-spec-05" {
		t.Fatalf("vector draft = %q", corpus.Draft)
	}
	for _, vector := range corpus.Instances {
		t.Run("instance/"+vector.Name, func(t *testing.T) {
			model, field := buildSigningGoldenInstance(t, vector)
			assertSigningGoldenDigest(t, "field", field, vector.FieldSHA256)
			target := buildSigningGoldenTarget(t, signingSignatureGolden{
				Name: "canonical", Form: string(PredecessorOrdinary), Algorithms: []string{signingGoldenEdAlgorithm},
				Sequence: vector.Number, RecipientCount: 1, InstanceNumber: vector.Number,
			})
			var inherited [][]byte
			if vector.Number > 1 {
				_, previousField := buildSigningGoldenInstance(t, signingInstanceGolden{Name: "previous", Number: vector.Number - 1})
				previousTarget := buildSigningGoldenTarget(t, signingSignatureGolden{
					Name: "previous", Form: string(PredecessorOrdinary), Algorithms: []string{signingGoldenEdAlgorithm},
					Sequence: vector.Number - 1, InstanceNumber: vector.Number - 1,
					RecipientCount: 1,
				})
				previousComplete, completeErr := previousTarget.Complete(signingGoldenSetValues([]string{signingGoldenEdAlgorithm}))
				if completeErr != nil {
					t.Fatalf("Complete(previous) error = %v", completeErr)
				}
				inherited = [][]byte{previousField, previousComplete.Bytes()}
			}
			headers, err := rawmsg.NewReconstructedHeaderBlock(inherited, rawmsg.DefaultParserOptions())
			if err != nil {
				t.Fatalf("NewReconstructedHeaderBlock() error = %v", err)
			}
			canonicalizer, err := canonical.NewCanonicalizer()
			if err != nil {
				t.Fatalf("NewCanonicalizer() error = %v", err)
			}
			input, err := canonicalizer.SigningInput(canonical.SigningInputSelection{
				Headers: headers, GeneratedInstance: model, GeneratedInstanceField: field,
				HasGeneratedInstance: true, Target: target,
			})
			if err != nil {
				t.Fatalf("SigningInput() error = %v", err)
			}
			assertSigningGoldenDigest(t, "section 9.6", input.Bytes(), vector.CanonicalBytes)
		})
	}
	for _, vector := range corpus.Signatures {
		t.Run("signature/"+vector.Name, func(t *testing.T) {
			target := buildSigningGoldenTarget(t, vector)
			assertSigningGoldenDigest(t, "unsigned", target.UnsignedBytes(), vector.UnsignedSHA256)
			complete, err := target.Complete(signingGoldenSetValues(vector.Algorithms))
			if err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
			assertSigningGoldenDigest(t, "complete", complete.Bytes(), vector.CompleteSHA256)
			rebuilt, err := target.RebuildUnsignedFromComplete(complete)
			if err != nil || !bytes.Equal(rebuilt.UnsignedBytes(), target.UnsignedBytes()) {
				t.Fatalf("RebuildUnsignedFromComplete() error = %v", err)
			}
		})
	}
	for _, vector := range corpus.Insertions {
		t.Run("insertion/"+vector.Name, func(t *testing.T) {
			sourceBytes := []byte(vector.InheritedBytes)
			source, err := rawmsg.Parse(sourceBytes)
			if err != nil {
				t.Fatalf("rawmsg.Parse(source) error = %v", err)
			}
			instanceModel, instanceField := buildSigningGoldenInstance(t, signingInstanceGolden{Name: "insert", Number: 1})
			_ = instanceModel
			target := buildSigningGoldenTarget(t, signingSignatureGolden{
				Name: "insert", Form: string(PredecessorOrdinary), Algorithms: []string{signingGoldenEdAlgorithm}, RecipientCount: 1,
			})
			complete, err := target.Complete(signingGoldenSetValues([]string{signingGoldenEdAlgorithm}))
			if err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
			inserted, err := rawmsg.InsertValidatedFields(rawmsg.InsertionRequest{
				Message: source, TransportForm: rawmsg.TransportFormFinalNetworkPreDotStuffing,
				Fields: [][]byte{instanceField, complete.Bytes()}, Options: rawmsg.DefaultParserOptions(),
			})
			if err != nil {
				t.Fatalf("InsertValidatedFields() error = %v", err)
			}
			if (inserted.Framing() == rawmsg.MessageFramingHeaderOnly) != vector.HeaderOnly {
				t.Fatalf("header-only framing = %t", inserted.Framing() == rawmsg.MessageFramingHeaderOnly)
			}
			assertSigningGoldenDigest(t, "inserted output", inserted.RawBytes(), vector.OutputSHA256)
		})
	}
}

// TestDraft05NextDomainGoldenChain validates the three exact nd flow artifacts as one custody chain.
func TestDraft05NextDomainGoldenChain(t *testing.T) {
	corpus := readSigningGoldenCorpus(t)
	predecessor := signingSignatureGolden{
		Name: "ordinary-predecessor", Form: string(PredecessorOrdinary), Sequence: 1, InstanceNumber: 1,
		Domain: "origin.example", Algorithms: []string{signingGoldenEdAlgorithm}, RecipientCount: 1,
	}
	vectors := []signingSignatureGolden{predecessor}
	for _, vector := range corpus.Signatures {
		switch vector.Name {
		case "terminal-next-domain-creation", "terminal-next-domain-continuation", "terminal-next-domain-completion":
			vectors = append(vectors, vector)
		}
	}
	if len(vectors) != 4 {
		t.Fatalf("next-domain vector count = %d, want 4 including predecessor", len(vectors))
	}
	fields := make([][]byte, len(vectors))
	for index, vector := range vectors {
		target := buildSigningGoldenTarget(t, vector)
		complete, err := target.Complete(signingGoldenSetValues(vector.Algorithms))
		if err != nil {
			t.Fatalf("Complete(%s) error = %v", vector.Name, err)
		}
		fields[index] = complete.Bytes()
	}
	headers, err := rawmsg.NewReconstructedHeaderBlock(fields, rawmsg.DefaultParserOptions())
	if err != nil {
		t.Fatalf("NewReconstructedHeaderBlock() error = %v", err)
	}
	parsed := make([]signature.Signature, len(fields))
	for index, field := range headers.FieldsByName(signature.HeaderName) {
		parsed[index], err = signature.Parse(field)
		if err != nil {
			t.Fatalf("Parse(chain %d) error = %v", index, err)
		}
	}
	result, err := signature.ValidateCustody(parsed, signature.DefaultCustodyLimits())
	if err != nil || !result.Valid() || result.Count() != 4 ||
		result.Status() != signature.CustodyStatusOrdinaryComplete || !result.HadNextDomain() {
		t.Fatalf("ValidateCustody() valid=%t count=%d status=%q nd=%t error=%v",
			result.Valid(), result.Count(), result.Status(), result.HadNextDomain(), err)
	}
}

// readSigningGoldenCorpus loads the version-pinned signing closeout corpus.
func readSigningGoldenCorpus(t *testing.T) signingGoldenCorpus {
	t.Helper()
	data, err := os.ReadFile("../../testdata/vectors/draft-ietf-dkim-dkim2-spec-05/signing-golden.json")
	if err != nil {
		t.Fatalf("ReadFile(signing-golden.json) error = %v", err)
	}
	var corpus signingGoldenCorpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatalf("Unmarshal(signing-golden.json) error = %v", err)
	}
	if len(corpus.Instances) == 0 || len(corpus.Signatures) == 0 || len(corpus.Insertions) == 0 {
		t.Fatal("signing golden corpus is incomplete")
	}
	return corpus
}

// buildSigningGoldenInstance constructs one fixed-hash Message-Instance vector.
func buildSigningGoldenInstance(t *testing.T, vector signingInstanceGolden) (instance.MessageInstance, []byte) {
	t.Helper()
	recipeBytes := []byte(vector.Recipe)
	model, err := instance.NewForSigning(instance.SigningRequest{
		Number:     vector.Number,
		HeaderHash: bytes.Repeat([]byte{0x11}, sha256.Size),
		BodyHash:   bytes.Repeat([]byte{0x22}, sha256.Size),
		Recipe:     recipeBytes, RecipePresent: len(recipeBytes) > 0,
	})
	if err != nil {
		t.Fatalf("NewForSigning() error = %v", err)
	}
	field, err := model.Render(instance.DefaultRenderLimits())
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	return model, field
}

// buildSigningGoldenTarget constructs one ordinary or terminal target vector.
func buildSigningGoldenTarget(t *testing.T, vector signingSignatureGolden) signature.UnsignedTarget {
	t.Helper()
	sets := make([]signature.SetPlan, len(vector.Algorithms))
	for index, algorithm := range vector.Algorithms {
		sets[index] = signature.SetPlan{Selector: signingGoldenSelector(algorithm), Algorithm: signature.Algorithm(algorithm)}
	}
	sequence := max(vector.Sequence, 1)
	instanceNumber := max(vector.InstanceNumber, 1)
	domain := vector.Domain
	if domain == "" {
		domain = "example.test"
	}
	request := signature.TargetRequest{
		Sequence: sequence, InstanceNumber: instanceNumber, Timestamp: 1_700_000_000,
		Domain: domain, Sets: sets, Flags: vector.Flags,
	}
	if vector.Form == "next_domain" {
		request.NextDomain = vector.NextDomain
		if request.NextDomain == "" {
			request.NextDomain = signingGoldenNextDomain
		}
	} else {
		request.MailFrom = []byte("<sender@" + domain + ">")
		request.Recipients = make([][]byte, vector.RecipientCount)
		for index := range request.Recipients {
			recipientDomain := signingGoldenNextDomain
			request.Recipients[index] = []byte("<recipient" + string(rune('a'+index)) + "@" + recipientDomain + ">")
		}
	}
	target, err := signature.NewUnsignedTarget(request, signature.DefaultRenderLimits())
	if err != nil {
		t.Fatalf("NewUnsignedTarget() error = %v", err)
	}
	return target
}

// signingGoldenSetValues returns deterministic algorithm-specific signature byte strings.
func signingGoldenSetValues(algorithms []string) []signature.SetValue {
	values := make([]signature.SetValue, len(algorithms))
	for index, algorithm := range algorithms {
		size := 64
		fill := byte(0x44)
		if algorithm == string(signature.AlgorithmRSASHA256) {
			size, fill = 128, 0x33
		}
		values[index] = signature.SetValue{
			Selector: signingGoldenSelector(algorithm), Algorithm: signature.Algorithm(algorithm),
			Signature: bytes.Repeat([]byte{fill}, size),
		}
	}
	return values
}

// signingGoldenSelector maps each baseline algorithm to one fixed distinct selector.
func signingGoldenSelector(algorithm string) string {
	if algorithm == string(signature.AlgorithmRSASHA256) {
		return "rsa"
	}
	return "ed"
}

// assertSigningGoldenDigest compares one exact byte artifact to its committed SHA-256.
func assertSigningGoldenDigest(t *testing.T, label string, value []byte, expected string) {
	t.Helper()
	digest := sha256.Sum256(value)
	got := hex.EncodeToString(digest[:])
	if got != expected {
		t.Errorf("%s sha256 = %q, want %q", label, got, expected)
	}
}
