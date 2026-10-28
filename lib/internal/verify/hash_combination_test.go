package verify

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

const hashCombinationBase = "Subject:hashes\r\n\r\nbody\r\n"

// hashCombinationValue renders an h= template over the fixed base message:
// {sha256} and {sha512} are matching sets, {sha256-header} and {sha512-body}
// mismatch in one dimension, and {x-new} is an unimplemented algorithm.
func hashCombinationValue(t *testing.T, template string) string {
	t.Helper()
	baseMessage, err := rawmsg.Parse([]byte(hashCombinationBase))
	if err != nil {
		t.Fatal(err)
	}
	set := func(algorithm canonical.HashAlgorithm, flipHeader, flipBody bool) string {
		canonicalizer, newErr := canonical.NewCanonicalizer(canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			t.Fatal(newErr)
		}
		header, headerErr := canonicalizer.HeaderHashFromMessage(baseMessage)
		body, bodyErr := canonicalizer.BodyHashFromMessage(baseMessage)
		if headerErr != nil || bodyErr != nil {
			t.Fatal(headerErr, bodyErr)
		}
		headerDigest, _ := header.Digest()
		bodyDigest, _ := body.Digest()
		headerBytes, bodyBytes := headerDigest.Bytes(), bodyDigest.Bytes()
		if flipHeader {
			headerBytes[0] ^= 0xff
		}
		if flipBody {
			bodyBytes[0] ^= 0xff
		}
		return string(algorithm) + ":" + base64.StdEncoding.EncodeToString(headerBytes) + ":" + base64.StdEncoding.EncodeToString(bodyBytes)
	}
	return strings.NewReplacer(
		"{sha256}", set(canonical.HashAlgorithmSHA256, false, false),
		"{sha512}", set(canonical.HashAlgorithmSHA512, false, false),
		"{sha256-header}", set(canonical.HashAlgorithmSHA256, true, false),
		"{sha512-body}", set(canonical.HashAlgorithmSHA512, false, true),
		"{x-new}", "x-new:"+base64.StdEncoding.EncodeToString([]byte("header"))+":"+base64.StdEncoding.EncodeToString([]byte("body")),
	).Replace(template)
}

// hashCombinationMessage parses one message whose Message-Instance carries
// the rendered template above the given remainder.
func hashCombinationMessage(t *testing.T, template, remainder string) (rawmsg.Message, instance.MessageInstance) {
	t.Helper()
	message, err := rawmsg.Parse([]byte("Message-Instance: m=1; h=" + hashCombinationValue(t, template) + ";\r\n" + remainder))
	if err != nil {
		t.Fatal(err)
	}
	instances, err := instance.Extract(message)
	if err != nil || len(instances) != 1 {
		t.Fatalf("instance.Extract() = %d, %v", len(instances), err)
	}
	return message, instances[0]
}

// TestDraft08HashCombinationReproducers pins the Section 14.7 algebra on
// real digests through the target comparison every verification path uses.
func TestDraft08HashCombinationReproducers(t *testing.T) {
	tests := []struct {
		name       string
		template   string
		pass       bool
		headerHash HashStatus
		bodyHash   HashStatus
	}{
		{"sha256|x-new with sha256 PASS passes", "{sha256}|{x-new}", true, HashStatusPass, HashStatusPass},
		{"sha256,x-new is PERMERROR", "{sha256},{x-new}", false, HashStatusUnsupported, HashStatusUnsupported},
		{"single unknown hash-set is PERMERROR", "{x-new}", false, HashStatusUnsupported, HashStatusUnsupported},
		{"mismatch in one group and PASS in another passes", "{sha256-header}|{sha512}", true, HashStatusPass, HashStatusPass},
		{"hash-all with one header mismatch fails", "{sha256-header},{sha512}", false, HashStatusMismatch, HashStatusPass},
		{"decisive body mismatch is reported in the body", "{sha512-body}|{sha256-header}", false, HashStatusPass, HashStatusMismatch},
		{"FAIL beats PERMERROR across groups", "{x-new}|{sha256-header}", false, HashStatusMismatch, HashStatusPass},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			message, parsed := hashCombinationMessage(t, test.template, hashCombinationBase)
			result, err := compareTargetHashes(mustCanonicalizer(t), message, parsed, Target{Sequence: 1, InstanceNumber: 1})
			if err != nil || result.pass != test.pass || result.header.HashStatus != test.headerHash || result.body.HashStatus != test.bodyHash {
				t.Fatalf("compareTargetHashes() = pass:%t header:%q body:%q error:%v", result.pass, result.header.HashStatus, result.body.HashStatus, err)
			}
		})
	}
}

// TestDraft08HeadersOnlyHashSetPassesOnHeaderHash pins Section 16.4 item 3:
// without a body, a hash-set passes when its header hash matches, and the
// Section 14.7 combination still applies.
func TestDraft08HeadersOnlyHashSetPassesOnHeaderHash(t *testing.T) {
	headersOnly := "Subject:hashes\r\n"
	tests := []struct {
		template string
		pass     bool
	}{
		{"{sha512-body}", true},
		{"{sha256-header}", false},
		{"{sha256-header}|{sha512-body}", true},
		{"{sha256},{x-new}", false},
		{"{x-new}|{sha256}", true},
	}
	for _, test := range tests {
		message, parsed := hashCombinationMessage(t, test.template, headersOnly)
		if message.Framing() != rawmsg.MessageFramingHeaderOnly {
			t.Fatal("fixture is not header-only")
		}
		result, err := compareTargetHeaderHash(mustCanonicalizer(t), message, parsed, Target{Sequence: 1, InstanceNumber: 1})
		if err != nil || result.pass != test.pass {
			t.Fatalf("%s: compareTargetHeaderHash() = pass:%t error:%v, want %t", test.template, result.pass, err, test.pass)
		}
	}
}

// TestDraft08HistoryEvaluatesLowerInstanceGroups proves Section 13 history
// checks evaluate each lower Message-Instance h= with the Section 14.7
// algebra against the recreated message: a mismatching group beside a
// passing alternative is accepted, an unknown algorithm inside the only
// group is unsupported, and a mismatching only group fails. A mismatching
// implemented set beside an unknown one in the same hash-all group fails as
// well: Section 14.7 step 4 lets a FAIL intermediate win over a PERMERROR
// intermediate, exactly as on the current-target path.
func TestDraft08HistoryEvaluatesLowerInstanceGroups(t *testing.T) {
	current := []byte("Subject:current\r\n\r\nbody\r\n")
	mismatch := historyHashSets(t, current, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256}, canonical.HashAlgorithmSHA256)
	sha512 := historyHashSets(t, current, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA512}, "")
	unknown := "x-new:" + base64.StdEncoding.EncodeToString([]byte("header")) + ":" + base64.StdEncoding.EncodeToString([]byte("body"))
	currentSets := historyHashSets(t, current, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256}, "")
	tests := []struct {
		name     string
		lower    string
		coverage HistoryCoverage
		stop     HistoryStopReason
	}{
		{"mismatch|pass", mismatch + " | " + sha512, HistoryCoverageComplete, HistoryStopOriginReached},
		{"pass,unknown", sha512 + "," + unknown, HistoryCoverageUnsupported, HistoryStopHashUnsupported},
		{"mismatch only", mismatch, HistoryCoverageFailed, HistoryStopHashMismatch},
		{"mismatch,unknown", mismatch + "," + unknown, HistoryCoverageFailed, HistoryStopHashMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collection := parseHistoryCollection(t, historyInstanceLineWithSets(1, test.lower, ""), historyInstanceLineWithSets(2, currentSets, ""))
			walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(2), collection, mustHistoryState(t, current))
			if err != nil || !walk.Valid() || walk.Coverage() != test.coverage || walk.StopReason() != test.stop {
				t.Fatalf("Walk() = valid:%t coverage:%q stop:%q error:%v", walk.Valid(), walk.Coverage(), walk.StopReason(), err)
			}
		})
	}
}

// TestHashCombinationComputableOnlyRejectsDigestFreeValues proves the cheap
// precondition is false only when no hash-set is implemented, which is
// exactly when every Section 14.7 intermediate is PERMERROR; a value with
// an implemented set beside an unknown one in a single group still needs
// the digest, because a mismatch there is FAIL.
func TestHashCombinationComputableOnlyRejectsDigestFreeValues(t *testing.T) {
	tests := []struct {
		template   string
		computable bool
	}{
		{"{x-new}", false},
		{"{sha256}", true},
		{"{sha256},{sha512}", true},
		{"{sha256-header},{x-new}", true},
		{"{x-new}|{sha256}", true},
	}
	for _, test := range tests {
		_, parsed := hashCombinationMessage(t, test.template, hashCombinationBase)
		if got := HashCombinationComputable(parsed); got != test.computable {
			t.Fatalf("%s: HashCombinationComputable() = %t, want %t", test.template, got, test.computable)
		}
		evaluation, digestFree := digestFreeHashEvaluation(parsed)
		if digestFree == test.computable || digestFree && !evaluation.permanentError() {
			t.Fatalf("%s: digestFreeHashEvaluation() = %v,%t", test.template, evaluation.outcome.Result(), digestFree)
		}
	}
}
