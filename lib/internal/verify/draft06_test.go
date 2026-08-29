package verify

import (
	"context"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/canonical"
	"github.com/croessner/dkim2/internal/instance"
	"github.com/croessner/dkim2/internal/rawmsg"
)

// TestVerifierAcceptsSHA512Only proves current content verification does not require an advertised SHA-256 tuple.
func TestVerifierAcceptsSHA512Only(t *testing.T) {
	message, parsed := draft06HashFixture(t, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA512}, "")
	result, err := compareTargetHashes(mustCanonicalizer(t), message, parsed, Target{Sequence: 1, InstanceNumber: 1})
	if err != nil || !result.pass || !result.hasLocalHeaderSHA256 {
		t.Fatalf("compareTargetHashes() = pass:%t projection:%t error:%v", result.pass, result.hasLocalHeaderSHA256, err)
	}
}

// TestVerifierRejectsOneMismatchingSupportedTuple proves one known mismatch cannot be hidden by another known match.
func TestVerifierRejectsOneMismatchingSupportedTuple(t *testing.T) {
	message, parsed := draft06HashFixture(t, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256, canonical.HashAlgorithmSHA512}, canonical.HashAlgorithmSHA512)
	result, err := compareTargetHashes(mustCanonicalizer(t), message, parsed, Target{Sequence: 1, InstanceNumber: 1})
	if err != nil || result.pass || result.header.HashStatus != HashStatusMismatch {
		t.Fatalf("compareTargetHashes() = pass:%t header:%q error:%v", result.pass, result.header.HashStatus, err)
	}
}

// TestHistoryAcceptsRecipeLessUnchangedTransitionMatrix proves every supported tuple must match an unchanged predecessor.
func TestHistoryAcceptsRecipeLessUnchangedTransitionMatrix(t *testing.T) {
	current := []byte("Subject:current\r\n\r\nbody\r\n")
	tests := []struct {
		name       string
		algorithms []canonical.HashAlgorithm
		mismatch   canonical.HashAlgorithm
		unknown    bool
		coverage   HistoryCoverage
		stop       HistoryStopReason
	}{
		{"sha256", []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256}, "", false, HistoryCoverageComplete, HistoryStopOriginReached},
		{testHashCaseSHA512Only, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA512}, "", false, HistoryCoverageComplete, HistoryStopOriginReached},
		{"dual", []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256, canonical.HashAlgorithmSHA512}, "", false, HistoryCoverageComplete, HistoryStopOriginReached},
		{testHashCaseDualMismatch, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256, canonical.HashAlgorithmSHA512}, canonical.HashAlgorithmSHA512, false, HistoryCoverageFailed, HistoryStopHashMismatch},
		{"unknown only", nil, "", true, HistoryCoverageUnsupported, HistoryStopHashUnsupported},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sets := historyHashSets(t, current, test.algorithms, test.mismatch)
			currentSets := historyHashSets(t, current, test.algorithms, "")
			if test.unknown {
				sets = "future:" + base64.StdEncoding.EncodeToString([]byte("header")) + ":" + base64.StdEncoding.EncodeToString([]byte("body"))
				currentSets = historyHashSets(t, current, []canonical.HashAlgorithm{canonical.HashAlgorithmSHA256}, "")
			}
			collection := parseHistoryCollection(t, historyInstanceLineWithSets(1, sets, ""), historyInstanceLineWithSets(2, currentSets, ""))
			walk, err := mustHistoryCoordinator(t, HistoryLimits{}).Walk(context.Background(), historyPassResult(2), collection, mustHistoryState(t, current))
			if err != nil || !walk.Valid() || walk.Coverage() != test.coverage || walk.StopReason() != test.stop || len(walk.Transitions()) != 1 {
				t.Fatalf("Walk() = valid:%t coverage:%q stop:%q transitions:%d error:%v", walk.Valid(), walk.Coverage(), walk.StopReason(), len(walk.Transitions()), err)
			}
		})
	}
}

// TestSignatureResultsPreserveOccurrenceOrder proves same-algorithm facts remain positional.
func TestSignatureResultsPreserveOccurrenceOrder(t *testing.T) {
	sets := []SignatureSetResult{
		{Index: 0, Algorithm: AlgorithmRSASHA256, Status: SignatureSetStatusPass, KeyStatus: KeyStatusFound},
		{Index: 1, Algorithm: AlgorithmRSASHA256, Status: SignatureSetStatusFail, KeyStatus: KeyStatusFound},
	}
	result := NewResult(Target{Sequence: 1, InstanceNumber: 1}, TargetStatusMixed, nil, sets)
	got := result.SignatureSets()
	if len(got) != 2 || got[0].Index != 0 || got[0].Status != SignatureSetStatusPass || got[1].Index != 1 || got[1].Status != SignatureSetStatusFail {
		t.Fatalf("SignatureSets() = %#v", got)
	}
}

// draft06HashFixture constructs one parsed current Message-Instance with controlled supported tuples.
func draft06HashFixture(t *testing.T, algorithms []canonical.HashAlgorithm, mismatch canonical.HashAlgorithm) (rawmsg.Message, instance.MessageInstance) {
	t.Helper()
	const base = "Subject:hashes\r\n\r\nbody\r\n"
	baseMessage, err := rawmsg.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	sets := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		canonicalizer, newErr := canonical.NewCanonicalizer(canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			t.Fatal(newErr)
		}
		header, headerErr := canonicalizer.HeaderHashFromMessage(baseMessage)
		body, bodyErr := canonicalizer.BodyHashFromMessage(baseMessage)
		if headerErr != nil || bodyErr != nil {
			t.Fatalf("canonical hashes = %v, %v", headerErr, bodyErr)
		}
		headerDigest, headerOK := header.Digest()
		bodyDigest, bodyOK := body.Digest()
		if !headerOK || !bodyOK {
			t.Fatal("canonical digest absent")
		}
		headerBytes := headerDigest.Bytes()
		if algorithm == mismatch {
			headerBytes[0] ^= 0xff
		}
		sets = append(sets, string(algorithm)+":"+base64.StdEncoding.EncodeToString(headerBytes)+":"+bodyDigest.Base64())
	}
	raw := "Message-Instance: m=1; h=" + strings.Join(sets, ",") + ";\r\n" + base
	message, err := rawmsg.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	instances, err := instance.Extract(message)
	if err != nil || len(instances) != 1 {
		t.Fatalf("instance.Extract() = %d, %v", len(instances), err)
	}
	return message, instances[0]
}

// historyHashSets renders controlled canonical digest tuples for one historical state.
func historyHashSets(t *testing.T, message []byte, algorithms []canonical.HashAlgorithm, mismatch canonical.HashAlgorithm) string {
	t.Helper()
	parsed, err := rawmsg.Parse(message)
	if err != nil {
		t.Fatal(err)
	}
	sets := make([]string, 0, len(algorithms))
	for _, algorithm := range algorithms {
		canonicalizer, newErr := canonical.NewCanonicalizer(canonical.WithHashAlgorithm(algorithm))
		if newErr != nil {
			t.Fatal(newErr)
		}
		headerResult, headerErr := canonicalizer.HeaderHashFromMessage(parsed)
		bodyResult, bodyErr := canonicalizer.BodyHashFromMessage(parsed)
		header := mustDigest(t, mustCanonicalResult(t, headerResult, headerErr))
		body := mustDigest(t, mustCanonicalResult(t, bodyResult, bodyErr))
		headerBytes := header.Bytes()
		if algorithm == mismatch {
			headerBytes[0] ^= 0xff
		}
		sets = append(sets, string(algorithm)+":"+base64.StdEncoding.EncodeToString(headerBytes)+":"+body.Base64())
	}
	return strings.Join(sets, ",")
}

// mustCanonicalResult unwraps one canonical result for compact fixture construction.
func mustCanonicalResult(t *testing.T, result canonical.Result, err error) canonical.Result {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// historyInstanceLineWithSets constructs one Message-Instance with a complete h= list.
func historyInstanceLineWithSets(number uint64, sets, recipeJSON string) string {
	line := "Message-Instance: m=" + strconv.FormatUint(number, 10) + "; h=" + sets
	if recipeJSON != "" {
		line += "; r=" + base64.StdEncoding.EncodeToString([]byte(recipeJSON))
	}
	return line + ";\r\n"
}
