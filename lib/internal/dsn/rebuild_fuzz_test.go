package dsn

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/verify"
)

// fuzzRebuildMaxInputBytes bounds every fuzzed rebuild input dimension so a
// single iteration stays cheap and deterministic.
const fuzzRebuildMaxInputBytes = 4096

// FuzzRebuild drives the rebuild itself: it fuzzes the authenticated recipe
// JSON, the origin and current header blocks and bodies, the headers-only
// and tamper switches, builds a signed two-instance chain through dsntest
// inside the harness, wraps it in a signed report, evaluates it, and rebuilds
// it. It proves the rebuild never panics, never returns an invalid report,
// keeps errors content-free, never exposes output for a failed rebuild, and
// emits only reports that the strict parsers accept without
// destination-specific fields and within the size bound.
func FuzzRebuild(f *testing.F) {
	keys := receivedKeys()
	staticKeys := make([]verify.StaticKey, 0, len(keys))
	for domain, key := range keys {
		staticKeys = append(staticKeys, verify.StaticKey{Domain: domain, Selector: key.Selector, Algorithm: verify.AlgorithmEd25519SHA256, Material: key.Public()})
	}
	provider, err := verify.NewStaticKeyProvider(staticKeys)
	if err != nil {
		f.Fatal(err)
	}
	verifier, err := verify.NewVerifier(provider, verify.WithClock(receivedFuzzClock))
	if err != nil {
		f.Fatal(err)
	}
	evaluator, err := NewReceivedEvaluator(verifier, ReceivedEvaluatorConfig{Parser: Options{MaxMessageBytes: 1 << 20, MaxPartBytes: 1 << 19, MaxBoundaryBytes: 70}})
	if err != nil {
		f.Fatal(err)
	}
	for _, recipeJSON := range []string{rebuildFullRecipe, rebuildHeaderRecipe, rebuildBodyRecipe, rebuildNullRecipe} {
		f.Add([]byte(recipeJSON), []byte(rebuildOriginHeaders), []byte(rebuildOriginBody), []byte(rebuildCurrentHeaders), []byte(rebuildCurrentBody), false, false)
		f.Add([]byte(recipeJSON), []byte(rebuildOriginHeaders), []byte(rebuildOriginBody), []byte(rebuildCurrentHeaders), []byte(rebuildCurrentBody), true, false)
	}
	f.Add([]byte(rebuildFullRecipe), []byte(rebuildOriginHeaders), []byte(rebuildOriginBody), []byte(rebuildCurrentHeaders), []byte(rebuildCurrentBody), false, true)
	f.Add([]byte(`{"h":{"subject":[{"x":1}]}}`), []byte(rebuildOriginHeaders), []byte(rebuildOriginBody), []byte(rebuildCurrentHeaders), []byte(rebuildCurrentBody), false, false)
	f.Add([]byte(rebuildFullRecipe), []byte("Received: r1\r\nX-Origin-Note: caf\xc3\xa9\r\n"+rebuildOriginHeaders), []byte("caf\xc3\xa9\r\n"), []byte("Received: r1\r\nX-Origin-Note: caf\xc3\xa9\r\n"+rebuildCurrentHeaders), []byte(rebuildCurrentBody), false, false)
	errorShape := regexp.MustCompile(`^dsn rebuild error: code=[a-z_]+$`)
	f.Fuzz(func(t *testing.T, recipeJSON, originHeaders, originBody, currentHeaders, currentBody []byte, headersOnly, tamper bool) {
		for _, input := range [][]byte{recipeJSON, originHeaders, originBody, currentHeaders, currentBody} {
			if len(input) > fuzzRebuildMaxInputBytes {
				return
			}
		}
		spec := propagationSpec{
			original: dsntest.Original{
				Headers: fuzzHeaderBlock(currentHeaders), Body: string(currentBody),
				Revisions: []dsntest.Revision{{Headers: fuzzHeaderBlock(originHeaders), Body: string(originBody), Recipe: string(recipeJSON)}},
				Hops:      defaultPropagationOriginal(rebuildFullRecipe).Hops,
			},
			headersOnly: headersOnly,
		}
		if tamper {
			spec.mutate = func(raw []byte) []byte { return bytes.Replace(raw, []byte("Subject:"), []byte("Subject: tampered"), 1) }
		}
		raw, ok := spec.tryBuild()
		if !ok {
			return
		}
		evaluation, err := evaluator.Evaluate(context.Background(), ReceivedRequest{Raw: raw, OuterRecipient: []byte(receivedLocalMailFrom), Authority: newReceivedAuthority(receivedLocalDomain)})
		if err != nil {
			return
		}
		report, err := evaluator.Rebuild(context.Background(), RebuildRequest{Evaluation: evaluation, ReportingMTA: rebuildReportingMTA, Timestamp: rebuildTimestamp, MessageIDToken: []byte(rebuildToken)})
		if err != nil {
			if !errorShape.MatchString(err.Error()) {
				t.Fatalf("error carries content beyond the closed shape: %v", err)
			}
			if !IsRebuildErrorCode(err, RebuildErrorNotEligible) {
				t.Fatalf("eligible evaluation rebuild error=%v", err)
			}
			return
		}
		if !report.Valid() {
			t.Fatalf("invalid report outcome=%q", report.Outcome())
		}
		if report.Outcome() != RebuildRebuilt {
			if report.Bytes() != nil || report.NextHopRecipient() != nil || report.SigningDomain() != "" {
				t.Fatal("failed rebuild exposed output")
			}
			return
		}
		if len(report.Bytes()) > len(raw)+PropagationFixedPartsBound {
			t.Fatal("rebuilt report exceeds the received report plus the fixed parts")
		}
		parsed, parseErr := Parse(report.Bytes())
		if parseErr != nil {
			t.Fatalf("rebuilt report does not parse: %v", parseErr)
		}
		machine := string(parsed.DeliveryStatus().BodyBytes())
		if _, ok := parseDeliveryStatusBody([]byte(machine), deliveryStatusProfileStrictSequence); !ok {
			t.Fatal("rebuilt machine part rejected by the strict parser")
		}
		for _, forbidden := range []string{"Remote-MTA", "Diagnostic-Code", "Will-Retry-Until", "Last-Attempt-Date", "Arrival-Date"} {
			if strings.Contains(machine, forbidden) {
				t.Fatalf("machine part carries %q", forbidden)
			}
		}
		if ProvePropagatedReport(report.Bytes(), report.NextHopRecipient(), report.SigningDomain()) == nil {
			t.Fatal("unsigned rebuilt report proved as a signed propagated report")
		}
	})
}

// fuzzHeaderBlock makes an arbitrary byte string usable as a dsntest header
// block by guaranteeing the CRLF terminator the builder requires; every other
// syntax decision is left to the parsers under test.
func fuzzHeaderBlock(value []byte) string {
	block := string(value)
	if !strings.HasSuffix(block, "\r\n") {
		block += "\r\n"
	}
	return block
}

// tryBuild renders the outer DSN bytes and reports false instead of failing
// when the fuzzed original cannot be built or signed.
func (s propagationSpec) tryBuild() (raw []byte, ok bool) {
	defer func() {
		if recover() != nil {
			raw, ok = nil, false
		}
	}()
	original, err := s.original.Build()
	if err != nil {
		return nil, false
	}
	if s.mutate != nil {
		original = s.mutate(original)
	}
	contentType := string(ContentTypeRFC822)
	if s.headersOnly {
		contentType = string(ContentTypeRFC822Headers)
		original = dsntest.HeaderBlock(original)
	}
	signer := receivedHop(receivedDestinationDomain, "<>", receivedLocalMailFrom)
	signer.Timestamp = dsntest.DefaultTimestamp + 120
	raw, err = (dsntest.Report{
		OuterHeaders:        "From: MAILER-DAEMON@destination.example\r\nSubject: Undelivered Mail\r\n",
		Human:               "human readable",
		DeliveryStatus:      dsntest.FailedDeliveryStatus(receivedDestinationDomain, receivedDestinationRaw, receivedFailedStatus),
		OriginalContentType: contentType,
		Original:            original,
		Signer:              &signer,
	}).Build()
	if err != nil {
		return nil, false
	}
	return raw, true
}
