package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/croessner/dkim2/internal/dsn/dsntest"
	"github.com/croessner/dkim2/internal/rawmsg"
	"github.com/croessner/dkim2/internal/signature"
)

const (
	runRemoteDomain   = "remote.example"
	runLocalDomain    = "local.example"
	runForwardDomain  = "forward.local.example"
	runSecondDomain   = "second.example"
	runDestination    = "<dest@destination.example>"
	runLocalRecipient = "<user@local.example>"
	runLocalMailFrom  = "<forwarded@local.example>"
)

// runAuthority answers locality from a fixed domain set and records lookups.
type runAuthority struct {
	local     map[string]struct{}
	lookups   int
	temporary bool
	unknown   bool
}

// LookupLocalAuthority implements LocalAuthority for tests.
func (a *runAuthority) LookupLocalAuthority(ctx context.Context, domain string) (LocalAuthorityStatus, error) {
	a.lookups++
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if a.temporary {
		return "", errors.New("datasource unavailable")
	}
	if a.unknown {
		return LocalAuthorityStatus("maybe"), nil
	}
	if _, ok := a.local[domain]; ok {
		return LocalAuthorityLocal, nil
	}
	return LocalAuthorityNotLocal, nil
}

// newRunAuthority constructs one authority that treats the named domains as local.
func newRunAuthority(domains ...string) *runAuthority {
	local := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		local[domain] = struct{}{}
	}
	return &runAuthority{local: local}
}

// runKeys returns the deterministic signing identities used by run fixtures.
func runKeys() map[string]dsntest.Key {
	return map[string]dsntest.Key{
		runRemoteDomain:  dsntest.KeyForLabel("remote", "sel"),
		runLocalDomain:   dsntest.KeyForLabel("local", "sel"),
		runForwardDomain: dsntest.KeyForLabel("forward", "sel"),
		runSecondDomain:  dsntest.KeyForLabel("second", "sel"),
	}
}

// runHop renders one ordinary hop for the named domain.
func runHop(domain string, mailFrom string, recipients ...string) dsntest.Hop {
	return dsntest.Hop{Domain: domain, Key: runKeys()[domain], MailFrom: mailFrom, Recipients: recipients}
}

// runNextDomainHop renders one nd= hop for the named domain.
func runNextDomainHop(domain string, next string) dsntest.Hop {
	return dsntest.Hop{Domain: domain, Key: runKeys()[domain], NextDomain: next}
}

// mustRunMessage builds one signed original and returns its parsed message and ordered signatures.
func mustRunMessage(t *testing.T, hops ...dsntest.Hop) (rawmsg.Message, []signature.Signature) {
	t.Helper()
	raw, err := (dsntest.Original{Headers: "From: sender@remote.example\r\nSubject: run\r\n", Body: "body\r\n", Hops: hops}).Build()
	if err != nil {
		t.Fatalf("Build() error=%v", err)
	}
	message, err := rawmsg.Parse(raw)
	if err != nil {
		t.Fatalf("rawmsg.Parse() error=%v", err)
	}
	signatures, err := signature.Extract(message)
	if err != nil {
		t.Fatalf("signature.Extract() error=%v", err)
	}
	ordered, err := signature.OrderBySequence(signatures)
	if err != nil {
		t.Fatalf("signature.OrderBySequence() error=%v", err)
	}
	return message, ordered
}

// mustRunVerifier builds a verifier that knows every run fixture key.
func mustRunVerifier(t *testing.T) Verifier {
	t.Helper()
	keys := make([]StaticKey, 0, 4)
	for domain, key := range runKeys() {
		keys = append(keys, StaticKey{Domain: domain, Selector: key.Selector, Algorithm: AlgorithmEd25519SHA256, Material: key.Public()})
	}
	return mustVerifierWithKeys(t, keys)
}

// TestLocalHopRunSingleCompletionSignature proves a completion signature with a
// foreign previous hop forms a one-member run and exposes bounded previous-hop facts.
func TestLocalHopRunSingleCompletionSignature(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalMailFrom, runDestination),
	)
	authority := newRunAuthority(runLocalDomain)
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 2, authority, LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || !run.Valid() {
		t.Fatalf("DetectLocalHopRun() outcome=%q valid=%t error=%v", outcome, run.Valid(), err)
	}
	if run.CompletionSequence() != 2 || run.LowestSequence() != 2 || len(run.Members()) != 1 || run.Members()[0] != 2 {
		t.Fatalf("run members=%v lowest=%d", run.Members(), run.LowestSequence())
	}
	if !run.HasPreviousHop() || run.PreviousHopSequence() != 1 || run.PreviousHopIsNextDomain() || run.PreviousHopNullSender() ||
		!bytes.Equal(run.PreviousHopMailFrom(), []byte("<sender@remote.example>")) || len(run.PreviousHopRecipients()) != 1 ||
		run.PreviousHopDomain() != runRemoteDomain || run.PreviousHopInstance() != 1 || run.PreviousHopTimestamp() != dsntest.DefaultTimestamp {
		t.Fatalf("previous hop facts mismatch: %+v", run)
	}
	mailFrom := run.PreviousHopMailFrom()
	mailFrom[1] = 'X'
	if bytes.Equal(run.PreviousHopMailFrom(), mailFrom) {
		t.Fatal("PreviousHopMailFrom() exposed mutable storage")
	}
}

// TestLocalHopRunNextDomainMembers proves one and several nd= members whose
// domains are local extend the run down to the first nd= signature.
func TestLocalHopRunNextDomainMembers(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		hops       []dsntest.Hop
		wantLowest uint64
	}{
		{name: "one nd member", hops: []dsntest.Hop{
			runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
			runNextDomainHop(runLocalDomain, runForwardDomain),
			runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
		}, wantLowest: 2},
		{name: "several nd members", hops: []dsntest.Hop{
			runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
			runNextDomainHop(runLocalDomain, runSecondDomain),
			runNextDomainHop(runSecondDomain, runForwardDomain),
			runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
		}, wantLowest: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, ordered := mustRunMessage(t, testCase.hops...)
			authority := newRunAuthority(runLocalDomain, runSecondDomain, runForwardDomain)
			completion := uint64(len(testCase.hops))
			run, outcome, err := DetectLocalHopRun(context.Background(), ordered, completion, authority, LocalHopRunLimits{})
			if err != nil || outcome != LocalHopRunDetected || run.LowestSequence() != testCase.wantLowest ||
				len(run.Members()) != int(completion-testCase.wantLowest+1) {
				t.Fatalf("DetectLocalHopRun() outcome=%q lowest=%d members=%v error=%v", outcome, run.LowestSequence(), run.Members(), err)
			}
			if !run.HasPreviousHop() || run.PreviousHopSequence() != 1 || run.PreviousHopIsNextDomain() {
				t.Fatalf("previous hop facts mismatch: sequence=%d nd=%t", run.PreviousHopSequence(), run.PreviousHopIsNextDomain())
			}
		})
	}
}

// TestLocalHopRunImaginaryHopPair proves the Section 9.3 imaginary-hop scheme
// between two local domains is absorbed into the run.
func TestLocalHopRunImaginaryHopPair(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalRecipient, "<user@forward.local.example>"),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	authority := newRunAuthority(runLocalDomain, runForwardDomain)
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 3, authority, LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || run.LowestSequence() != 2 || run.PreviousHopSequence() != 1 {
		t.Fatalf("DetectLocalHopRun() outcome=%q lowest=%d previous=%d error=%v", outcome, run.LowestSequence(), run.PreviousHopSequence(), err)
	}
}

// TestLocalHopRunImaginaryHopRequiresEveryDomainLocal proves a candidate whose
// rt= names a foreign domain is the previous hop, not a run member.
func TestLocalHopRunImaginaryHopRequiresEveryDomainLocal(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalRecipient, "<user@forward.local.example>", "<other@remote.example>"),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	authority := newRunAuthority(runLocalDomain, runForwardDomain)
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 3, authority, LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || run.LowestSequence() != 3 || run.PreviousHopSequence() != 2 {
		t.Fatalf("DetectLocalHopRun() outcome=%q lowest=%d previous=%d error=%v", outcome, run.LowestSequence(), run.PreviousHopSequence(), err)
	}
}

// TestLocalHopRunNextDomainMemberNotLocalEndsRun proves an nd= signature under
// a foreign domain terminates the run and becomes an nd= previous hop.
func TestLocalHopRunNextDomainMemberNotLocalEndsRun(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runNextDomainHop(runLocalDomain, runForwardDomain),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	authority := newRunAuthority(runForwardDomain)
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 3, authority, LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || run.LowestSequence() != 3 || !run.HasPreviousHop() ||
		run.PreviousHopSequence() != 2 || !run.PreviousHopIsNextDomain() {
		t.Fatalf("DetectLocalHopRun() outcome=%q lowest=%d previous=%d nd=%t error=%v",
			outcome, run.LowestSequence(), run.PreviousHopSequence(), run.PreviousHopIsNextDomain(), err)
	}
}

// TestLocalHopRunTerminalOrigin proves a completion signature at i=1 has no previous hop.
func TestLocalHopRunTerminalOrigin(t *testing.T) {
	_, ordered := mustRunMessage(t, runHop(runLocalDomain, runLocalMailFrom, runDestination))
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 1, newRunAuthority(runLocalDomain), LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || run.LowestSequence() != 1 || run.HasPreviousHop() || run.PreviousHopSequence() != 0 {
		t.Fatalf("DetectLocalHopRun() outcome=%q lowest=%d previous=%t error=%v", outcome, run.LowestSequence(), run.HasPreviousHop(), err)
	}
}

// TestLocalHopRunNullPreviousSender proves a null previous mf= is reported as a bounded fact.
func TestLocalHopRunNullPreviousSender(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<>", runLocalRecipient),
		runHop(runLocalDomain, runLocalMailFrom, runDestination),
	)
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 2, newRunAuthority(runLocalDomain), LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || !run.PreviousHopNullSender() || !bytes.Equal(run.PreviousHopMailFrom(), []byte("<>")) {
		t.Fatalf("DetectLocalHopRun() outcome=%q null=%t error=%v", outcome, run.PreviousHopNullSender(), err)
	}
}

// TestLocalHopRunOrdinaryLocalHopBelowNextDomainRunIsPreviousHop pins the
// literal rule (b) reading: an ordinary signature directly below an nd= member
// cannot be absorbed because the nd= member carries no mf= to match.
func TestLocalHopRunOrdinaryLocalHopBelowNextDomainRunIsPreviousHop(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalRecipient, "<user@second.example>"),
		runNextDomainHop(runSecondDomain, runForwardDomain),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	authority := newRunAuthority(runLocalDomain, runSecondDomain, runForwardDomain)
	run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 4, authority, LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || run.LowestSequence() != 3 || run.PreviousHopSequence() != 2 || run.PreviousHopIsNextDomain() {
		t.Fatalf("DetectLocalHopRun() outcome=%q lowest=%d previous=%d error=%v", outcome, run.LowestSequence(), run.PreviousHopSequence(), err)
	}
}

// TestLocalHopRunAuthorityFailuresFailClosed proves temporary, contract, and
// limit outcomes never produce a run and never fall through to a foreign classification.
func TestLocalHopRunAuthorityFailuresFailClosed(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalRecipient, "<user@forward.local.example>"),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	for _, testCase := range []struct {
		name      string
		authority *runAuthority
		limits    LocalHopRunLimits
		want      LocalHopRunOutcome
	}{
		{name: "temporary", authority: &runAuthority{temporary: true}, want: LocalHopRunTemporary},
		{name: "unknown status", authority: &runAuthority{unknown: true}, want: LocalHopRunTemporary},
		{name: "lookup limit", authority: newRunAuthority(runLocalDomain, runForwardDomain), limits: LocalHopRunLimits{MaxAuthorityLookups: 1}, want: LocalHopRunLimitExceeded},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			run, outcome, err := DetectLocalHopRun(context.Background(), ordered, 3, testCase.authority, testCase.limits)
			if err != nil || outcome != testCase.want || run.Valid() {
				t.Fatalf("DetectLocalHopRun() outcome=%q valid=%t error=%v", outcome, run.Valid(), err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := DetectLocalHopRun(ctx, ordered, 3, newRunAuthority(runLocalDomain, runForwardDomain), LocalHopRunLimits{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("DetectLocalHopRun(canceled) error=%v", err)
	}
	_, outcome, err := DetectLocalHopRun(context.Background(), ordered, 3, nil, LocalHopRunLimits{})
	if err == nil || outcome != "" {
		t.Fatalf("DetectLocalHopRun(nil authority) outcome=%q error=%v", outcome, err)
	}
	_, outcome, err = DetectLocalHopRun(context.Background(), ordered, 7, newRunAuthority(runLocalDomain), LocalHopRunLimits{})
	if err == nil || outcome != "" {
		t.Fatalf("DetectLocalHopRun(unknown completion) outcome=%q error=%v", outcome, err)
	}
}

// TestLocalHopRunDeduplicatesAuthorityLookups proves repeated domains cost one
// lookup each: the local domain is asked once and the foreign origin once.
func TestLocalHopRunDeduplicatesAuthorityLookups(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalRecipient, "<user@local.example>", "<other@local.example>"),
		runHop(runLocalDomain, runLocalRecipient, runDestination),
	)
	authority := newRunAuthority(runLocalDomain)
	_, outcome, err := DetectLocalHopRun(context.Background(), ordered, 3, authority, LocalHopRunLimits{})
	if err != nil || outcome != LocalHopRunDetected || authority.lookups != 2 {
		t.Fatalf("DetectLocalHopRun() outcome=%q lookups=%d error=%v", outcome, authority.lookups, err)
	}
}

// TestLocalHopRunRedactsFormatting proves run facts never format addresses or domains.
func TestLocalHopRunRedactsFormatting(t *testing.T) {
	_, ordered := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runHop(runLocalDomain, runLocalMailFrom, runDestination),
	)
	run, _, err := DetectLocalHopRun(context.Background(), ordered, 2, newRunAuthority(runLocalDomain), LocalHopRunLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{run.String(), run.GoString(), fmt.Sprintf("%v", run), fmt.Sprintf("%+v", run), fmt.Sprintf("%#v", run)} {
		if strings.Contains(rendered, "example") || strings.Contains(rendered, "sender") {
			t.Fatalf("formatted run leaked content: %q", rendered)
		}
	}
}

// TestRunMemberVerificationVerifiesEveryMember proves each named sequence is
// verified over its Section 9.6 input with the local keys.
func TestRunMemberVerificationVerifiesEveryMember(t *testing.T) {
	message, _ := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runNextDomainHop(runLocalDomain, runSecondDomain),
		runNextDomainHop(runSecondDomain, runForwardDomain),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	verifier := mustRunVerifier(t)
	outcome, err := verifier.VerifyEmbeddedSignatures(context.Background(), mustEmbeddedInput(t, verifier, message), []uint64{2, 3})
	if err != nil || outcome != RunMemberVerified {
		t.Fatalf("VerifyEmbeddedSignatures() outcome=%q error=%v", outcome, err)
	}
	outcome, err = verifier.VerifyEmbeddedSignatures(context.Background(), mustEmbeddedInput(t, verifier, message), nil)
	if err != nil || outcome != RunMemberVerified {
		t.Fatalf("VerifyEmbeddedSignatures(empty) outcome=%q error=%v", outcome, err)
	}
}

// TestRunMemberVerificationRejectsNonVerifyingMember proves a damaged run member is unverified.
func TestRunMemberVerificationRejectsNonVerifyingMember(t *testing.T) {
	corrupt := runNextDomainHop(runLocalDomain, runForwardDomain)
	corrupt.CorruptSignature = true
	message, _ := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		corrupt,
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	verifier := mustRunVerifier(t)
	outcome, err := verifier.VerifyEmbeddedSignatures(context.Background(), mustEmbeddedInput(t, verifier, message), []uint64{2})
	if err != nil || outcome != RunMemberUnverified {
		t.Fatalf("VerifyEmbeddedSignatures() outcome=%q error=%v", outcome, err)
	}
}

// TestRunMemberVerificationMissingKeyIsUnverified proves a member whose key
// is not published is unverified rather than skipped.
func TestRunMemberVerificationMissingKeyIsUnverified(t *testing.T) {
	message, _ := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runNextDomainHop(runLocalDomain, runForwardDomain),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	forward := runKeys()[runForwardDomain]
	verifier := mustVerifierWithKeys(t, []StaticKey{{Domain: runForwardDomain, Selector: forward.Selector, Algorithm: AlgorithmEd25519SHA256, Material: forward.Public()}})
	outcome, err := verifier.VerifyEmbeddedSignatures(context.Background(), mustEmbeddedInput(t, verifier, message), []uint64{2})
	if err != nil || outcome != RunMemberUnverified {
		t.Fatalf("VerifyEmbeddedSignatures() outcome=%q error=%v", outcome, err)
	}
}

// TestRunMemberVerificationTemporaryProviderAndCancellation proves provider
// temporaries stay temporary and cancellation stays a Go error.
func TestRunMemberVerificationTemporaryProviderAndCancellation(t *testing.T) {
	message, _ := mustRunMessage(t,
		runHop(runRemoteDomain, "<sender@remote.example>", runLocalRecipient),
		runNextDomainHop(runLocalDomain, runForwardDomain),
		runHop(runForwardDomain, "<forwarded@forward.local.example>", runDestination),
	)
	temporary, err := NewVerifier(temporaryKeyProvider{})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := temporary.VerifyEmbeddedSignatures(context.Background(), mustEmbeddedInput(t, temporary, message), []uint64{2})
	if err != nil || outcome != RunMemberTemporary {
		t.Fatalf("VerifyEmbeddedSignatures(temporary) outcome=%q error=%v", outcome, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = mustRunVerifier(t).VerifyEmbeddedSignatures(ctx, mustEmbeddedInput(t, mustRunVerifier(t), message), []uint64{2})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("VerifyEmbeddedSignatures(canceled) error=%v", err)
	}
	verifier := mustRunVerifier(t)
	_, err = verifier.VerifyEmbeddedSignatures(context.Background(), mustEmbeddedInput(t, verifier, message), []uint64{9})
	if err == nil {
		t.Fatal("VerifyEmbeddedSignatures(unknown sequence) accepted an absent member")
	}
}

// temporaryKeyProvider always reports a typed temporary provider failure.
type temporaryKeyProvider struct{}

// LookupKey returns a temporary provider classification.
func (temporaryKeyProvider) LookupKey(context.Context, KeyQuery) (PublicKey, error) {
	return PublicKey{}, NewProviderFailure(ProviderFailureTemporary)
}

// mustEmbeddedInput extracts the embedded protocol fields once under the verifier's limits.
func mustEmbeddedInput(t *testing.T, verifier Verifier, message rawmsg.Message) EmbeddedInput {
	t.Helper()
	input, err := verifier.ExtractEmbeddedInput(message)
	if err != nil || !input.Valid() {
		t.Fatalf("ExtractEmbeddedInput() valid=%t error=%v", input.Valid(), err)
	}
	return input
}

// TestRunMemberVerificationRejectsZeroInput proves the seam fails closed on an unextracted input.
func TestRunMemberVerificationRejectsZeroInput(t *testing.T) {
	if _, err := mustRunVerifier(t).VerifyEmbeddedSignatures(context.Background(), EmbeddedInput{}, []uint64{2}); err == nil {
		t.Fatal("VerifyEmbeddedSignatures(zero input) accepted an unextracted input")
	}
	if _, err := mustRunVerifier(t).ExtractEmbeddedInput(rawmsg.Message{}); err == nil {
		t.Fatal("ExtractEmbeddedInput(zero message) accepted an uninitialized message")
	}
}
