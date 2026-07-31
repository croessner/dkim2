package filter

import (
	"context"
	"errors"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const (
	testLocator            = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	testOutgoingSender     = "<outgoing@example.test>"
	testTransportSender    = "<sender@example.test>"
	testTransportRecipient = "<recipient@example.test>"
)

// evidenceStub provides deliberately distinct receive-time authority.
type evidenceStub struct {
	incoming adapter.IncomingEvidence
	calls    int
	err      error
}

// Load returns only the test-controlled immutable incoming authority.
func (s *evidenceStub) Load(context.Context, string) (adapter.IncomingEvidence, error) {
	s.calls++
	return s.incoming, s.err
}

// TestBuildRequestKeepsRevisionEnvelopeAuthoritiesDistinct proves a router
// return path cannot substitute receive-time evidence and vice versa.
func TestBuildRequestKeepsRevisionEnvelopeAuthoritiesDistinct(t *testing.T) {
	incoming, err := adapter.NewIncomingEvidence([]byte("<incoming@example.test>"), [][]byte{[]byte("<received@example.test>")}, adapter.SessionSMTP)
	if err != nil {
		t.Fatal("incoming construction failed")
	}
	loader := &evidenceStub{incoming: incoming}
	request, err := BuildRequest(context.Background(), adapter.FilterRevise, []string{testLocator, testOutgoingSender, "<batch@example.test>"}, []byte("Subject: test\n\nbody\n"), loader)
	if err != nil || loader.calls != 1 {
		t.Fatal("revision did not load exact immutable evidence")
	}
	stored, ok := request.Incoming()
	if !ok || string(stored.MailFrom()) != "<incoming@example.test>" || string(request.Outgoing().MailFrom()) != testOutgoingSender {
		t.Fatal("revision envelope authority was substituted")
	}
}

// TestBuildRequestRejectsBccLikeGroupsBeforeEvidence proves group policy is
// evaluated before the revision evidence loader receives authority.
func TestBuildRequestRejectsBccLikeGroupsBeforeEvidence(t *testing.T) {
	incoming, _ := adapter.NewIncomingEvidence([]byte("<i@example.test>"), [][]byte{[]byte("<r@example.test>")}, adapter.SessionSMTP)
	loader := &evidenceStub{incoming: incoming}
	if _, err := BuildRequest(
		context.Background(),
		adapter.FilterRevise,
		[]string{
			testLocator,
			"<o@example.test>",
			"<a@example.test>",
			"<b@example.test>",
		},
		[]byte("Subject: test\n\nbody\n"),
		loader,
	); err == nil || loader.calls != 0 {
		t.Fatal("Bcc-like group reached evidence authority")
	}
}

// TestBuildRequestCanonicalizesEmptyBouncePath proves one quoted empty argv
// becomes the sole RFC 5321 null reverse path rather than disappearing.
func TestBuildRequestCanonicalizesEmptyBouncePath(t *testing.T) {
	request, err := BuildRequest(context.Background(),
		adapter.FilterSign,
		[]string{"", testTransportRecipient},
		[]byte("Subject: bounce\n\nbody\n"),
		nil)

	if err != nil || string(request.Outgoing().MailFrom()) != "<>" {
		t.Fatal("quoted empty reverse path was not canonicalized")
	}
}

// TestBuildRequestCanonicalizesBareEximPaths proves direct Exim expansion
// reaches the daemon as unambiguous RFC 5321 envelope paths.
func TestBuildRequestCanonicalizesBareEximPaths(t *testing.T) {
	request, err := BuildRequest(
		context.Background(),
		adapter.FilterSign,
		[]string{"sender@example.test", "recipient@example.test"},
		[]byte("Subject: paths\n\nbody\n"),
		nil,
	)
	if err != nil || string(request.Outgoing().MailFrom()) != "<sender@example.test>" ||
		string(request.Outgoing().Recipient()) != "<recipient@example.test>" {
		t.Fatal("bare Exim paths were not canonicalized")
	}
}

// TestBuildRequestTreatsPipeAddressAsOneOpaqueArg proves Bcc batching is owned
// by Exim argv cardinality rather than lossy mailbox-syntax guessing.
func TestBuildRequestTreatsPipeAddressAsOneOpaqueArg(t *testing.T) {
	request, err := BuildRequest(
		context.Background(),
		adapter.FilterSign,
		[]string{testTransportSender, "<\"quoted, local\"@example.test>"},
		[]byte("Subject: quoted\n\nbody\n"),
		nil,
	)
	if err != nil ||
		string(request.Outgoing().Recipient()) != "<\"quoted, local\"@example.test>" {
		t.Fatal("sole opaque pipe-address argument was re-parsed")
	}
}

// TestBuildRequestRejectsOutboundSMTPUTF8BeforeEvidence proves unsupported
// transport authority cannot reach the immutable evidence owner.
func TestBuildRequestRejectsOutboundSMTPUTF8BeforeEvidence(t *testing.T) {
	incoming, _ := adapter.NewIncomingEvidence(
		[]byte("<old@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	for _, arguments := range [][]string{
		{testLocator, "<séndér@example.test>", testTransportRecipient},
		{testLocator, testTransportSender, "<réçipient@example.test>"},
	} {
		loader := &evidenceStub{incoming: incoming}
		_, err := BuildRequest(context.Background(),
			adapter.FilterRevise,
			arguments,
			[]byte("Subject: \xc3\xa9\n\nbody \xf0\x9f\x93\xa8\n"),
			loader)

		if err == nil || loader.calls != 0 {
			t.Fatal("non-ASCII outgoing envelope reached evidence authority")
		}
	}
}

// TestBuildRequestRejectsFramingArguments proves direct argv values cannot
// smuggle framing bytes or an absent revision locator.
func TestBuildRequestRejectsFramingArguments(t *testing.T) {
	incoming, _ := adapter.NewIncomingEvidence(
		[]byte("<old@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	tests := [][]string{
		{testLocator, "<sender@example.test>\n", testTransportRecipient},
		{testLocator, testTransportSender, "<recipient@example.test>\x00"},
		{"", testTransportSender, testTransportRecipient},
		{testLocator, testTransportSender, "<a@example.test>", "<b@example.test>"},
	}
	for _, arguments := range tests {
		loader := &evidenceStub{incoming: incoming}
		if _, err := BuildRequest(context.Background(),
			adapter.FilterRevise,
			arguments,
			[]byte("Subject: test\n\nbody\n"),
			loader); err == nil || loader.calls != 0 {
			t.Fatal("invalid direct argument reached evidence authority")
		}
	}
}

// TestBuildRequestNeverSubstitutesUnavailableEvidence proves revision cannot
// fall back to the current outgoing envelope.
func TestBuildRequestNeverSubstitutesUnavailableEvidence(t *testing.T) {
	loader := &evidenceStub{err: errors.New("unavailable")}
	if _, err := BuildRequest(context.Background(),
		adapter.FilterRevise,
		[]string{testLocator, testTransportSender, testTransportRecipient},
		[]byte("Subject: test\n\nbody\n"),
		loader); err == nil || loader.calls != 1 {
		t.Fatal("missing revision evidence was substituted or ignored")
	}
}

// TestBuildRequestValidatesMessageBeforeEvidence proves malformed message
// state cannot cause an evidence-store read.
func TestBuildRequestValidatesMessageBeforeEvidence(t *testing.T) {
	incoming, _ := adapter.NewIncomingEvidence(
		[]byte("<old@example.test>"),
		[][]byte{[]byte("<received@example.test>")},
		adapter.SessionSMTP,
	)
	loader := &evidenceStub{incoming: incoming}
	if _, err := BuildRequest(context.Background(),
		adapter.FilterRevise,
		[]string{testLocator, testTransportSender, testTransportRecipient},
		[]byte("malformed\n\nbody\n"),
		loader); err == nil || loader.calls != 0 {
		t.Fatal("malformed message reached evidence authority")
	}
}

// FuzzInvocationParsing exercises exact direct-argv admission without invoking
// evidence or daemon authorities.
func FuzzInvocationParsing(f *testing.F) {
	f.Add(uint8(adapter.FilterSign), "", testTransportRecipient)
	f.Add(uint8(adapter.FilterRevise), testLocator, testTransportRecipient)
	f.Fuzz(func(_ *testing.T, rawOperation uint8, first, second string) {
		operation := adapter.FilterOperation(rawOperation)
		_, _ = parseInvocation(operation, []string{first, second})
		_, _ = parseInvocation(operation, []string{first, second, first})
	})
}
