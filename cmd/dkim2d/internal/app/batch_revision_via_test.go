package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
)

// batchTestAuthority explicitly provisions all three signing policy uses for its test keys.
type batchTestAuthority struct {
	*propagationtest.Authority
	profiles map[string]dkim2.SigningProfile
	keys     []propagationtest.SigningKey
}

// TestBatchRevisionControlledReturnRejectsUntrustedEvidence keeps SRS routing distinct from DSN authorization.
func TestBatchRevisionControlledReturnRejectsUntrustedEvidence(t *testing.T) {
	for _, name := range []string{"tampered body", "decoded recipient", "different issued recipient", "wrong tenant", "temporary outer key"} {
		t.Run(name, func(t *testing.T) {
			f := newBatchViaFixture(t, signingFlagPolicy{})
			batch, err := f.forwarder.ReviseBatch(context.Background(), f.request)
			if err != nil || batch.Result() != OperationPass {
				t.Fatal("forward fixture failed")
			}
			raw := batchRemoteDSN(t, f, batch.Outputs()[0], 0)
			recipient := f.request.state.copies[1].message.state.reverse
			tenant := propagationTestTenant
			want := PropagationDispositionReject
			switch name {
			case "tampered body":
				raw = append(raw, []byte("unauthenticated suffix\r\n")...)
			case "decoded recipient":
				recipient = []byte("<sender@origin.test>")
			case "different issued recipient":
				recipient = f.request.state.copies[2].message.state.reverse
			case "wrong tenant":
				tenant = propagationTestOtherTenant
			case "temporary outer key":
				f.propagation.provider.FailTemporarily(batchFixtureDestinationDomain)
				want = PropagationDispositionTempfail
			}
			request, err := NewPropagationRequest(raw, []byte("<>"), [][]byte{recipient}, false, tenant, "mx.forwarder.test", FidelityRawRFC5322)
			if err != nil {
				t.Fatal("negative propagation request invalid")
			}
			result := f.propagation.propagate(t, request)
			if _, present := result.Output(); present || result.Disposition() != want {
				t.Fatalf("unexpected return outcome %s/%s", result.Result(), result.Disposition())
			}
		})
	}
}

// TestBatchRevisionSignedNullSenderStillNeedsValidDSN reuses an unchanged real-signature conformance vector.
func TestBatchRevisionSignedNullSenderStillNeedsValidDSN(t *testing.T) {
	f := newPropagationFixture(t)
	data, err := os.ReadFile("../../../../lib/testdata/vectors/draft-ietf-dkim-dkim2-spec-06/received-dsn-golden.json")
	if err != nil {
		t.Fatal("received DSN corpus unavailable")
	}
	var corpus struct {
		Keys map[string]struct {
			Selector string `json:"selector"`
			Public   string `json:"ed25519_public_base64"`
		} `json:"keys"`
		Cases []struct {
			Name       string   `json:"name"`
			Raw        string   `json:"raw_base64"`
			Recipients []string `json:"forward_paths_base64"`
		} `json:"cases"`
	}
	if json.Unmarshal(data, &corpus) != nil {
		t.Fatal("received DSN corpus invalid")
	}
	for domain, key := range corpus.Keys {
		public, err := base64.StdEncoding.DecodeString(key.Public)
		if err != nil || len(public) != ed25519.PublicKeySize {
			t.Fatal("corpus public key invalid")
		}
		f.provider.Publish(propagationtest.SigningKey{Domain: domain, Selector: key.Selector, Public: ed25519.PublicKey(public)})
	}
	for _, vector := range corpus.Cases {
		if vector.Name != "structure_malformed" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(vector.Raw)
		if err != nil || len(vector.Recipients) != 1 {
			t.Fatal("malformed-report vector invalid")
		}
		recipient, err := base64.StdEncoding.DecodeString(vector.Recipients[0])
		if err != nil {
			t.Fatal("vector envelope invalid")
		}
		verification, err := f.verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, []byte("<>"), [][]byte{recipient}))
		if err != nil || verification.State() != dkim2.ResultStatePASS {
			t.Fatal("negative fixture lacks a valid outer signature")
		}
		request, err := NewPropagationRequest(raw, []byte("<>"), [][]byte{recipient}, false, propagationTestTenant, propagationtest.ReportingMTA, FidelityRawRFC5322)
		if err != nil {
			t.Fatal("signed malformed-report request invalid")
		}
		result := f.propagate(t, request)
		if _, present := result.Output(); present || result.Disposition() != PropagationDispositionReject || result.Projection().Structure() != dkim2.ReceivedDSNStructureMalformed {
			t.Fatal("outer cryptographic pass substituted for valid DSN evidence")
		}
		return
	}
	t.Fatal("signed malformed-report vector missing")
}

// Acquire opens one real-crypto fixture lease without sharing authority across tenants.
func (a *batchTestAuthority) Acquire(ctx context.Context) (SigningLease, error) {
	if err := a.Open(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

// ResolvePolicy admits only the fixture tenant, provisioned domains, and declared policy uses.
func (a *batchTestAuthority) ResolvePolicy(ctx context.Context, tenant, domain string, use signingstore.PolicyUse, at time.Time) (dkim2.SigningProfile, error) {
	if err := a.ResolveAnyProfile(ctx, tenant, domain, at); err != nil {
		return dkim2.SigningProfile{}, err
	}
	profile, ok := a.profiles[domain]
	if !ok || use != signingstore.PolicyOriginator && use != signingstore.PolicyOrdinaryTransit && use != signingstore.PolicyDeliveryStatus {
		return dkim2.SigningProfile{}, provider.NewError(provider.ErrorCodeNotFound)
	}
	return profile, nil
}

// newBatchTestAuthority provisions exact signing and local-authority keys for one tenant.
func newBatchTestAuthority(keys ...propagationtest.SigningKey) *batchTestAuthority {
	a := &batchTestAuthority{Authority: propagationtest.NewAuthority(), profiles: make(map[string]dkim2.SigningProfile), keys: append([]propagationtest.SigningKey(nil), keys...)}
	for _, key := range keys {
		a.AddProfile(propagationTestTenant, key)
		a.profiles[key.Domain] = key.Profile
	}
	return a
}

// batchViaFixture keeps remote origin, local custody, and remote reporting authorities separate.
type batchViaFixture struct {
	propagation               *propagationFixture
	origin, forwarder, remote *SigningService
	request                   BatchRevisionRequest
}

// newBatchViaFixture signs actual SMTP input whose hosted recipient differs from the return domain.
func newBatchViaFixture(t *testing.T, policy signingFlagPolicy) batchViaFixture {
	t.Helper()
	return newBatchViaFixtureAt(t, policy, time.Time{})
}

// newBatchViaFixtureAt optionally uses current time for exported integration inputs.
func newBatchViaFixtureAt(t *testing.T, policy signingFlagPolicy, at time.Time) batchViaFixture {
	t.Helper()
	f := newPropagationFixture(t)
	if !at.IsZero() {
		f.clock.now = at
	}
	var err error
	f.verifier, err = dkim2.NewVerifier(f.provider, dkim2.WithVerificationClock(f.clock.Now))
	if err != nil {
		t.Fatal("batch verifier construction failed")
	}
	keys := make([]propagationtest.SigningKey, 0, 4)
	for _, domain := range []string{batchFixtureOriginDomain, batchFixtureHostedDomain, batchFixtureForwarderDomain, batchFixtureDestinationDomain} {
		key := propagationtest.NewSigningKey(t, domain)
		f.provider.Publish(key)
		keys = append(keys, key)
	}
	origin := &SigningService{publicKeys: f.provider, store: newBatchTestAuthority(keys[0]), clock: f.clock.Now, policies: signingPolicies{originator: policy}}
	forwarder := &SigningService{publicKeys: f.provider, store: newBatchTestAuthority(keys[1], keys[2]), clock: f.clock.Now}
	remote := &SigningService{publicKeys: f.provider, store: newBatchTestAuthority(keys[3]), clock: f.clock.Now}
	f.authority = propagationtest.NewAuthority().AddProfile(propagationTestTenant, keys[1]).AddProfile(propagationTestTenant, keys[2])
	f.coordinator = f.newCoordinator(t, f.enabledReplay(t))
	raw := []byte("From: sender@origin.test\r\nTo: alias@hosted.test\r\nDate: " + f.clock.Now().Format(time.RFC1123Z) +
		"\r\nMessage-ID: <batch-" + fmt.Sprint(f.clock.Now().UnixNano()) + "@origin.test>\r\nSubject: Native forwarding qualification\r\nX-Spacing:\t  exact\r\n\r\noriginal body\r\n")
	signRequest, err := NewOperationRequest(OperationSign, raw, []byte("<sender@origin.test>"), [][]byte{[]byte("<alias@hosted.test>")}, propagationTestTenant, batchFixtureOriginDomain, FidelityRawRFC5322)
	if err != nil {
		t.Fatal("origin request invalid")
	}
	assessment, err := origin.Sign(context.Background(), signRequest)
	result, ok := assessment.Result()
	if err != nil || !ok || result.Result() != OperationPass {
		t.Fatal("origin signature failed")
	}
	original := insertSigningServiceFields(result.Fields(), raw)
	current := append([]byte("Received: by queue.hosted.test\r\n"), original...)
	incoming, err := NewBatchMessage(original, []byte("<sender@origin.test>"), [][]byte{[]byte("<alias@hosted.test>")}, FidelityRawRFC5322)
	if err != nil {
		t.Fatal("original batch message invalid")
	}
	local, err := NewBatchMessage(current, []byte("<sender@origin.test>"), [][]byte{[]byte("<local@hosted.test>")}, FidelityLMTPDeliveredCRLF)
	if err != nil {
		t.Fatal("local batch message invalid")
	}
	localCopy, err := NewBatchCopy("local", true, local, "", "")
	if err != nil {
		t.Fatal("local copy invalid")
	}
	copies := []BatchCopy{localCopy}
	for index := range 2 {
		message, err := NewBatchMessage(current, []byte(fmt.Sprintf("<SRS0=opaque-%d@srs.forwarder.test>", index)), [][]byte{[]byte(fmt.Sprintf("<private-%d@destination.test>", index))}, FidelityRawRFC5322)
		if err != nil {
			t.Fatal("external batch message invalid")
		}
		branch, err := NewBatchCopy(fmt.Sprintf("external-%d", index), false, message, propagationTestTenant, batchFixtureForwarderDomain)
		if err != nil {
			t.Fatal("external batch copy invalid")
		}
		branch, err = branch.WithVia([]byte("<alias@hosted.test>"), [][]byte{[]byte("<router@forwarder.test>")}, propagationTestTenant, batchFixtureHostedDomain)
		if err != nil {
			t.Fatal("controlled hop invalid")
		}
		copies = append(copies, branch)
	}
	request, err := NewBatchRevisionRequest(strings.Repeat("b", 64), incoming, copies)
	if err != nil {
		t.Fatal("controlled fanout invalid")
	}
	return batchViaFixture{propagation: f, origin: origin, forwarder: forwarder, remote: remote, request: request}
}

// TestBatchRevisionControlledViaProducesVerifiablePrivateCopies proves the reference imaginary-hop route.
func TestBatchRevisionControlledViaProducesVerifiablePrivateCopies(t *testing.T) {
	f := newBatchViaFixture(t, signingFlagPolicy{})
	result, err := f.forwarder.ReviseBatch(context.Background(), f.request)
	if err != nil || result.Result() != OperationPass || len(result.Outputs()) != 2 {
		inspectBatchRevisionStages(t, f.forwarder, f.request)
		t.Fatal("controlled fanout failed")
	}
	for index, output := range result.Outputs() {
		branch := f.request.state.copies[index+1]
		raw := insertBatchFields(branch.message.state.raw, output.InsertionOffset(), output.Fields())
		verified, err := f.propagation.verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, branch.message.state.reverse, branch.message.state.recipients))
		if err != nil || verified.State() != dkim2.ResultStatePASS {
			t.Fatalf("controlled output: state=%s reason=%s", verified.State(), verified.PrimaryReason())
		}
		if output.CurrentSHA256() != batchSHA256(branch.message.state.raw) || output.ResultSHA256() != batchSHA256(raw) || len(output.Fields()) > 3 {
			t.Fatal("controlled delta binding lost")
		}
		if bytes.Count(raw, []byte("DKIM2-Signature:")) != 3 {
			t.Fatal("controlled chain has wrong hop count")
		}
	}
}

// TestBatchRevisionControlledViaRejectsUnauthorizedOrInvalidRoutes proves no alignment or policy bypass.
func TestBatchRevisionControlledViaRejectsUnauthorizedOrInvalidRoutes(t *testing.T) {
	for _, name := range []string{"missing via", "unowned intermediate recipient", "wrong final sender domain", "missing final profile", "donotexplode", "null final sender", "temporary intermediate key"} {
		t.Run(name, func(t *testing.T) {
			policy := signingFlagPolicy{}
			if name == "donotexplode" {
				policy.doNotExplode = true
			}
			f := newBatchViaFixture(t, policy)
			branch := &f.request.state.copies[2]
			want := OperationPermerror
			switch name {
			case "missing via":
				branch.via = nil
			case "unowned intermediate recipient":
				branch.via.recipients = [][]byte{[]byte("<router@unowned.test>")}
			case "wrong final sender domain":
				branch.message.state.reverse = []byte("<prepared@wrong.test>")
			case "missing final profile":
				branch.domain = "unowned.test"
			case "null final sender":
				branch.message.state.reverse = []byte("<>")
			case "temporary intermediate key":
				f.propagation.provider.FailTemporarily(batchFixtureHostedDomain)
				want = OperationTemperror
			}
			result, err := f.forwarder.ReviseBatch(context.Background(), f.request)
			if err != nil || result.Result() != want || len(result.Outputs()) != 0 {
				t.Fatalf("unexpected controlled failure: result=%s err=%v", result.Result(), err)
			}
		})
	}
}

// batchRemoteDSN builds and genuinely signs a remote failure report for one completed external copy.
func batchRemoteDSN(t *testing.T, f batchViaFixture, output BatchRevisionOutput, index int) []byte {
	t.Helper()
	branch := f.request.state.copies[index+1]
	embedded := insertBatchFields(branch.message.state.raw, output.InsertionOffset(), output.Fields())
	return signBatchRemoteDSN(t, f, embedded, branch.message.state.reverse, branch.message.state.recipients)
}

// signBatchRemoteDSN processes exact externally observed bytes through the remote custody and DSN services.
func signBatchRemoteDSN(t *testing.T, f batchViaFixture, embedded, reverse []byte, recipients [][]byte) []byte {
	t.Helper()
	if len(recipients) != 1 || len(recipients[0]) < 3 || recipients[0][0] != '<' || recipients[0][len(recipients[0])-1] != '>' || bytes.ContainsAny(recipients[0], "\r\n") {
		t.Fatal("remote fixture recipient shape invalid")
	}
	embedded = recordBatchRemoteCustody(t, f, embedded, reverse, recipients)
	remoteSender := []byte("<responsible@destination.test>")
	outer := []byte("From: postmaster@destination.test\r\n" +
		"Content-Type: multipart/report; report-type=delivery-status; boundary=dsn\r\n\r\n" +
		"--dsn\r\nContent-Type: text/plain\r\n\r\ndelivery failed\r\n" +
		"--dsn\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.destination.test\r\n\r\n" +
		"Final-Recipient: rfc822; " + string(recipients[0][1:len(recipients[0])-1]) + "\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n" +
		"--dsn\r\nContent-Type: message/rfc822\r\n\r\n" + string(embedded) + "\r\n--dsn--\r\n")
	request, err := NewPostfixDeliveryStatusRequest(outer, []byte("<>"), [][]byte{remoteSender}, propagationTestTenant)
	if err != nil {
		t.Fatal("remote DSN request invalid")
	}
	result, err := f.remote.SignDeliveryStatus(context.Background(), request)
	if err != nil || result.Result() != OperationPass {
		t.Fatalf("remote DSN signing: result=%s", result.Result())
	}
	signed := insertSigningServiceFields(result.Fields(), outer)
	remote := newPropagationFixture(t)
	remote.provider = f.propagation.provider
	remote.verifier = f.propagation.verifier
	remote.clock = f.propagation.clock
	remote.authority = f.remote.store.(*batchTestAuthority).Authority
	remote.coordinator = remote.newCoordinator(t, remote.enabledReplay(t))
	received, err := NewPropagationRequest(signed, []byte("<>"), [][]byte{remoteSender}, false, propagationTestTenant, "mx.destination.test", FidelityRawRFC5322)
	if err != nil {
		t.Fatal("remote local notification invalid")
	}
	propagated := remote.propagate(t, received)
	requireOutcome(t, propagated, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	notification, ok := propagated.Output()
	if !ok || !bytes.Equal(notification.NextHopRecipient(), reverse) {
		t.Fatal("remote report did not return to prepared sender")
	}
	return notification.RawMessage()
}

// recordBatchRemoteCustody records the remote system's own controlled hop before its local failure.
func recordBatchRemoteCustody(t *testing.T, f batchViaFixture, raw, reverse []byte, recipients [][]byte) []byte {
	t.Helper()
	incoming, err := NewBatchMessage(raw, reverse, recipients, FidelityRawRFC5322)
	if err != nil {
		t.Fatal("remote input invalid")
	}
	current, err := NewBatchMessage(raw, []byte("<responsible@destination.test>"), recipients, FidelityRawRFC5322)
	if err != nil {
		t.Fatal("remote custody envelope invalid")
	}
	branch, err := NewBatchCopy("remote-custody", false, current, propagationTestTenant, batchFixtureDestinationDomain)
	if err != nil {
		t.Fatal("remote custody copy invalid")
	}
	request, err := NewBatchRevisionRequest(strings.Repeat("c", 64), incoming, []BatchCopy{branch})
	if err != nil {
		t.Fatal("remote custody plan invalid")
	}
	result, err := f.remote.ReviseBatch(context.Background(), request)
	if err != nil || result.Result() != OperationPass || len(result.Outputs()) != 1 {
		t.Fatal("remote custody signature failed")
	}
	output := result.Outputs()[0]
	return insertBatchFields(raw, output.InsertionOffset(), output.Fields())
}

// TestBatchRevisionControlledViaDSNReturnsAcrossBothOwnedHops proves the complete library propagation path.
func TestBatchRevisionControlledViaDSNReturnsAcrossBothOwnedHops(t *testing.T) {
	f := newBatchViaFixture(t, signingFlagPolicy{})
	batch, err := f.forwarder.ReviseBatch(context.Background(), f.request)
	if err != nil || batch.Result() != OperationPass {
		t.Fatal("forward signing failed")
	}
	for index, output := range batch.Outputs() {
		outer := batchRemoteDSN(t, f, output, index)
		srs := f.request.state.copies[index+1].message.state.reverse
		request, err := NewPropagationRequest(outer, []byte("<>"), [][]byte{srs}, false, propagationTestTenant, "mx.forwarder.test", FidelityRawRFC5322)
		if err != nil {
			t.Fatal("return request invalid")
		}
		result := f.propagation.propagate(t, request)
		requireOutcome(t, result, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
		rebuilt, ok := result.Output()
		if !ok || !bytes.Equal(rebuilt.NextHopRecipient(), []byte("<sender@origin.test>")) {
			t.Fatal("local hop run did not return to authenticated origin")
		}
		verified, err := f.propagation.verifier.Verify(context.Background(), dkim2.NewVerifyRequest(rebuilt.RawMessage(), []byte("<>"), [][]byte{rebuilt.NextHopRecipient()}))
		if err != nil || verified.State() != dkim2.ResultStatePASS {
			t.Fatalf("return verification state=%s reason=%s", verified.State(), verified.PrimaryReason())
		}
		if bytes.Count(rebuilt.RawMessage(), []byte("DKIM2-Signature:")) != 2 {
			t.Fatal("expected only the new outer DSN signature and the original embedded signature")
		}
		if state, err := f.propagation.coordinator.CommitPropagation(context.Background(), rebuilt.CommitToken()); err != nil || state != PropagationCommitCommitted {
			t.Fatal("return commit failed")
		}
		again := f.propagation.propagate(t, request)
		if again.Disposition() != PropagationDispositionDiscard {
			t.Fatal("committed return replay was not suppressed")
		}
	}
}
