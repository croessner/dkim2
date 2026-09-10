package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

const (
	batchFixtureHostedDomain      = "hosted.test"
	batchFixtureOriginDomain      = "origin.test"
	batchFixtureDestinationDomain = "destination.test"
	batchFixtureGeneration        = "0123456789abcdef0123456789abcdef"
	batchFixtureForwarderDomain   = "forwarder.test"
	batchFixtureVersionField      = "version"
	batchFixturePrivateKeyType    = "PRIVATE KEY"
)

// batchFixtureEnvelope is a private test-file format for an observed SMTP transaction, not a daemon DTO.
type batchFixtureEnvelope struct {
	MailFrom string   `json:"mail_from"`
	RcptTo   []string `json:"rcpt_to"`
}

// TestBatchRevisionIntegrationFixture is an opt-in file-only bridge for independent native-MTA qualification.
func TestBatchRevisionIntegrationFixture(t *testing.T) {
	directory := os.Getenv("DKIM2_BATCH_FIXTURE_DIR")
	if directory == "" {
		t.Skip("set a private fixture directory to export native-integration inputs")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("fixture directory must be canonical and absolute")
	}
	messageFile, envelopeFile := os.Getenv("DKIM2_BATCH_REMOTE_MESSAGE_FILE"), os.Getenv("DKIM2_BATCH_REMOTE_ENVELOPE_FILE")
	verifyMessage, verifyEnvelope := os.Getenv("DKIM2_BATCH_VERIFY_MESSAGE_FILE"), os.Getenv("DKIM2_BATCH_VERIFY_ENVELOPE_FILE")
	if verifyMessage != "" || verifyEnvelope != "" {
		if messageFile != "" || envelopeFile != "" {
			t.Fatal("choose either verification or remote report generation")
		}
		f := loadBatchFixture(t, directory)
		raw, envelope := readBatchFixtureMessage(t, verifyMessage, verifyEnvelope)
		verifyBatchFixtureMessage(t, f, raw, envelope)
		return
	}
	if messageFile == "" && envelopeFile == "" {
		exportBatchFixture(t, directory)
		return
	}
	f := loadBatchFixture(t, directory)
	raw, envelope := readBatchFixtureMessage(t, messageFile, envelopeFile)
	dsn := signBatchRemoteDSN(t, f, raw, []byte(envelope.MailFrom), [][]byte{[]byte(envelope.RcptTo[0])})
	writeBatchFixtureFile(t, filepath.Join(directory, "remote-dsn.eml"), dsn)
	writeBatchFixtureJSON(t, filepath.Join(directory, "remote-dsn-envelope.json"), batchFixtureEnvelope{MailFrom: "<>", RcptTo: []string{envelope.MailFrom}})
}

// exportBatchFixture writes a new isolated test generation and current genuinely signed SMTP input.
func exportBatchFixture(t *testing.T, directory string) batchViaFixture {
	t.Helper()
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal("fixture directory must not already exist")
	}
	f := newBatchViaFixtureAt(t, signingFlagPolicy{}, time.Now().UTC())
	keys := append([]propagationtest.SigningKey(nil), f.origin.store.(*batchTestAuthority).keys...)
	keys = append(keys, f.forwarder.store.(*batchTestAuthority).keys...)
	keys = append(keys, f.remote.store.(*batchTestAuthority).keys...)
	keyDir := filepath.Join(directory, "test-source-keys")
	generationDir := filepath.Join(directory, "protected", batchFixtureGeneration)
	if os.Mkdir(keyDir, 0700) != nil || os.Mkdir(filepath.Join(directory, "protected"), 0700) != nil || os.Mkdir(generationDir, 0700) != nil {
		t.Fatal("fixture generation creation failed")
	}
	dns := make(map[string]string, len(keys))
	for _, key := range keys {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key.Private)
		if err != nil {
			t.Fatal("fixture key encoding failed")
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: batchFixturePrivateKeyType, Bytes: pkcs8})
		clear(pkcs8)
		writeBatchFixtureFile(t, filepath.Join(keyDir, key.Domain+".pem"), encoded)
		if key.Domain == batchFixtureHostedDomain || key.Domain == batchFixtureForwarderDomain {
			writeBatchFixtureFile(t, filepath.Join(generationDir, key.Domain+".pem"), encoded)
		}
		clear(encoded)
		dns[key.Selector+"._domainkey."+key.Domain+"."] = "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(key.Public)
	}
	writeBatchFixtureFile(t, filepath.Join(directory, "original.eml"), f.request.state.original.state.raw)
	writeBatchFixtureJSON(t, filepath.Join(directory, "original-envelope.json"), batchFixtureEnvelope{MailFrom: "<sender@origin.test>", RcptTo: []string{"<alias@hosted.test>"}})
	exportBatchFixtureAuthority(t, generationDir, keys[1:3], dns)
	writeBatchFixtureJSON(t, filepath.Join(directory, "dns-txt.json"), dns)
	for _, name := range []string{"process-capability", "batch-capability", "propagate-capability", "replay-hmac"} {
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			t.Fatal("fixture credential generation failed")
		}
		writeBatchFixtureFile(t, filepath.Join(generationDir, name), value)
		clear(value)
	}
	configuration := "config:\n  version: dkim2d-config-v1\nprotected:\n  generation: " + batchFixtureGeneration + "\nserver:\n  listen: 127.0.0.1:18081\n" +
		"  capability_file: " + generationDir + "/process-capability\n  batch_revise_capability_file: " + generationDir + "/batch-capability\n  dsn_propagate_capability_file: " + generationDir + "/propagate-capability\n" +
		"replay:\n  backend: memory\n  hmac_key_file: " + generationDir + "/replay-hmac\n  epoch: 1\nsigning:\n  backend: flat_file\n  datasource_file: " + generationDir + "/datasource.json\n  private_manifest_file: " + generationDir + "/manifest.json\n"
	writeBatchFixtureFile(t, filepath.Join(directory, "dkim2d.yaml"), []byte(configuration))
	if os.Chmod(generationDir, 0500) != nil {
		t.Fatal("fixture generation sealing failed")
	}
	return f
}

// exportBatchFixtureAuthority provisions only the two local custody domains for the real daemon.
func exportBatchFixtureAuthority(t *testing.T, directory string, keys []propagationtest.SigningKey, dns map[string]string) {
	t.Helper()
	handles, profiles, policies, entries := []any{}, []any{}, []any{}, []any{}
	for _, key := range keys {
		for _, use := range []string{"ordinary_transit", "delivery_status"} {
			selected, privateFile := key, key.Domain+".pem"
			if use == "delivery_status" {
				selected = propagationtest.NewSigningKey(t, key.Domain)
				selected.Selector = "return"
				privateFile = key.Domain + "-return.pem"
				pkcs8, err := x509.MarshalPKCS8PrivateKey(selected.Private)
				if err != nil {
					t.Fatal("return profile key encoding failed")
				}
				encoded := pem.EncodeToMemory(&pem.Block{Type: batchFixturePrivateKeyType, Bytes: pkcs8})
				clear(pkcs8)
				writeBatchFixtureFile(t, filepath.Join(directory, privateFile), encoded)
				clear(encoded)
				dns[selected.Selector+"._domainkey."+key.Domain+"."] = "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(selected.Public)
			}
			handle := "fixture-" + strings.ReplaceAll(key.Domain, ".", "-") + "-" + use
			profile := signingServiceProfile(handle, key.Domain, handle, selected.Selector, signingServiceAnySPKI(t, selected.Public))
			profile["credentials"].([]any)[0].(map[string]any)[signingServiceAlgorithmField] = signingServiceEd25519Algorithm
			handles = append(handles, map[string]any{"id": handle})
			profiles = append(profiles, profile)
			policies = append(policies, signingServicePolicy(key.Domain, use, handle))
			entries = append(entries, signingServiceEdManifestEntry(t, key.Domain, handle, use, privateFile, selected.Public))
		}
	}
	writeBatchFixtureJSON(t, filepath.Join(directory, "datasource.json"), map[string]any{batchFixtureVersionField: "dkim2-datasource-v1", "handles": handles, "profiles": profiles, "policies": policies})
	writeBatchFixtureJSON(t, filepath.Join(directory, "manifest.json"), map[string]any{batchFixtureVersionField: "dkim2-private-keys-v1", "entries": entries})
}

// loadBatchFixture restores only test-owned fixture credentials without changing any existing artifact.
func loadBatchFixture(t *testing.T, directory string) batchViaFixture {
	t.Helper()
	f := newPropagationFixture(t)
	f.clock.now = time.Now().UTC()
	var err error
	f.verifier, err = dkim2.NewVerifier(f.provider, dkim2.WithVerificationClock(f.clock.Now))
	if err != nil {
		t.Fatal("fixture verifier failed")
	}
	keys := make([]propagationtest.SigningKey, 0, 4)
	for _, domain := range []string{batchFixtureOriginDomain, batchFixtureHostedDomain, batchFixtureForwarderDomain, batchFixtureDestinationDomain} {
		key := loadBatchFixtureKey(t, filepath.Join(directory, "test-source-keys", domain+".pem"), domain, propagationtest.DeliveryStatusSelector)
		keys = append(keys, key)
		f.provider.Publish(key)
	}
	for _, domain := range []string{batchFixtureHostedDomain, batchFixtureForwarderDomain} {
		key := loadBatchFixtureKey(t, filepath.Join(directory, "protected", batchFixtureGeneration, domain+"-return.pem"), domain, "return")
		f.provider.Publish(key)
	}
	f.authority = propagationtest.NewAuthority().AddProfile(propagationTestTenant, keys[1]).AddProfile(propagationTestTenant, keys[2])
	f.coordinator = f.newCoordinator(t, f.enabledReplay(t))
	return batchViaFixture{propagation: f,
		origin:    &SigningService{publicKeys: f.provider, store: newBatchTestAuthority(keys[0]), clock: f.clock.Now},
		forwarder: &SigningService{publicKeys: f.provider, store: newBatchTestAuthority(keys[1], keys[2]), clock: f.clock.Now},
		remote:    &SigningService{publicKeys: f.provider, store: newBatchTestAuthority(keys[3]), clock: f.clock.Now}}
}

// loadBatchFixtureKey reads one isolated fixture key without printing any protected material.
func loadBatchFixtureKey(t *testing.T, path, domain, selector string) propagationtest.SigningKey {
	t.Helper()
	encoded := readBatchFixtureFile(t, path, 4096)
	block, rest := pem.Decode(encoded)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != batchFixturePrivateKeyType {
		t.Fatal("fixture key framing invalid")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(encoded)
	clear(block.Bytes)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		t.Fatal("fixture private key invalid")
	}
	public := private.Public().(ed25519.PublicKey)
	handle, err := dkim2.NewPrivateKeyHandle([]byte("handle:" + domain + ":" + selector))
	if err != nil {
		t.Fatal("fixture handle invalid")
	}
	credential, err := dkim2.NewEd25519SigningCredential(selector, public, handle)
	if err != nil {
		t.Fatal("fixture credential invalid")
	}
	profile, err := dkim2.NewEd25519SigningProfile(domain, credential)
	if err != nil {
		t.Fatal("fixture profile invalid")
	}
	return propagationtest.SigningKey{Domain: domain, Selector: selector, Public: public, Private: private, Handle: handle, Profile: profile}
}

// readBatchFixtureMessage loads an exact privately recorded DATA message and observed envelope.
func readBatchFixtureMessage(t *testing.T, messageFile, envelopeFile string) ([]byte, batchFixtureEnvelope) {
	t.Helper()
	if !filepath.IsAbs(messageFile) || !filepath.IsAbs(envelopeFile) {
		t.Fatal("recorded inputs require absolute file paths")
	}
	raw := readBatchFixtureFile(t, messageFile, MaxBatchRevisionMessageBytes)
	var envelope batchFixtureEnvelope
	decoder := json.NewDecoder(bytes.NewReader(readBatchFixtureFile(t, envelopeFile, 4096)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF || len(envelope.RcptTo) != 1 {
		t.Fatal("recorded envelope file invalid")
	}
	return raw, envelope
}

// verifyBatchFixtureMessage verifies real recorded bytes and envelope with the unchanged public verifier.
func verifyBatchFixtureMessage(t *testing.T, f batchViaFixture, raw []byte, envelope batchFixtureEnvelope) {
	t.Helper()
	verification, err := f.propagation.verifier.Verify(context.Background(), dkim2.NewVerifyRequest(raw, []byte(envelope.MailFrom), [][]byte{[]byte(envelope.RcptTo[0])}))
	if err != nil || verification.State() != dkim2.ResultStatePASS {
		t.Fatalf("recorded message verification: state=%s reason=%s", verification.State(), verification.PrimaryReason())
	}
}

// readBatchFixtureFile refuses links, unsafe file modes, and oversized fixture inputs.
func readBatchFixtureFile(t *testing.T, path string, limit int) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > int64(limit) {
		t.Fatal("fixture input file rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("fixture input unavailable")
	}
	defer func() { _ = file.Close() }()
	value, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(value) > limit {
		t.Fatal("fixture input size invalid")
	}
	return value
}

// writeBatchFixtureFile creates one private artifact without overwriting any prior result.
func writeBatchFixtureFile(t *testing.T, path string, value []byte) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("fixture output already exists or cannot be created")
	}
	_, writeErr := file.Write(value)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("fixture output failed")
	}
}

// writeBatchFixtureJSON serializes a private artifact directly to disk without diagnostics.
func writeBatchFixtureJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal("fixture JSON encoding failed")
	}
	writeBatchFixtureFile(t, path, append(encoded, '\n'))
}

// TestBatchRevisionIntegrationFixtureRoundtrip proves exported keys reproduce the actual outgoing-message DSN.
func TestBatchRevisionIntegrationFixtureRoundtrip(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("physical fixture path unavailable")
	}
	directory := filepath.Join(base, "fixture")
	f := exportBatchFixture(t, directory)
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(directory, "protected", batchFixtureGeneration), 0700) })
	owner, err := config.LoadProtected(filepath.Join(directory, "dkim2d.yaml"), config.FlagValues{})
	if err != nil {
		t.Fatalf("exported protected configuration: %s", config.CodeOf(err))
	}
	t.Cleanup(func() { _ = owner.Close() })
	preparation, err := owner.PrepareRuntime()
	if err != nil {
		t.Fatal("exported protected preparation failed")
	}
	service, err := NewSigningService(f.propagation.provider, preparation.SigningStore(), false)
	if err != nil {
		t.Fatal("exported flat-file service construction failed")
	}
	batch, err := service.ReviseBatch(context.Background(), f.request)
	if err != nil || batch.Result() != OperationPass {
		t.Fatal("exported fixture forward signing failed")
	}
	branch, output := f.request.state.copies[1], batch.Outputs()[0]
	raw := insertBatchFields(branch.message.state.raw, output.InsertionOffset(), output.Fields())
	loaded := loadBatchFixture(t, directory)
	verifyBatchFixtureMessage(t, loaded, raw, batchFixtureEnvelope{MailFrom: string(branch.message.state.reverse), RcptTo: []string{string(branch.message.state.recipients[0])}})
	dsn := signBatchRemoteDSN(t, loaded, raw, branch.message.state.reverse, branch.message.state.recipients)
	loaded.propagation.coordinator, err = NewPropagationCoordinator(PropagationDependencies{
		Verifier: loaded.propagation.verifier, Evaluator: loaded.propagation.verifier, PublicKeys: loaded.propagation.provider,
		Authority: service.store, Replay: loaded.propagation.enabledReplay(t), TokenRetention: propagationTestRetention, Clock: loaded.propagation.clock.Now,
	})
	if err != nil {
		t.Fatal("exported flat-file propagation construction failed")
	}
	request, err := NewPropagationRequest(dsn, []byte("<>"), [][]byte{branch.message.state.reverse}, false, propagationTestTenant, "mx.forwarder.test", FidelityRawRFC5322)
	if err != nil {
		t.Fatal("exported fixture return request invalid")
	}
	result := loaded.propagation.propagate(t, request)
	requireOutcome(t, result, PropagationPass, PropagationDispositionAccept, PropagationFailureNone)
	propagated, ok := result.Output()
	if !ok {
		t.Fatal("exported flat-file propagation output missing")
	}
	verifyBatchFixtureMessage(t, loaded, propagated.RawMessage(), batchFixtureEnvelope{MailFrom: "<>", RcptTo: []string{string(propagated.NextHopRecipient())}})
}
