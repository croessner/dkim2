package signingstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/croessner/dkim2"
	"golang.org/x/sys/unix"
)

const (
	testEd25519Algorithm = "ed25519-sha256"
	testPKCS8PEMType     = "PRIVATE KEY"
)

type ed25519SigningStorePublicKeys struct {
	key ed25519.PublicKey
}

// LookupPublicKey returns the exact Ed25519 fixture credential.
func (p ed25519SigningStorePublicKeys) LookupPublicKey(
	_ context.Context,
	query dkim2.PublicKeyQuery,
) (dkim2.PublicKeyResult, error) {
	if query.Algorithm() != dkim2.AlgorithmEd25519SHA256 {
		return dkim2.MissingPublicKey(query.Algorithm()), nil
	}
	return dkim2.FoundEd25519PublicKey(p.key), nil
}

type ed25519DatasourceDocument struct {
	Version  string                     `json:"version"`
	Handles  []map[string]any           `json:"handles"`
	Profiles []ed25519DatasourceProfile `json:"profiles"`
	Policies []map[string]any           `json:"policies"`
}

type ed25519DatasourceProfile struct {
	ID          string           `json:"id"`
	Domain      string           `json:"domain"`
	Status      string           `json:"status"`
	Credentials []map[string]any `json:"credentials"`
}

type signingStorePrivacyContract interface {
	fmt.Stringer
	fmt.GoStringer
	fmt.Formatter
	json.Marshaler
}

// requireSigningStorePrivacyContract makes protected formatting and JSON
// behavior a compile-time obligation.
func requireSigningStorePrivacyContract[T signingStorePrivacyContract]() {}

// TestStoreParsesAndSignsWithEd25519 proves the PKCS#8 Ed25519 path reaches
// the real opaque signing callback and publishes the expected algorithm fact.
func TestStoreParsesAndSignsWithEd25519(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	publicKey := rewriteSigningStoreFixtureForEd25519(t, fixture)
	store, err := Open(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	profile, err := store.ResolvePolicy(
		context.Background(),
		"tenant-a",
		"example.test",
		PolicyOriginator,
		time.Now().UTC(),
	)
	if err != nil || !profile.Valid() {
		t.Fatalf("ResolvePolicy() valid=%t error=%v", profile.Valid(), err)
	}
	signer, err := dkim2.NewSigner(
		ed25519SigningStorePublicKeys{key: publicKey},
		dkim2.NewRequestRouteAuthority(),
		signingStoreAuthorizer{},
		store,
	)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	raw := []byte("From: sender@example.test\r\nSubject: ed25519 store\r\n\r\nbody\r\n")
	reverse := []byte("<sender@example.test>")
	recipients := [][]byte{[]byte("<recipient@example.net>")}
	source, err := dkim2.NewSigningSource(raw)
	if err != nil {
		t.Fatalf("NewSigningSource() error = %v", err)
	}
	entry, err := dkim2.NewOriginatorRouteEntry(
		source,
		reverse,
		recipients,
		dkim2.RouteDisclosureSingle,
		[]byte("local"),
	)
	if err != nil {
		t.Fatalf("NewOriginatorRouteEntry() error = %v", err)
	}
	fanout, err := dkim2.NewRouteFanoutRequest([]dkim2.RouteEntry{entry})
	if err != nil {
		t.Fatalf("NewRouteFanoutRequest() error = %v", err)
	}
	_, tickets, err := signer.PlanRouteFanout(context.Background(), fanout)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("PlanRouteFanout() tickets=%d error=%v", len(tickets), err)
	}
	result, recovery, err := signer.SignOriginator(
		context.Background(),
		dkim2.NewOriginatorSigningRequest(
			raw,
			reverse,
			recipients,
			tickets[0],
			profile,
			dkim2.SigningMetadata{},
			dkim2.SigningTransportFinalNetworkPreDotStuffing,
		),
	)
	if err != nil || recovery.Valid() || !result.Valid() {
		t.Fatalf(
			"SignOriginator() valid=%t recovery=%t error=%v",
			result.Valid(),
			recovery.Valid(),
			err,
		)
	}
	signed, ok := result.Unrestricted()
	if !ok {
		t.Fatal("SignOriginator() did not return unrestricted output")
	}
	algorithms := signed.Facts().Algorithms()
	if len(algorithms) != 1 || algorithms[0] != dkim2.AlgorithmEd25519SHA256 {
		t.Fatalf("Algorithms() = %v", algorithms)
	}
	fields := signed.GeneratedFields()
	if len(fields) != 2 {
		t.Fatalf("GeneratedFields() count = %d", len(fields))
	}
	if !bytes.Contains(
		fields[1],
		[]byte(":"+testEd25519Algorithm+":"),
	) {
		t.Fatal("generated signature did not declare Ed25519-SHA256")
	}
}

// TestStoreRejectsAmbiguousPEMRepresentations freezes the exact single,
// header-free PKCS#8 PRIVATE KEY representation.
func TestStoreRejectsAmbiguousPEMRepresentations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "leading material",
			mutate: func(valid []byte) []byte {
				return append([]byte("ambiguous-leading-material\n"), valid...)
			},
		},
		{
			name: "trailing material",
			mutate: func(valid []byte) []byte {
				return append(bytes.Clone(valid), []byte("ambiguous-trailing-material\n")...)
			},
		},
		{
			name: "second block",
			mutate: func(valid []byte) []byte {
				return append(bytes.Clone(valid), valid...)
			},
		},
		{
			name: "PEM headers",
			mutate: func(valid []byte) []byte {
				block, _ := pem.Decode(valid)
				return pem.EncodeToMemory(&pem.Block{
					Type:    block.Type,
					Headers: map[string]string{"Comment": "ambiguous"},
					Bytes:   block.Bytes,
				})
			},
		},
		{
			name: "legacy block label",
			mutate: func(valid []byte) []byte {
				block, _ := pem.Decode(valid)
				return pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: block.Bytes,
				})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSigningStoreFixture(t)
			valid, err := os.ReadFile(filepath.Join(fixture.rootPath, fixture.privateKey))
			if err != nil {
				t.Fatalf("os.ReadFile() error = %v", err)
			}
			if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
				t.Fatalf("os.Chmod(unseal) error = %v", err)
			}
			rewriteProtectedTestFile(
				t,
				filepath.Join(fixture.rootPath, fixture.privateKey),
				test.mutate(valid),
			)
			if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
				t.Fatalf("os.Chmod(seal) error = %v", err)
			}
			if store, openErr := Open(
				fixture.rootFD,
				fixture.datasource,
				fixture.manifest,
			); openErr == nil || store != nil {
				t.Fatal("Open() accepted an ambiguous PEM representation")
			}
		})
	}
}

// TestStoreRejectsUnsafeFilesystemChildren proves symlinks, special files,
// and excessive child permissions cannot enter a protected generation.
func TestStoreRejectsUnsafeFilesystemChildren(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, signingStoreFixture)
	}{
		{
			name: "symlink",
			mutate: func(t *testing.T, fixture signingStoreFixture) {
				t.Helper()
				path := filepath.Join(fixture.rootPath, fixture.privateKey)
				if err := os.Remove(path); err != nil {
					t.Fatalf("os.Remove() error = %v", err)
				}
				if err := os.Symlink(fixture.manifest, path); err != nil {
					t.Fatalf("os.Symlink() error = %v", err)
				}
			},
		},
		{
			name: "FIFO",
			mutate: func(t *testing.T, fixture signingStoreFixture) {
				t.Helper()
				path := filepath.Join(fixture.rootPath, fixture.privateKey)
				if err := os.Remove(path); err != nil {
					t.Fatalf("os.Remove() error = %v", err)
				}
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatalf("unix.Mkfifo() error = %v", err)
				}
			},
		},
		{
			name: "group readable mode",
			mutate: func(t *testing.T, fixture signingStoreFixture) {
				t.Helper()
				if err := os.Chmod(
					filepath.Join(fixture.rootPath, fixture.privateKey),
					0o640,
				); err != nil {
					t.Fatalf("os.Chmod(private key) error = %v", err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSigningStoreFixture(t)
			if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
				t.Fatalf("os.Chmod(unseal) error = %v", err)
			}
			test.mutate(t, fixture)
			if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
				t.Fatalf("os.Chmod(seal) error = %v", err)
			}
			if store, err := Open(
				fixture.rootFD,
				fixture.datasource,
				fixture.manifest,
			); err == nil || store != nil {
				t.Fatal("Open() accepted an unsafe filesystem child")
			}
		})
	}
}

// TestValidateCompoundGenerationRejectsInPlaceChildMutation proves a retained
// child descriptor detects same-inode, same-size content replacement through
// the mandatory timestamp recheck.
func TestValidateCompoundGenerationRejectsInPlaceChildMutation(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	rootState, err := protectedRootState(fixture.rootFD)
	if err != nil {
		t.Fatalf("protectedRootState() error = %v", err)
	}
	child, err := openRetainedChild(
		fixture.rootFD,
		fixture.privateKey,
		maxPrivateBytes,
		rootState,
	)
	if err != nil {
		t.Fatalf("openRetainedChild() error = %v", err)
	}
	t.Cleanup(func() { _ = closeRetainedChild(child) })
	if len(child.data) == 0 {
		t.Fatal("openRetainedChild() returned empty fixture data")
	}
	replacement := child.data[0] ^ byte(0x01)
	path := filepath.Join(fixture.rootPath, fixture.privateKey)
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("os.OpenFile() error = %v", err)
	}
	if _, err := file.WriteAt([]byte{replacement}, 0); err != nil {
		_ = file.Close()
		t.Fatalf("WriteAt() error = %v", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatalf("Sync() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close(mutator) error = %v", err)
	}
	distinctModificationTime := time.Unix(
		child.before.mtimeSec+2,
		child.before.mtimeNsec,
	)
	if err := os.Chtimes(path, distinctModificationTime, distinctModificationTime); err != nil {
		t.Fatalf("os.Chtimes() error = %v", err)
	}
	after, err := descriptorState(child.fd)
	if err != nil {
		t.Fatalf("descriptorState() error = %v", err)
	}
	if after.device != child.before.device ||
		after.inode != child.before.inode ||
		after.size != child.before.size {
		t.Fatal("mutation did not preserve child device, inode, and size")
	}
	if after.mtimeSec == child.before.mtimeSec &&
		after.mtimeNsec == child.before.mtimeNsec {
		t.Fatal("mutation did not produce a distinct modification timestamp")
	}
	var observed [1]byte
	if count, err := unix.Pread(child.fd, observed[:], 0); err != nil || count != 1 {
		t.Fatalf("unix.Pread() count=%d error=%v", count, err)
	}
	if observed[0] != replacement {
		t.Fatal("retained descriptor did not observe the in-place byte mutation")
	}
	if err := validateCompoundGeneration(
		fixture.rootFD,
		rootState,
		[]*retainedChild{child},
	); err == nil {
		t.Fatal("validateCompoundGeneration() accepted in-place child mutation")
	}
}

// TestStoreRejectsDuplicateManifestBindings proves handle, path, and public
// identity uniqueness are independent fail-closed manifest invariants.
func TestStoreRejectsDuplicateManifestBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(manifestEntry) manifestEntry
	}{
		{
			name: "handle",
			mutate: func(entry manifestEntry) manifestEntry {
				entry.PrivateKeyFile = "alternate-private.pem"
				entry.PublicSPKISHA256 = base64.StdEncoding.EncodeToString(
					bytes.Repeat([]byte{0x11}, sha256.Size),
				)
				return entry
			},
		},
		{
			name: "path",
			mutate: func(entry manifestEntry) manifestEntry {
				entry.HandleID = "alternate-handle"
				entry.PublicSPKISHA256 = base64.StdEncoding.EncodeToString(
					bytes.Repeat([]byte{0x22}, sha256.Size),
				)
				return entry
			},
		},
		{
			name: "public identity",
			mutate: func(entry manifestEntry) manifestEntry {
				entry.HandleID = "alternate-handle"
				entry.PrivateKeyFile = "alternate-private.pem"
				return entry
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSigningStoreFixture(t)
			var document manifestDocument
			if err := json.Unmarshal(fixture.manifestData, &document); err != nil {
				t.Fatalf("json.Unmarshal(manifest) error = %v", err)
			}
			document.Entries = append(
				document.Entries,
				test.mutate(document.Entries[0]),
			)
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatalf("json.Marshal(manifest) error = %v", err)
			}
			if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
				t.Fatalf("os.Chmod(unseal) error = %v", err)
			}
			rewriteProtectedTestFile(
				t,
				filepath.Join(fixture.rootPath, fixture.manifest),
				encoded,
			)
			if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
				t.Fatalf("os.Chmod(seal) error = %v", err)
			}
			if store, openErr := Open(
				fixture.rootFD,
				fixture.datasource,
				fixture.manifest,
			); openErr == nil || store != nil {
				t.Fatal("Open() accepted a duplicate manifest binding")
			}
		})
	}
}

// TestSigningStorePrivacyFormattingAndJSON proves generation and runtime
// diagnostics cannot traverse provider, path, or private-key state.
func TestSigningStorePrivacyFormattingAndJSON(t *testing.T) {
	requireSigningStorePrivacyContract[*Generation]()
	requireSigningStorePrivacyContract[*Runtime]()
	fixture := newSigningStoreFixture(t)
	generation, err := Open(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = generation.Close(context.Background()) })
	runtime, err := NewRuntime(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	for name, value := range map[string]any{
		"generation": generation,
		"runtime":    runtime,
	} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{
				"%v",
				"%+v",
				"%#v",
				"%s",
				"%q",
				"%x",
				"%X",
			} {
				if formatted := fmt.Sprintf(format, value); formatted != storeRedacted {
					t.Fatalf("format %q produced %q", format, formatted)
				}
			}
			encoded, marshalErr := json.Marshal(value)
			if marshalErr != nil || !bytes.Equal(encoded, []byte("{}")) {
				t.Fatalf("json.Marshal() = %q, %v", encoded, marshalErr)
			}
		})
	}
}

// TestRuntimeRejectsAcquisitionWhileDegraded proves a failed candidate closes
// new work while retaining the already pinned generation until exact recovery.
func TestRuntimeRejectsAcquisitionWhileDegraded(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	runtime, err := NewRuntime(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	lease, err := runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire(initial) error = %v", err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
		t.Fatalf("os.Chmod(unseal) error = %v", err)
	}
	rewriteProtectedTestFile(
		t,
		filepath.Join(fixture.rootPath, fixture.manifest),
		[]byte(`{"version":"dkim2-private-keys-v1","entries":[]}`),
	)
	if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
		t.Fatalf("os.Chmod(seal) error = %v", err)
	}
	if err := runtime.Reload(context.Background()); err == nil {
		t.Fatal("Reload() accepted an invalid generation")
	}
	if acquired, acquireErr := runtime.Acquire(); acquireErr == nil || acquired != nil {
		t.Fatal("Acquire() accepted new work while degraded")
	}
	if profile, resolveErr := lease.ResolvePolicy(
		context.Background(),
		"tenant-a",
		"example.test",
		PolicyOriginator,
		time.Now().UTC(),
	); resolveErr != nil || !profile.Valid() {
		t.Fatalf("pinned lease was lost while degraded: %v", resolveErr)
	}
	if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
		t.Fatalf("os.Chmod(recovery unseal) error = %v", err)
	}
	rewriteProtectedTestFile(
		t,
		filepath.Join(fixture.rootPath, fixture.manifest),
		fixture.manifestData,
	)
	if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
		t.Fatalf("os.Chmod(recovery seal) error = %v", err)
	}
	if err := runtime.Reload(context.Background()); err != nil {
		t.Fatalf("Reload(recovery) error = %v", err)
	}
	recovered, err := runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire(recovered) error = %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatalf("Close(recovered lease) error = %v", err)
	}
}

// TestRuntimeCancellationAndClosePreserveActiveLease proves canceled lifecycle
// calls do not mutate state and final close drains ownership without revoking
// already admitted signing work.
func TestRuntimeCancellationAndClosePreserveActiveLease(t *testing.T) {
	fixture := newSigningStoreFixture(t)
	runtime, err := NewRuntime(fixture.rootFD, fixture.datasource, fixture.manifest)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	lease, err := runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire(active) error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Reload(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reload(canceled) error = %v", err)
	}
	if err := runtime.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close(canceled) error = %v", err)
	}
	probe, err := runtime.Acquire()
	if err != nil {
		t.Fatalf("Acquire(after canceled close) error = %v", err)
	}
	if err := probe.Close(); err != nil {
		t.Fatalf("Close(probe lease) error = %v", err)
	}
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("Close(runtime) error = %v", err)
	}
	if acquired, acquireErr := runtime.Acquire(); acquireErr == nil || acquired != nil {
		t.Fatal("Acquire() succeeded after runtime close")
	}
	if profile, resolveErr := lease.ResolvePolicy(
		context.Background(),
		"tenant-a",
		"example.test",
		PolicyOriginator,
		time.Now().UTC(),
	); resolveErr != nil || !profile.Valid() {
		t.Fatalf("active lease was revoked by runtime close: %v", resolveErr)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("Close(active lease) error = %v", err)
	}
}

// rewriteSigningStoreFixtureForEd25519 replaces the RSA fixture with one
// exact same-generation Ed25519 PKCS#8 credential.
func rewriteSigningStoreFixtureForEd25519(
	t *testing.T,
	fixture signingStoreFixture,
) ed25519.PublicKey {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey() error = %v", err)
	}
	detachedPublic := ed25519.PublicKey(bytes.Clone(publicKey))
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	clear(privateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: testPKCS8PEMType, Bytes: pkcs8})
	clear(pkcs8)
	spki, err := x509.MarshalPKIXPublicKey(detachedPublic)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey() error = %v", err)
	}
	digest := sha256.Sum256(spki)
	var manifest manifestDocument
	if err := json.Unmarshal(fixture.manifestData, &manifest); err != nil {
		t.Fatalf("json.Unmarshal(manifest) error = %v", err)
	}
	manifest.Entries[0].Algorithm = testEd25519Algorithm
	manifest.Entries[0].PublicSPKISHA256 = base64.StdEncoding.EncodeToString(digest[:])
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal(manifest) error = %v", err)
	}
	datasourceData, err := os.ReadFile(filepath.Join(fixture.rootPath, fixture.datasource))
	if err != nil {
		t.Fatalf("os.ReadFile(datasource) error = %v", err)
	}
	var datasource ed25519DatasourceDocument
	if err := json.Unmarshal(datasourceData, &datasource); err != nil {
		t.Fatalf("json.Unmarshal(datasource) error = %v", err)
	}
	datasource.Profiles[0].Credentials[0]["algorithm"] = testEd25519Algorithm
	datasource.Profiles[0].Credentials[0]["public_key_spki"] =
		base64.StdEncoding.EncodeToString(spki)
	clear(spki)
	datasourceData, err = json.Marshal(datasource)
	if err != nil {
		t.Fatalf("json.Marshal(datasource) error = %v", err)
	}
	if err := os.Chmod(fixture.rootPath, 0o700); err != nil {
		t.Fatalf("os.Chmod(unseal) error = %v", err)
	}
	rewriteProtectedTestFile(
		t,
		filepath.Join(fixture.rootPath, fixture.privateKey),
		privatePEM,
	)
	clear(privatePEM)
	rewriteProtectedTestFile(
		t,
		filepath.Join(fixture.rootPath, fixture.manifest),
		manifestData,
	)
	rewriteProtectedTestFile(
		t,
		filepath.Join(fixture.rootPath, fixture.datasource),
		datasourceData,
	)
	if err := os.Chmod(fixture.rootPath, 0o500); err != nil {
		t.Fatalf("os.Chmod(seal) error = %v", err)
	}
	return detachedPublic
}
