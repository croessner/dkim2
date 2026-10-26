package command

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	keyAlgorithmFlag = "--algorithm"
	keyDomainFlag    = "--domain"
	keyTestEd25519   = "ed25519-sha256"
	keyPrivateFlag   = "--private-key"
	keySelectorFlag  = "--selector"
	keyTestDomain    = "example.test"
)

// runKeyCommandForTest executes one datasource key command without runtime ownership.
func runKeyCommandForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	owner := &commandOwnerFake{stopLimit: time.Second}
	application := &commandApplicationFake{}
	exit, stdout, stderr, loads, _ := commandHarness(t,
		append([]string{datasourceCommandName, keyCommandName, keyGenerateCommandName}, args...),
		owner, application, nil, nil)
	if loads != 0 {
		t.Fatal("key generation loaded daemon configuration")
	}
	return exit, stdout, stderr
}

// TestKeyGenerateWritesCustodyKeyAndPublicRecord proves the generated key
// lands only in a new owner-only file and stdout carries public material.
func TestKeyGenerateWritesCustodyKeyAndPublicRecord(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ed.pem")
	exit, stdout, stderr := runKeyCommandForTest(t,
		keyAlgorithmFlag, keyTestEd25519, keyDomainFlag, keyTestDomain,
		keySelectorFlag, "ed-20261021", keyPrivateFlag, path, "--machine")
	if exit != 0 || stderr != "" {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	if strings.Contains(stdout, "PRIVATE KEY") {
		t.Fatal("stdout exposed private key material")
	}
	var document keyGenerateDocument
	if err := json.Unmarshal([]byte(stdout), &document); err != nil || document.Schema != keyGenerateSchema {
		t.Fatalf("machine output = %q, error = %v", stdout, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key file mode = %v, error = %v", info, err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read generated key")
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		t.Fatal("generated key is not one PKCS#8 PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal("generated key is not a PKCS#8 key")
	}
	signer, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		t.Fatal("generated key has no public half")
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal("marshal generated public key")
	}
	digest := sha256.Sum256(spki)
	if document.PublicKeySPKI != base64.StdEncoding.EncodeToString(spki) ||
		document.PublicSPKISHA256 != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatal("printed public credential does not match the key file")
	}
	if !strings.Contains(document.DNSZone, "ed-20261021._domainkey.example.test. 3600 IN TXT") ||
		!strings.Contains(document.DNSZone, `"v=DKIM1; k=ed25519; p=`) {
		t.Fatalf("DNS zone = %q", document.DNSZone)
	}

	before := bytes.Clone(encoded)
	exit, _, _ = runKeyCommandForTest(t,
		keyAlgorithmFlag, keyTestEd25519, keyDomainFlag, keyTestDomain,
		keySelectorFlag, "ed-20261021", keyPrivateFlag, path)
	after, err := os.ReadFile(path)
	if exit != 1 || err != nil || !bytes.Equal(before, after) {
		t.Fatalf("existing key file was not preserved: exit=%d", exit)
	}
}

// TestKeyGenerateTextOutputAndShapeFailures proves human output and that
// invalid requests fail before any key file exists.
func TestKeyGenerateTextOutputAndShapeFailures(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "ed.pem")
	exit, stdout, _ := runKeyCommandForTest(t,
		keyAlgorithmFlag, keyTestEd25519, keyDomainFlag, keyTestDomain,
		keySelectorFlag, "ed1", keyPrivateFlag, path, "--ttl", "300")
	if exit != 0 || !strings.HasPrefix(stdout, "algorithm=ed25519-sha256 domain=example.test selector=ed1\npublic_key_spki=") ||
		!strings.Contains(stdout, "\npublic_spki_sha256=") || !strings.Contains(stdout, `"v=DKIM1; k=ed25519; p=`) {
		t.Fatalf("exit=%d stdout=%q", exit, stdout)
	}
	for _, args := range [][]string{
		{keyAlgorithmFlag, "rsa-sha1", keyDomainFlag, keyTestDomain, keySelectorFlag, "s", keyPrivateFlag, filepath.Join(directory, "a.pem")},
		{keyAlgorithmFlag, "mldsa44-ed25519-sha512", keyDomainFlag, keyTestDomain, keySelectorFlag, "s", keyPrivateFlag, filepath.Join(directory, "pq.pem")},
		{keyAlgorithmFlag, keyTestEd25519, keyDomainFlag, keyTestDomain, keySelectorFlag, "bad selector", keyPrivateFlag, filepath.Join(directory, "b.pem")},
		{keyAlgorithmFlag, keyTestEd25519, keyDomainFlag, keyTestDomain, keySelectorFlag, "s", keyPrivateFlag, "relative.pem"},
		{keyAlgorithmFlag, "rsa-sha256", keyDomainFlag, keyTestDomain, keySelectorFlag, "s", keyPrivateFlag, filepath.Join(directory, "c.pem"), "--rsa-bits", "1024"},
		{keyAlgorithmFlag, keyTestEd25519, keyDomainFlag, keyTestDomain, keySelectorFlag, "s", keyPrivateFlag, filepath.Join(directory, "d.pem"), "--ttl", "0"},
	} {
		if exit, _, _ := runKeyCommandForTest(t, args...); exit != 2 {
			t.Fatalf("args %q exit = %d, want 2", args, exit)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("shape failures created key files: %d", len(entries))
	}
}
