package redisstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/replay/redisgrammar"
)

// TestDefaultConfigIsValidForEveryMode proves documented defaults validate.
func TestDefaultConfigIsValidForEveryMode(t *testing.T) {
	standalone := DefaultConfig("redis.internal:6379")
	if err := standalone.Validate(); err != nil {
		t.Fatalf("standalone default err=%v", err)
	}
	sentinel := DefaultConfig("")
	sentinel.Mode = ModeSentinel
	sentinel.StandaloneAddress = ""
	sentinel.SentinelMasterName = testSentinelMaster
	sentinel.SentinelAddresses = []string{testSentinelAddress, "sentinel-2.internal:26379"}
	if err := sentinel.Validate(); err != nil {
		t.Fatalf("sentinel err=%v", err)
	}
	cluster := DefaultConfig("")
	cluster.Mode = ModeCluster
	cluster.ClusterAddresses = []string{testClusterAddress, "10.0.0.2:7000", "[::1]:7000"}
	if err := cluster.Validate(); err != nil {
		t.Fatalf("cluster err=%v", err)
	}
}

// TestConfigValidationRejectsEveryBoundViolation proves the closed rule set.
func TestConfigValidationRejectsEveryBoundViolation(t *testing.T) {
	cases := map[string]func(*Config){
		"unknown mode":            func(c *Config) { c.Mode = 0 },
		"missing address":         func(c *Config) { c.StandaloneAddress = "" },
		"address without port":    func(c *Config) { c.StandaloneAddress = testServerName },
		"zero port":               func(c *Config) { c.StandaloneAddress = "redis.internal:0" },
		"padded port":             func(c *Config) { c.StandaloneAddress = "redis.internal:06379" },
		"uppercase host":          func(c *Config) { c.StandaloneAddress = "Redis.internal:6379" },
		"zoned host":              func(c *Config) { c.StandaloneAddress = "[fe80::1%en0]:6379" },
		"long address":            func(c *Config) { c.StandaloneAddress = strings.Repeat("a", 250) + ".b:6379" },
		"standalone with cluster": func(c *Config) { c.ClusterAddresses = []string{testClusterAddress} },
		"sentinel name standalone": func(c *Config) {
			c.SentinelMasterName = testSentinelMaster
		},
		"sentinel without master": func(c *Config) {
			c.Mode, c.StandaloneAddress, c.SentinelAddresses = ModeSentinel, "", []string{testSentinelAddress}
		},
		"sentinel duplicate addresses": func(c *Config) {
			c.Mode, c.StandaloneAddress, c.SentinelMasterName = ModeSentinel, "", testSentinelMaster
			c.SentinelAddresses = []string{testSentinelAddress, testSentinelAddress}
		},
		"sentinel too many addresses": func(c *Config) {
			c.Mode, c.StandaloneAddress, c.SentinelMasterName = ModeSentinel, "", testSentinelMaster
			c.SentinelAddresses = manyAddresses(maximumSentinelAddresses + 1)
		},
		"cluster too many addresses": func(c *Config) {
			c.Mode, c.StandaloneAddress = ModeCluster, ""
			c.ClusterAddresses = manyAddresses(maximumClusterAddresses + 1)
		},
		"cluster database": func(c *Config) {
			c.Mode, c.StandaloneAddress, c.ClusterAddresses, c.DatabaseNumber = ModeCluster, "", []string{testClusterAddress}, 1
		},
		"redirects zero":    func(c *Config) { c.ClusterMaxRedirects = 0 },
		"redirects high":    func(c *Config) { c.ClusterMaxRedirects = 17 },
		"bad username":      func(c *Config) { c.Username = "bad user" },
		"database high":     func(c *Config) { c.DatabaseNumber = 16 },
		"database negative": func(c *Config) { c.DatabaseNumber = -1 },
		"prefix brace":      func(c *Config) { c.KeyPrefix = "{tag}:" },
		"prefix space":      func(c *Config) { c.KeyPrefix = "a b" },
		"prefix long":       func(c *Config) { c.KeyPrefix = strings.Repeat("a", 65) },
		"protocol":          func(c *Config) { c.Protocol = 1 },
		"tls name disabled": func(c *Config) { c.TLS.ServerName = testServerName },
		"tls skip disabled": func(c *Config) { c.TLS.InsecureSkipVerify = true },
		"tls version disabled": func(c *Config) {
			c.TLS.MinVersion = TLSVersion12
		},
		"tls bad version":     func(c *Config) { c.TLS = TLSConfig{Enabled: true, MinVersion: tls.VersionTLS11} },
		"tls bad name":        func(c *Config) { c.TLS = TLSConfig{Enabled: true, MinVersion: TLSVersion12, ServerName: "Bad_Name"} },
		"pool zero":           func(c *Config) { c.PoolSize = 0 },
		"pool high":           func(c *Config) { c.PoolSize = maximumPoolSize + 1 },
		"idle above pool":     func(c *Config) { c.MinIdleConnections = c.PoolSize + 1 },
		"pool timeout zero":   func(c *Config) { c.PoolTimeout = 0 },
		"dial timeout low":    func(c *Config) { c.DialTimeout = 99 * time.Millisecond },
		"read timeout high":   func(c *Config) { c.ReadTimeout = 31 * time.Second },
		"write timeout zero":  func(c *Config) { c.WriteTimeout = 0 },
		"attempts zero":       func(c *Config) { c.MaxAttempts = 0 },
		"attempts high":       func(c *Config) { c.MaxAttempts = 11 },
		"backoff inverted":    func(c *Config) { c.MinRetryBackoff, c.MaxRetryBackoff = time.Second, time.Millisecond },
		"backoff high":        func(c *Config) { c.MaxRetryBackoff = 6 * time.Second },
		"interval low":        func(c *Config) { c.Health.Interval = 999 * time.Millisecond },
		"interval high":       func(c *Config) { c.Health.Interval = 61 * time.Second },
		"timeout at interval": func(c *Config) { c.Health.Timeout = c.Health.Interval },
		"timeout zero":        func(c *Config) { c.Health.Timeout = 0 },
		"threshold zero":      func(c *Config) { c.Health.FailureThreshold = 0 },
		"threshold high":      func(c *Config) { c.Health.FailureThreshold = 11 },
		"retention low":       func(c *Config) { c.MinimumRetention = time.Millisecond },
		"retention high":      func(c *Config) { c.MaximumRetention = 31 * 24 * time.Hour },
		"retention inverted":  func(c *Config) { c.MinimumRetention, c.MaximumRetention = time.Hour, time.Minute },
		"limits widened":      func(c *Config) { c.Limits.MaxInFlight = 1 << 30 },
	}
	for name, mutate := range cases {
		config := testConfig()
		mutate(&config)
		if err := config.Validate(); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}

// manyAddresses returns count distinct valid addresses.
func manyAddresses(count int) []string {
	addresses := make([]string, count)
	for index := range addresses {
		addresses[index] = "10.0.0.1:" + strconv.Itoa(7000+index)
	}
	return addresses
}

// TestSecretsValidation proves credential, Sentinel, and TLS material rules.
func TestSecretsValidation(t *testing.T) {
	root, certificatePEM, keyPEM := testCertificateMaterial(t)
	tlsConfig := func(c *Config) {
		c.TLS = TLSConfig{Enabled: true, MinVersion: TLSVersion13, ServerName: testServerName}
	}
	cases := []struct {
		name    string
		mutate  func(*Config)
		secrets Secrets
		valid   bool
	}{
		{name: "no auth", valid: true},
		{name: "password only", secrets: Secrets{Password: []byte("pw")}, valid: true},
		{name: "user with password", mutate: func(c *Config) { c.Username = testUsername }, secrets: Secrets{Password: []byte("pw")}, valid: true},
		{name: "user without password", mutate: func(c *Config) { c.Username = testUsername }},
		{name: "oversized password", secrets: Secrets{Password: make([]byte, maximumSecretBytes+1)}},
		{name: "sentinel password outside sentinel", secrets: Secrets{SentinelPassword: []byte("pw")}},
		{name: "roots without tls", secrets: Secrets{RootsDER: [][]byte{root}}},
		{name: "pair without tls", secrets: Secrets{ClientCertificatePEM: certificatePEM, ClientKeyPEM: keyPEM}},
		{name: "tls roots", mutate: tlsConfig, secrets: Secrets{RootsDER: [][]byte{root}}, valid: true},
		{name: "tls system roots", mutate: tlsConfig, valid: true},
		{name: "tls mutual", mutate: tlsConfig, secrets: Secrets{RootsDER: [][]byte{root}, ClientCertificatePEM: certificatePEM, ClientKeyPEM: keyPEM}, valid: true},
		{name: "tls cert without key", mutate: tlsConfig, secrets: Secrets{ClientCertificatePEM: certificatePEM}},
		{name: "tls mismatched key", mutate: tlsConfig, secrets: Secrets{ClientCertificatePEM: certificatePEM, ClientKeyPEM: []byte("junk")}},
		{name: "tls malformed root", mutate: tlsConfig, secrets: Secrets{RootsDER: [][]byte{{1, 2, 3}}}},
		{name: "tls duplicate root", mutate: tlsConfig, secrets: Secrets{RootsDER: [][]byte{root, root}}},
		{name: "tls leaf as root", mutate: tlsConfig, secrets: Secrets{RootsDER: [][]byte{leafDER(t, certificatePEM)}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			fake := newFakeBackend()
			config := testConfig()
			if test.mutate != nil {
				test.mutate(&config)
			}
			store, err := newStoreWithDependencies(context.Background(), config, test.secrets, fakeDependencies(fake))
			if test.valid != (err == nil) {
				t.Fatalf("valid=%t err=%v", test.valid, err)
			}
			if err != nil {
				requireCode(t, err, dkim2.ReplayErrorMisconfigured)
				return
			}
			_ = store.Close(context.Background())
		})
	}
}

// TestSentinelPasswordRules proves the Sentinel credential pairing.
func TestSentinelPasswordRules(t *testing.T) {
	sentinel := func(username string) validatedConfig {
		return validatedConfig{mode: ModeSentinel, sentinelUsername: username}
	}
	if validateSentinelPassword(sentinel(""), nil) != nil ||
		validateSentinelPassword(sentinel(""), []byte("pw")) != nil ||
		validateSentinelPassword(sentinel("watcher"), []byte("pw")) != nil {
		t.Fatal("valid Sentinel credentials rejected")
	}
	if validateSentinelPassword(sentinel("watcher"), nil) == nil ||
		validateSentinelPassword(sentinel(""), make([]byte, maximumSecretBytes+1)) == nil {
		t.Fatal("invalid Sentinel credentials accepted")
	}
}

// TestCredentialVaultCopiesAndClears proves secret ownership.
func TestCredentialVaultCopiesAndClears(t *testing.T) {
	password := []byte("secret-password")
	vault, err := newCredentialVault(testUsername, password)
	if err != nil {
		t.Fatal(err)
	}
	clear(password)
	username, provided, err := vault.provide(context.Background())
	if err != nil || username != testUsername || provided != "secret-password" {
		t.Fatal("vault did not own an independent copy")
	}
	owned := vault.password
	vault.clear()
	for _, value := range owned {
		if value != 0 {
			t.Fatal("vault clear left password bytes")
		}
	}
	if _, _, err := vault.provide(context.Background()); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorClosed {
		t.Fatal("cleared vault still provided credentials")
	}
}

// TestBuildTLSConfigAppliesPolicy proves the produced client TLS policy.
func TestBuildTLSConfigAppliesPolicy(t *testing.T) {
	root, certificatePEM, keyPEM := testCertificateMaterial(t)
	config, err := buildTLSConfig(
		TLSConfig{Enabled: true, MinVersion: TLSVersion13, ServerName: testServerName},
		Secrets{RootsDER: [][]byte{root}, ClientCertificatePEM: certificatePEM, ClientKeyPEM: keyPEM},
	)
	if err != nil || config.MinVersion != tls.VersionTLS13 || config.ServerName != testServerName ||
		config.RootCAs == nil || len(config.Certificates) != 1 || config.InsecureSkipVerify {
		t.Fatalf("tls config err=%v", err)
	}
	disabled, err := buildTLSConfig(TLSConfig{}, Secrets{})
	if err != nil || disabled != nil {
		t.Fatal("disabled TLS produced a policy")
	}
}

// TestBuildTLSConfigClientPEMBoundMatchesTheLoader proves the provider admits
// a client pair padded to exactly the loader's shared PEM bound and refuses
// one byte more, so a protected generation that loads also starts.
func TestBuildTLSConfigClientPEMBoundMatchesTheLoader(t *testing.T) {
	_, certificatePEM, keyPEM := testCertificateMaterial(t)
	pad := func(value []byte, size int) []byte {
		padded := append([]byte(nil), value...)
		return append(padded, bytes.Repeat([]byte("\n"), size-len(padded))...)
	}
	transport := TLSConfig{Enabled: true, MinVersion: TLSVersion12}
	limit := redisgrammar.MaxClientPEMBytes
	if _, err := buildTLSConfig(transport, Secrets{
		ClientCertificatePEM: pad(certificatePEM, limit), ClientKeyPEM: pad(keyPEM, limit),
	}); err != nil {
		t.Fatalf("pair at the shared bound was refused: %v", err)
	}
	if _, err := buildTLSConfig(transport, Secrets{
		ClientCertificatePEM: pad(certificatePEM, limit+1), ClientKeyPEM: keyPEM,
	}); err == nil {
		t.Fatal("certificate above the shared bound was accepted")
	}
}

// testCertificateMaterial returns one CA DER plus a CA-signed client certificate pair in PEM.
func testCertificateMaterial(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "synthetic replay CA"},
		NotBefore:             time.Unix(1_700_000_000, 0),
		NotAfter:              time.Unix(1_700_000_000, 0).Add(100 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "synthetic replay client"},
		NotBefore:    caTemplate.NotBefore,
		NotAfter:     caTemplate.NotAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return caDER,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// leafDER decodes the client certificate PEM back to DER.
func leafDER(t *testing.T, certificatePEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("leaf PEM decode failed")
	}
	return block.Bytes
}
