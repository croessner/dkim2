package valkey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	dkim2 "github.com/croessner/dkim2"
	valkeygo "github.com/valkey-io/valkey-go"
)

const (
	syntheticConfigPassword  = "synthetic-config-password"
	syntheticAuditorPassword = "synthetic-auditor-password"
)

// TestClientConfigBuildsExactStandaloneOption proves the complete restrictive client projection.
func TestClientConfigBuildsExactStandaloneOption(t *testing.T) {
	config := validClientConfig(t)
	validated, err := validateClientConfig(config)
	if err != nil {
		t.Fatal("valid client configuration was rejected")
	}

	option := validated.option()
	assertExactTLSOption(t, option.TLSConfig, config)
	assertExactStandaloneOption(t, option, config)
	assertOnlyFrozenClientOptionFields(t, option)

	second := validated.option()
	if second.ClientSetInfo == nil || len(second.ClientSetInfo) != 0 ||
		second.InitAddress == nil || second.TLSConfig == nil ||
		second.TLSConfig == option.TLSConfig ||
		second.TLSConfig.RootCAs == option.TLSConfig.RootCAs {
		t.Fatal("client option projection did not allocate fresh owned values")
	}
}

// assertExactTLSOption proves the complete private TLS projection.
func assertExactTLSOption(t *testing.T, option *tls.Config, config ClientConfig) {
	t.Helper()
	if option == nil ||
		option.ServerName != config.TLSServerName ||
		option.MinVersion != tls.VersionTLS13 ||
		option.MaxVersion != tls.VersionTLS13 ||
		option.InsecureSkipVerify ||
		option.RootCAs == nil ||
		len(option.Certificates) != 0 ||
		option.GetCertificate != nil ||
		option.GetClientCertificate != nil ||
		option.GetConfigForClient != nil ||
		option.VerifyPeerCertificate != nil ||
		option.VerifyConnection != nil ||
		option.Renegotiation != 0 ||
		!option.SessionTicketsDisabled ||
		len(option.NextProtos) != 0 {
		t.Fatal("TLS option projection is not exact")
	}
}

// assertExactStandaloneOption proves the complete least-privileged client projection.
func assertExactStandaloneOption(
	t *testing.T,
	option valkeygo.ClientOption,
	config ClientConfig,
) {
	t.Helper()
	if !reflect.DeepEqual(option.Dialer, net.Dialer{
		Timeout:   config.DialTimeout,
		KeepAlive: config.TCPKeepAlive,
	}) {
		t.Fatal("dialer projection is not exact")
	}
	if option.TLSConfig == nil ||
		option.Username != config.Username ||
		option.Password != syntheticConfigPassword ||
		option.ClientName != "" ||
		option.ClientSetInfo == nil ||
		len(option.ClientSetInfo) != 0 ||
		cap(option.ClientSetInfo) != 0 ||
		!reflect.DeepEqual(option.InitAddress, []string{config.Endpoint}) ||
		option.SelectDB != 0 ||
		option.ConnWriteTimeout != config.ConnWriteTimeout ||
		option.ConnLifetime != 0 ||
		option.ClusterOption.ShardsRefreshInterval != 0 ||
		!option.DisableRetry ||
		!option.DisableCache ||
		!option.ForceSingleClient {
		t.Fatal("standalone client option projection is not exact")
	}
}

// TestClientConfigValidationRejectsEveryUnsafeLocalChoice covers exact closed bounds.
func TestClientConfigValidationRejectsEveryUnsafeLocalChoice(t *testing.T) {
	valid := validClientConfig(t)
	longEndpoint := strings.Repeat("1", 48)
	longLabel := strings.Repeat("a", 64) + ".example"
	longServerName := strings.Repeat("a.", 126) + "aa"
	badLimits := valid.Limits
	badLimits.MaxInFlight = 65_537

	tests := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{name: "empty endpoint", mutate: func(c *ClientConfig) { c.Endpoint = "" }},
		{name: "oversized endpoint", mutate: func(c *ClientConfig) { c.Endpoint = longEndpoint }},
		{name: "dns endpoint", mutate: func(c *ClientConfig) { c.Endpoint = "valkey.example:6379" }},
		{name: "scheme endpoint", mutate: func(c *ClientConfig) { c.Endpoint = "tls://127.0.0.1:6379" }},
		{name: "unbracketed ipv6", mutate: func(c *ClientConfig) { c.Endpoint = "::1:6379" }},
		{name: "ipv6 zone", mutate: func(c *ClientConfig) { c.Endpoint = "[fe80::1%lo0]:6379" }},
		{name: "noncanonical ipv6", mutate: func(c *ClientConfig) { c.Endpoint = "[0:0:0:0:0:0:0:1]:6379" }},
		{name: "zero port", mutate: func(c *ClientConfig) { c.Endpoint = "127.0.0.1:0" }},
		{name: "leading-zero port", mutate: func(c *ClientConfig) { c.Endpoint = "127.0.0.1:06379" }},
		{name: "whitespace", mutate: func(c *ClientConfig) { c.Endpoint = " 127.0.0.1:6379" }},
		{name: "zero topology", mutate: func(c *ClientConfig) { c.Topology = 0 }},
		{name: "cluster topology", mutate: func(c *ClientConfig) { c.Topology = TopologyCluster }},
		{name: "unknown topology", mutate: func(c *ClientConfig) { c.Topology = 255 }},
		{name: "nonzero database", mutate: func(c *ClientConfig) { c.Database = 1 }},
		{name: "client name", mutate: func(c *ClientConfig) { c.ClientName = "dkim2" }},
		{name: "cache enabled", mutate: func(c *ClientConfig) { c.DisableCache = false }},
		{name: "retry enabled", mutate: func(c *ClientConfig) { c.DisableRetry = false }},
		{name: "empty server name", mutate: func(c *ClientConfig) { c.TLSServerName = "" }},
		{name: "uppercase server name", mutate: func(c *ClientConfig) { c.TLSServerName = "Valkey.example" }},
		{name: "root dot", mutate: func(c *ClientConfig) { c.TLSServerName = "valkey.example." }},
		{name: "leading hyphen", mutate: func(c *ClientConfig) { c.TLSServerName = "-valkey.example" }},
		{name: "trailing hyphen", mutate: func(c *ClientConfig) { c.TLSServerName = "valkey-.example" }},
		{name: "long label", mutate: func(c *ClientConfig) { c.TLSServerName = longLabel }},
		{name: "long server name", mutate: func(c *ClientConfig) { c.TLSServerName = longServerName }},
		{name: "no roots", mutate: func(c *ClientConfig) { c.RootCertificatesDER = nil }},
		{name: "empty root", mutate: func(c *ClientConfig) { c.RootCertificatesDER = [][]byte{{}} }},
		{name: "too many roots", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = repeatRoot(c.RootCertificatesDER[0], 129)
		}},
		{name: "oversized root", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = [][]byte{make([]byte, 64*1024+1)}
		}},
		{name: "aggregate roots", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = repeatRootWithUniqueSuffix(make([]byte, 2049), 128)
		}},
		{name: "malformed root", mutate: func(c *ClientConfig) { c.RootCertificatesDER = [][]byte{{1, 2, 3}} }},
		{name: "duplicate roots", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = [][]byte{
				append([]byte(nil), c.RootCertificatesDER[0]...),
				append([]byte(nil), c.RootCertificatesDER[0]...),
			}
		}},
		{name: "trailing root data", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER[0] = append(c.RootCertificatesDER[0], 0)
		}},
		{name: "non-ca root", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = [][]byte{testCertificateDER(t, false, 0)}
		}},
		{name: "ca without cert-sign usage", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = [][]byte{testCertificateDER(t, true, x509.KeyUsageDigitalSignature)}
		}},
		{name: "empty username", mutate: func(c *ClientConfig) { c.Username = "" }},
		{name: "oversized username", mutate: func(c *ClientConfig) { c.Username = strings.Repeat("a", 129) }},
		{name: "invalid username", mutate: func(c *ClientConfig) { c.Username = "user:name" }},
		{name: "empty password", mutate: func(c *ClientConfig) { c.Password = nil }},
		{name: "oversized password", mutate: func(c *ClientConfig) { c.Password = make([]byte, 1025) }},
		{name: "short dial", mutate: func(c *ClientConfig) { c.DialTimeout = 100*time.Millisecond - 1 }},
		{name: "long dial", mutate: func(c *ClientConfig) { c.DialTimeout = 30*time.Second + 1 }},
		{name: "short keepalive", mutate: func(c *ClientConfig) { c.TCPKeepAlive = time.Second - 1 }},
		{name: "long keepalive", mutate: func(c *ClientConfig) { c.TCPKeepAlive = 5*time.Minute + 1 }},
		{name: "short write", mutate: func(c *ClientConfig) { c.ConnWriteTimeout = 100*time.Millisecond - 1 }},
		{name: "long write", mutate: func(c *ClientConfig) { c.ConnWriteTimeout = 30*time.Second + 1 }},
		{name: "wrong draft", mutate: func(c *ClientConfig) { c.Draft = "future-draft" }},
		{name: "wrong algorithm", mutate: func(c *ClientConfig) { c.Algorithm = "future-algorithm" }},
		{name: "wrong namespace", mutate: func(c *ClientConfig) { c.Namespace = "other:" }},
		{name: "zero epoch", mutate: func(c *ClientConfig) { c.Epoch = 0 }},
		{name: "wrong minimum retention", mutate: func(c *ClientConfig) { c.MinimumRetention = time.Second + time.Millisecond }},
		{name: "wrong maximum retention", mutate: func(c *ClientConfig) { c.MaximumRetention = 30*24*time.Hour - time.Millisecond }},
		{name: "invalid limits", mutate: func(c *ClientConfig) { c.Limits = badLimits }},
		{name: "invalid entry limit", mutate: func(c *ClientConfig) { c.Limits.MaxEntries = -1 }},
		{name: "invalid memory waiter limit", mutate: func(c *ClientConfig) { c.Limits.MaxWaiters = 65_537 }},
		{name: "invalid prune budget", mutate: func(c *ClientConfig) { c.Limits.PruneBudget = 65_537 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneClientConfig(valid)
			test.mutate(&candidate)
			if _, err := validateClientConfig(candidate); dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
				t.Fatal("unsafe client configuration was not rejected as misconfigured")
			}
		})
	}
}

// TestClientConfigAcceptsExactEndpointNameAndTimingBoundaries freezes inclusive limits.
func TestClientConfigAcceptsExactEndpointNameAndTimingBoundaries(t *testing.T) {
	valid := validClientConfig(t)
	tests := []struct {
		name   string
		mutate func(*ClientConfig)
	}{
		{name: "ipv4", mutate: func(c *ClientConfig) { c.Endpoint = "192.0.2.1:1" }},
		{name: "ipv6", mutate: func(c *ClientConfig) { c.Endpoint = "[2001:db8::1]:65535" }},
		{name: "maximum endpoint bytes", mutate: func(c *ClientConfig) {
			c.Endpoint = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"
		}},
		{name: "ip server name", mutate: func(c *ClientConfig) { c.TLSServerName = "192.0.2.1" }},
		{name: "ipv6 server name", mutate: func(c *ClientConfig) { c.TLSServerName = "2001:db8::1" }},
		{name: "one-byte dns labels", mutate: func(c *ClientConfig) { c.TLSServerName = "a.b" }},
		{name: "maximum dns name bytes", mutate: func(c *ClientConfig) {
			c.TLSServerName = strings.Repeat("a", 63) + "." +
				strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." +
				strings.Repeat("d", 61)
		}},
		{name: "minimum username and password", mutate: func(c *ClientConfig) {
			c.Username = "a"
			c.Password = []byte{0}
		}},
		{name: "maximum username and password", mutate: func(c *ClientConfig) {
			c.Username = strings.Repeat("a", 128)
			c.Password = bytes.Repeat([]byte{'x'}, 1024)
		}},
		{name: "ca with zero key usage", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = [][]byte{testCertificateDER(t, true, 0)}
		}},
		{name: "maximum root count", mutate: func(c *ClientConfig) {
			c.RootCertificatesDER = testCertificateRoots(t, 128)
		}},
		{name: "minimum timings", mutate: func(c *ClientConfig) {
			c.DialTimeout = 100 * time.Millisecond
			c.TCPKeepAlive = time.Second
			c.ConnWriteTimeout = 100 * time.Millisecond
		}},
		{name: "maximum timings", mutate: func(c *ClientConfig) {
			c.DialTimeout = 30 * time.Second
			c.TCPKeepAlive = 5 * time.Minute
			c.ConnWriteTimeout = 30 * time.Second
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneClientConfig(valid)
			test.mutate(&candidate)
			if _, err := validateClientConfig(candidate); err != nil {
				t.Fatal("exact valid boundary was rejected")
			}
		})
	}
}

// TestClientConfigAdmissionLimitsApplyExactDefaultsAndHardBounds freezes 0/1/65536/65537.
func TestClientConfigAdmissionLimitsApplyExactDefaultsAndHardBounds(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		inFlight   int
		waiters    int
		wantFlight int
		wantWaiter int
		valid      bool
	}{
		{name: "defaults", wantFlight: 1024, wantWaiter: 1024, valid: true},
		{name: "minimum", inFlight: 1, waiters: 1, wantFlight: 1, wantWaiter: 1, valid: true},
		{name: "maximum", inFlight: 65_536, waiters: 65_536, wantFlight: 65_536, wantWaiter: 65_536, valid: true},
		{name: "inflight cap plus one", inFlight: 65_537, waiters: 1},
		{name: "waiter cap plus one", inFlight: 1, waiters: 65_537},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			config := validClientConfig(t)
			config.Limits.MaxInFlight = testCase.inFlight
			config.Limits.MaxAdmissionWaiters = testCase.waiters
			validated, err := validateClientConfig(config)
			if !testCase.valid {
				if dkim2.ReplayErrorCodeOf(err) != dkim2.ReplayErrorMisconfigured {
					t.Fatal("widened admission limits were accepted")
				}
				return
			}
			if err != nil ||
				validated.limits.MaxInFlight != testCase.wantFlight ||
				validated.limits.MaxAdmissionWaiters != testCase.wantWaiter {
				t.Fatal("admission limits were not normalized exactly")
			}
		})
	}
}

// TestClientConfigValidationClonesProtectedInputs proves post-call mutation isolation.
func TestClientConfigValidationClonesProtectedInputs(t *testing.T) {
	config := validClientConfig(t)
	rootBefore := append([]byte(nil), config.RootCertificatesDER[0]...)
	validated, err := validateClientConfig(config)
	if err != nil {
		t.Fatal("valid client configuration was rejected")
	}

	for index := range config.Password {
		config.Password[index] = 'x'
	}
	for index := range config.RootCertificatesDER[0] {
		config.RootCertificatesDER[0][index] ^= 0xff
	}
	config.RootCertificatesDER = nil

	option := validated.option()
	if option.Password != syntheticConfigPassword ||
		option.TLSConfig == nil ||
		option.TLSConfig.RootCAs == nil {
		t.Fatal("caller mutation changed validated client configuration")
	}
	certificate, err := x509.ParseCertificate(rootBefore)
	if err != nil || !option.TLSConfig.RootCAs.Equal(singleCertificatePool(certificate)) {
		t.Fatal("caller mutation changed owned root trust")
	}
}

// TestClientOptionCannotFallBackToSystemRootsAfterInternalDERCorruption guards explicit trust.
func TestClientOptionCannotFallBackToSystemRootsAfterInternalDERCorruption(t *testing.T) {
	validated, err := validateClientConfig(validClientConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	clear(validated.rootCertificatesDER[0])
	option := validated.option()
	if option.TLSConfig == nil || option.TLSConfig.RootCAs == nil {
		t.Fatal("validated option fell back to system trust")
	}
	validated.rootCertificates = nil
	defer func() {
		if recover() == nil {
			t.Fatal("forged validated config published nil system-root fallback")
		}
	}()
	_ = validated.option()
}

// TestClientAndAuditorConfigPrivacyRejectsFormattingAndSerialization protects credentials and authority.
func TestClientAndAuditorConfigPrivacyRejectsFormattingAndSerialization(t *testing.T) {
	client := validClientConfig(t)
	auditor := AuditorConfig{
		Username: "synthetic-auditor",
		Password: []byte(syntheticAuditorPassword),
	}
	for name, value := range map[string]any{"client": client, "auditor": auditor} {
		t.Run(name, func(t *testing.T) {
			for _, format := range []string{"%v", testFormatDetailed, testFormatGoSyntax, "%s", "%q"} {
				formatted := fmt.Sprintf(format, value)
				if strings.Contains(formatted, syntheticConfigPassword) ||
					strings.Contains(formatted, syntheticAuditorPassword) ||
					strings.Contains(formatted, client.Endpoint) ||
					strings.Contains(formatted, client.TLSServerName) ||
					strings.Contains(formatted, auditor.Username) ||
					strings.Contains(formatted, client.Username) {
					t.Fatal("protected configuration escaped formatting")
				}
			}
			if encoded, err := json.Marshal(value); err == nil || len(encoded) != 0 {
				t.Fatal("protected configuration unexpectedly marshaled as JSON")
			}
			textMarshaler, ok := value.(interface{ MarshalText() ([]byte, error) })
			if !ok {
				t.Fatal("protected configuration does not own text-marshaling rejection")
			}
			if encoded, err := textMarshaler.MarshalText(); err == nil || len(encoded) != 0 {
				t.Fatal("protected configuration unexpectedly marshaled as text")
			}
		})
	}
}

// TestAuditorConfigIsCredentialsOnlyAndBounded freezes its narrow redacted contract.
func TestAuditorConfigIsCredentialsOnlyAndBounded(t *testing.T) {
	auditorType := reflect.TypeOf(AuditorConfig{})
	if auditorType.NumField() != 2 ||
		auditorType.Field(0).Name != "Username" ||
		auditorType.Field(1).Name != "Password" {
		t.Fatal("auditor configuration widened beyond credentials")
	}
	valid := AuditorConfig{
		Username: "audit_user-1",
		Password: []byte(syntheticAuditorPassword),
	}
	validated, err := validateAuditorConfig(valid)
	if err != nil {
		t.Fatal("valid auditor credentials were rejected")
	}
	for index := range valid.Password {
		valid.Password[index] = 'x'
	}
	if validated.username != "audit_user-1" ||
		!bytes.Equal(validated.password, []byte(syntheticAuditorPassword)) {
		t.Fatal("validated auditor credentials retained caller mutation")
	}

	tests := []AuditorConfig{
		{},
		{Username: "audit", Password: nil},
		{Username: strings.Repeat("a", 129), Password: []byte("x")},
		{Username: "bad:user", Password: []byte("x")},
		{Username: "audit", Password: make([]byte, 1025)},
	}
	for _, candidate := range tests {
		if _, validationErr := validateAuditorConfig(candidate); dkim2.ReplayErrorCodeOf(validationErr) != dkim2.ReplayErrorMisconfigured {
			t.Fatal("invalid auditor credentials were not rejected")
		}
	}
}

// validClientConfig constructs one complete synthetic production-safe local value.
func validClientConfig(t *testing.T) ClientConfig {
	t.Helper()
	return ClientConfig{
		Endpoint:            "127.0.0.1:6379",
		Topology:            TopologyStandalonePrimary,
		Database:            0,
		ClientName:          "",
		DisableCache:        true,
		DisableRetry:        true,
		TLSServerName:       "valkey.example",
		RootCertificatesDER: [][]byte{testCertificateDER(t, true, x509.KeyUsageCertSign)},
		Username:            "dkim2_replay",
		Password:            []byte(syntheticConfigPassword),
		DialTimeout:         2 * time.Second,
		TCPKeepAlive:        30 * time.Second,
		ConnWriteTimeout:    2 * time.Second,
		Draft:               dkim2.DraftIdentifier,
		Algorithm:           dkim2.ReplayKeyAlgorithm,
		Namespace:           "dkim2:replay:v1:",
		Epoch:               1,
		MinimumRetention:    time.Second,
		MaximumRetention:    30 * 24 * time.Hour,
		Limits: dkim2.ReplayLimits{
			MaxEntries:          65_536,
			MaxWaiters:          1_024,
			PruneBudget:         4_096,
			MaxInFlight:         1_024,
			MaxAdmissionWaiters: 1_024,
		},
	}
}

// cloneClientConfig copies every caller-owned mutable field for table isolation.
func cloneClientConfig(config ClientConfig) ClientConfig {
	cloned := config
	cloned.Password = append([]byte(nil), config.Password...)
	cloned.RootCertificatesDER = make([][]byte, len(config.RootCertificatesDER))
	for index := range config.RootCertificatesDER {
		cloned.RootCertificatesDER[index] = append([]byte(nil), config.RootCertificatesDER[index]...)
	}
	return cloned
}

// testCertificateDER creates one bounded synthetic certificate fixture.
func testCertificateDER(t *testing.T, isCA bool, usage x509.KeyUsage) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate synthetic certificate key")
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "synthetic-root"},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(4_102_444_800, 0),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal("create synthetic certificate")
	}
	return der
}

// testCertificateRoots creates the requested number of distinct valid CA roots.
func testCertificateRoots(t *testing.T, count int) [][]byte {
	t.Helper()
	roots := make([][]byte, count)
	for index := range roots {
		roots[index] = testCertificateDER(t, true, x509.KeyUsageCertSign)
	}
	return roots
}

// repeatRoot returns repeated clones of one DER value.
func repeatRoot(root []byte, count int) [][]byte {
	roots := make([][]byte, count)
	for index := range roots {
		roots[index] = append([]byte(nil), root...)
	}
	return roots
}

// repeatRootWithUniqueSuffix builds invalid unique aggregate-cap fixtures.
func repeatRootWithUniqueSuffix(root []byte, count int) [][]byte {
	roots := make([][]byte, count)
	for index := range roots {
		roots[index] = append(append([]byte(nil), root...), byte(index))
	}
	return roots
}

// singleCertificatePool constructs one private pool for equality testing.
func singleCertificatePool(certificate *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	return pool
}

// assertOnlyFrozenClientOptionFields rejects every dependency option outside the allowlist.
func assertOnlyFrozenClientOptionFields(t *testing.T, option any) {
	t.Helper()
	value := reflect.ValueOf(option)
	typ := value.Type()
	allowed := map[string]bool{
		"TLSConfig": true, "Dialer": true, "Username": true, "Password": true,
		"ClientSetInfo": true, "InitAddress": true, "ConnWriteTimeout": true,
		"DisableRetry": true, "DisableCache": true, "ForceSingleClient": true,
	}
	for index := 0; index < value.NumField(); index++ {
		if allowed[typ.Field(index).Name] {
			continue
		}
		if !value.Field(index).IsZero() {
			t.Fatalf("unexpected nonzero client option field %q", typ.Field(index).Name)
		}
	}
}
