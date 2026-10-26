package command

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/domainadmin"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"github.com/croessner/dkim2/provider"
	"github.com/spf13/cobra"
)

const (
	keyCommandName         = "key"
	keyGenerateCommandName = "generate"
	keyGenerateSchema      = "dkim2-key-generate-v1"
	defaultKeyRSABits      = 3072
	defaultKeyDNSTTL       = 3600
)

// keyGenerateOptions holds the closed flag set of one key generation.
type keyGenerateOptions struct {
	algorithm  string
	domain     string
	selector   string
	privateKey string
	rsaBits    int
	ttl        uint64
	machine    bool
}

// keyGenerateDocument is the public machine output of one key generation.
type keyGenerateDocument struct {
	Schema           string `json:"schema"`
	Algorithm        string `json:"algorithm"`
	Domain           string `json:"domain"`
	Selector         string `json:"selector"`
	PublicKeySPKI    string `json:"public_key_spki"`
	PublicSPKISHA256 string `json:"public_spki_sha256"`
	DNSZone          string `json:"dns_zone"`
}

// newKeyCommand constructs the offline flat-file custody key group.
func newKeyCommand(stdout io.Writer) (*cobra.Command, error) {
	group := &cobra.Command{
		Use: keyCommandName, Short: "Manage flat-file custody signing keys offline",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error { return errCommandShape },
	}
	options := keyGenerateOptions{rsaBits: defaultKeyRSABits, ttl: defaultKeyDNSTTL}
	generate := &cobra.Command{
		Use: keyGenerateCommandName, Short: "Generate one custody key file and print its public credential and DNS record",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			return runKeyGenerate(command.Context(), stdout, options)
		},
	}
	flags := generate.Flags()
	flags.StringVar(&options.algorithm, "algorithm", "", "rsa-sha256 or ed25519-sha256")
	flags.StringVar(&options.domain, "domain", "", "signing domain of the DNS key record")
	flags.StringVar(&options.selector, "selector", "", "selector of the DNS key record")
	flags.StringVar(&options.privateKey, "private-key", "", "absolute path of the new owner-only PKCS#8 PEM file")
	flags.IntVar(&options.rsaBits, "rsa-bits", defaultKeyRSABits, "RSA modulus size: 2048, 3072, or 4096")
	flags.Uint64Var(&options.ttl, "ttl", defaultKeyDNSTTL, "TTL of the printed DNS record in seconds")
	flags.BoolVar(&options.machine, "machine", false, "emit one JSON document")
	for _, name := range []string{"algorithm", "domain", "selector", "private-key"} {
		if generate.MarkFlagRequired(name) != nil {
			return nil, errCommandRuntime
		}
	}
	group.AddCommand(generate)
	return group, nil
}

// runKeyGenerate validates the request before any key exists, writes the
// private key only to the new file, and prints only public material. A key
// whose DNS record cannot be rendered is removed again.
func runKeyGenerate(ctx context.Context, stdout io.Writer, options keyGenerateOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	algorithm, err := provider.ParseAlgorithm(options.algorithm)
	if err != nil || stdout == nil || options.ttl == 0 || options.ttl > 604800 ||
		!filepath.IsAbs(options.privateKey) || filepath.Clean(options.privateKey) != options.privateKey ||
		provider.ValidateDomainSelector(options.domain, options.selector, algorithm) != nil ||
		(algorithm == provider.AlgorithmRSASHA256 && options.rsaBits != 2048 && options.rsaBits != 3072 && options.rsaBits != 4096) {
		return errCommandShape
	}
	generated, err := signingstore.WriteGeneratedKeyFile(options.privateKey, algorithm, options.rsaBits)
	if err != nil {
		return errCommandRuntime
	}
	zone, err := domainadmin.FormatCanonicalDNSRecord(ctx, options.domain, options.selector, algorithm, generated.PublicSPKI, options.ttl)
	if err != nil {
		_ = os.Remove(options.privateKey)
		return errCommandRuntime
	}
	document := keyGenerateDocument{
		Schema: keyGenerateSchema, Algorithm: string(algorithm),
		Domain: options.domain, Selector: options.selector,
		PublicKeySPKI:    base64.StdEncoding.EncodeToString(generated.PublicSPKI),
		PublicSPKISHA256: base64.StdEncoding.EncodeToString(generated.PublicSPKISHA256[:]),
		DNSZone:          string(zone),
	}
	var output []byte
	if options.machine {
		output, err = json.Marshal(document)
		output = append(output, '\n')
	} else {
		var builder strings.Builder
		builder.WriteString("algorithm=" + document.Algorithm + " domain=" + document.Domain + " selector=" + document.Selector + "\n")
		builder.WriteString("public_key_spki=" + document.PublicKeySPKI + "\n")
		builder.WriteString("public_spki_sha256=" + document.PublicSPKISHA256 + "\n")
		builder.WriteString(document.DNSZone)
		output = []byte(builder.String())
	}
	if err != nil {
		return errCommandRuntime
	}
	if _, err := stdout.Write(output); err != nil {
		return errCommandRuntime
	}
	return nil
}
