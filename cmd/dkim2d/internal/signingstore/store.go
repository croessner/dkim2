package signingstore

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/croessner/dkim2"
	signingflatfile "github.com/croessner/dkim2/provider/flatfile"
)

const (
	manifestVersion         = "dkim2-private-keys-v1"
	manifestOriginator      = "originator"
	manifestOrdinaryTransit = "ordinary_transit"
	manifestRSASHA256       = "rsa-sha256"
	manifestEd25519SHA256   = "ed25519-sha256"
	privateKeyPEMType       = "PRIVATE KEY"
	maxManifestBytes        = 256 << 10
	maxPrivateBytes         = 64 << 10
	maxDatasourceBytes      = 1 << 20
	storeRedacted           = "dkim2d_signing_store{redacted}"
)

// Error is the sole content-free signing-store failure.
type Error struct{}

// Error returns a constant diagnostic with no protected facts.
func (*Error) Error() string { return "dkim2d signing store failure" }

// Is recognizes the closed signing-store error class.
func (*Error) Is(target error) bool {
	_, ok := target.(*Error)
	return ok
}

type manifestDocument struct {
	Version string          `json:"version"`
	Entries []manifestEntry `json:"entries"`
}

type manifestEntry struct {
	TenantID         string `json:"tenant_id"`
	Domain           string `json:"domain"`
	Use              string `json:"use"`
	HandleID         string `json:"handle_id"`
	Algorithm        string `json:"algorithm"`
	PublicSPKISHA256 string `json:"public_spki_sha256"`
	PrivateKeyFile   string `json:"private_key_file"`
}

type privateCredential struct {
	publicHandle dkim2.PrivateKeyHandle
	use          PolicyUse
	algorithm    dkim2.Algorithm
	key          crypto.PrivateKey
	publicDigest [sha256.Size]byte
}

// Generation is one immutable same-root datasource and private-key snapshot.
type Generation struct {
	provider *signingflatfile.Resolver
	keys     map[dkim2.PrivateKeyHandle]privateCredential
	mu       sync.RWMutex
	closed   bool
}

// Open validates and publishes one immutable compound signing generation.
func Open(
	rootFD int,
	datasourceFile string,
	manifestFile string,
) (*Generation, error) {
	if rootFD < 0 || !validChildName(datasourceFile) ||
		!validChildName(manifestFile) || datasourceFile == manifestFile {
		return nil, &Error{}
	}
	rootBefore, err := protectedRootState(rootFD)
	if err != nil {
		return nil, &Error{}
	}
	children := make([]*retainedChild, 0, 3)
	defer func() {
		for _, child := range children {
			_ = closeRetainedChild(child)
		}
	}()
	manifestChild, err := openRetainedChild(
		rootFD, manifestFile, maxManifestBytes, rootBefore,
	)
	if err != nil {
		return nil, &Error{}
	}
	children = append(children, manifestChild)
	entries, err := decodeManifest(manifestChild.data)
	clear(manifestChild.data)
	if err != nil {
		return nil, &Error{}
	}
	credentials, bindings, err := loadCredentials(
		rootFD, rootBefore, &children, entries,
	)
	if err != nil {
		return nil, &Error{}
	}
	datasourceChild, err := openRetainedChild(
		rootFD, datasourceFile, maxDatasourceBytes, rootBefore,
	)
	if err != nil {
		clearCredentials(credentials)
		return nil, &Error{}
	}
	children = append(children, datasourceChild)
	provider, err := signingflatfile.Open(
		datasourceChild.data, bindings, time.Now().UTC(),
	)
	clear(datasourceChild.data)
	if err != nil {
		clearCredentials(credentials)
		return nil, &Error{}
	}
	if err := validateCompoundGeneration(rootFD, rootBefore, children); err != nil {
		_ = provider.Close(context.Background())
		clearCredentials(credentials)
		return nil, &Error{}
	}
	if closeRetainedChildren(children) != nil {
		children = nil
		_ = provider.Close(context.Background())
		clearCredentials(credentials)
		return nil, &Error{}
	}
	children = nil
	generation := &Generation{
		provider: provider,
		keys:     credentials,
	}
	return generation, nil
}

// closeRetainedChildren releases every protected descriptor before candidate
// publication and reports any indeterminate release.
func closeRetainedChildren(children []*retainedChild) error {
	var failed bool
	for _, child := range children {
		if closeRetainedChild(child) != nil {
			failed = true
		}
	}
	if failed {
		return &Error{}
	}
	return nil
}

// ResolvePolicy projects one exact tenant, domain, and use through the sole
// signing-profile registry bridge.
func (g *Generation) ResolvePolicy(
	ctx context.Context,
	tenant string,
	domain string,
	use PolicyUse,
	at time.Time,
) (dkim2.SigningProfile, error) {
	if g == nil || ctx == nil || !use.Known() || at.IsZero() {
		return dkim2.SigningProfile{}, &Error{}
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed || g.provider == nil {
		return dkim2.SigningProfile{}, &Error{}
	}
	profile, err := g.provider.ResolvePolicy(ctx, tenant, domain, use, at)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return dkim2.SigningProfile{}, contextError
		}
		if dkim2.ProviderErrorClassOf(err).Known() {
			return dkim2.SigningProfile{}, err
		}
		return dkim2.SigningProfile{}, &Error{}
	}
	return profile, nil
}

// SignDigest signs one canonical digest through an exact opaque handle.
func (g *Generation) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	if g == nil || ctx == nil || !handle.Valid() || !request.Valid() {
		return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
	}
	if err := ctx.Err(); err != nil {
		return dkim2.PrivateKeySignResult{}, err
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.closed {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	credential, found := g.keys[handle]
	if !found || !credential.publicHandle.Valid() {
		return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
	}
	return signPrivateCredential(ctx, credential, request)
}

// signPrivateCredential signs one bounded digest through an already-selected key.
func signPrivateCredential(
	ctx context.Context,
	credential privateCredential,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	if ctx == nil || !credential.publicHandle.Valid() || !request.Valid() {
		return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
	}
	if err := ctx.Err(); err != nil {
		return dkim2.PrivateKeySignResult{}, err
	}
	digest := request.Digest()
	var signature []byte
	var err error
	switch {
	case request.Algorithm() == dkim2.AlgorithmRSASHA256 &&
		credential.algorithm == dkim2.AlgorithmRSASHA256:
		key, ok := credential.key.(*rsa.PrivateKey)
		if !ok {
			return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
		}
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	case request.Algorithm() == dkim2.AlgorithmEd25519SHA256 &&
		credential.algorithm == dkim2.AlgorithmEd25519SHA256:
		key, ok := credential.key.(ed25519.PrivateKey)
		if !ok {
			return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
		}
		signature = ed25519.Sign(key, digest[:])
	default:
		return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
	}
	if err != nil || len(signature) == 0 {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	return dkim2.NewPrivateKeySignResult(signature), nil
}

// Close makes future operations fail closed and releases the datasource root.
func (g *Generation) Close(ctx context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	if ctx == nil || ctx.Err() != nil {
		return &Error{}
	}
	g.closed = true
	err := g.provider.Close(ctx)
	g.provider = nil
	for handle, credential := range g.keys {
		clearPrivateKey(credential.key)
		delete(g.keys, handle)
	}
	if err != nil {
		return &Error{}
	}
	return nil
}

// String returns a constant protected store summary.
func (*Generation) String() string { return storeRedacted }

// GoString returns a constant protected store representation.
func (*Generation) GoString() string { return storeRedacted }

// Format prevents formatting verbs from traversing provider or key state.
func (*Generation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, storeRedacted)
}

// MarshalJSON emits an empty object without provider or private-key facts.
func (*Generation) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// decodeManifest validates the exact closed manifest schema.
func decodeManifest(document []byte) ([]manifestEntry, error) {
	if len(document) == 0 || len(document) > maxManifestBytes ||
		!json.Valid(document) || duplicateJSONMember(document) {
		return nil, &Error{}
	}
	var decoded manifestDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return nil, &Error{}
	}
	if decoder.Decode(&struct{}{}) != io.EOF ||
		decoded.Version != manifestVersion || len(decoded.Entries) == 0 ||
		len(decoded.Entries) > 1024 {
		return nil, &Error{}
	}
	return append([]manifestEntry(nil), decoded.Entries...), nil
}

// duplicateJSONMember reports duplicate object names or malformed token shape.
func duplicateJSONMember(document []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	var visit func(json.Token) bool
	visit = func(token json.Token) bool {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return false
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				nameToken, err := decoder.Token()
				name, nameOK := nameToken.(string)
				if err != nil || !nameOK {
					return true
				}
				if _, exists := seen[name]; exists {
					return true
				}
				seen[name] = struct{}{}
				value, err := decoder.Token()
				if err != nil || visit(value) {
					return true
				}
			}
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || visit(value) {
					return true
				}
			}
		default:
			return true
		}
		end, err := decoder.Token()
		if err != nil {
			return true
		}
		closing, ok := end.(json.Delim)
		return !ok ||
			delimiter == '{' && closing != '}' ||
			delimiter == '[' && closing != ']'
	}
	first, err := decoder.Token()
	if err != nil || visit(first) {
		return true
	}
	_, err = decoder.Token()
	return !errors.Is(err, io.EOF)
}

// loadCredentials validates every manifest binding before constructing a registry.
func loadCredentials(
	rootFD int,
	rootState fileState,
	children *[]*retainedChild,
	entries []manifestEntry,
) (
	map[dkim2.PrivateKeyHandle]privateCredential,
	[]signingflatfile.Binding,
	error,
) {
	keys := make(map[dkim2.PrivateKeyHandle]privateCredential, len(entries))
	success := false
	defer func() {
		if !success {
			clearCredentials(keys)
		}
	}()
	bindings := make([]signingflatfile.Binding, 0, len(entries))
	handles := make(map[string]struct{}, len(entries))
	paths := make(map[string]struct{}, len(entries))
	identities := make(map[[sha256.Size]byte]struct{}, len(entries))
	for _, entry := range entries {
		use, algorithm, identity, err := validateManifestEntry(entry)
		if err != nil {
			return nil, nil, &Error{}
		}
		if _, duplicate := handles[entry.HandleID]; duplicate {
			return nil, nil, &Error{}
		}
		if _, duplicate := paths[entry.PrivateKeyFile]; duplicate {
			return nil, nil, &Error{}
		}
		if _, duplicate := identities[identity]; duplicate {
			return nil, nil, &Error{}
		}
		child, err := openRetainedChild(
			rootFD, entry.PrivateKeyFile, maxPrivateBytes, rootState,
		)
		if err != nil {
			return nil, nil, &Error{}
		}
		*children = append(*children, child)
		key, derived, err := parsePrivateKey(child.data, algorithm)
		clear(child.data)
		if err != nil || derived != identity {
			clearPrivateKey(key)
			return nil, nil, &Error{}
		}
		publicHandle, err := dkim2.NewPrivateKeyHandle([]byte(entry.HandleID))
		if err != nil {
			clearPrivateKey(key)
			return nil, nil, &Error{}
		}
		binding, err := signingflatfile.NewBinding(
			entry.TenantID, entry.Domain, use, entry.HandleID,
			publicHandle, algorithm, identity,
		)
		if err != nil {
			clearPrivateKey(key)
			return nil, nil, &Error{}
		}
		keys[publicHandle] = privateCredential{
			publicHandle: publicHandle, use: use, algorithm: algorithm,
			key: key, publicDigest: identity,
		}
		bindings = append(bindings, binding)
		handles[entry.HandleID] = struct{}{}
		paths[entry.PrivateKeyFile] = struct{}{}
		identities[identity] = struct{}{}
	}
	success = true
	return keys, bindings, nil
}

// validateManifestEntry parses one exact provider-neutral binding.
func validateManifestEntry(
	entry manifestEntry,
) (PolicyUse, dkim2.Algorithm, [sha256.Size]byte, error) {
	if entry.HandleID == "" || !validChildName(entry.PrivateKeyFile) ||
		entry.TenantID == "" || entry.Domain == "" {
		return "", dkim2.AlgorithmUnknown, [sha256.Size]byte{}, &Error{}
	}
	var use PolicyUse
	switch entry.Use {
	case manifestOriginator:
		use = PolicyOriginator
	case manifestOrdinaryTransit:
		use = PolicyOrdinaryTransit
	default:
		return "", dkim2.AlgorithmUnknown, [sha256.Size]byte{}, &Error{}
	}
	var algorithm dkim2.Algorithm
	switch entry.Algorithm {
	case manifestRSASHA256:
		algorithm = dkim2.AlgorithmRSASHA256
	case manifestEd25519SHA256:
		algorithm = dkim2.AlgorithmEd25519SHA256
	default:
		return "", dkim2.AlgorithmUnknown, [sha256.Size]byte{}, &Error{}
	}
	decoded, err := base64.StdEncoding.DecodeString(entry.PublicSPKISHA256)
	if err != nil || len(decoded) != sha256.Size ||
		base64.StdEncoding.EncodeToString(decoded) != entry.PublicSPKISHA256 {
		return "", dkim2.AlgorithmUnknown, [sha256.Size]byte{}, &Error{}
	}
	var identity [sha256.Size]byte
	copy(identity[:], decoded)
	clear(decoded)
	return use, algorithm, identity, nil
}

// parsePrivateKey accepts exactly one unencrypted PKCS#8 PRIVATE KEY block.
func parsePrivateKey(
	encoded []byte,
	algorithm dkim2.Algorithm,
) (crypto.PrivateKey, [sha256.Size]byte, error) {
	const privateKeyPEMBegin = "-----BEGIN PRIVATE KEY-----"
	if !bytes.HasPrefix(encoded, []byte(privateKeyPEMBegin)) {
		return nil, [sha256.Size]byte{}, &Error{}
	}
	block, rest := pemDecode(encoded)
	if block == nil || block.blockType != privateKeyPEMType ||
		len(block.headers) != 0 || len(rest) != 0 {
		return nil, [sha256.Size]byte{}, &Error{}
	}
	defer clear(block.der)
	key, err := x509.ParsePKCS8PrivateKey(block.der)
	if err != nil {
		return nil, [sha256.Size]byte{}, &Error{}
	}
	var public any
	switch typed := key.(type) {
	case *rsa.PrivateKey:
		if algorithm != dkim2.AlgorithmRSASHA256 ||
			typed.Validate() != nil || typed.N.BitLen() < 1024 ||
			len(typed.Primes) != 2 {
			clearPrivateKey(key)
			return nil, [sha256.Size]byte{}, &Error{}
		}
		public = &typed.PublicKey
	case ed25519.PrivateKey:
		if algorithm != dkim2.AlgorithmEd25519SHA256 ||
			len(typed) != ed25519.PrivateKeySize {
			clearPrivateKey(key)
			return nil, [sha256.Size]byte{}, &Error{}
		}
		public = typed.Public()
	default:
		clearPrivateKey(key)
		return nil, [sha256.Size]byte{}, &Error{}
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		clearPrivateKey(key)
		return nil, [sha256.Size]byte{}, &Error{}
	}
	digest := sha256.Sum256(spki)
	clear(spki)
	return key, digest, nil
}

type decodedPEM struct {
	blockType string
	headers   map[string]string
	der       []byte
}

// pemDecode isolates strict PEM parsing while retaining the sole decoded DER
// allocation for deterministic clearing by the caller.
func pemDecode(encoded []byte) (*decodedPEM, []byte) {
	block, rest := decodePEMBlock(encoded)
	if block == nil {
		return nil, nil
	}
	return &decodedPEM{
		blockType: block.Type,
		headers:   block.Headers,
		der:       block.Bytes,
	}, rest
}

// clearPrivateKey best-effort clears mutable private-key storage.
func clearPrivateKey(key crypto.PrivateKey) {
	switch typed := key.(type) {
	case ed25519.PrivateKey:
		clear(typed)
	case *rsa.PrivateKey:
		if typed == nil {
			return
		}
		if typed.D != nil {
			typed.D.SetInt64(0)
		}
		for _, prime := range typed.Primes {
			if prime != nil {
				prime.SetInt64(0)
			}
		}
		if typed.Precomputed.Dp != nil {
			typed.Precomputed.Dp.SetInt64(0)
		}
		if typed.Precomputed.Dq != nil {
			typed.Precomputed.Dq.SetInt64(0)
		}
		if typed.Precomputed.Qinv != nil {
			typed.Precomputed.Qinv.SetInt64(0)
		}
	}
}

// clearCredentials best-effort clears every private key in a failed candidate.
func clearCredentials(credentials map[dkim2.PrivateKeyHandle]privateCredential) {
	for handle, credential := range credentials {
		clearPrivateKey(credential.key)
		delete(credentials, handle)
	}
}
