package signingstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync"

	"github.com/croessner/dkim2"
	datasourceruntime "github.com/croessner/dkim2/cmd/dkim2d/internal/datasource/runtime"
	"github.com/croessner/dkim2/provider"
)

const registryManifestVersion = "dkim2-private-keys-v2"

type registryManifestDocument struct {
	Version    string          `json:"version"`
	Generation string          `json:"generation"`
	Entries    []manifestEntry `json:"entries"`
}

// Registry owns one immutable generation-specific protected signer registry.
type Registry struct {
	mu         sync.RWMutex
	generation uint64
	keys       map[dkim2.PrivateKeyHandle]privateCredential
	bindings   []provider.Binding
	closed     bool
}

// RegistrySource owns a protected generations directory and opens only the
// exact immutable generation requested by a datasource fence.
type RegistrySource struct {
	mu             sync.Mutex
	parentFD       int
	seedFD         int
	seedGeneration uint64
	manifestFile   string
	closed         bool
}

// NewRegistrySource retains the parent of one already-confined generation.
func NewRegistrySource(generationFD int, manifestFile string) (*RegistrySource, error) {
	if generationFD < 0 || !validChildName(manifestFile) {
		return nil, &Error{}
	}
	parentFD, err := openRegistrySourceParent(generationFD)
	if err != nil {
		return nil, &Error{}
	}
	seedFD, err := duplicateRootDescriptor(generationFD)
	if err != nil {
		_ = closeRootDescriptor(parentFD)
		return nil, &Error{}
	}
	registry, err := OpenRegistry(seedFD, manifestFile)
	if err != nil || registry == nil {
		_ = closeRootDescriptor(seedFD)
		_ = closeRootDescriptor(parentFD)
		return nil, &Error{}
	}
	seedGeneration, generationErr := registry.Generation(context.Background())
	closeErr := registry.Close(context.Background())
	if generationErr != nil || closeErr != nil || seedGeneration == 0 {
		_ = closeRootDescriptor(seedFD)
		_ = closeRootDescriptor(parentFD)
		return nil, &Error{}
	}
	return &RegistrySource{
		parentFD: parentFD, seedFD: seedFD, seedGeneration: seedGeneration,
		manifestFile: manifestFile,
	}, nil
}

// Load opens and validates one exact immutable generation registry.
func (s *RegistrySource) Load(
	ctx context.Context,
	generation uint64,
) (datasourceruntime.Registry, error) {
	if s == nil || ctx == nil || generation == 0 {
		return nil, &Error{}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.parentFD < 0 {
		return nil, &Error{}
	}
	var generationFD int
	closeGenerationFD := true
	var err error
	if generation == s.seedGeneration {
		generationFD = s.seedFD
		closeGenerationFD = false
	} else {
		generationFD, err = openRegistryGeneration(
			s.parentFD, strconv.FormatUint(generation, 10),
		)
		if err != nil {
			return nil, &Error{}
		}
	}
	registry, openErr := OpenRegistry(generationFD, s.manifestFile)
	var closeErr error
	if closeGenerationFD {
		closeErr = closeRootDescriptor(generationFD)
	}
	if openErr != nil || closeErr != nil || registry == nil {
		if registry != nil {
			_ = registry.Close(context.Background())
		}
		return nil, &Error{}
	}
	actual, err := registry.Generation(ctx)
	if err != nil || actual != generation {
		_ = registry.Close(context.Background())
		return nil, &Error{}
	}
	return registry, nil
}

// Close releases the retained generations-directory capability.
func (s *RegistrySource) Close(context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	parentFD := s.parentFD
	seedFD := s.seedFD
	s.parentFD = -1
	s.seedFD = -1
	var failed bool
	if seedFD >= 0 && closeRootDescriptor(seedFD) != nil {
		failed = true
	}
	if parentFD >= 0 && closeRootDescriptor(parentFD) != nil {
		failed = true
	}
	if failed {
		return &Error{}
	}
	return nil
}

// OpenRegistry validates one generation-specific manifest and all private keys.
func OpenRegistry(rootFD int, manifestFile string) (*Registry, error) {
	if rootFD < 0 || !validChildName(manifestFile) {
		return nil, &Error{}
	}
	rootBefore, err := protectedRootState(rootFD)
	if err != nil {
		return nil, &Error{}
	}
	children := make([]*retainedChild, 0, 2)
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
	generation, entries, err := decodeRegistryManifest(manifestChild.data)
	clear(manifestChild.data)
	if err != nil {
		return nil, &Error{}
	}
	keys, _, err := loadCredentials(rootFD, rootBefore, &children, entries)
	if err != nil {
		return nil, &Error{}
	}
	success := false
	defer func() {
		if !success {
			clearCredentials(keys)
		}
	}()
	bindings := make([]provider.Binding, 0, len(entries))
	for _, entry := range entries {
		_, _, digest, validateErr := validateManifestEntry(entry)
		credential := keysByID(keys, entry.HandleID)
		if validateErr != nil || credential == nil {
			return nil, &Error{}
		}
		use, useErr := provider.ParseProfileUse(entry.Use)
		algorithm := provider.AlgorithmRSASHA256
		if entry.Algorithm == manifestEd25519SHA256 {
			algorithm = provider.AlgorithmEd25519SHA256
		}
		if useErr != nil {
			return nil, &Error{}
		}
		binding, bindingErr := provider.NewBinding(
			entry.TenantID,
			entry.Domain,
			use,
			entry.HandleID,
			credential.publicHandle,
			algorithm,
			digest,
		)
		if bindingErr != nil {
			return nil, &Error{}
		}
		bindings = append(bindings, binding)
	}
	if err := validateCompoundGeneration(rootFD, rootBefore, children); err != nil {
		return nil, &Error{}
	}
	if closeRetainedChildren(children) != nil {
		children = nil
		return nil, &Error{}
	}
	children = nil
	success = true
	return &Registry{
		generation: generation,
		keys:       keys,
		bindings:   bindings,
	}, nil
}

// Generation returns the exact protected registry generation.
func (r *Registry) Generation(ctx context.Context) (uint64, error) {
	if r == nil || ctx == nil {
		return 0, &Error{}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || r.generation == 0 {
		return 0, &Error{}
	}
	return r.generation, nil
}

// Bindings returns detached opaque signing projection bindings.
func (r *Registry) Bindings() []provider.Binding {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil
	}
	return append([]provider.Binding(nil), r.bindings...)
}

// SignDigest signs through one exact opaque registry handle.
func (r *Registry) SignDigest(
	ctx context.Context,
	handle dkim2.PrivateKeyHandle,
	request dkim2.PrivateKeySignRequest,
) (dkim2.PrivateKeySignResult, error) {
	if r == nil || ctx == nil || !handle.Valid() || !request.Valid() {
		return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
	}
	if err := ctx.Err(); err != nil {
		return dkim2.PrivateKeySignResult{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return dkim2.PrivateKeySignResult{}, dkim2.NewTemporaryProviderError()
	}
	credential, found := r.keys[handle]
	if !found {
		return dkim2.PrivateKeySignResult{}, dkim2.NewPermanentProviderError()
	}
	return signPrivateCredential(ctx, credential, request)
}

// Close destroys retained private-key material exactly once.
func (r *Registry) Close(context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	clearCredentials(r.keys)
	r.keys = nil
	r.bindings = nil
	r.generation = 0
	return nil
}

// String returns a constant protected registry summary.
func (*Registry) String() string { return storeRedacted }

// GoString returns a constant protected registry representation.
func (*Registry) GoString() string { return storeRedacted }

// Format prevents formatting verbs from exposing registry facts.
func (*Registry) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, storeRedacted)
}

// MarshalJSON emits an empty object without registry facts.
func (*Registry) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// decodeRegistryManifest validates the exact generation-specific manifest schema.
func decodeRegistryManifest(document []byte) (uint64, []manifestEntry, error) {
	if len(document) == 0 || len(document) > maxManifestBytes ||
		!json.Valid(document) || duplicateJSONMember(document) {
		return 0, nil, &Error{}
	}
	var decoded registryManifestDocument
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return 0, nil, &Error{}
	}
	generation, err := strconv.ParseUint(decoded.Generation, 10, 64)
	if decoder.Decode(&struct{}{}) != io.EOF || err != nil ||
		generation == 0 || strconv.FormatUint(generation, 10) != decoded.Generation ||
		decoded.Version != registryManifestVersion || len(decoded.Entries) == 0 ||
		len(decoded.Entries) > 1024 {
		return 0, nil, &Error{}
	}
	return generation, append([]manifestEntry(nil), decoded.Entries...), nil
}

// keysByID returns the unique already-validated credential for an opaque ID.
func keysByID(
	keys map[dkim2.PrivateKeyHandle]privateCredential,
	handleID string,
) *privateCredential {
	handle, err := dkim2.NewPrivateKeyHandle([]byte(handleID))
	if err != nil {
		return nil
	}
	credential, found := keys[handle]
	if !found {
		return nil
	}
	return &credential
}
