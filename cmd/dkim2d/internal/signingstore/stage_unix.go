//go:build linux || darwin

package signingstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const registryManifestFile = "private-manifest.json"

type registryStageEvent uint8

const (
	registryKeySynchronized registryStageEvent = iota + 1
	registryManifestSynchronized
	registryDirectorySynchronized
	registryDirectorySealed
	registryParentSynchronized
)

// RegistryStagingEntry owns one explicit protected manifest binding and key.
type RegistryStagingEntry struct {
	tenantID string
	domain   string
	use      string
	handleID string
	key      *ImportedPrivateKey
}

// NewRegistryStagingEntry validates one explicit opaque-handle registry input.
func NewRegistryStagingEntry(
	tenantID string,
	domain string,
	use string,
	handleID string,
	key *ImportedPrivateKey,
) (RegistryStagingEntry, error) {
	if tenantID == "" || domain == "" || handleID == "" || key == nil ||
		(use != manifestOriginator && use != manifestOrdinaryTransit && use != manifestDeliveryStatus) ||
		len(key.Encoded()) == 0 || len(key.PublicSPKIDER()) == 0 {
		return RegistryStagingEntry{}, &Error{}
	}
	return RegistryStagingEntry{
		tenantID: tenantID, domain: domain, use: use, handleID: handleID, key: key,
	}, nil
}

// String returns a constant protected staging-entry summary.
func (RegistryStagingEntry) String() string { return storeRedacted }

// GoString returns a constant protected staging-entry representation.
func (RegistryStagingEntry) GoString() string { return storeRedacted }

// Format prevents formatting verbs from exposing staging facts.
func (RegistryStagingEntry) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, storeRedacted)
}

// MarshalJSON emits an empty object without protected staging facts.
func (RegistryStagingEntry) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// StageRegistry installs one inert immutable generation beneath a protected parent.
func StageRegistry(
	parentPath string,
	generation uint64,
	inputs []RegistryStagingEntry,
) (string, error) {
	return stageRegistryObserved(parentPath, generation, inputs, nil)
}

// stageRegistryObserved exposes content-free durability events to owned tests.
//
//nolint:gocyclo // Every filesystem durability boundary is checked independently.
func stageRegistryObserved(
	parentPath string,
	generation uint64,
	inputs []RegistryStagingEntry,
	observe func(registryStageEvent) error,
) (string, error) {
	if generation == 0 || len(inputs) == 0 || len(inputs) > 1024 {
		return "", &Error{}
	}
	parentFD, err := openRegistryParent(parentPath)
	if err != nil {
		return "", &Error{}
	}
	defer func() { _ = unix.Close(parentFD) }()
	generationName := strconv.FormatUint(generation, 10)
	entries, keyBytes, err := prepareRegistryStage(inputs)
	if err != nil {
		return "", &Error{}
	}
	defer func() {
		for _, encoded := range keyBytes {
			clear(encoded)
		}
	}()
	document, err := json.Marshal(registryManifestDocument{
		Version: registryManifestVersion, Generation: generationName, Entries: entries,
	})
	if err != nil || len(document) == 0 || len(document) > maxManifestBytes {
		return "", &Error{}
	}
	document = append(document, '\n')
	defer clear(document)
	if err := unix.Mkdirat(parentFD, generationName, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) &&
			exactRegistryGeneration(parentFD, generationName, generation, document, keyBytes) {
			return generationName + "/" + registryManifestFile, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", &Error{}
		}
	}
	generationFD, err := unix.Openat(
		parentFD, generationName,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return "", &Error{}
	}
	defer func() { _ = unix.Close(generationFD) }()
	var generationStat unix.Stat_t
	if unix.Fstat(generationFD, &generationStat) != nil ||
		generationStat.Uid != uint32(os.Geteuid()) ||
		generationStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		generationStat.Mode&0o777 != 0o700 {
		return "", &Error{}
	}
	for index, encoded := range keyBytes {
		if err := writeRegistryChild(
			generationFD, registryKeyFile(index), encoded,
		); err != nil {
			return "", &Error{}
		}
		if observe != nil && observe(registryKeySynchronized) != nil {
			return "", &Error{}
		}
	}
	if err := writeRegistryChild(generationFD, registryManifestFile, document); err != nil {
		return "", &Error{}
	}
	if observe != nil && observe(registryManifestSynchronized) != nil {
		return "", &Error{}
	}
	if err := unix.Fsync(generationFD); err != nil {
		return "", &Error{}
	}
	if observe != nil && observe(registryDirectorySynchronized) != nil {
		return "", &Error{}
	}
	if unix.Fchmod(generationFD, 0o500) != nil || unix.Fsync(generationFD) != nil {
		return "", &Error{}
	}
	if observe != nil && observe(registryDirectorySealed) != nil {
		return "", &Error{}
	}
	if unix.Fsync(parentFD) != nil {
		return "", &Error{}
	}
	if observe != nil && observe(registryParentSynchronized) != nil {
		return "", &Error{}
	}
	return generationName + "/" + registryManifestFile, nil
}

// prepareRegistryStage builds deterministic manifest entries and detached key bytes.
func prepareRegistryStage(
	inputs []RegistryStagingEntry,
) ([]manifestEntry, [][]byte, error) {
	entries := make([]manifestEntry, 0, len(inputs))
	keys := make([][]byte, 0, len(inputs))
	handles := make(map[string]struct{}, len(inputs))
	for index, input := range inputs {
		if input.tenantID == "" || input.domain == "" || input.handleID == "" ||
			input.key == nil || (input.use != manifestOriginator &&
			input.use != manifestOrdinaryTransit && input.use != manifestDeliveryStatus) {
			return nil, nil, &Error{}
		}
		if _, duplicate := handles[input.handleID]; duplicate {
			return nil, nil, &Error{}
		}
		handles[input.handleID] = struct{}{}
		encoded := input.key.Encoded()
		spki := input.key.PublicSPKIDER()
		if len(encoded) == 0 || len(encoded) > maxPrivateBytes || len(spki) == 0 {
			clear(encoded)
			clear(spki)
			return nil, nil, &Error{}
		}
		digest := sha256.Sum256(spki)
		clear(spki)
		algorithm := manifestRSASHA256
		if input.key.Algorithm() == "" {
			clear(encoded)
			return nil, nil, &Error{}
		}
		if input.key.Algorithm() == manifestEd25519SHA256 {
			algorithm = manifestEd25519SHA256
		} else if input.key.Algorithm() != manifestRSASHA256 {
			clear(encoded)
			return nil, nil, &Error{}
		}
		entries = append(entries, manifestEntry{
			TenantID: input.tenantID, Domain: input.domain, Use: input.use,
			HandleID: input.handleID, Algorithm: algorithm,
			PublicSPKISHA256: base64.StdEncoding.EncodeToString(digest[:]),
			PrivateKeyFile:   registryKeyFile(index),
		})
		keys = append(keys, encoded)
	}
	return entries, keys, nil
}

// registryKeyFile returns one sequence-only protected file name.
func registryKeyFile(index int) string {
	return fmt.Sprintf("private-key-%04d.pem", index+1)
}

// openRegistryParent opens one exact owner-only writable directory without links.
func openRegistryParent(path string) (int, error) {
	if path == "" || path[0] != '/' {
		return -1, &Error{}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return -1, &Error{}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return -1, &Error{}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &Error{}
	}
	return fd, nil
}

// writeRegistryChild creates, synchronizes, and closes one protected child.
func writeRegistryChild(directoryFD int, name string, data []byte) error {
	if !validChildName(name) || len(data) == 0 {
		return &Error{}
	}
	fd, err := unix.Openat(
		directoryFD, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0o600,
	)
	if err != nil {
		return &Error{}
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return &Error{}
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || written != len(data) || syncErr != nil || closeErr != nil {
		return &Error{}
	}
	return nil
}

// exactRegistryGeneration recognizes only an exact immutable prior result.
func exactRegistryGeneration(
	parentFD int,
	name string,
	generation uint64,
	document []byte,
	keys [][]byte,
) bool {
	fd, err := unix.Openat(
		parentFD, name,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&0o777 != 0o500 {
		return false
	}
	expected := append([][]byte{document}, keys...)
	names := make([]string, 0, len(expected))
	names = append(names, registryManifestFile)
	for index := range keys {
		names = append(names, registryKeyFile(index))
	}
	for index, child := range names {
		actual, readErr := readExactRegistryChild(fd, child, int64(len(expected[index])))
		equal := readErr == nil && bytes.Equal(actual, expected[index])
		clear(actual)
		if !equal {
			return false
		}
	}
	duplicateFD, duplicateErr := unix.Dup(fd)
	if duplicateErr != nil {
		return false
	}
	directory := os.NewFile(uintptr(duplicateFD), name)
	if directory == nil {
		_ = unix.Close(duplicateFD)
		return false
	}
	actualNames, namesErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if namesErr != nil || closeErr != nil || len(actualNames) < len(names) {
		return false
	}
	expectedNames := make(map[string]struct{}, len(names))
	for _, child := range names {
		expectedNames[child] = struct{}{}
	}
	for _, child := range actualNames {
		if _, exists := expectedNames[child]; !exists &&
			(child == registryManifestFile || strings.HasPrefix(child, "private-key-")) {
			return false
		}
	}
	registry, openErr := OpenRegistry(fd, registryManifestFile)
	if openErr != nil || registry == nil {
		return false
	}
	defer func() { _ = registry.Close(context.Background()) }()
	actualGeneration, generationErr := registry.Generation(context.Background())
	return generationErr == nil && actualGeneration == generation
}

// readExactRegistryChild reads one exact owner-only immutable registry child.
func readExactRegistryChild(directoryFD int, name string, size int64) ([]byte, error) {
	if size <= 0 || size > maxManifestBytes {
		return nil, &Error{}
	}
	fd, err := unix.Openat(
		directoryFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0,
	)
	if err != nil {
		return nil, &Error{}
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, &Error{}
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() != size {
		return nil, &Error{}
	}
	data, err := io.ReadAll(io.LimitReader(file, size+1))
	if err != nil || int64(len(data)) != size {
		clear(data)
		return nil, &Error{}
	}
	return data, nil
}
