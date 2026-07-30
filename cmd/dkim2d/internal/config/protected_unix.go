//go:build linux || darwin

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/signingstore"
	"golang.org/x/sys/unix"
)

const (
	maxProtectedPathBytes      = 4_096
	maxProtectedPathComponents = 64
	maxProtectedComponentBytes = 255
	maxYAMLDocumentBytes       = 262_144
)

type protectedFileRole uint8

const (
	protectedYAML protectedFileRole = iota + 1
	protectedCapability
	protectedSignCapability
	protectedReviseCapability
	protectedHMAC
	protectedApplicationPassword
	protectedAuditorPassword
	protectedCA
	protectedTracingCA
	protectedDatasourcePassword
	protectedDatasourceCA
)

type ownedDescriptor struct {
	fd      int
	closeFn func(int) error
}

type retainedProtectedFile struct {
	descriptor ownedDescriptor
	role       protectedFileRole
	pre        descriptorState
	immediate  descriptorState
	data       []byte
}

// LoadProtected opens one YAML snapshot and its immutable generation through retained descriptors.
func LoadProtected(path string, flags FlagValues) (owner *Prebootstrap, resultErr error) {
	return loadProtectedObserved(path, flags, nil)
}

type protectedLoadEvent uint8

const (
	protectedEventYAMLRead protectedLoadEvent = iota + 1
	protectedEventGenerationOpened
	protectedEventChildOpened
	protectedEventBeforeChildRead
	protectedEventChildRead
	protectedEventBeforeFinalChildren
	protectedEventChildFinal
	protectedEventGenerationFinal
	protectedEventYAMLFinal
)

type protectedLoadObserver func(protectedLoadEvent, protectedFileRole)

// loadProtectedObserved exposes content-free phase events to instance-owned deterministic tests.
func loadProtectedObserved(
	path string,
	flags FlagValues,
	observe protectedLoadObserver,
) (owner *Prebootstrap, resultErr error) {
	return loadProtectedObservedWithUID(path, flags, observe, uint32(os.Geteuid()))
}

// loadProtectedObservedWithUID runs one load against exactly one captured effective UID.
func loadProtectedObservedWithUID(
	path string,
	flags FlagValues,
	observe protectedLoadObserver,
	effectiveUID uint32,
) (owner *Prebootstrap, resultErr error) {
	yaml, yamlParent, yamlAncestry, err := openProtectedPathAndParent(path, false, effectiveUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		applyProtectedClose(&owner, &resultErr, yamlParent.close())
	}()
	defer func() {
		applyProtectedClose(&owner, &resultErr, yaml.close())
	}()
	if err := validateTrustedDirectory(yamlParent.fd, effectiveUID); err != nil {
		return nil, err
	}
	yamlPre, err := validateProtectedDescriptor(yaml.fd, protectedYAML, effectiveUID)
	if err != nil {
		return nil, err
	}
	yamlBytes, err := readProtectedDescriptor(yaml.fd, maxYAMLDocumentBytes)
	if err != nil {
		return nil, err
	}
	yamlImmediate, err := captureDescriptorState(yaml.fd, yamlPre.metadata.modeBits, false)
	if err != nil || yamlImmediate != yamlPre {
		return nil, newError(CodeProtectedAccess)
	}
	notifyProtectedObserver(observe, protectedEventYAMLRead, protectedYAML)
	snapshot, err := Load(yamlBytes, flags)
	if err != nil {
		return nil, err
	}
	return loadProtectedGeneration(
		path,
		&yaml,
		yamlPre,
		yamlImmediate,
		yamlAncestry,
		snapshot,
		observe,
		effectiveUID,
	)
}

// loadProtectedGeneration retains every selected descriptor through the complete bundle proof.
func loadProtectedGeneration(
	yamlPath string,
	yaml *ownedDescriptor,
	yamlPre, yamlImmediate descriptorState,
	yamlAncestry [][2]uint64,
	snapshot Snapshot,
	observe protectedLoadObserver,
	effectiveUID uint32,
) (owner *Prebootstrap, resultErr error) {
	generationPath := filepath.Dir(snapshot.Server().CapabilityFile())
	if filepath.Base(generationPath) != snapshot.Generation() ||
		pathWithinDirectory(yamlPath, generationPath) {
		return nil, newError(CodeProtectedPath)
	}
	generation, err := openProtectedPathWithUID(generationPath, true, effectiveUID)
	if err != nil {
		return nil, err
	}
	defer func() {
		applyProtectedClose(&owner, &resultErr, generation.close())
	}()
	generationPre, err := validateGenerationDescriptor(generation.fd, effectiveUID)
	if err != nil {
		return nil, err
	}
	if sameDescriptorIdentity(yamlPre.metadata, generationPre.metadata) {
		return nil, newError(CodeProtectedAccess)
	}
	if descriptorAncestryContains(yamlAncestry, generationPre.metadata) {
		return nil, newError(CodeProtectedAccess)
	}
	notifyProtectedObserver(observe, protectedEventGenerationOpened, 0)

	files, err := openGenerationChildren(generation.fd, snapshot, yamlPre.metadata, observe, effectiveUID)
	if err != nil {
		_ = closeRetainedFiles(files)
		return nil, err
	}
	defer func() {
		applyProtectedClose(&owner, &resultErr, closeRetainedFiles(files))
	}()
	if err := readGenerationChildren(files, observe); err != nil {
		return nil, err
	}
	if err := validateFinalDescriptorStates(
		files,
		generation.fd,
		generationPre,
		yaml.fd,
		yamlPre,
		yamlImmediate,
		observe,
	); err != nil {
		return nil, err
	}
	state, err := buildProtectedState(snapshot, files, generation.fd)
	if err != nil {
		return nil, err
	}
	// Recheck the already-read outer protected files after the optional
	// compound signing store has finished parsing. This proves an overlapping
	// immutable interval across capabilities, datasource, manifest, and keys.
	if err := validateFinalDescriptorStates(
		files,
		generation.fd,
		generationPre,
		yaml.fd,
		yamlPre,
		yamlImmediate,
		nil,
	); err != nil {
		state.clearProtected(protectedOwnedByPrebootstrap)
		return nil, newError(CodeProtectedAccess)
	}
	return &Prebootstrap{state: state}, nil
}

// openGenerationChildren opens and prechecks every child before the first content read.
func openGenerationChildren(
	generationFD int,
	snapshot Snapshot,
	yamlMetadata descriptorMetadata,
	observe protectedLoadObserver,
	effectiveUID uint32,
) ([]*retainedProtectedFile, error) {
	paths := selectedProtectedPaths(snapshot)
	files := make([]*retainedProtectedFile, 0, len(paths))
	identities := map[[2]uint64]struct{}{
		{yamlMetadata.device, yamlMetadata.inode}: {},
	}
	for _, selected := range paths {
		descriptor, err := openProtectedChild(generationFD, filepath.Base(selected.path))
		if err != nil {
			return files, err
		}
		file := &retainedProtectedFile{descriptor: descriptor, role: selected.role}
		pre, validateErr := validateProtectedDescriptor(descriptor.fd, selected.role, effectiveUID)
		if validateErr != nil {
			_ = descriptor.close()
			return files, validateErr
		}
		file.pre = pre
		identity := [2]uint64{pre.metadata.device, pre.metadata.inode}
		if _, duplicate := identities[identity]; duplicate {
			_ = descriptor.close()
			return files, newError(CodeProtectedAccess)
		}
		identities[identity] = struct{}{}
		files = append(files, file)
		notifyProtectedObserver(observe, protectedEventChildOpened, selected.role)
	}
	return files, nil
}

type selectedProtectedPath struct {
	path string
	role protectedFileRole
}

// selectedProtectedPaths returns the exact backend-conditional child inventory.
func selectedProtectedPaths(snapshot Snapshot) []selectedProtectedPath {
	paths := []selectedProtectedPath{{
		path: snapshot.Server().CapabilityFile(),
		role: protectedCapability,
	}}
	if snapshot.Signing().Enabled() {
		if snapshot.Server().SignEnabled() {
			paths = append(paths, selectedProtectedPath{
				path: snapshot.Server().SignCapabilityFile(),
				role: protectedSignCapability,
			})
		}
		if ldap, enabled := snapshot.Signing().LDAP(); enabled {
			paths = append(paths,
				selectedProtectedPath{path: ldap.PasswordFile(), role: protectedDatasourcePassword},
				selectedProtectedPath{path: ldap.CAFile(), role: protectedDatasourceCA},
			)
		}
		if postgresql, enabled := snapshot.Signing().PostgreSQL(); enabled {
			paths = append(paths,
				selectedProtectedPath{path: postgresql.PasswordFile(), role: protectedDatasourcePassword},
				selectedProtectedPath{path: postgresql.CAFile(), role: protectedDatasourceCA},
			)
		}
		if snapshot.Server().ReviseEnabled() {
			paths = append(paths, selectedProtectedPath{
				path: snapshot.Server().ReviseCapabilityFile(),
				role: protectedReviseCapability,
			})
		}
	}
	replay := snapshot.Replay()
	if replay.Enabled() {
		paths = append(paths, selectedProtectedPath{
			path: replay.HMACKeyFile(),
			role: protectedHMAC,
		})
		valkey, enabled := replay.Valkey()
		if enabled {
			paths = append(paths,
				selectedProtectedPath{path: valkey.ApplicationPasswordFile(), role: protectedApplicationPassword},
				selectedProtectedPath{path: valkey.AuditorPasswordFile(), role: protectedAuditorPassword},
				selectedProtectedPath{path: valkey.CAFile(), role: protectedCA},
			)
		}
	}
	tracing := snapshot.Observability().Tracing()
	if tracing.Exporter() == TracingOTLPHTTP {
		paths = append(paths, selectedProtectedPath{path: tracing.CAFile(), role: protectedTracingCA})
	}
	return paths
}

// readGenerationChildren reads and immediately rechecks every already-open child.
func readGenerationChildren(files []*retainedProtectedFile, observe protectedLoadObserver) error {
	for _, file := range files {
		notifyProtectedObserver(observe, protectedEventBeforeChildRead, file.role)
		data, err := readProtectedDescriptor(file.descriptor.fd, protectedReadCap(file.role))
		if err != nil {
			return err
		}
		immediate, err := captureDescriptorState(
			file.descriptor.fd,
			file.pre.metadata.modeBits,
			false,
		)
		if err != nil || immediate != file.pre {
			return newError(CodeProtectedAccess)
		}
		file.data = data
		file.immediate = immediate
		notifyProtectedObserver(observe, protectedEventChildRead, file.role)
	}
	return nil
}

// validateFinalDescriptorStates rechecks every child, generation directory, then YAML descriptor.
func validateFinalDescriptorStates(
	files []*retainedProtectedFile,
	generationFD int,
	generationPre descriptorState,
	yamlFD int,
	yamlPre, yamlImmediate descriptorState,
	observe protectedLoadObserver,
) error {
	notifyProtectedObserver(observe, protectedEventBeforeFinalChildren, 0)
	for _, file := range files {
		final, err := captureDescriptorState(
			file.descriptor.fd,
			file.pre.metadata.modeBits,
			false,
		)
		if err != nil || final != file.pre || final != file.immediate {
			return newError(CodeProtectedAccess)
		}
		notifyProtectedObserver(observe, protectedEventChildFinal, file.role)
	}
	generationFinal, err := captureDescriptorState(
		generationFD,
		generationPre.metadata.modeBits,
		true,
	)
	if err != nil || generationFinal != generationPre {
		return newError(CodeProtectedAccess)
	}
	notifyProtectedObserver(observe, protectedEventGenerationFinal, 0)
	yamlFinal, err := captureDescriptorState(yamlFD, yamlPre.metadata.modeBits, false)
	if err != nil || yamlFinal != yamlPre || yamlFinal != yamlImmediate {
		return newError(CodeProtectedAccess)
	}
	notifyProtectedObserver(observe, protectedEventYAMLFinal, protectedYAML)
	return nil
}

// notifyProtectedObserver emits one content-free deterministic phase marker.
func notifyProtectedObserver(
	observe protectedLoadObserver,
	event protectedLoadEvent,
	role protectedFileRole,
) {
	if observe != nil {
		observe(event, role)
	}
}

// buildProtectedState validates content and constructs one exclusive startup owner.
//
//nolint:gocyclo // Each protected role is handled explicitly to preserve ownership.
func buildProtectedState(
	snapshot Snapshot,
	files []*retainedProtectedFile,
	generationFD int,
) (state *protectedState, resultErr error) {
	state = &protectedState{
		phase:    protectedOwnedByPrebootstrap,
		snapshot: snapshot,
	}
	allocated := state
	defer func() {
		if resultErr != nil {
			_ = allocated.releasePrebootstrap()
			state = nil
		}
	}()
	for _, file := range files {
		switch file.role {
		case protectedCapability:
			if err := validateExactKey(file.data); err != nil {
				return nil, err
			}
			copy(state.capability[:], file.data)
		case protectedSignCapability:
			if err := validateExactKey(file.data); err != nil {
				return nil, err
			}
			copy(state.signCapability[:], file.data)
			state.hasSign = true
		case protectedReviseCapability:
			if err := validateExactKey(file.data); err != nil {
				return nil, err
			}
			copy(state.reviseCapability[:], file.data)
			state.hasRevise = true
		case protectedHMAC:
			if err := validateExactKey(file.data); err != nil {
				return nil, err
			}
			copy(state.hmac[:], file.data)
			state.hasHMAC = true
		case protectedApplicationPassword:
			if err := validatePassword(file.data); err != nil {
				return nil, err
			}
			state.applicationPassword = append([]byte(nil), file.data...)
		case protectedAuditorPassword:
			if err := validatePassword(file.data); err != nil {
				return nil, err
			}
			state.auditorPassword = append([]byte(nil), file.data...)
		case protectedCA:
			roots, err := parseCertificateRoots(file.data)
			if err != nil {
				return nil, err
			}
			state.rootCertificatesDER = roots
		case protectedTracingCA:
			roots, err := parseTracingCertificateRoots(file.data)
			if err != nil {
				return nil, err
			}
			state.tracingRootCertificatesDER = roots
		case protectedDatasourcePassword:
			if err := validatePassword(file.data); err != nil {
				return nil, err
			}
			state.datasourcePassword = append([]byte(nil), file.data...)
		case protectedDatasourceCA:
			roots, err := parseCertificateRoots(file.data)
			if err != nil {
				return nil, err
			}
			state.datasourceRootsDER = roots
		default:
			return nil, newError(CodeInternal)
		}
	}
	if snapshot.Signing().Enabled() {
		if generationFD < 0 ||
			state.hasSign != snapshot.Server().SignEnabled() ||
			state.hasRevise != snapshot.Server().ReviseEnabled() ||
			(!state.hasSign && !state.hasRevise) {
			return nil, newError(CodeProtectedContent)
		}
		if snapshot.Signing().Backend() == SigningFlatFile {
			store, err := signingstore.NewRuntime(
				generationFD,
				filepath.Base(snapshot.Signing().DatasourceFile()),
				filepath.Base(snapshot.Signing().PrivateManifestFile()),
			)
			if err != nil || store == nil {
				return nil, newError(CodeProtectedContent)
			}
			state.signingStore = store
		} else {
			if len(state.datasourcePassword) == 0 || len(state.datasourceRootsDER) == 0 {
				return nil, newError(CodeProtectedContent)
			}
			registry, err := signingstore.NewRegistrySource(
				generationFD,
				filepath.Base(snapshot.Signing().PrivateManifestFile()),
			)
			if err != nil || registry == nil {
				return nil, newError(CodeProtectedContent)
			}
			state.signingRegistry = registry
		}
	}
	if err := validateProtectedSeparation(state); err != nil {
		return nil, err
	}
	return state, nil
}

// validateGenerationDescriptor enforces the immutable generation-directory policy.
func validateGenerationDescriptor(fd int, effectiveUID uint32) (descriptorState, error) {
	state, err := captureDescriptorState(fd, 0o500, true)
	if err != nil {
		return descriptorState{}, err
	}
	if err := validateGenerationMetadata(state.metadata, effectiveUID); err != nil {
		return descriptorState{}, err
	}
	return state, nil
}

// validateGenerationMetadata enforces published ownership and directory metadata.
func validateGenerationMetadata(metadata descriptorMetadata, effectiveUID uint32) error {
	if metadata.typeBits != unix.S_IFDIR || metadata.uid != effectiveUID ||
		metadata.modeBits != 0o500 || metadata.linkCount == 0 {
		return newError(CodeProtectedAccess)
	}
	return nil
}

// validateProtectedDescriptor enforces one exact YAML, secret, or trust-file policy.
func validateProtectedDescriptor(fd int, role protectedFileRole, effectiveUID uint32) (descriptorState, error) {
	metadata, err := statDescriptor(fd)
	if err != nil {
		return descriptorState{}, err
	}
	if err := validateProtectedFileMetadata(metadata, role, effectiveUID); err != nil {
		return descriptorState{}, err
	}
	access, err := descriptorAccessFingerprint(fd, false, metadata.modeBits)
	if err != nil {
		return descriptorState{}, err
	}
	return descriptorState{metadata: metadata, access: access}, nil
}

// validateProtectedFileMetadata applies the exact per-role descriptor policy.
func validateProtectedFileMetadata(
	metadata descriptorMetadata,
	role protectedFileRole,
	effectiveUID uint32,
) error {
	if metadata.typeBits != unix.S_IFREG || metadata.uid != effectiveUID || metadata.size < 0 {
		return newError(CodeProtectedAccess)
	}
	modeAccepted := false
	requireSingleLink := role != protectedCA && role != protectedDatasourceCA
	switch role {
	case protectedYAML, protectedCapability, protectedSignCapability,
		protectedReviseCapability, protectedHMAC,
		protectedApplicationPassword, protectedAuditorPassword,
		protectedDatasourcePassword:
		modeAccepted = metadata.modeBits == 0o400 || metadata.modeBits == 0o600
	case protectedCA, protectedDatasourceCA:
		switch metadata.modeBits {
		case 0o400, 0o440, 0o444, 0o600, 0o640, 0o644:
			modeAccepted = true
		}
	case protectedTracingCA:
		modeAccepted = metadata.modeBits == 0o400 || metadata.modeBits == 0o600
	default:
		return newError(CodeInternal)
	}
	if !modeAccepted || metadata.linkCount == 0 || requireSingleLink && metadata.linkCount != 1 ||
		!protectedSizeAccepted(role, metadata.size) {
		return newError(CodeProtectedAccess)
	}
	return nil
}

// captureDescriptorState freezes metadata and ACL state through one owned descriptor.
func captureDescriptorState(fd int, acceptedMode uint32, directory bool) (descriptorState, error) {
	metadata, err := statDescriptor(fd)
	if err != nil {
		return descriptorState{}, err
	}
	access, err := descriptorAccessFingerprint(fd, directory, acceptedMode)
	if err != nil {
		return descriptorState{}, err
	}
	return descriptorState{metadata: metadata, access: access}, nil
}

// protectedSizeAccepted validates pre-read size bounds for one protected role.
func protectedSizeAccepted(role protectedFileRole, size int64) bool {
	switch role {
	case protectedYAML:
		return size >= 1 && size <= maxYAMLDocumentBytes
	case protectedCapability, protectedSignCapability, protectedReviseCapability,
		protectedHMAC:
		return size == exactKeyBytes
	case protectedApplicationPassword, protectedAuditorPassword:
		return size >= 1 && size <= maxPasswordBytes
	case protectedDatasourcePassword:
		return size >= 1 && size <= maxPasswordBytes
	case protectedCA, protectedDatasourceCA:
		return size >= 1 && size <= maxCAPEMBytes
	case protectedTracingCA:
		return size >= 1 && size <= maxTracingCAPEMBytes
	default:
		return false
	}
}

// protectedReadCap returns the independent content cap for one protected role.
func protectedReadCap(role protectedFileRole) int {
	switch role {
	case protectedYAML:
		return maxYAMLDocumentBytes
	case protectedCapability, protectedSignCapability, protectedReviseCapability,
		protectedHMAC:
		return exactKeyBytes
	case protectedApplicationPassword, protectedAuditorPassword:
		return maxPasswordBytes
	case protectedDatasourcePassword:
		return maxPasswordBytes
	case protectedCA, protectedDatasourceCA:
		return maxCAPEMBytes
	case protectedTracingCA:
		return maxTracingCAPEMBytes
	default:
		return 0
	}
}

// readProtectedDescriptor reads cap plus one and requires exact EOF.
func readProtectedDescriptor(fd int, limit int) ([]byte, error) {
	return readProtectedDescriptorWith(limit, func(destination []byte) (int, error) {
		return unix.Read(fd, destination)
	})
}

// readProtectedDescriptorWith applies exact cap-plus-one semantics to one injected reader.
func readProtectedDescriptorWith(
	limit int,
	read func([]byte) (int, error),
) ([]byte, error) {
	if limit <= 0 {
		return nil, newError(CodeInternal)
	}
	if read == nil {
		return nil, newError(CodeInternal)
	}
	data := make([]byte, 0, min(limit+1, 4096))
	buffer := make([]byte, min(limit+1, 4096))
	for {
		remaining := limit + 1 - len(data)
		if remaining <= 0 {
			return nil, newError(CodeProtectedContent)
		}
		window := buffer[:min(len(buffer), remaining)]
		count, err := read(window)
		if count < 0 || count > len(window) {
			return nil, newError(CodeProtectedIO)
		}
		if count > 0 {
			data = append(data, window[:count]...)
			if len(data) > limit {
				return nil, newError(CodeProtectedContent)
			}
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, newError(CodeProtectedIO)
		}
		if count == 0 {
			break
		}
	}
	return data, nil
}

// openProtectedPath traverses an absolute path through trusted directory descriptors.
func openProtectedPath(path string, directory bool) (ownedDescriptor, error) {
	return openProtectedPathWithUID(path, directory, uint32(os.Geteuid()))
}

// openProtectedPathWithUID traverses one path against a single captured effective UID.
func openProtectedPathWithUID(
	path string,
	directory bool,
	effectiveUID uint32,
) (ownedDescriptor, error) {
	final, parent, _, err := openProtectedPathAndParent(path, directory, effectiveUID)
	if err != nil {
		return ownedDescriptor{fd: -1}, err
	}
	if closeErr := parent.close(); closeErr != nil {
		_ = final.close()
		return ownedDescriptor{fd: -1}, closeErr
	}
	return final, nil
}

// openProtectedPathAndParent retains the exact traversal parent used for the final open.
func openProtectedPathAndParent(
	path string,
	directory bool,
	effectiveUID uint32,
) (ownedDescriptor, ownedDescriptor, [][2]uint64, error) {
	components, err := protectedPathComponents(path)
	if err != nil {
		return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, err
	}
	current, err := openRootDescriptor()
	if err != nil {
		return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, err
	}
	rootMetadata, err := statDescriptor(current.fd)
	if err != nil {
		_ = current.close()
		return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, err
	}
	ancestry := make([][2]uint64, 0, len(components))
	ancestry = append(ancestry, descriptorIdentity(rootMetadata))
	for index, component := range components {
		final := index == len(components)-1
		if final {
			next, openErr := openPreclassifiedChild(current.fd, component, directory)
			if openErr != nil {
				_ = current.close()
				return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, openErr
			}
			return next, current, ancestry, nil
		}
		next, openErr := openPreclassifiedChild(current.fd, component, true)
		if openErr != nil {
			_ = current.close()
			return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, openErr
		}
		if trustErr := validateTrustedDirectory(next.fd, effectiveUID); trustErr != nil {
			_ = next.close()
			_ = current.close()
			return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, trustErr
		}
		nextMetadata, statErr := statDescriptor(next.fd)
		if statErr != nil {
			_ = next.close()
			_ = current.close()
			return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, statErr
		}
		ancestry = append(ancestry, descriptorIdentity(nextMetadata))
		if closeErr := current.close(); closeErr != nil {
			_ = next.close()
			return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, closeErr
		}
		current = next
	}
	_ = current.close()
	return ownedDescriptor{fd: -1}, ownedDescriptor{fd: -1}, nil, newError(CodeProtectedPath)
}

// openRootDescriptor opens and validates the filesystem root as the first trusted parent.
func openRootDescriptor() (ownedDescriptor, error) {
	fd, err := retryOpenat(unix.AT_FDCWD, "/", directoryOpenFlags())
	if err != nil {
		return ownedDescriptor{fd: -1}, err
	}
	descriptor := newOwnedDescriptor(fd)
	if err := validateTrustedRootDirectory(fd); err != nil {
		_ = descriptor.close()
		return ownedDescriptor{fd: -1}, err
	}
	return descriptor, nil
}

// validateTrustedRootDirectory permits only the closed container-root exception.
func validateTrustedRootDirectory(fd int) error {
	metadata, err := statDescriptor(fd)
	if err != nil {
		return err
	}
	if metadata.typeBits != unix.S_IFDIR ||
		metadata.uid != 0 ||
		metadata.modeBits&0o022 != 0 {
		return newError(CodeProtectedAccess)
	}
	return inspectTrustedRootAccess(fd, metadata.modeBits)
}

// openProtectedChild opens a preclassified regular child relative to the generation descriptor.
func openProtectedChild(parentFD int, name string) (ownedDescriptor, error) {
	return openPreclassifiedChild(parentFD, name, false)
}

// openPreclassifiedChild requires type and inode equality across fstatat and openat.
func openPreclassifiedChild(parentFD int, name string, directory bool) (ownedDescriptor, error) {
	before, err := statAtNoFollow(parentFD, name)
	if err != nil {
		return ownedDescriptor{fd: -1}, err
	}
	expectedType := uint32(unix.S_IFREG)
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if directory {
		expectedType = unix.S_IFDIR
		flags = directoryOpenFlags()
	}
	if before.typeBits != expectedType {
		return ownedDescriptor{fd: -1}, newError(CodeProtectedPath)
	}
	fd, err := retryOpenat(parentFD, name, flags)
	if err != nil {
		return ownedDescriptor{fd: -1}, err
	}
	descriptor := newOwnedDescriptor(fd)
	after, err := statDescriptor(fd)
	if err != nil || after.typeBits != expectedType ||
		!sameDescriptorIdentity(before, after) {
		_ = descriptor.close()
		return ownedDescriptor{fd: -1}, newError(CodeProtectedAccess)
	}
	return descriptor, nil
}

// validateTrustedDirectory enforces owner, mode, local-filesystem, and trivial-ACL policy.
func validateTrustedDirectory(fd int, effectiveUID uint32) error {
	metadata, err := statDescriptor(fd)
	if err != nil {
		return err
	}
	if metadata.typeBits != unix.S_IFDIR ||
		metadata.uid != 0 && metadata.uid != effectiveUID ||
		metadata.modeBits&0o022 != 0 {
		return newError(CodeProtectedAccess)
	}
	return inspectTrustedAncestorAccess(
		fd,
		metadata.modeBits,
		metadata.uid == 0,
	)
}

// retryOpenat retries interrupted descriptor opens and maps all failures content-free.
func retryOpenat(parentFD int, name string, flags int) (int, error) {
	return retryOpenatWith(func() (int, error) {
		return unix.Openat(parentFD, name, flags, 0)
	})
}

// retryOpenatWith retries one injected open operation and maps terminal failures.
func retryOpenatWith(open func() (int, error)) (int, error) {
	for {
		fd, err := open()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return -1, newError(CodeProtectedIO)
		}
		return fd, nil
	}
}

// retryDescriptorOperation retries one interrupted stat-family operation.
func retryDescriptorOperation(operation func() error) error {
	for {
		err := operation()
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return newError(CodeProtectedIO)
		}
		return nil
	}
}

// directoryOpenFlags returns the closed directory traversal flag set.
func directoryOpenFlags() int {
	return unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
}

// protectedPathComponents checks lexical bounds before descriptor traversal.
func protectedPathComponents(path string) ([]string, error) {
	if !validProtectedPath(path) || len(path) > maxProtectedPathBytes {
		return nil, newError(CodeProtectedPath)
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	if len(components) == 0 || len(components) > maxProtectedPathComponents {
		return nil, newError(CodeProtectedPath)
	}
	for _, component := range components {
		if component == "" || len(component) > maxProtectedComponentBytes {
			return nil, newError(CodeProtectedPath)
		}
	}
	return components, nil
}

// pathWithinDirectory reports whether one clean absolute path names the directory or a descendant.
func pathWithinDirectory(path, directory string) bool {
	return path == directory || strings.HasPrefix(path, directory+string(filepath.Separator))
}

// sameDescriptorIdentity compares only descriptor-native device and inode identity.
func sameDescriptorIdentity(left, right descriptorMetadata) bool {
	return left.device == right.device && left.inode == right.inode
}

// descriptorIdentity returns the stable device/inode tuple for bounded ancestry tracking.
func descriptorIdentity(metadata descriptorMetadata) [2]uint64 {
	return [2]uint64{metadata.device, metadata.inode}
}

// descriptorAncestryContains reports whether one descriptor is any traversed ancestor.
func descriptorAncestryContains(ancestry [][2]uint64, metadata descriptorMetadata) bool {
	expected := descriptorIdentity(metadata)
	for _, identity := range ancestry {
		if identity == expected {
			return true
		}
	}
	return false
}

// close releases one descriptor at most once and never retries close.
func (d *ownedDescriptor) close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	fd := d.fd
	d.fd = -1
	closeFn := d.closeFn
	d.closeFn = nil
	if closeFn == nil {
		closeFn = unix.Close
	}
	if err := closeFn(fd); err != nil {
		return newError(CodeProtectedIO)
	}
	return nil
}

// newOwnedDescriptor assigns one close-once owner to an acquired descriptor.
func newOwnedDescriptor(fd int) ownedDescriptor {
	return ownedDescriptor{fd: fd, closeFn: unix.Close}
}

// closeRetainedFiles closes every opened child at most once.
func closeRetainedFiles(files []*retainedProtectedFile) error {
	var result error
	for _, file := range files {
		if file != nil {
			if err := file.descriptor.close(); err != nil && result == nil {
				result = err
			}
		}
	}
	return result
}

// applyProtectedClose withholds a successful owner when descriptor cleanup is ambiguous.
func applyProtectedClose(owner **Prebootstrap, resultErr *error, closeErr error) {
	if closeErr == nil || *resultErr != nil {
		return
	}
	if *owner != nil {
		_ = (*owner).Close()
		*owner = nil
	}
	*resultErr = closeErr
}
