package filter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/croessner/dkim2/cmd/dkim2-exim/internal/adapter"
)

const streamBufferBytes = 32 << 10

// privateWorkspace owns confined input and transformed-output files for one run.
type privateWorkspace struct {
	root   string
	input  *os.File
	output *os.File
}

// newPrivateWorkspace creates one mode-0700 directory for all transient mail bytes.
func newPrivateWorkspace(parent string) (*privateWorkspace, error) {
	root, err := os.MkdirTemp(parent, ".dkim2-exim-filter-")
	if err != nil {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		_ = os.Remove(root)
		return nil, adapter.NewError(adapter.FailureResource)
	}
	workspace := &privateWorkspace{root: root}
	workspace.input, err = workspace.create("input")
	if err != nil {
		_ = workspace.close()
		return nil, err
	}
	workspace.output, err = workspace.create("output")
	if err != nil {
		_ = workspace.close()
		return nil, err
	}
	return workspace, nil
}

// create opens one exclusive mode-0600 regular child in the owned directory.
func (w *privateWorkspace) create(name string) (*os.File, error) {
	if w == nil || w.root == "" {
		return nil, adapter.NewError(adapter.FailureInternal)
	}
	file, err := os.OpenFile(
		filepath.Join(w.root, name),
		os.O_CREATE|os.O_EXCL|os.O_RDWR,
		0o600,
	)
	if err != nil {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(filepath.Join(w.root, name))
		return nil, adapter.NewError(adapter.FailureResource)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		_ = os.Remove(filepath.Join(w.root, name))
		return nil, adapter.NewError(adapter.FailureResource)
	}
	return file, nil
}

// capture copies bounded stdin into private storage and returns one owned copy.
func (w *privateWorkspace) capture(input io.Reader, configured ...int) ([]byte, error) {
	maximum := maxInputBytes
	if len(configured) == 1 {
		maximum = configured[0]
	} else if len(configured) > 1 {
		return nil, adapter.NewError(adapter.FailureContract)
	}
	if w == nil || w.input == nil || input == nil || maximum < 1 || maximum > maxInputBytes {
		return nil, adapter.NewError(adapter.FailureInvalidRequest)
	}
	buffer := make([]byte, streamBufferBytes)
	defer clear(buffer)
	total := 0
	for {
		count, readErr := input.Read(buffer)
		if count < 0 || count > len(buffer) {
			return nil, adapter.NewError(adapter.FailureInternal)
		}
		if count > 0 {
			if total > maximum-count {
				return nil, adapter.NewError(adapter.FailureResource)
			}
			if err := writePrivate(w.input, buffer[:count]); err != nil {
				return nil, err
			}
			total += count
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return nil, adapter.NewError(adapter.FailureUnavailable)
			}
			break
		}
		if count == 0 {
			return nil, adapter.NewError(adapter.FailureUnavailable)
		}
	}
	if total == 0 {
		return nil, adapter.NewError(adapter.FailureInvalidRequest)
	}
	last := make([]byte, 1)
	if _, err := w.input.ReadAt(last, int64(total-1)); err != nil {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	if last[0] != '\n' {
		if total >= maximum || writePrivate(w.input, []byte{'\n'}) != nil {
			return nil, adapter.NewError(adapter.FailureResource)
		}
		total++
	}
	if _, err := w.input.Seek(0, io.SeekStart); err != nil {
		return nil, adapter.NewError(adapter.FailureResource)
	}
	message := make([]byte, total)
	if _, err := io.ReadFull(w.input, message); err != nil {
		clear(message)
		return nil, adapter.NewError(adapter.FailureResource)
	}
	return message, nil
}

// prepareOutput stores the complete prevalidated message before stdout begins.
func (w *privateWorkspace) prepareOutput(message []byte, configured ...Limits) error {
	limits := DefaultLimits()
	if len(configured) == 1 {
		limits = configured[0]
	} else if len(configured) > 1 {
		return adapter.NewError(adapter.FailureContract)
	}
	if w == nil || w.output == nil || len(message) == 0 ||
		len(message) > maxTransformedBytes || !limits.Valid() {
		return adapter.NewError(adapter.FailureResource)
	}
	if err := writePrivate(w.output, message); err != nil {
		return err
	}
	if _, err := w.output.Seek(0, io.SeekStart); err != nil {
		return adapter.NewError(adapter.FailureResource)
	}
	proof := make([]byte, len(message))
	defer clear(proof)
	if _, err := io.ReadFull(w.output, proof); err != nil ||
		!bytes.Equal(proof, message) {
		return adapter.NewError(adapter.FailureResource)
	}
	if err := validateCompleteMessageLimited(proof, limits); err != nil {
		return err
	}
	if _, err := w.output.Seek(0, io.SeekStart); err != nil {
		return adapter.NewError(adapter.FailureResource)
	}
	return nil
}

// seal unlinks every transient pathname before protocol output begins.
func (w *privateWorkspace) seal() error {
	if w == nil || w.root == "" || w.input == nil || w.output == nil {
		return adapter.NewError(adapter.FailureInternal)
	}
	for _, name := range []string{"input", "output"} {
		if err := os.Remove(filepath.Join(w.root, name)); err != nil {
			return adapter.NewError(adapter.FailureResource)
		}
	}
	if err := os.Remove(w.root); err != nil {
		return adapter.NewError(adapter.FailureResource)
	}
	w.root = ""
	return nil
}

// stream emits the prepared message once and treats any write anomaly as indeterminate.
func (w *privateWorkspace) stream(ctx context.Context, destination io.Writer) error {
	if w == nil || w.output == nil || ctx == nil || destination == nil {
		return adapter.NewError(adapter.FailureContract)
	}
	buffer := make([]byte, streamBufferBytes)
	defer clear(buffer)
	for {
		if ctx.Err() != nil {
			return adapter.NewError(adapter.FailurePartialOutput)
		}
		count, readErr := w.output.Read(buffer)
		if count < 0 || count > len(buffer) {
			return adapter.NewError(adapter.FailurePartialOutput)
		}
		if count > 0 {
			if err := writeOutput(destination, buffer[:count]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return adapter.NewError(adapter.FailurePartialOutput)
		}
		if count == 0 {
			return adapter.NewError(adapter.FailurePartialOutput)
		}
	}
}

// writePrivate completes writes only inside private pre-output storage.
func writePrivate(destination io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := destination.Write(value)
		if err != nil || count <= 0 || count > len(value) {
			return adapter.NewError(adapter.FailureResource)
		}
		value = value[count:]
	}
	return nil
}

// close clears file lengths, closes descriptors, and removes any unsealed path.
func (w *privateWorkspace) close() error {
	if w == nil {
		return nil
	}
	failed := false
	for _, file := range []*os.File{w.input, w.output} {
		if file == nil {
			continue
		}
		if err := file.Truncate(0); err != nil {
			failed = true
		}
		if err := file.Close(); err != nil {
			failed = true
		}
	}
	if w.root != "" {
		for _, name := range []string{"input", "output"} {
			err := os.Remove(filepath.Join(w.root, name))
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				failed = true
			}
		}
		err := os.Remove(w.root)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			failed = true
		}
	}
	w.input = nil
	w.output = nil
	w.root = ""
	if failed {
		return adapter.NewError(adapter.FailureResource)
	}
	return nil
}
