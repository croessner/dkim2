package replay

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"sync"
)

const (
	// KeyAlgorithm identifies the frozen HMAC replay-key algorithm.
	KeyAlgorithm = "dkim2-replay-hmac-sha256-v1"
	// StoredValue is the exact bounded marker retained by enabled stores.
	StoredValue = "v1"

	keyDomainLabel       = "dkim2-replay-v1"
	keyNamespacePrefix   = "dkim2:replay:v1:"
	deriverRedactedText  = "replay_deriver"
	storageKeyByteLength = 68
)

// Deriver owns one cloned deployment-local HMAC secret and its lifecycle.
type Deriver struct {
	state *deriverState
}

// deriverState owns protected derivation state behind one format-safe handle.
type deriverState struct {
	closeOnce    sync.Once
	gate         *lifecycleGate
	secret       [32]byte
	epoch        uint32
	beforeHMAC   chan struct{}
	continueHMAC chan struct{}
}

// NewDeriver validates and clones one exact replay-key secret and epoch.
func NewDeriver(secret []byte, epoch uint32) (*Deriver, error) {
	if len(secret) != sha256.Size || epoch == 0 || allZero(secret) {
		return nil, NewError(ErrorCodeMisconfigured)
	}
	deriver := &Deriver{
		state: &deriverState{
			epoch: epoch,
			gate:  newLifecycleGate(StoreReady),
		},
	}
	copy(deriver.state.secret[:], secret)
	return deriver, nil
}

// Derive produces one protected fixed storage key from one sealed identity.
func (d *Deriver) Derive(ctx context.Context, identity Identity) (key Key, resultErr error) {
	if err := PreflightContext(ctx); err != nil {
		return Key{}, err
	}
	if d == nil || d.state == nil {
		return Key{}, NewError(ErrorCodeMisconfigured)
	}
	if err := d.state.gate.admit(StoreReady); err != nil {
		return Key{}, err
	}
	defer func() {
		d.finish()
		if recover() != nil {
			key = Key{}
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if !identity.Valid() {
		return Key{}, NewError(ErrorCodeInvalidRequest)
	}

	if d.state.beforeHMAC != nil {
		close(d.state.beforeHMAC)
	}
	if d.state.continueHMAC != nil {
		<-d.state.continueHMAC
	}

	frame := replayHMACFrame(identity)
	mac := hmac.New(sha256.New, d.state.secret[:])
	if _, err := mac.Write(frame); err != nil {
		return Key{}, NewError(ErrorCodeInternalInvariant)
	}
	digest := mac.Sum(nil)
	encoded := base64.RawURLEncoding.EncodeToString(digest)
	storage := fmt.Sprintf("%s%08x:%s", keyNamespacePrefix, d.state.epoch, encoded)
	if len(storage) != storageKeyByteLength {
		return Key{}, NewError(ErrorCodeInternalInvariant)
	}
	key.state = &keyState{}
	copy(key.state.storage[:], storage)
	if !validStorageKey(key) {
		return Key{}, NewError(ErrorCodeInternalInvariant)
	}
	return key, nil
}

// Close rejects new derives, drains admitted work, and clears the owned secret.
func (d *Deriver) Close(ctx context.Context) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if err := PreflightContext(ctx); err != nil {
		return err
	}
	if d == nil || d.state == nil {
		return NewError(ErrorCodeMisconfigured)
	}

	drained, err := d.state.gate.beginClose()
	if err != nil {
		return err
	}
	if err := waitForDrain(ctx, drained); err != nil {
		return err
	}
	return d.clearAndClose()
}

// String returns a constant representation without secret or epoch material.
func (Deriver) String() string { return deriverRedactedText }

// GoString returns a constant representation without secret or epoch material.
func (Deriver) GoString() string { return deriverRedactedText }

// Format prevents every formatting verb from exposing deriver state.
func (Deriver) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, deriverRedactedText)
}

// finish releases one derive and performs owner cleanup after a timed-out close.
func (d *Deriver) finish() {
	d.state.gate.finish()
	if d.state.gate.drainedNow() {
		_ = d.clearAndClose()
	}
}

// clearAndClose clears owned secret bytes exactly once and publishes closed.
func (d *Deriver) clearAndClose() error {
	d.state.closeOnce.Do(func() {
		for index := range d.state.secret {
			d.state.secret[index] = 0
		}
	})
	return d.state.gate.publishClosed()
}

// UseStorageKey authorizes one synchronous pre-dispatch callback for a protected key.
func UseStorageKey(key Key, use func(string) error) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = NewError(ErrorCodeInternalInvariant)
		}
	}()
	if !validStorageKey(key) || use == nil {
		return NewError(ErrorCodeInvalidRequest)
	}
	storage, present := key.storageValue()
	if !present {
		return NewError(ErrorCodeInvalidRequest)
	}
	if err := use(string(storage[:])); err != nil {
		if IsTypedError(err) {
			return err
		}
		return NewError(ErrorCodeInternalInvariant)
	}
	return nil
}

// replayHMACFrame builds the exact versioned length-delimited identity input.
func replayHMACFrame(identity Identity) []byte {
	state := identity.state
	frame := make([]byte, 0, 161)
	frame = append(frame, keyDomainLabel...)
	frame = append(frame, 0, 1)
	frame = appendUint32Bytes(frame, []byte(DraftIdentifier))
	frame = append(frame, 2)
	frame = appendUint32Bytes(frame, state.messageDigest[:])
	frame = append(frame, 3)
	frame = appendUint32Bytes(frame, state.signatureInputDigest[:])
	frame = append(frame, 4)
	frame = appendUint32Bytes(frame, state.recipientDigest[:])
	return frame
}

// appendUint32Bytes appends one unsigned big-endian byte-string length and value.
func appendUint32Bytes(output []byte, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	output = append(output, length[:]...)
	return append(output, value...)
}

// validStorageKey validates the exact fixed namespace and encoding grammar.
func validStorageKey(key Key) bool {
	storage, present := key.storageValue()
	if !present {
		return false
	}
	value := string(storage[:])
	if len(value) != storageKeyByteLength || !strings.HasPrefix(value, keyNamespacePrefix) ||
		value[24] != ':' {
		return false
	}
	for _, character := range value[16:24] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	epoch := binary.BigEndian.Uint32([]byte{
		fromLowerHex(value[16])<<4 | fromLowerHex(value[17]),
		fromLowerHex(value[18])<<4 | fromLowerHex(value[19]),
		fromLowerHex(value[20])<<4 | fromLowerHex(value[21]),
		fromLowerHex(value[22])<<4 | fromLowerHex(value[23]),
	})
	if epoch == 0 {
		return false
	}
	encoding := base64.RawURLEncoding.Strict()
	encoded := value[25:]
	decoded, err := encoding.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size &&
		encoding.EncodeToString(decoded) == encoded
}

// fromLowerHex decodes one already-validated lowercase hexadecimal digit.
func fromLowerHex(value byte) byte {
	if value >= '0' && value <= '9' {
		return value - '0'
	}
	return value - 'a' + 10
}

// allZero reports whether every secret byte is zero.
func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
