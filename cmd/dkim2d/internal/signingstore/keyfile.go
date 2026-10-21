package signingstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/croessner/dkim2/provider"
)

// GeneratedKeyFile is the public outcome of writing one new custody key: the
// canonical public SPKI and its SHA-256 manifest identity. It never carries
// private material.
type GeneratedKeyFile struct {
	PublicSPKI       []byte
	PublicSPKISHA256 [sha256.Size]byte
}

// WriteGeneratedKeyFile generates one custody key for algorithm and writes it
// as an unencrypted PKCS#8 PEM to a new owner-only file at path. The path must
// be absolute and clean and must not exist; an existing file or symlink is
// never replaced. A partial file is removed on failure. The private key never
// leaves this function except through the file.
func WriteGeneratedKeyFile(path string, algorithm provider.Algorithm, rsaBits int) (GeneratedKeyFile, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return GeneratedKeyFile{}, &Error{}
	}
	privatePKCS8, spki, err := GeneratePrivateKey(algorithm, rand.Reader, rsaBits)
	if err != nil {
		return GeneratedKeyFile{}, &Error{}
	}
	defer clear(privatePKCS8)
	encoded := pem.EncodeToMemory(&pem.Block{Type: privateKeyPEMType, Bytes: privatePKCS8})
	defer clear(encoded)
	if len(encoded) == 0 || len(encoded) > maxPrivateBytes {
		return GeneratedKeyFile{}, &Error{}
	}
	if err := writeExclusiveOwnerFile(path, encoded); err != nil {
		return GeneratedKeyFile{}, &Error{}
	}
	return GeneratedKeyFile{PublicSPKI: spki, PublicSPKISHA256: sha256.Sum256(spki)}, nil
}

// writeExclusiveOwnerFile creates path with mode 0600, writes data, and syncs
// it. It removes the file again when any step after creation fails.
func writeExclusiveOwnerFile(path string, data []byte) (resultErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := file.Close()
		if resultErr == nil {
			resultErr = closeErr
		}
		if resultErr != nil {
			_ = os.Remove(path)
		}
	}()
	if written, err := file.Write(data); err != nil || written != len(data) {
		return errors.Join(err, errShortWrite)
	}
	return file.Sync()
}

// errShortWrite reports an incomplete key-file write.
var errShortWrite = errors.New("short key file write")
