package reference

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

const (
	vendorLDAPMD4Import  = `"golang.org/x/crypto/md4" //nolint:staticcheck`
	vendorLocalMD4Import = `"github.com/go-ldap/ldap/v3/internal/md4"`
	vendorCryptoBlock    = "# golang.org/x/crypto v0.54.0\n## explicit; go 1.25.0\ngolang.org/x/crypto/md4\n"
	vendorCryptoMetadata = "# golang.org/x/crypto v0.54.0\n## explicit; go 1.25.0\n"
	vendorLDAPPackage    = "github.com/go-ldap/ldap/v3\n"
	vendorLocalMD4       = "github.com/go-ldap/ldap/v3/internal/md4\n"
)

var vendorCryptoPaths = []string{
	"LICENSE",
	"PATENTS",
	"md4/md4.go",
	"md4/md4block.go",
}

// HardenVendorTree applies the reviewed source-preserving compatibility delta
// to a freshly generated workspace vendor tree.
func HardenVendorTree(root string) error {
	return hardenVendorTree(filepath.Join(root, "vendor"))
}

// hardenVendorTree relocates the sole required MD4 package into go-ldap while
// retaining only the explicit x/crypto requirement metadata needed by Go.
func hardenVendorTree(vendorRoot string) error {
	bindPath := filepath.Join(vendorRoot, "github.com", "go-ldap", "ldap", "v3", "bind.go")
	modulesPath := filepath.Join(vendorRoot, "modules.txt")
	cryptoRoot := filepath.Join(vendorRoot, "golang.org", "x", "crypto")
	targetRoot := filepath.Join(vendorRoot, "github.com", "go-ldap", "ldap", "v3", "internal", "md4")

	bind, err := readStableRegular(bindPath, 4<<20)
	if err != nil || bytes.Count(bind, []byte(vendorLDAPMD4Import)) != 1 ||
		bytes.Contains(bind, []byte(vendorLocalMD4Import)) {
		return errors.New("vendor_harden")
	}
	modules, err := readStableRegular(modulesPath, 4<<20)
	if err != nil || bytes.Count(modules, []byte(vendorCryptoBlock)) != 1 ||
		bytes.Count(modules, []byte(vendorLDAPPackage)) != 1 ||
		bytes.Contains(modules, []byte(vendorLocalMD4)) {
		return errors.New("vendor_harden")
	}
	paths, err := regularTreePaths(cryptoRoot)
	if err != nil || !slices.Equal(paths, vendorCryptoPaths) {
		return errors.New("vendor_harden")
	}
	if _, err := os.Lstat(targetRoot); !os.IsNotExist(err) {
		return errors.New("vendor_harden")
	}
	content := make(map[string][]byte, len(vendorCryptoPaths))
	for _, path := range vendorCryptoPaths {
		value, err := readStableRegular(filepath.Join(cryptoRoot, filepath.FromSlash(path)), 4<<20)
		if err != nil {
			return errors.New("vendor_harden")
		}
		content[path] = value
	}

	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		return errors.New("vendor_harden")
	}
	for _, path := range vendorCryptoPaths {
		name := filepath.Base(path)
		if err := os.WriteFile(filepath.Join(targetRoot, name), content[path], 0o644); err != nil {
			return errors.New("vendor_harden")
		}
	}
	bind = bytes.Replace(bind, []byte(vendorLDAPMD4Import), []byte(vendorLocalMD4Import), 1)
	if err := os.WriteFile(bindPath, bind, 0o644); err != nil {
		return errors.New("vendor_harden")
	}
	modules = bytes.Replace(modules, []byte(vendorLDAPPackage), []byte(vendorLDAPPackage+vendorLocalMD4), 1)
	modules = bytes.Replace(modules, []byte(vendorCryptoBlock), []byte(vendorCryptoMetadata), 1)
	if err := os.WriteFile(modulesPath, modules, 0o644); err != nil {
		return errors.New("vendor_harden")
	}
	for index := len(vendorCryptoPaths) - 1; index >= 0; index-- {
		if err := os.Remove(filepath.Join(cryptoRoot, filepath.FromSlash(vendorCryptoPaths[index]))); err != nil {
			return errors.New("vendor_harden")
		}
	}
	for _, directory := range []string{
		filepath.Join(cryptoRoot, "md4"),
		cryptoRoot,
	} {
		if err := os.Remove(directory); err != nil {
			return errors.New("vendor_harden")
		}
	}
	return nil
}
