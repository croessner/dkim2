package domainadmin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOperatorDomainExamplesValidate proves the committed onboarding examples
// are accepted by the authoritative protected configuration and intent loaders.
func TestOperatorDomainExamplesValidate(t *testing.T) {
	root := filepath.Join("..", "..", "..", "..")
	exampleRoot := filepath.Join(root, "docs", "operator", "examples")
	adminDocument, err := os.ReadFile(filepath.Join(exampleRoot, "dkim2d-domain-admin-ldap.yaml"))
	if err != nil {
		t.Fatal("read committed domain administration example")
	}
	protectedRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(protectedRoot, 0o700) != nil {
		t.Fatal("protect operator example fixture directory")
	}
	caPath := filepath.Join(protectedRoot, "ca.pem")
	writeTestCA(t, caPath)
	replacements := map[string]string{
		"/run/dkim2/domain-admin/ca.pem":              caPath,
		"/run/dkim2/domain-admin/snapshot.password":   filepath.Join(protectedRoot, "snapshot.password"),
		"/run/dkim2/domain-admin/staging.password":    filepath.Join(protectedRoot, "staging.password"),
		"/run/dkim2/domain-admin/activation.password": filepath.Join(protectedRoot, "activation.password"),
	}
	for placeholder, path := range replacements {
		adminDocument = []byte(strings.ReplaceAll(string(adminDocument), placeholder, path))
	}
	for _, name := range []string{"snapshot.password", "staging.password", "activation.password"} {
		if err := os.WriteFile(filepath.Join(protectedRoot, name), []byte("protected-"+name+"\n"), 0o600); err != nil {
			t.Fatal("write protected operator example credential")
		}
	}
	adminPath := filepath.Join(protectedRoot, "admin.yaml")
	if err := os.WriteFile(adminPath, adminDocument, 0o600); err != nil {
		t.Fatal("write protected operator administration example")
	}
	configuration, err := LoadAdminConfig(adminPath)
	if err != nil || configuration == nil {
		t.Fatalf("operator administration example rejected: %s", CodeOf(err))
	}
	_ = configuration.Close()

	intentDocument, err := os.ReadFile(filepath.Join(exampleRoot, "dkim2d-domain-intent.yaml"))
	if err != nil {
		t.Fatal("read committed domain intent example")
	}
	intentPath := filepath.Join(protectedRoot, "intent.yaml")
	if err := os.WriteFile(intentPath, intentDocument, 0o600); err != nil {
		t.Fatal("write protected operator intent example")
	}
	intent, err := LoadIntent(intentPath)
	if err != nil || intent.Domain() != "mail.example.test" || len(intent.Algorithms()) != 2 {
		t.Fatalf("operator intent example rejected: %s", CodeOf(err))
	}
}
