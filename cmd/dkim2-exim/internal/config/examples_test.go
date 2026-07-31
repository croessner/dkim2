package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestPackagedExamplesMatchStableSchema proves every installed snapshot is usable.
func TestPackagedExamplesMatchStableSchema(t *testing.T) {
	t.Setenv("DKIM2_EXIM_UID", strconv.Itoa(os.Geteuid()))
	cases := map[string]Operation{
		"inbound.yaml": OperationInbound,
		"sign.yaml":    OperationSign,
		"revise.yaml":  OperationRevise,
	}
	for name, operation := range cases {
		data, err := os.ReadFile(filepath.Join("..", "..", "examples", "config", name))
		if err != nil {
			t.Fatal("packaged config example could not be read")
		}
		if _, err := DecodeForOperation(data, operation); err != nil {
			t.Fatal("packaged config example violates the stable schema")
		}
	}
}
