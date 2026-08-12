package rotationruntime

import (
	"os"
	"testing"

	"github.com/croessner/dkim2/cmd/dkim2d/internal/testsupport"
)

func TestMain(suite *testing.M) {
	os.Exit(testsupport.RunWithTrustedTemp(suite))
}
