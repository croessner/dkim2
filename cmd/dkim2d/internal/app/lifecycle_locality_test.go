package app

import (
	"context"
	"strings"
	"testing"

	"github.com/croessner/dkim2"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/config"
	"github.com/croessner/dkim2/cmd/dkim2d/internal/propagationtest"
)

const localityTestTenant = "tenant-a"

// localitySnapshot loads one flat-file signing document that carries the
// process capability and, optionally, the originator route capability and the
// received-DSN locality tenant.
func localitySnapshot(t *testing.T, signRoute, tenant bool) config.Snapshot {
	t.Helper()
	document := `config:
  version: dkim2d-config-v1
protected:
  generation: ` + lifecyclePropagationGeneration + `
server:
  capability_file: /secure/` + lifecyclePropagationGeneration + `/capability
  sign_capability_file: /secure/` + lifecyclePropagationGeneration + `/sign-capability
replay:
  backend: disabled
signing:
  backend: flat_file
  datasource_file: /secure/` + lifecyclePropagationGeneration + `/datasource
  private_manifest_file: /secure/` + lifecyclePropagationGeneration + `/private-manifest
`
	if !signRoute {
		document = strings.Replace(
			document,
			"  sign_capability_file: /secure/"+lifecyclePropagationGeneration+"/sign-capability\n",
			"", 1,
		)
	}
	if tenant {
		document += "process:\n  default_tenant: " + localityTestTenant + "\n"
	}
	snapshot, err := config.Load([]byte(document), config.FlagValues{})
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return snapshot
}

// TestComposeSigningGenerationOmitsTheSignerWithoutRouteCapabilities proves a
// verification-only daemon composes the shared local-authority registry over
// the datasource without constructing a signing service, while the same
// generation with a route capability still composes one.
func TestComposeSigningGenerationOmitsTheSignerWithoutRouteCapabilities(t *testing.T) {
	corpus := propagationtest.Load(t)
	provider := corpus.Provider(t)
	authority := propagationtest.NewAuthority()
	authority.AddLocal(localityTestTenant, "local.example")
	seam := lifecycleAuthority{authority}

	operation, authorities, err := composeSigningGeneration(
		provider, seam, localitySnapshot(t, false, true),
	)
	if err != nil {
		t.Fatalf("verification-only composition error = %v", err)
	}
	if operation != nil {
		t.Fatal("verification-only composition constructed a signing service")
	}
	if !authorities.Available() {
		t.Fatal("verification-only composition lost the datasource authority")
	}
	resolver, err := authorities.resolverFor(localityTestTenant)
	if err != nil || nilInterface(resolver) {
		t.Fatalf("locality resolver error = %v", err)
	}
	status, err := resolver.LookupLocalAuthority(context.Background(), "local.example")
	if err != nil || status != dkim2.LocalAuthorityLocal {
		t.Fatalf("locality lookup status=%q error=%v", status, err)
	}
	status, err = resolver.LookupLocalAuthority(context.Background(), "foreign.example")
	if err != nil || status != dkim2.LocalAuthorityNotLocal {
		t.Fatalf("foreign lookup status=%q error=%v", status, err)
	}

	signing, signingAuthorities, err := composeSigningGeneration(
		provider, seam, localitySnapshot(t, true, true),
	)
	if err != nil || signing == nil || !signingAuthorities.Available() {
		t.Fatalf("route composition service=%v error=%v", signing != nil, err)
	}
	if _, _, err := composeSigningGeneration(provider, nil, localitySnapshot(t, true, true)); err == nil {
		t.Fatal("composition without an authority constructed a signing generation")
	}
}

// TestVerificationOnlyAssemblyInputRejectsAnUnexpectedSigner proves the
// transport assembly contract: the signing service must be absent exactly
// when no route capability authorizes a signing route, and present whenever
// one does.
func TestVerificationOnlyAssemblyInputRejectsAnUnexpectedSigner(t *testing.T) {
	corpus := propagationtest.Load(t)
	provider := corpus.Provider(t)
	authority := lifecycleAuthority{propagationtest.NewAuthority()}
	service, err := newSigningServiceOver(provider, authority, false)
	if err != nil {
		t.Fatalf("newSigningServiceOver() error = %v", err)
	}
	verification := localitySnapshot(t, false, true)
	if verification.Server().AnyRouteCapability() {
		t.Fatal("verification-only snapshot reported a route capability")
	}
	base := HTTPAssemblyInput{
		snapshot:    verification,
		processor:   &InboundProcessor{},
		readiness:   &Readiness{},
		fatal:       lifecycleAssemblyStub{},
		serveReturn: lifecycleAssemblyStub{},
		activation:  lifecycleAssemblyStub{},
		baseContext: context.Background(),
	}
	if !base.Valid() {
		t.Fatal("verification-only assembly input without a signer was refused")
	}
	if base.withOperation(service, config.SignCapability{}, config.ReviseCapability{},
		config.DSNSignCapability{}).Valid() {
		t.Fatal("verification-only assembly input accepted a signing service")
	}
	routed := base
	routed.snapshot = localitySnapshot(t, true, true)
	if routed.Valid() {
		t.Fatal("configured signing route assembled without a signing service")
	}
	if !routed.withOperation(service, config.SignCapability{}, config.ReviseCapability{},
		config.DSNSignCapability{}).Valid() {
		t.Fatal("configured signing route refused its signing service")
	}
}

// lifecycleAssemblyStub satisfies the narrow transport arbiter seams of one
// assembly input without owning any runtime resource.
type lifecycleAssemblyStub struct{}

// NotifyFatal records nothing; the assembly contract only requires presence.
func (lifecycleAssemblyStub) NotifyFatal() {}

// NotifyServeReturn records nothing for the assembly contract.
func (lifecycleAssemblyStub) NotifyServeReturn() {}

// AllowHTTPActivation refuses the one registration-gate transition.
func (lifecycleAssemblyStub) AllowHTTPActivation() bool { return false }
