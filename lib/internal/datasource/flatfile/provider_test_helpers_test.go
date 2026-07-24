package flatfile

import "github.com/croessner/dkim2/internal/datasource"

const (
	flatfileProviderName     = "provider.json"
	flatfileCloseOperation   = "close"
	flatfileReloadOperation  = "reload"
	flatfileReservedConsole  = "CON"
	flatfileReservedNullName = "NUL"
)

// flatfileProviderState returns an opaque lifecycle state for nil-safe diagnostics.
func flatfileProviderState(provider *Provider) datasource.ProviderState {
	if provider == nil {
		return 0
	}
	state, err := provider.State()
	if err != nil {
		return 0
	}
	return state
}
