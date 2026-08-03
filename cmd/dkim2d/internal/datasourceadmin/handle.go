package datasourceadmin

import "github.com/croessner/dkim2/provider"

// ValidateHandleDeclaration delegates opaque-handle grammar and bounds to the public dataset owner.
func ValidateHandleDeclaration(value string) error {
	dataset, err := provider.NewDataset(
		1, []string{value}, nil, nil, provider.DefaultLimits(),
	)
	if err != nil || dataset == nil || !dataset.Valid() || dataset.Generation() != 1 {
		return newError(CodeInvalid)
	}
	return nil
}
