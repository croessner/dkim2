package dkim2

import "github.com/croessner/dkim2/internal/policy"

const (
	// HardMaxPolicyAuthenticatedHops bounds authenticated facts consumed by one public evaluation.
	HardMaxPolicyAuthenticatedHops = 128
	// HardMaxPolicyFindings bounds retained findings returned by one public evaluation.
	HardMaxPolicyFindings = 128
)

type policyConfig struct {
	mode                    PolicyMode
	maxAuthenticatedHops    int
	maxFindings             int
	modeSet                 bool
	maxAuthenticatedHopsSet bool
	maxFindingsSet          bool
}

// PolicyOption narrows one public policy setting exactly once.
type PolicyOption func(*policyConfig) error

// WithPolicyMode selects one explicit local policy posture.
func WithPolicyMode(mode PolicyMode) PolicyOption {
	return func(config *policyConfig) error {
		if config == nil || config.modeSet || !mode.Known() {
			return newPolicyError(PolicyErrorInvalidOption)
		}
		config.mode, config.modeSet = mode, true
		return nil
	}
}

// WithPolicyMaxAuthenticatedHops narrows the authenticated-hop evaluation limit.
func WithPolicyMaxAuthenticatedHops(limit int) PolicyOption {
	return func(config *policyConfig) error {
		if config == nil || config.maxAuthenticatedHopsSet || limit <= 0 || limit > HardMaxPolicyAuthenticatedHops {
			return newPolicyError(PolicyErrorInvalidOption)
		}
		config.maxAuthenticatedHops, config.maxAuthenticatedHopsSet = limit, true
		return nil
	}
}

// WithPolicyMaxFindings narrows the retained-finding evaluation limit.
func WithPolicyMaxFindings(limit int) PolicyOption {
	return func(config *policyConfig) error {
		if config == nil || config.maxFindingsSet || limit <= 0 || limit > HardMaxPolicyFindings {
			return newPolicyError(PolicyErrorInvalidOption)
		}
		config.maxFindings, config.maxFindingsSet = limit, true
		return nil
	}
}

// applyPolicyOptions validates options atomically and returns zero configuration on failure.
func applyPolicyOptions(options ...PolicyOption) (policyConfig, error) {
	config := policyConfig{mode: PolicyModeStrict, maxAuthenticatedHops: HardMaxPolicyAuthenticatedHops, maxFindings: HardMaxPolicyFindings}
	for _, option := range options {
		if option == nil {
			return policyConfig{}, newPolicyError(PolicyErrorInvalidOption)
		}
		if err := option(&config); err != nil {
			return policyConfig{}, newPolicyError(PolicyErrorInvalidOption)
		}
	}
	return config, nil
}

// internalConfig maps validated public configuration to the internal evaluator contract.
func (c policyConfig) internalConfig() policy.Config {
	return policy.Config{
		Mode:   policy.Mode(c.mode),
		Limits: policy.Limits{MaxAuthenticatedHops: c.maxAuthenticatedHops, MaxFindings: c.maxFindings, MaxActions: 1},
	}
}
