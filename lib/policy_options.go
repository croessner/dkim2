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
	receivedDSN             ReceivedDSNEvaluation
	modeSet                 bool
	maxAuthenticatedHopsSet bool
	maxFindingsSet          bool
	receivedDSNSet          bool
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

// WithReceivedDSNEvaluation attaches the read-only received-DSN evaluation of
// the same inbound message, so that one evaluation yields one PolicyDecision
// covering the outer verification and the received-DSN mapping table. The
// row selected in stage order is recorded as the last finding: reject,
// tempfail, and continue rows replace the outer verdict, accept rows keep it,
// and an outer verification or final replay state other than PASS keeps the
// outer policy. The caller must pass the evaluation produced for the message
// whose result is evaluated; the evaluation carries no identifiers, so the
// library cannot verify that binding. An invalid evaluation or a second use
// of the option is rejected.
func WithReceivedDSNEvaluation(evaluation ReceivedDSNEvaluation) PolicyOption {
	return func(config *policyConfig) error {
		if config == nil || config.receivedDSNSet || !evaluation.Valid() {
			return newPolicyError(PolicyErrorInvalidOption)
		}
		config.receivedDSN, config.receivedDSNSet = evaluation, true
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

// projection clones the sealed verification projection and, when a
// received-DSN evaluation was attached, seals its closed facts into the copy
// so the internal evaluator remains the single policy authority.
func (c policyConfig) projection(base policy.Projection) (policy.Projection, error) {
	projection := base.Clone()
	if !c.receivedDSNSet {
		return projection, nil
	}
	facts, err := c.receivedDSN.policyFacts()
	if err != nil {
		return policy.Projection{}, err
	}
	projection, err = projection.WithReceivedDSN(facts)
	if err != nil {
		return policy.Projection{}, adaptPolicyError(err)
	}
	return projection, nil
}

// internalConfig maps validated public configuration to the internal evaluator contract.
func (c policyConfig) internalConfig() policy.Config {
	return policy.Config{
		Mode:   policy.Mode(c.mode),
		Limits: policy.Limits{MaxAuthenticatedHops: c.maxAuthenticatedHops, MaxFindings: c.maxFindings, MaxActions: 1},
	}
}
