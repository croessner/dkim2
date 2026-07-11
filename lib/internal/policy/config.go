package policy

const (
	hardMaxAuthenticatedHops = 128
	hardMaxFindings          = 128
	hardMaxActions           = 1
)

// Limits bounds authenticated facts and retained policy output.
type Limits struct {
	MaxAuthenticatedHops int
	MaxFindings          int
	MaxActions           int
}

// DefaultLimits returns the restrictive policy hard maxima.
func DefaultLimits() Limits {
	return Limits{MaxAuthenticatedHops: hardMaxAuthenticatedHops, MaxFindings: hardMaxFindings, MaxActions: hardMaxActions}
}

// Validate rejects zero, negative, or widening policy limits.
func (l Limits) Validate() error {
	if l.MaxAuthenticatedHops <= 0 || l.MaxAuthenticatedHops > hardMaxAuthenticatedHops ||
		l.MaxFindings <= 0 || l.MaxFindings > hardMaxFindings ||
		l.MaxActions <= 0 || l.MaxActions > hardMaxActions {
		return newError(ErrorInvalidConfig)
	}
	return nil
}

// Config contains immutable evaluator policy and resource limits.
type Config struct {
	Mode   Mode
	Limits Limits
}

// DefaultConfig returns strict policy with hard-bounded defaults.
func DefaultConfig() Config { return Config{Mode: ModeStrict, Limits: DefaultLimits()} }

// Validate rejects unknown mode or unsafe limits.
func (c Config) Validate() error {
	if !c.Mode.Known() {
		return newError(ErrorInvalidConfig)
	}
	return c.Limits.Validate()
}
