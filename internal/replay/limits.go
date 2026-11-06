package replay

// Limits contains reusable hard-bounded replay provider resources.
type Limits struct {
	MaxEntries          int
	MaxWaiters          int
	PruneBudget         int
	MaxInFlight         int
	MaxAdmissionWaiters int
}

// DefaultLimits returns the frozen restrictive provider defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:          65_536,
		MaxWaiters:          1_024,
		PruneBudget:         4_096,
		MaxInFlight:         1_024,
		MaxAdmissionWaiters: 1_024,
	}
}

// HardLimits returns every non-widenable provider maximum.
func HardLimits() Limits {
	return Limits{
		MaxEntries:          1_048_576,
		MaxWaiters:          65_536,
		PruneBudget:         65_536,
		MaxInFlight:         65_536,
		MaxAdmissionWaiters: 65_536,
	}
}

// ResolveLimits applies per-field defaults and validates every hard bound.
func ResolveLimits(config Limits) (Limits, error) {
	defaults := DefaultLimits()
	if config.MaxEntries == 0 {
		config.MaxEntries = defaults.MaxEntries
	}
	if config.MaxWaiters == 0 {
		config.MaxWaiters = defaults.MaxWaiters
	}
	if config.PruneBudget == 0 {
		config.PruneBudget = defaults.PruneBudget
	}
	if config.MaxInFlight == 0 {
		config.MaxInFlight = defaults.MaxInFlight
	}
	if config.MaxAdmissionWaiters == 0 {
		config.MaxAdmissionWaiters = defaults.MaxAdmissionWaiters
	}
	if err := config.Validate(); err != nil {
		return Limits{}, err
	}
	return config, nil
}

// Validate rejects incomplete, negative, or widened resource bounds.
func (l Limits) Validate() error {
	hard := HardLimits()
	values := []struct {
		value   int
		maximum int
	}{
		{l.MaxEntries, hard.MaxEntries},
		{l.MaxWaiters, hard.MaxWaiters},
		{l.PruneBudget, hard.PruneBudget},
		{l.MaxInFlight, hard.MaxInFlight},
		{l.MaxAdmissionWaiters, hard.MaxAdmissionWaiters},
	}
	for _, candidate := range values {
		if candidate.value <= 0 || candidate.value > candidate.maximum {
			return NewError(ErrorCodeMisconfigured)
		}
	}
	return nil
}
