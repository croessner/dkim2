package config

import (
	"bytes"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// mergeValues captures explicit source presence, applies precedence, and proves
// the owned result against one isolated Viper merge.
func mergeValues(yamlBytes []byte, yamlValues map[string]rawValue, flags FlagValues) (map[string]rawValue, map[string]Presence, error) {
	specs := stableFieldSpecs()
	specByPath, err := indexFieldSpecs(specs)
	if err != nil {
		return nil, nil, err
	}
	if err := validateYAMLValues(yamlValues, specByPath); err != nil {
		return nil, nil, err
	}

	environment := captureEnvironment(specs)
	if err := validateSourceAggregate(specs, yamlValues, environment, flags); err != nil {
		return nil, nil, err
	}
	presence := capturePresence(specs, yamlValues, environment, flags)
	merged, err := applySourcePrecedence(specs, yamlValues, environment, flags, presence)
	if err != nil {
		return nil, nil, err
	}
	if err := proveViperMerge(yamlBytes, specs, merged, presence, flags, specByPath); err != nil {
		return nil, nil, err
	}

	return merged, presence, nil
}

// indexFieldSpecs validates the literal schema and returns a path lookup.
func indexFieldSpecs(specs []fieldSpec) (map[string]fieldSpec, error) {
	indexed := make(map[string]fieldSpec, len(specs))
	environments := make(map[string]struct{}, len(specs))
	flags := make(map[string]struct{}, 3)
	for _, spec := range specs {
		if spec.path == "" {
			return nil, newError(CodeInternal)
		}
		if _, exists := indexed[spec.path]; exists {
			return nil, newError(CodeInternal)
		}
		indexed[spec.path] = spec

		if spec.yamlOnly {
			if spec.env != "" || spec.flag != "" {
				return nil, newError(CodeInternal)
			}
			continue
		}
		expectedEnvironment := "DKIM2D_" + strings.ToUpper(strings.ReplaceAll(spec.path, ".", "_"))
		if spec.env != expectedEnvironment {
			return nil, newError(CodeInternal)
		}
		if _, exists := environments[spec.env]; exists {
			return nil, newError(CodeInternal)
		}
		environments[spec.env] = struct{}{}
		if spec.flag != "" {
			if _, exists := flags[spec.flag]; exists {
				return nil, newError(CodeInternal)
			}
			flags[spec.flag] = struct{}{}
		}
	}
	if len(flags) != 3 {
		return nil, newError(CodeInternal)
	}
	for _, name := range []string{flagListen, flagPolicyMode, flagReplayBackend} {
		if _, exists := flags[name]; !exists {
			return nil, newError(CodeInternal)
		}
	}
	return indexed, nil
}

// validateYAMLValues rejects unknown paths and invalid preflight provenance.
func validateYAMLValues(values map[string]rawValue, specs map[string]fieldSpec) error {
	for path, value := range values {
		if _, exists := specs[path]; !exists {
			return newError(CodeInvalidSource)
		}
		if value.source != SourceYAML {
			return newError(CodeInvalidSource)
		}
		switch value.kind {
		case scalarString, scalarBool, scalarUint:
		default:
			return newError(CodeInvalidSource)
		}
	}
	return nil
}

// captureEnvironment reads each literal binding exactly once.
func captureEnvironment(specs []fieldSpec) map[string]rawValue {
	values := make(map[string]rawValue)
	for _, spec := range specs {
		if spec.env == "" {
			continue
		}
		value, present := os.LookupEnv(spec.env)
		if !present {
			continue
		}
		values[spec.path] = rawValue{
			text:   strings.Clone(value),
			kind:   scalarString,
			source: SourceEnvironment,
		}
	}
	return values
}

// validateSourceAggregate charges every explicit key and value before expansion.
func validateSourceAggregate(specs []fieldSpec, yamlValues, environment map[string]rawValue, flags FlagValues) error {
	total := 0
	charge := func(path string, value rawValue) bool {
		if len(value.text) > maxScalarBytes {
			return false
		}
		total += len(path) + len(value.text)
		return total <= maxAggregateBytes
	}
	for path, value := range yamlValues {
		if !charge(path, value) {
			return newError(CodeInvalidField)
		}
	}
	for path, value := range environment {
		if !charge(path, value) {
			return newError(CodeInvalidField)
		}
	}
	for _, spec := range specs {
		if value, present := flagValueForSpec(spec, flags); present && !charge(spec.path, value) {
			return newError(CodeInvalidField)
		}
	}
	return nil
}

// capturePresence freezes every explicit source bit and its eventual winner
// before defaults are materialized.
func capturePresence(specs []fieldSpec, yamlValues, environment map[string]rawValue, flags FlagValues) map[string]Presence {
	presence := make(map[string]Presence, len(specs))
	for _, spec := range specs {
		_, yamlPresent := yamlValues[spec.path]
		_, environmentPresent := environment[spec.path]
		_, flagPresent := flagValueForSpec(spec, flags)

		winner := Source(0)
		switch {
		case flagPresent:
			winner = SourceFlag
		case environmentPresent:
			winner = SourceEnvironment
		case yamlPresent:
			winner = SourceYAML
		case spec.hasDefault:
			winner = SourceDefault
		}
		presence[spec.path] = Presence{
			YAML:        yamlPresent,
			Environment: environmentPresent,
			Flag:        flagPresent,
			Winner:      winner,
		}
	}
	return presence
}

// applySourcePrecedence materializes winners without changing frozen presence.
func applySourcePrecedence(
	specs []fieldSpec,
	yamlValues map[string]rawValue,
	environment map[string]rawValue,
	flags FlagValues,
	presence map[string]Presence,
) (map[string]rawValue, error) {
	merged := make(map[string]rawValue, len(specs))
	for _, spec := range specs {
		switch presence[spec.path].Winner {
		case SourceFlag:
			value, present := flagValueForSpec(spec, flags)
			if !present {
				return nil, newError(CodeInternal)
			}
			merged[spec.path] = value
		case SourceEnvironment:
			value, present := environment[spec.path]
			if !present {
				return nil, newError(CodeInternal)
			}
			merged[spec.path] = value
		case SourceYAML:
			value, present := yamlValues[spec.path]
			if !present {
				return nil, newError(CodeInternal)
			}
			merged[spec.path] = value
		case SourceDefault:
			value, err := defaultRawValue(spec)
			if err != nil {
				return nil, err
			}
			merged[spec.path] = value
		case 0:
		default:
			return nil, newError(CodeInternal)
		}
	}
	return merged, nil
}

// flagValueForSpec selects one of the three closed flag inputs.
func flagValueForSpec(spec fieldSpec, flags FlagValues) (rawValue, bool) {
	var flag flagValue
	if flags.state == nil {
		return rawValue{}, false
	}
	switch spec.flag {
	case "":
		return rawValue{}, false
	case flagListen:
		flag = flags.state.listen
	case flagPolicyMode:
		flag = flags.state.policyMode
	case flagReplayBackend:
		flag = flags.state.replayBackend
	default:
		return rawValue{}, false
	}
	if !flag.changed {
		return rawValue{}, false
	}
	return rawValue{
		text:   flag.value,
		kind:   scalarString,
		source: SourceFlag,
	}, true
}

// defaultRawValue converts one declared typed default into its owned raw form.
func defaultRawValue(spec fieldSpec) (rawValue, error) {
	if !spec.hasDefault {
		return rawValue{}, newError(CodeInternal)
	}
	kind := scalarString
	switch spec.kind {
	case valueString, valueDuration:
	case valueBool:
		if spec.defaultVal != canonicalTrue && spec.defaultVal != canonicalFalse {
			return rawValue{}, newError(CodeInternal)
		}
		kind = scalarBool
	case valueUint:
		if _, err := strconv.ParseUint(spec.defaultVal, 10, 64); err != nil {
			return rawValue{}, newError(CodeInternal)
		}
		kind = scalarUint
	default:
		return rawValue{}, newError(CodeInternal)
	}
	return rawValue{
		text:   spec.defaultVal,
		kind:   kind,
		source: SourceDefault,
	}, nil
}

// proveViperMerge independently applies the declared layers and requires exact
// scalar equality with the owned canonical merge.
func proveViperMerge(
	yamlBytes []byte,
	specs []fieldSpec,
	merged map[string]rawValue,
	presence map[string]Presence,
	flags FlagValues,
	specByPath map[string]fieldSpec,
) error {
	checked := viper.New()
	checked.AllowEmptyEnv(true)
	checked.SetConfigType("yaml")
	if err := checked.ReadConfig(bytes.NewReader(yamlBytes)); err != nil {
		return newError(CodeInternal)
	}
	for _, spec := range specs {
		if spec.env != "" {
			if err := checked.BindEnv(spec.path, spec.env); err != nil {
				return newError(CodeInternal)
			}
		}
		if value, present := flagValueForSpec(spec, flags); present {
			checked.Set(spec.path, value.text)
		}
	}

	// Defaults are installed only after the explicit presence map is complete.
	for _, spec := range specs {
		if !spec.hasDefault {
			continue
		}
		value, err := defaultRawValue(spec)
		if err != nil {
			return err
		}
		typed, err := viperScalar(value)
		if err != nil {
			return err
		}
		checked.SetDefault(spec.path, typed)
	}

	for _, key := range checked.AllKeys() {
		if _, exists := specByPath[key]; !exists {
			return newError(CodeInternal)
		}
	}
	for _, spec := range specs {
		expected, present := merged[spec.path]
		if !present {
			if checked.IsSet(spec.path) {
				return newError(CodeInternal)
			}
			continue
		}
		actual, err := rawViperScalar(checked.Get(spec.path), presence[spec.path].Winner)
		if err != nil {
			return err
		}
		if actual.text != expected.text || actual.kind != expected.kind {
			return newError(CodeInternal)
		}
	}
	return nil
}

// viperScalar supplies typed defaults without weak conversion.
func viperScalar(value rawValue) (any, error) {
	switch value.kind {
	case scalarString:
		return value.text, nil
	case scalarBool:
		switch value.text {
		case "true":
			return true, nil
		case "false":
			return false, nil
		default:
			return nil, newError(CodeInternal)
		}
	case scalarUint:
		parsed, err := strconv.ParseUint(value.text, 10, 64)
		if err != nil {
			return nil, newError(CodeInternal)
		}
		return parsed, nil
	default:
		return nil, newError(CodeInternal)
	}
}

// rawViperScalar converts only exact scalar types into content-owned text.
func rawViperScalar(value any, source Source) (rawValue, error) {
	raw := rawValue{source: source}
	switch typed := value.(type) {
	case string:
		raw.text = typed
		raw.kind = scalarString
	case bool:
		raw.text = strconv.FormatBool(typed)
		raw.kind = scalarBool
	case int:
		if typed < 0 {
			return rawValue{}, newError(CodeInternal)
		}
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case int8:
		if typed < 0 {
			return rawValue{}, newError(CodeInternal)
		}
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case int16:
		if typed < 0 {
			return rawValue{}, newError(CodeInternal)
		}
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case int32:
		if typed < 0 {
			return rawValue{}, newError(CodeInternal)
		}
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case int64:
		if typed < 0 {
			return rawValue{}, newError(CodeInternal)
		}
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case uint:
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case uint8:
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case uint16:
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case uint32:
		raw.text = strconv.FormatUint(uint64(typed), 10)
		raw.kind = scalarUint
	case uint64:
		raw.text = strconv.FormatUint(typed, 10)
		raw.kind = scalarUint
	default:
		return rawValue{}, newError(CodeInternal)
	}
	return raw, nil
}
