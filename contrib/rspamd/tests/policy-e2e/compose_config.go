//go:build ignore

// Copyright 2026 Christian Roessner
// SPDX-License-Identifier: Apache-2.0

// This fixture command runs from the matching Nauthilus checkout to reuse its canonical example merger.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/policy/testsupport"
	"gopkg.in/yaml.v3"
)

// object returns one required fixture mapping without coercing malformed input.
func object(parent map[string]any, name string) (map[string]any, error) {
	value, ok := parent[name].(map[string]any)
	if !ok {
		return nil, errors.New("fixture mapping is missing")
	}

	return value, nil
}

// clients detaches exact API principals before the documented scalar-list replacement merge.
func clients(fragment map[string]any, known map[string]bool) ([]any, error) {
	policy, err := object(fragment, "policy")
	if err != nil {
		return nil, nil
	}

	api, err := object(policy, "api")
	if err != nil {
		return nil, nil
	}

	items, ok := api["clients"].([]any)
	if !ok {
		return nil, nil
	}

	for _, item := range items {
		client, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("fixture API client must be a mapping")
		}

		principal, ok := client["principal"].(string)
		if !ok || principal == "" || known[principal] {
			return nil, errors.New("fixture API principals must be explicit and unique")
		}

		known[principal] = true
	}

	delete(api, "clients")

	return items, nil
}

// readFixture bounds allocation before decoding one tracked configuration fragment.
func readFixture(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open fixture input")
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 1048577))
	if err != nil || len(data) > 1048576 {
		return nil, errors.New("cannot read bounded fixture input")
	}

	return data, nil
}

// merge uses the real host example composition rules and preserves distinct API caller authorities.
func merge(paths []string) (map[string]any, error) {
	result := make(map[string]any)
	known := make(map[string]bool)
	var callers []any

	for _, path := range paths {
		data, err := readFixture(path)
		if err != nil {
			return nil, errors.New("cannot read bounded fixture input")
		}

		var fragment map[string]any
		if err := yaml.Unmarshal(data, &fragment); err != nil {
			return nil, errors.New("invalid fixture YAML")
		}

		additional, err := clients(fragment, known)
		if err != nil {
			return nil, err
		}

		callers = append(callers, additional...)
		result = testsupport.MergeExample(result, fragment).(map[string]any)
	}

	policy, err := object(result, "policy")
	if err != nil {
		return nil, err
	}

	api, err := object(policy, "api")
	if err != nil {
		return nil, err
	}

	api["clients"] = callers

	return result, nil
}

// preserveNumericKinds retains authored float scalars when the final configuration is loaded as YAML.
func preserveNumericKinds(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = preserveNumericKinds(item)
		}
	case []any:
		for index, item := range typed {
			typed[index] = preserveNumericKinds(item)
		}
	case float64:
		scalar := strconv.FormatFloat(typed, 'g', -1, 64)
		if !strings.ContainsAny(scalar, ".eE") {
			scalar += ".0"
		}

		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: scalar}
	}

	return value
}

// run writes one protected complete YAML configuration without resolving or rendering credentials.
func run(args []string) error {
	if len(args) < 2 || len(args) > 17 {
		return errors.New("usage: compose_config.go OUTPUT INPUT...")
	}

	configuration, err := merge(args[1:])
	if err != nil {
		return err
	}

	data, err := yaml.Marshal(preserveNumericKinds(configuration))
	if err != nil {
		return errors.New("cannot encode composed fixture")
	}

	file, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("cannot create protected fixture output")
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return errors.New("cannot write fixture output")
	}

	return nil
}

// main exposes only bounded fixture-generation failure categories.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
