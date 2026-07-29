// Package containerownership validates project-scoped container-engine objects.
//
//nolint:goconst // Closed engine object classes stay explicit in each ownership branch.
package containerownership

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/croessner/dkim2/tools/internal/strictjson"
)

const projectLabelValue = "runtime-test"

type engineObject struct {
	ID       string   `json:"Id"`
	Name     string   `json:"Name"`
	RepoTags []string `json:"RepoTags"`
	Config   *struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	Labels map[string]string `json:"Labels"`
}

// ValidateSourceImage binds a unique local tag to one policy-verified config ID.
func ValidateSourceImage(expectedIdentity string, expectedTag string, content []byte) error {
	if expectedIdentity == "" || expectedTag == "" {
		return errors.New("ownership_input")
	}
	var objects []engineObject
	if err := strictjson.Validate(content, 64, 100_000); err != nil ||
		json.Unmarshal(content, &objects) != nil ||
		len(objects) != 1 ||
		objects[0].ID != expectedIdentity ||
		!slices.Contains(objects[0].RepoTags, expectedTag) {
		return errors.New("ownership_mismatch")
	}
	return nil
}

// ValidateInspect binds one inspect document to exact ID, run, and project labels.
func ValidateInspect(kind string, expectedIdentity string, runID string, content []byte) error {
	if expectedIdentity == "" || runID == "" {
		return errors.New("ownership_input")
	}
	var objects []engineObject
	if err := strictjson.Validate(content, 64, 100_000); err != nil ||
		json.Unmarshal(content, &objects) != nil ||
		len(objects) != 1 {
		return errors.New("ownership_document")
	}
	object := objects[0]
	var identity string
	var labels map[string]string
	switch kind {
	case "container", "image":
		identity = object.ID
		if object.Config == nil {
			return errors.New("ownership_config")
		}
		labels = object.Config.Labels
	case "volume":
		identity = object.Name
		labels = object.Labels
	default:
		return errors.New("ownership_kind")
	}
	if identity != expectedIdentity ||
		labels["com.croessner.dkim2.runtime-run"] != runID ||
		labels["com.croessner.dkim2.project"] != projectLabelValue {
		return errors.New("ownership_mismatch")
	}
	return nil
}

// marshalFixture creates one package-local ownership fixture.
func marshalFixture(kind string, identity string, runID string) ([]byte, error) {
	labels := map[string]string{
		"com.croessner.dkim2.runtime-run": runID,
		"com.croessner.dkim2.project":     projectLabelValue,
	}
	object := engineObject{}
	switch kind {
	case "container", "image":
		object.ID = identity
		object.Config = &struct {
			Labels map[string]string `json:"Labels"`
		}{Labels: labels}
	case "volume":
		object.Name = identity
		object.Labels = labels
	default:
		return nil, errors.New("ownership_kind")
	}
	return json.Marshal([]engineObject{object})
}
