// Package strictjson owns bounded duplicate-free evidence JSON decoding.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Decode parses one duplicate-free JSON document into a closed typed value.
func Decode(content []byte, value any, maxDepth int, maxTokens int) error {
	if value == nil || maxDepth < 1 || maxTokens < 1 {
		return errors.New("strict_json_policy")
	}
	if err := scan(content, maxDepth, maxTokens); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("strict_json_trailing")
	}
	return nil
}

// Validate checks one duplicate-free single JSON document without a typed projection.
func Validate(content []byte, maxDepth int, maxTokens int) error {
	if maxDepth < 1 || maxTokens < 1 {
		return errors.New("strict_json_policy")
	}
	return scan(content, maxDepth, maxTokens)
}

// scan rejects duplicate keys before typed decoding.
func scan(content []byte, maxDepth int, maxTokens int) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	tokens := 0
	if err := scanValue(decoder, 0, &tokens, maxDepth, maxTokens); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("strict_json_trailing")
	}
	return nil
}

// scanValue validates one recursive value within fixed structural bounds.
func scanValue(
	decoder *json.Decoder,
	depth int,
	tokens *int,
	maxDepth int,
	maxTokens int,
) error {
	if depth > maxDepth || *tokens >= maxTokens {
		return errors.New("strict_json_limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	*tokens++
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			if *tokens >= maxTokens {
				return errors.New("strict_json_limit")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			*tokens++
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("strict_json_key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("strict_json_duplicate")
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder, depth+1, tokens, maxDepth, maxTokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("strict_json_object")
		}
		*tokens++
	case '[':
		for decoder.More() {
			if err := scanValue(decoder, depth+1, tokens, maxDepth, maxTokens); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("strict_json_array")
		}
		*tokens++
	default:
		return errors.New("strict_json_delimiter")
	}
	return nil
}
