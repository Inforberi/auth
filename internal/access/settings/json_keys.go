package settings

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// Reject ambiguous duplicate fields (including case variants) before the schema decoder.
func checkJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidCatalog
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalidCatalog
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	if delimiter != '{' && delimiter != '[' {
		return ErrInvalidCatalog
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		if delimiter == '{' {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return ErrInvalidCatalog
			}
			key = strings.ToLower(key)
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidCatalog
			}
			seen[key] = struct{}{}
		}
		if err := checkJSONValue(decoder, depth+1); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
