package jsonconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var ErrInvalidJSON = errors.New("invalid configuration JSON")

func Decode(data []byte, destination any) error {
	if !utf8.Valid(data) {
		return ErrInvalidJSON
	}
	if err := checkJSONKeys(data); err != nil {
		return ErrInvalidJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrInvalidJSON
	}
	return nil
}

func checkJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := checkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidJSON
	}
	return nil
}

func checkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalidJSON
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
		return ErrInvalidJSON
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
				return ErrInvalidJSON
			}
			key = strings.ToLower(key)
			if _, duplicate := seen[key]; duplicate {
				return ErrInvalidJSON
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
