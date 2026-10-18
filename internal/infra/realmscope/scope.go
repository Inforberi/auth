package realmscope

import (
	"encoding/hex"
	"errors"
	"strings"
)

type Scope struct {
	name   string
	legacy bool
}

// Legacy is only for the unchanged single-project installation, not a missing realm ID.
func Legacy() Scope { return Scope{legacy: true} }

func New(kind, id string) (Scope, error) {
	if kind != "platform" && kind != "project" {
		return Scope{}, errors.New("invalid realm kind")
	}
	if len(id) != 36 || id != strings.ToLower(id) || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || id == "00000000-0000-0000-0000-000000000000" {
		return Scope{}, errors.New("invalid realm ID")
	}
	if _, err := hex.DecodeString(strings.ReplaceAll(id, "-", "")); err != nil {
		return Scope{}, errors.New("invalid realm ID")
	}
	return Scope{name: kind + ":" + id}, nil
}

func (s Scope) Valid() bool { return s.name != "" || s.legacy }

func (s Scope) Purpose(purpose string) (string, error) {
	if !s.Valid() || !validPurpose(purpose) {
		return "", errors.New("invalid realm scope or purpose")
	}
	if s.legacy {
		return purpose, nil
	}
	return "realm:" + s.name + ":" + purpose, nil
}

func (s Scope) RedisPrefix(purpose, legacy string) (string, error) {
	context, err := s.Purpose(purpose)
	if err != nil {
		return "", err
	}
	if s.legacy {
		if legacy == "" {
			return "", errors.New("legacy Redis prefix is required")
		}
		return legacy, nil
	}
	// Every multi-key script keeps one realm+purpose slot, not a slot shared by all projects.
	return "auth:{" + context + "}:", nil
}

func validPurpose(value string) bool {
	if len(value) == 0 || len(value) > 96 {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != ':' {
			return false
		}
	}
	return true
}
