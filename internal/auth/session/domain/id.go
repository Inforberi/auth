package domain

import (
	"encoding/hex"
	"strings"
)

func ValidateID(id string) error {
	if id != strings.ToLower(id) {
		return ErrInvalidSessionID
	}
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return ErrInvalidSessionID
	}
	compact := strings.ReplaceAll(id, "-", "")
	if len(compact) != 32 {
		return ErrInvalidSessionID
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return ErrInvalidSessionID
	}
	return nil
}
