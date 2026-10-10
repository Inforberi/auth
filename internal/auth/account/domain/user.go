package domain

import (
	"encoding/hex"
	"strings"
	"time"
)

type UserID string

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
)

type AuthVersion int64

type User struct {
	ID          UserID
	Status      Status
	AuthVersion AuthVersion
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

func ValidUserID(id UserID) bool {
	value := string(id)
	if len(value) != 36 || value != strings.ToLower(value) || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}
