package domain

import (
	"encoding/hex"
	"errors"
	"strings"
)

var (
	ErrInvalidStatusChange = errors.New("invalid account status change")
	ErrAccountNotFound     = errors.New("account not found")
	ErrAccountDeleted      = errors.New("account deleted")
	ErrAccountConflict     = errors.New("account version conflict")
)

type StatusChange struct {
	UserID          UserID
	ActorID         UserID
	ExpectedVersion AuthVersion
	Status          Status
}

func (change StatusChange) Validate() error {
	if change.Status != StatusActive && change.Status != StatusBlocked || change.ExpectedVersion <= 0 {
		return ErrInvalidStatusChange
	}
	if !validUserID(change.UserID) || !validUserID(change.ActorID) {
		return ErrInvalidStatusChange
	}
	return nil
}

func validUserID(id UserID) bool {
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
