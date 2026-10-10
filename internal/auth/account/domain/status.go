package domain

import "errors"

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
	if !ValidUserID(change.UserID) || !ValidUserID(change.ActorID) {
		return ErrInvalidStatusChange
	}
	return nil
}
