package domain

import "errors"

var (
	ErrInvalidStatusChange   = errors.New("invalid account status change")
	ErrAccountNotFound       = errors.New("account not found")
	ErrAccountDeleted        = errors.New("account deleted")
	ErrAccountConflict       = errors.New("account version conflict")
	ErrLastAdministrator     = errors.New("last administrator cannot be removed or administratively blocked")
	ErrInvalidUserQuery      = errors.New("invalid user directory query")
	ErrUserDirectoryConflict = errors.New("user directory data exceeds supported bounds")
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
