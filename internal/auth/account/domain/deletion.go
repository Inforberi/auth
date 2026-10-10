package domain

import "errors"

var ErrInvalidAccountDeletion = errors.New("invalid account deletion")

type AccountDeletion struct {
	UserID          UserID
	ActorID         UserID
	ExpectedVersion AuthVersion
}

func (deletion AccountDeletion) Validate() error {
	if !ValidUserID(deletion.UserID) || !ValidUserID(deletion.ActorID) || deletion.ExpectedVersion <= 0 {
		return ErrInvalidAccountDeletion
	}
	return nil
}
