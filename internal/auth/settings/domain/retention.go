package domain

import "errors"

var (
	ErrInvalidRetention      = errors.New("invalid retention settings")
	ErrRetentionConfirmation = errors.New("shorter retention requires confirmation")
)

// MaxRetentionDays keeps conversion to a time.Duration within int64.
const MaxRetentionDays = 106751

type RetentionPolicy struct {
	EmailReservationDays int `json:"emailReservationDays"`
	SessionDays          int `json:"sessionDays"`
	SecurityAuditDays    int `json:"securityAuditDays"`
}

func (p RetentionPolicy) Validate() error {
	for _, days := range []int{p.EmailReservationDays, p.SessionDays, p.SecurityAuditDays} {
		if days < 1 || days > MaxRetentionDays {
			return ErrInvalidRetention
		}
	}
	return nil
}

func (p RetentionPolicy) Shortens(previous RetentionPolicy) bool {
	return p.EmailReservationDays < previous.EmailReservationDays || p.SessionDays < previous.SessionDays || p.SecurityAuditDays < previous.SecurityAuditDays
}

type RetentionSnapshot struct {
	Version int64           `json:"version"`
	Policy  RetentionPolicy `json:"policy"`
}
