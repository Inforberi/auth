package domain

import "errors"

var (
	ErrEmailBindingDisabled = errors.New("email binding disabled")
	ErrInvalidEmailBinding  = errors.New("invalid email binding")
	ErrEmailBindingConflict = errors.New("email binding unavailable")
)

func ValidEmailBindingCode(code string) bool {
	if len(code) != 8 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
