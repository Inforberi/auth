package service

import (
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

func parseCredentials(rawEmail, password string) (accountdomain.Email, error) {
	email, err := accountdomain.NewEmail(rawEmail)
	// Preserve the API order: missing email, missing password, invalid email.
	if rawEmail == "" {
		return email, err
	}
	if password == "" {
		return accountdomain.Email{}, domain.ErrPasswordRequired
	}
	return email, err
}
