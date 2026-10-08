package domain

import (
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Credential struct {
	UserID       accountdomain.UserID
	PasswordHash string
}
