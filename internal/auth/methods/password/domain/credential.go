package domain

import (
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type Credential struct {
	AuthVersion  int64
	UserID       accountdomain.UserID
	PasswordHash string
}
