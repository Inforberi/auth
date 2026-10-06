package model

import (
	"time"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

type FindByEmailResult struct {
	UserID       accountmodel.UserID
	PasswordHash string
}

type FindUserPassword struct {
	PasswordHash string
}

type LoginResult struct {
	UserID    accountmodel.UserID
	Token     string
	ExpiresAt time.Time
}

type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type RegisterResult struct {
	UserID    accountmodel.UserID
	Token     string
	ExpiresAt time.Time
}
