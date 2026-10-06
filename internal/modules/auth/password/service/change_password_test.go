package service

import (
	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

const (
	userID           = accountmodel.UserID("user-1")
	oldPassword      = "Qwertypay2"
	newPassword      = "Qwertypay3"
	newPasswordHash  = "123456"
	oldPasswordHash  = "1234567"
	currentTokenHash = "token-hash"
)
