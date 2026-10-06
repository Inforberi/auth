package http

import (
	"time"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

var (
	user      = accountmodel.UserID("user-1")
	token     = "RawToken"
	expiresAt = time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
)
