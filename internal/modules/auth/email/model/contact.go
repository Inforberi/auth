package model

import (
	"time"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
)

type AddressID string

// Contact is an owned address. Its presence does not imply verification.
type Contact struct {
	ID         AddressID
	UserID     accountmodel.UserID
	Email      Email
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
