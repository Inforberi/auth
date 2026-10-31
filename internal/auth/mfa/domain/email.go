package domain

import (
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type EmailFactor struct {
	Allowed     bool
	Configured  bool
	EmailID     accountdomain.AddressID
	EnabledAt   *time.Time
	SuspendedAt *time.Time
	Usable      bool
}
