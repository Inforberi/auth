package register_domain

import (
	"time"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
)

type RegisterResult struct {
	UserID    domain.UserID
	Token     string
	ExpiresAt time.Time
}
