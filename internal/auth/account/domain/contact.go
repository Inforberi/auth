package domain

import (
	"time"
)

type AddressID string

// Contact is an owned address. Its presence does not imply verification.
type Contact struct {
	ID         AddressID
	UserID     UserID
	Email      Email
	VerifiedAt *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
