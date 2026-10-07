package model

import "time"

type UserID string

type Status string

const (
	StatusActive  Status = "active"
	StatusBlocked Status = "blocked"
)

type AuthVersion int64

type User struct {
	ID          UserID
	Status      Status
	AuthVersion AuthVersion
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}
