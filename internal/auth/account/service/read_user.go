package service

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

type UserContact struct {
	Email      string
	VerifiedAt *time.Time
}

type UserRole struct {
	ID      accessdomain.RoleID
	Key     string
	Name    string
	System  bool
	Version int64
}

type UserDetail struct {
	UserSummary
	AuthVersion               domain.AuthVersion
	AccessVersion             int64
	DeletedAt                 *time.Time
	PasswordConfigured        bool
	TemporaryPasswordRequired bool
	MFAEnrolled               bool
	Contacts                  []UserContact
	ExternalIssuers           []string
	Roles                     []UserRole
}

func (s *UserDirectory) Read(ctx context.Context, actor accessservice.Principal, id domain.UserID) (UserDetail, error) {
	if actor.Validate() != nil {
		return UserDetail{}, accessdomain.ErrForbidden
	}
	if !domain.ValidUserID(id) {
		return UserDetail{}, domain.ErrInvalidUserQuery
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadUser(ctx, actor, id)
}
