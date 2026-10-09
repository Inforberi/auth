package service

import (
	"context"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type session interface {
	CreateSessionAtVersion(context.Context, accountdomain.UserID, string, string, int64) (*sessionservice.CreatedSession, error)
}
type passwordRepo interface {
	FindByEmail(context.Context, string) (*passworddomain.Credential, error)
	ExistsByEmail(context.Context, string) (bool, error)
	CreateUser(context.Context, string, string) (accountdomain.UserID, error)
	FindUserByUserID(context.Context, accountdomain.UserID) (*passworddomain.Credential, error)
	ChangePassword(context.Context, accountdomain.UserID, string, string, string) error
}
type hasher interface {
	GenerateHash([]byte) (string, error)
	Compare(string, string) error
}
