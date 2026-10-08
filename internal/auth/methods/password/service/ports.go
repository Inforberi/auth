package service

import (
	"context"
	"time"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
)

type session interface {
	CreateSession(ctx context.Context, userID accountdomain.UserID, userAgent, IP string) (*sessionservice.CreatedSession, error)
	LogoutAllExcept(ctx context.Context, tokenHash string, userID accountdomain.UserID) error
}

type passwordRepo interface {
	FindByEmail(ctx context.Context, email string) (*passworddomain.Credential, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	// Account, contact, profile and credential must commit in one transaction.
	CreateUser(ctx context.Context, email, passwordHash string) (accountdomain.UserID, error)
	FindUserByUserID(ctx context.Context, userID accountdomain.UserID) (*passworddomain.Credential, error)
	UpdatePasswordHash(ctx context.Context, userID accountdomain.UserID, passwordHash string) error
}

type redisRepo interface {
	SaveResetToken(ctx context.Context, tokenHash string, userID accountdomain.UserID, ttl time.Duration) error
}

type hasher interface {
	GenerateHash(password []byte) (string, error)
	Compare(password, encodedHash string) error
}

type clock interface {
	NowUTC() time.Time
}

type tokenManager interface {
	GenerateToken(lengths ...int) (string, error)
	Hash(rawToken string) string
}

type mailer interface {
	Send(to, subject, htmlBody string) error
}
