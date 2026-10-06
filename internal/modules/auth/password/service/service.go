package service

import (
	"context"
	"time"

	accountmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/account/model"
	passwordmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/password/model"
	sessionmodel "github.com/Inforberi/financial-intelligence/internal/modules/auth/session/model"
)

type session interface {
	CreateSession(ctx context.Context, userID accountmodel.UserID, userAgent, IP string) (*sessionmodel.CreatedSession, error)
	LogoutAllExcept(ctx context.Context, tokenHash string, userID accountmodel.UserID) error
}

type passwordRepo interface {
	FindByEmail(ctx context.Context, email string) (*passwordmodel.FindByEmailResult, error)
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	CreateUser(ctx context.Context, email, passwordHash string) (accountmodel.UserID, error)
	FindUserByUserID(ctx context.Context, userID accountmodel.UserID) (*passwordmodel.FindUserPassword, error)
	UpdatePasswordHash(ctx context.Context, userID accountmodel.UserID, passwordHash string) error
}

type redisRepo interface {
	SaveResetToken(ctx context.Context, tokenHash string, userID accountmodel.UserID, ttl time.Duration) error
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

type PasswordService struct {
	repo    passwordRepo
	session session
	hash    hasher
	now     clock
	tm      tokenManager
	redis   redisRepo
	cfg     passwordmodel.Config
	mailer  mailer
}

func New(repo passwordRepo, session session, hash hasher, now clock, tm tokenManager, redis redisRepo, cfg passwordmodel.Config, mailer mailer) *PasswordService {
	return &PasswordService{
		repo:    repo,
		session: session,
		hash:    hash,
		now:     now,
		tm:      tm,
		redis:   redis,
		cfg:     cfg,
		mailer:  mailer,
	}
}
