package service

import (
	"context"
	"errors"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type emailChangeRepository interface {
	EmailChangeSnapshot(context.Context, domain.UserID) (domain.EmailChangeSnapshot, error)
	RequestEmailChange(context.Context, domain.EmailChangeSnapshot, string, string, domain.EmailChangeIntent, bool, time.Duration) error
	ConfirmEmailChange(context.Context, string) error
	ReportEmailChange(context.Context, string) error
}

type passwordVerifier interface {
	Compare(context.Context, string, string) error
}

type EmailChangeService struct {
	repo     emailChangeRepository
	hash     passwordVerifier
	account  *Service
	cfg      EmailChangeConfig
	freshFor time.Duration
}

func NewEmailChange(repo emailChangeRepository, hash passwordVerifier, account *Service, cfg EmailChangeConfig, freshFor time.Duration) *EmailChangeService {
	return &EmailChangeService{repo: repo, hash: hash, account: account, cfg: cfg, freshFor: freshFor}
}

func (s *EmailChangeService) Request(ctx context.Context, user domain.UserID, session, rawEmail, password, ip string) error {
	email, err := domain.NewEmail(rawEmail)
	if err != nil {
		return err
	}
	if !domain.ValidUserID(user) || len(session) != 64 || len(password) > 1024 {
		return domain.ErrFreshAuthRequired
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.account.limit(ctx, "email-change-user:"+string(user), 5, time.Hour); err != nil {
		return err
	}
	if err := s.account.limit(ctx, "email-change-request-ip:"+ip, 20, time.Minute); err != nil {
		return err
	}
	snapshot, err := s.repo.EmailChangeSnapshot(ctx, user)
	if err != nil {
		return err
	}
	passwordVerified := password != ""
	if passwordVerified {
		if err := s.hash.Compare(ctx, password, snapshot.PasswordHash); err != nil {
			if errors.Is(err, passworddomain.ErrHashBusy) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return domain.ErrFreshAuthRequired
		}
	}
	if email.String() == snapshot.Email {
		return domain.ErrInvalidEmailChange
	}
	prepared, err := s.prepareChange(snapshot.Email, email.String())
	if err != nil {
		return err
	}
	return s.repo.RequestEmailChange(ctx, snapshot, session, email.String(), prepared, passwordVerified, s.freshFor)
}

func (s *EmailChangeService) Confirm(ctx context.Context, token, ip string) error {
	return s.consume(ctx, token, ip, "email-change-confirm:", s.repo.ConfirmEmailChange)
}

func (s *EmailChangeService) Report(ctx context.Context, token, ip string) error {
	return s.consume(ctx, token, ip, "email-change-report:", s.repo.ReportEmailChange)
}

func (s *EmailChangeService) consume(ctx context.Context, token, ip, purpose string, consume func(context.Context, string) error) error {
	if !validChangeToken(token) {
		return domain.ErrInvalidEmailChange
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.account.limit(ctx, purpose+ip, 20, time.Minute); err != nil {
		return err
	}
	return consume(ctx, tokenDigest(token))
}
