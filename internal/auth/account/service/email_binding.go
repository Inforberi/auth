package service

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

type EmailBindingRepository interface {
	CanRequestEmailBinding(context.Context, accessservice.Principal) error
	IssueEmailBinding(context.Context, EmailBindingCommand) (time.Time, error)
	ConfirmEmailBinding(context.Context, mfaservice.Proof, string) error
}

type EmailBindingService struct {
	repo    EmailBindingRepository
	limiter Limiter
	cipher  Cipher
	cfg     EmailBindingConfig
}

func NewEmailBinding(repo EmailBindingRepository, limiter Limiter, cipher Cipher, cfg EmailBindingConfig) *EmailBindingService {
	return &EmailBindingService{repo: repo, limiter: limiter, cipher: cipher, cfg: cfg}
}

type EmailBindingInput struct {
	Actor  accessservice.Principal
	UserID domain.UserID
	Email  string
	IP     string
}

type EmailBindingCommand struct {
	Actor           accessservice.Principal
	UserID          domain.UserID
	Email, Verifier string
	Payload         []byte
	TTL             time.Duration
}

func (s *EmailBindingService) Request(ctx context.Context, input EmailBindingInput) (time.Time, error) {
	if !s.cfg.Enabled {
		return time.Time{}, domain.ErrEmailBindingDisabled
	}
	if err := input.Actor.Validate(); err != nil {
		return time.Time{}, domain.ErrFreshAuthRequired
	}
	if !domain.ValidUserID(input.UserID) || input.Actor.UserID == input.UserID {
		return time.Time{}, domain.ErrEmailBindingConflict
	}
	email, err := domain.NewEmail(input.Email)
	if err != nil {
		return time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, limit := range []struct {
		key    string
		count  int
		window time.Duration
	}{
		{"request:actor:" + string(input.Actor.UserID), 30, time.Minute},
		{"request:ip:" + input.IP, 30, time.Minute},
		{"request:project", s.cfg.RequestsPerMinute, time.Minute},
	} {
		if err := s.admit(ctx, limit.key, limit.count, limit.window); err != nil {
			return time.Time{}, err
		}
	}
	// Reject callers without management rights before consuming the target's small issuance budget.
	// The transaction rechecks authority under locks; this preflight is admission, not write authorization.
	if err := s.repo.CanRequestEmailBinding(ctx, input.Actor); err != nil {
		return time.Time{}, err
	}
	if err := s.admit(ctx, "request:user:"+string(input.UserID), 3, 15*time.Minute); err != nil {
		return time.Time{}, err
	}
	number, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return time.Time{}, err
	}
	code := fmt.Sprintf("%08d", number.Int64())
	plain, err := json.Marshal(emailMessage{To: email.String(), Subject: "Привязка почты к аккаунту", Body: "<p>Администратор разрешил привязку этой почты. Код: <strong>" + code + "</strong>.</p><p>Введите его только в своём аккаунте. Если вы не запрашивали привязку, никому не сообщайте код.</p>"})
	if err != nil {
		return time.Time{}, err
	}
	payload, err := s.cipher.Seal(plain)
	if err != nil {
		return time.Time{}, err
	}
	return s.repo.IssueEmailBinding(ctx, EmailBindingCommand{Actor: input.Actor, UserID: input.UserID, Email: email.String(), Verifier: s.verifier(input.UserID, code), Payload: payload, TTL: s.cfg.TTL})
}

func (s *EmailBindingService) verifier(user domain.UserID, code string) string {
	return s.cipher.Digest("email-binding:code:" + string(user) + ":" + code)
}

func (s *EmailBindingService) admit(ctx context.Context, key string, count int, window time.Duration) error {
	allowed, err := s.limiter.Allow(ctx, s.cipher.Digest("email-binding:"+key), count, window)
	if err != nil {
		return err
	}
	if !allowed {
		return domain.ErrVerificationLimited
	}
	return nil
}
