package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
)

type (
	SetupStartInput struct {
		OperatorSecret string
		Email          string
		Password       string
		IP             string
	}
	SetupStarted struct {
		Token     string `json:"-"`
		Secret    string `json:"-"`
		URI       string `json:"-"`
		ExpiresAt time.Time
	}
)

func (s *SetupService) Start(ctx context.Context, input SetupStartInput) (*SetupStarted, error) {
	ctx, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	if err := s.admit(ctx, input.OperatorSecret, input.IP, "start"); err != nil {
		return nil, err
	}
	email, err := domain.NewEmail(input.Email)
	if err != nil {
		return nil, err
	}
	if err := passworddomain.ValidatePassword(input.Password); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrSetupPasswordPolicy, err)
	}
	hash, err := s.hash.GenerateHash(ctx, []byte(input.Password))
	if err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	id[6], id[8] = (id[6]&15)|64, (id[8]&63)|128
	user := domain.UserID(fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]))
	secret, uri, err := s.code.Generate(s.issuer, string(user))
	if err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	number, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	code := fmt.Sprintf("%08d", number.Int64())
	pending := setupPayload{
		UserID:       user,
		Email:        email.String(),
		PasswordHash: hash,
		Secret:       secret,
		EmailDigest:  s.cipher.Digest("email:" + token + ":" + code),
	}
	plain, err := json.Marshal(pending) //nolint:gosec // G117: encrypted setup envelope, never an HTTP DTO or log payload.
	if err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	defer clear(plain)
	payload, err := s.cipher.Seal(plain)
	if err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	expires, err := s.repo.SaveSetup(ctx, tokenDigest(input.OperatorSecret), s.cipher.Digest("request:"+token), payload)
	if err != nil {
		return nil, err
	}
	// No user exists yet. One-off setup mail is bounded by the HTTP deadline; retry starts a new intent.
	if err := s.mail.SendContext(ctx, email.String(), "Первичная настройка администратора", "<p>Код подтверждения почты первого администратора: <strong>"+code+"</strong></p><p>Действует 10 минут. Если вы не настраиваете сервис, не передавайте код.</p>"); err != nil {
		return nil, domain.ErrDependencyUnavailable
	}
	return &SetupStarted{Token: token, Secret: secret, URI: uri, ExpiresAt: expires}, nil
}
