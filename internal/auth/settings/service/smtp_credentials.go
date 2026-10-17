package service

import (
	"context"
	"errors"
	"strings"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

type SMTPUpdateInput struct {
	Actor           accessservice.Principal
	ExpectedVersion int64
	Config          domain.SMTPConfig
	Password        *string `json:"-"`
}

func validSMTPPassword(password string) bool {
	return len(password) <= 4096 && !strings.ContainsAny(password, "\x00\r\n")
}

func (s *SMTP) Initialize(ctx context.Context, config domain.SMTPConfig, password string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadSMTP(ctx)
	if errors.Is(err, domain.ErrNotInitialized) {
		if err := s.validate(config); err != nil {
			return err
		}
		if !validSMTPPassword(password) || config.Username != "" && password == "" {
			return domain.ErrInvalidSMTP
		}
		encrypted, err := s.cipher.Seal([]byte(password))
		if err != nil {
			return domain.ErrInvalidSMTP
		}
		stored, err = s.repo.InitializeSMTP(ctx, SMTPStored{SMTPSnapshot: domain.SMTPSnapshot{Config: config, PasswordSet: password != ""}, Password: encrypted})
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	_, _, err = s.open(stored)
	return err
}

// Credentials is an internal delivery read, never an administrator response.
func (s *SMTP) Credentials(ctx context.Context) (domain.SMTPConfig, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stored, err := s.repo.LoadSMTP(ctx)
	if err != nil {
		return domain.SMTPConfig{}, "", err
	}
	return s.open(stored)
}

func (s *SMTP) open(stored SMTPStored) (domain.SMTPConfig, string, error) {
	if err := s.validate(stored.Config); err != nil {
		return domain.SMTPConfig{}, "", err
	}
	plain, err := s.cipher.Open(stored.Password)
	if err != nil {
		return domain.SMTPConfig{}, "", errors.New("SMTP secret cannot be decrypted")
	}
	defer clear(plain)
	password := string(plain)
	if !validSMTPPassword(password) || stored.PasswordSet != (password != "") || stored.Config.Username != "" && password == "" {
		return domain.SMTPConfig{}, "", domain.ErrInvalidSMTP
	}
	return stored.Config, password, nil
}

func (s *SMTP) Update(ctx context.Context, input SMTPUpdateInput) (domain.SMTPSnapshot, error) {
	if input.Actor.Validate() != nil {
		return domain.SMTPSnapshot{}, accessdomain.ErrForbidden
	}
	if input.ExpectedVersion < 1 {
		return domain.SMTPSnapshot{}, domain.ErrInvalidSMTP
	}
	if err := s.validate(input.Config); err != nil {
		return domain.SMTPSnapshot{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	update := SMTPUpdate{Actor: input.Actor, ExpectedVersion: input.ExpectedVersion, Config: input.Config}
	if input.Password != nil {
		if !validSMTPPassword(*input.Password) {
			return domain.SMTPSnapshot{}, domain.ErrInvalidSMTP
		}
		var err error
		update.Password, err = s.cipher.Seal([]byte(*input.Password))
		if err != nil {
			return domain.SMTPSnapshot{}, errors.New("SMTP secret cannot be encrypted")
		}
		update.PasswordSet = *input.Password != ""
	}
	return s.repo.UpdateSMTP(ctx, update)
}
