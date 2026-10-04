package password_service

import (
	"context"
	"errors"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
	"github.com/Inforberi/financial-intelligence/internal/core/infra/mailer/templates"
	password_domain "github.com/Inforberi/financial-intelligence/internal/featers/password_auth/domain"
)

func (p *PasswordService) ForgotPassword(ctx context.Context, email string) error {
	// validate email
	mail, err := domain.NewEmail(email)
	if err != nil {
		return fmt.Errorf("forgot password invalid email %w", err)
	}

	// find user by email
	findResult, err := p.repo.FindByEmail(ctx, mail.String())
	if err != nil {
		if errors.Is(err, password_domain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("forgot password lookup: %w", err)
	}

	// if find generate token
	rawToken, err := p.tm.GenerateToken(32)
	if err != nil {
		return fmt.Errorf("forgot password generate token %w", err)
	}
	hashToken := p.tm.Hash(rawToken)
	body, err := templates.RenderResetPassword(p.cfg.ResetURL, rawToken, p.cfg.ResetTokenTTL, p.now.NowUTC())
	if err != nil {
		return err
	}

	// save token in redis
	err = p.redis.SaveResetToken(ctx, hashToken, findResult.UserID, p.cfg.ResetTokenTTL)
	if err != nil {
		return fmt.Errorf("save reset token: %w", err)
	}

	// if find send email with link with token
	if err := p.mailer.Send(mail.String(), "Сброс пароля", body); err != nil {
		return fmt.Errorf("forgot password delivery: %w", err)
	}
	return nil
}
