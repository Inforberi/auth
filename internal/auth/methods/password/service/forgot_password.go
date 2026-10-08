package service

import (
	"context"
	"errors"
	"fmt"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/methods/password/templates"
)

func (p *PasswordService) ForgotPassword(ctx context.Context, email string) error {
	mail, err := accountdomain.NewEmail(email)
	if err != nil {
		return fmt.Errorf("forgot password invalid email %w", err)
	}

	findResult, err := p.repo.FindByEmail(ctx, mail.String())
	if err != nil {
		if errors.Is(err, passworddomain.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("forgot password lookup: %w", err)
	}

	rawToken, err := p.tm.GenerateToken(32)
	if err != nil {
		return fmt.Errorf("forgot password generate token %w", err)
	}
	hashToken := p.tm.Hash(rawToken)
	body, err := templates.RenderResetPassword(p.cfg.ResetURL, rawToken, p.cfg.ResetTokenTTL, p.now.NowUTC())
	if err != nil {
		return err
	}

	err = p.redis.SaveResetToken(ctx, hashToken, findResult.UserID, p.cfg.ResetTokenTTL)
	if err != nil {
		return fmt.Errorf("save reset token: %w", err)
	}

	if err := p.mailer.Send(mail.String(), "Сброс пароля", body); err != nil {
		return fmt.Errorf("forgot password delivery: %w", err)
	}
	return nil
}
