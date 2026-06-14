package password_service

import (
	"context"
	"fmt"

	"github.com/Inforberi/financial-intelligence/internal/core/domain"
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
		return nil
	}

	// if find generate token
	rawToken, err := p.tm.GenerateToken(32)
	if err != nil {
		return fmt.Errorf("forgot password generate token %w", err)
	}
	hashToken := p.tm.Hash(rawToken)

	// save token in redis
	err = p.redis.SaveResetToken(ctx, hashToken, findResult.UserID, p.cfg.ResetTokenTTL)
	if err != nil {
		return fmt.Errorf("err save reset token %w:", err)
	}

	// if find send email with link with token
	p.mailer.Send(mail.String(), )
	return nil
}
