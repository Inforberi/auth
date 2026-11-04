package runtime

import (
	"context"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

func (s *SMTP) Settings(repo settingssmtp.SMTPRepository, gate *settingssmtp.SMTPTestGate) (*settingssmtp.SMTP, error) {
	return settingssmtp.NewSMTPWithTestGate(repo, s.cipher, func(ctx context.Context, config settingsdomain.SMTPConfig, password string) error {
		if err := s.RequireCurrent(ctx); err != nil {
			return err
		}
		if err := mailer.CheckContext(ctx, MailConfig(config, password)); err != nil {
			return err
		}
		return s.RequireCurrent(ctx)
	}, s.limits, s.allowed, true, gate)
}
