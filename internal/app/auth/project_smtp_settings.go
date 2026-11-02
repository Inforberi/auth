package auth

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/infra/mailer"
)

type ProjectSMTPSettingsConfig struct{ AllowedTargets []string }

type projectSMTPSettings struct {
	repo    *projectSMTPSettingsRepository
	service *settingsservice.SMTP
}

func (p *ProjectProfile) buildProfileSMTPSettings(cfg ProjectProfileConfig, root string, redisReady bool) {
	if cfg.SMTPSettings == nil {
		return
	}
	if !cfg.BrowserEnabled {
		p.state("smtp_settings_read", "browser_disabled")
		p.state("smtp_settings_write", "browser_disabled")
		return
	}
	s := &projectSMTPSettings{repo: &projectSMTPSettingsRepository{profile: p}}
	p.smtpSettings = s
	p.state("smtp_settings_read", "")
	reason := ""
	switch {
	case p.mfaManagement == nil:
		reason = "mfa_unavailable"
	case !redisReady:
		reason = "redis_unavailable"
	default:
		source, err := newProjectSMTP(p.key, root, cfg.SMTPSettings.AllowedTargets, ProjectSMTPDependencies{Registry: p.deps.Registry, Reader: p.deps.Reader, Redis: p.deps.Redis})
		if err == nil {
			gate := p.deps.SMTPTests
			if gate == nil {
				gate = settingsservice.NewSMTPTestGate()
			}
			s.service, err = settingsservice.NewSMTPWithTestGate(s.repo, source.cipher, func(ctx context.Context, config settingsdomain.SMTPConfig, password string) error {
				if err := source.requireCurrent(ctx); err != nil {
					return err
				}
				if err := mailer.CheckContext(ctx, smtpMailerConfig(config, password)); err != nil {
					return err
				}
				return source.requireCurrent(ctx)
			}, source.limits, source.allowed, true, gate)
		}
		if err != nil {
			reason = "invalid_smtp_configuration"
		}
	}
	p.state("smtp_settings_write", reason)
}

func (s *projectSMTPSettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.SMTPSnapshot, error) {
	if actor.Validate() != nil {
		return settingsdomain.SMTPSnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadSMTP(ctx, actor)
}

func (s *projectSMTPSettings) Update(ctx context.Context, input settingsservice.SMTPUpdateInput) (settingsdomain.SMTPSnapshot, error) {
	if s.service == nil {
		return settingsdomain.SMTPSnapshot{}, projectdomain.ErrUnavailable
	}
	return s.service.Update(ctx, input)
}

func (s *projectSMTPSettings) TestConnection(ctx context.Context, actor accessservice.Principal, version int64) error {
	if s.service == nil {
		return projectdomain.ErrUnavailable
	}
	return s.service.TestConnection(ctx, actor, version)
}
