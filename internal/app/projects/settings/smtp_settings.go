package settings

import (
	"context"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

type ProjectSMTPSettingsConfig struct{ AllowedTargets []string }

type ProjectSMTPSettings struct {
	repo    *projectSMTPSettingsRepository
	service *settingssmtp.SMTP
}

func (s *ProjectSMTPSettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.SMTPSnapshot, error) {
	if actor.Validate() != nil {
		return settingsdomain.SMTPSnapshot{}, accessdomain.ErrForbidden
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return s.repo.ReadSMTP(ctx, actor)
}

func (s *ProjectSMTPSettings) Update(ctx context.Context, input settingssmtp.SMTPUpdateInput) (settingsdomain.SMTPSnapshot, error) {
	if s.service == nil {
		return settingsdomain.SMTPSnapshot{}, projectdomain.ErrUnavailable
	}
	return s.service.Update(ctx, input)
}

func (s *ProjectSMTPSettings) TestConnection(ctx context.Context, actor accessservice.Principal, version int64) error {
	if s.service == nil {
		return projectdomain.ErrUnavailable
	}
	return s.service.TestConnection(ctx, actor, version)
}
