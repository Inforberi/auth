package settings

import (
	"context"
	"time"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectapp "github.com/Inforberi/financial-intelligence/internal/app/projects/runtime"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

func NewProjectRetentionSettings(binding projectapp.Binding) *ProjectRetentionSettings {
	return &ProjectRetentionSettings{binding: binding}
}

func NewProjectProviderSettings(binding projectapp.Binding) *ProjectProviderSettings {
	return &ProjectProviderSettings{binding: binding}
}

func NewProjectMFASettings(binding projectapp.Binding, ready bool) *ProjectMFASettings {
	return &ProjectMFASettings{binding: binding, ready: ready}
}

func NewProjectAuthSettings(binding projectapp.Binding, timeout time.Duration, assess func(context.Context) (projectdomain.AuthPolicyReadiness, error)) *ProjectAuthSettings {
	return &ProjectAuthSettings{binding: binding, timeout: timeout, assess: assess}
}

func NewProjectSMTPSettings(binding projectapp.Binding) *ProjectSMTPSettings {
	return &ProjectSMTPSettings{repo: &projectSMTPSettingsRepository{binding: binding}}
}

func (s *ProjectSMTPSettings) Configure(source *projectapp.SMTP, gate *settingssmtp.SMTPTestGate) error {
	var err error
	s.service, err = source.Settings(s.repo, gate)
	return err
}
