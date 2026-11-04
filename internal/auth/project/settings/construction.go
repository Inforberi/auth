package settings

import (
	"context"
	"time"

	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	projectbinding "github.com/Inforberi/financial-intelligence/internal/auth/project/runtime"
	settingssmtp "github.com/Inforberi/financial-intelligence/internal/auth/settings/smtp/service"
)

func NewProjectRetentionSettings(binding projectbinding.Binding) *ProjectRetentionSettings {
	return &ProjectRetentionSettings{binding: binding}
}

func NewProjectProviderSettings(binding projectbinding.Binding) *ProjectProviderSettings {
	return &ProjectProviderSettings{binding: binding}
}

func NewProjectMFASettings(binding projectbinding.Binding, ready bool) *ProjectMFASettings {
	return &ProjectMFASettings{binding: binding, ready: ready}
}

func NewProjectAuthSettings(binding projectbinding.Binding, timeout time.Duration, assess func(context.Context) (projectdomain.AuthPolicyReadiness, error)) *ProjectAuthSettings {
	return &ProjectAuthSettings{binding: binding, timeout: timeout, assess: assess}
}

func NewProjectSMTPSettings(binding projectbinding.Binding) *ProjectSMTPSettings {
	return &ProjectSMTPSettings{repo: &projectSMTPSettingsRepository{binding: binding}}
}

func (s *ProjectSMTPSettings) Configure(source *projectbinding.SMTP, gate *settingssmtp.SMTPTestGate) error {
	var err error
	s.service, err = source.Settings(s.repo, gate)
	return err
}
