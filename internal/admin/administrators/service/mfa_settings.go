package service

import (
	"context"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

type MFASettings struct {
	repo  MFASettingsRepository
	ready bool
}

type MFASettingsRepository interface {
	ReadMFAPolicy(context.Context, operatordomain.Principal) (settingsdomain.MFASnapshot, error)
	UpdateMFAPolicy(context.Context, operatordomain.Principal, settingsservice.MFAChange, bool) (settingsdomain.MFASnapshot, error)
}

func NewMFASettings(repo MFASettingsRepository, ready bool) *MFASettings {
	return &MFASettings{repo: repo, ready: ready}
}

func (s *MFASettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.MFASnapshot, error) {
	return s.repo.ReadMFAPolicy(ctx, operatordomain.Principal{UserID: actor.UserID, TokenHash: actor.TokenHash})
}

func (s *MFASettings) Update(ctx context.Context, input settingsservice.MFAUpdateInput) (settingsdomain.MFASnapshot, error) {
	return s.repo.UpdateMFAPolicy(ctx, operatordomain.Principal{UserID: input.Actor.UserID, TokenHash: input.Actor.TokenHash}, input.MFAChange, s.ready)
}
