package settings

import (
	"context"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	projectdomain "github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func (s *ProjectAuthSettings) ReadWithReadiness(ctx context.Context, actor accessservice.Principal) (settingshttp.SettingsResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	before, err := s.Read(ctx, actor)
	if err != nil {
		return settingshttp.SettingsResponse{}, err
	}
	view, err := s.assess(ctx)
	if err != nil {
		return settingshttp.SettingsResponse{}, err
	}
	if view.PolicyVersion != before.Version {
		return settingshttp.SettingsResponse{}, settingsdomain.ErrPolicyConflict
	}
	current, err := s.Read(ctx, actor)
	if err != nil {
		return settingshttp.SettingsResponse{}, err
	}
	if current != before {
		return settingshttp.SettingsResponse{}, settingsdomain.ErrPolicyConflict
	}
	return projectSettingsResponse(current, view), nil
}

func (s *ProjectAuthSettings) UpdateWithReadiness(ctx context.Context, input settingsservice.UpdateInput) (settingshttp.SettingsResponse, error) {
	snapshot, view, err := s.updateObserved(ctx, input)
	if err != nil {
		return settingshttp.SettingsResponse{}, err
	}
	return projectSettingsResponse(snapshot, view), nil
}

func projectSettingsResponse(snapshot settingsdomain.Snapshot, view projectdomain.AuthPolicyReadiness) settingshttp.SettingsResponse {
	response := settingshttp.SettingsResponseWithDeployment(snapshot, view.Runtime.Methods, view.Tokens)
	response.Readiness = &settingshttp.ReadinessResponse{PolicyVersion: view.PolicyVersion, ObservedAt: view.ObservedAt, Features: view.Features}
	return response
}
