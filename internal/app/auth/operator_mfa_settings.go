package auth

import (
	"context"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

type operatorMFASettings struct {
	repo  *operatorpostgres.Repository
	ready bool
}

func newOperatorMFASettings(repo *operatorpostgres.Repository, ready bool, log *zap.Logger) *settingshttp.MFAHandler {
	return settingshttp.NewMFA(&operatorMFASettings{repo: repo, ready: ready}, log,
		httpx.MatchError(operatordomain.ErrForbidden, 403, "forbidden", "forbidden"),
		httpx.MatchError(operatordomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh primary proof and required MFA needed"),
	)
}

func (s *operatorMFASettings) Read(ctx context.Context, actor accessservice.Principal) (settingsdomain.MFASnapshot, error) {
	return s.repo.ReadMFAPolicy(ctx, operatordomain.Principal{UserID: actor.UserID, TokenHash: actor.TokenHash})
}

func (s *operatorMFASettings) Update(ctx context.Context, input settingsservice.MFAUpdateInput) (settingsdomain.MFASnapshot, error) {
	return s.repo.UpdateMFAPolicy(ctx, operatordomain.Principal{UserID: input.Actor.UserID, TokenHash: input.Actor.TokenHash}, input.MFAChange, s.ready)
}
