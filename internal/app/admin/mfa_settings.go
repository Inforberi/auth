package admin

import (
	"go.uber.org/zap"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/admin/administrators/repository/postgres"
	operatorservice "github.com/Inforberi/financial-intelligence/internal/admin/administrators/service"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/httpx"
)

func MFASettings(repo *operatorpostgres.Repository, ready bool, log *zap.Logger) *settingshttp.MFAHandler {
	return settingshttp.NewMFA(operatorservice.NewMFASettings(repo, ready), log,
		httpx.MatchError(operatordomain.ErrForbidden, 403, "forbidden", "forbidden"),
		httpx.MatchError(operatordomain.ErrFreshAuthRequired, 403, "fresh_auth_required", "fresh primary proof and required MFA needed"),
	)
}
