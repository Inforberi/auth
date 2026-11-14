package settings

import (
	"context"
	"time"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	sessions "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func AssembleBrowserSessionPolicy(ctx context.Context, repo *settingspostgres.Repository, config sessions.Config, mode domain.SourceMode, log *zap.Logger) (*settingshttp.BrowserSessionPolicyHandler, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ceiling := config.BrowserPolicy()
	if err := ceiling.Validate(ceiling); err != nil {
		return nil, err
	}
	store := repo.BrowserSessionPolicy()
	if err := store.Initialize(ctx, ceiling); err != nil {
		return nil, err
	}
	if mode.Effective() == domain.SourceAPI {
		policy, err := store.Load(ctx)
		if err != nil {
			return nil, err
		}
		if err := policy.Validate(ceiling); err != nil {
			return nil, err
		}
	}
	view := func(snapshot settingspostgres.PolicySnapshot[sessions.BrowserPolicy]) settingshttp.BrowserSessionPolicyView {
		return settingshttp.BrowserSessionPolicyView{Version: snapshot.Version, Policy: settingshttp.BrowserSessionPolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.BrowserSessionPolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.BrowserSessionPolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = ceiling
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy sessions.BrowserPolicy) (settingshttp.BrowserSessionPolicyView, error) {
			if err := policy.Validate(ceiling); err != nil {
				return settingshttp.BrowserSessionPolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			return view(snapshot), err
		},
	}, nil
}
