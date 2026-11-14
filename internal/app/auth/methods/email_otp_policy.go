package methods

import (
	"context"

	"go.uber.org/zap"

	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	otp "github.com/Inforberi/financial-intelligence/internal/auth/methods/emailotp/service"
	"github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func assembleEmailOTPPolicy(ctx context.Context, repo *settingspostgres.Repository, config *otp.Config, mode domain.SourceMode, log *zap.Logger) (*settingshttp.EmailOTPPolicyHandler, error) {
	ceiling := config.Policy()
	if err := ceiling.Validate(ceiling); err != nil {
		return nil, err
	}
	store := repo.EmailOTPPolicy()
	if err := store.Initialize(ctx, ceiling); err != nil {
		return nil, err
	}
	if mode.Effective() == domain.SourceAPI {
		config.PolicySource = func(ctx context.Context) (otp.Policy, error) {
			policy, err := store.Load(ctx)
			if err != nil {
				return otp.Policy{}, err
			}
			return policy, policy.Validate(ceiling)
		}
		if _, err := config.PolicySource(ctx); err != nil {
			return nil, err
		}
	}
	view := func(snapshot settingspostgres.PolicySnapshot[otp.Policy]) settingshttp.EmailOTPPolicyView {
		return settingshttp.EmailOTPPolicyView{Version: snapshot.Version, Policy: settingshttp.EmailOTPPolicyDTO(snapshot.Policy), Source: mode.Metadata()}
	}
	return &settingshttp.EmailOTPPolicyHandler{
		Log: log,
		ReadPolicy: func(ctx context.Context, actor accessservice.Principal) (settingshttp.EmailOTPPolicyView, error) {
			snapshot, err := store.Read(ctx, actor)
			if mode == domain.SourceENV {
				snapshot.Policy = ceiling
			}
			return view(snapshot), err
		},
		UpdatePolicy: func(ctx context.Context, actor accessservice.Principal, version int64, policy otp.Policy) (settingshttp.EmailOTPPolicyView, error) {
			if err := policy.Validate(ceiling); err != nil {
				return settingshttp.EmailOTPPolicyView{}, err
			}
			snapshot, err := store.Update(ctx, actor, version, policy)
			return view(snapshot), err
		},
	}, nil
}
