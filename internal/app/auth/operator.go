package auth

import (
	"context"
	"errors"

	"github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	accountservice "github.com/Inforberi/financial-intelligence/internal/auth/account/service"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
	passwordservice "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/service"
	passwordhttp "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/transport/http"
	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	sessionhttp "github.com/Inforberi/financial-intelligence/internal/auth/session/transport/http"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
	"github.com/Inforberi/financial-intelligence/internal/config"
	"github.com/Inforberi/financial-intelligence/internal/infra/clock"
	"github.com/Inforberi/financial-intelligence/internal/infra/realmscope"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/transport/http/router"
)

func assembleOperator(ctx context.Context, cfg *config.Config, deps realmDependencies, mail accountservice.Mailer) (*realm, error) {
	if err := cfg.ValidatePlatform(); err != nil {
		return nil, err
	}
	if err := deps.validate(); err != nil {
		return nil, err
	}
	// The installation chooses this identity; never reuse a caller-supplied project scope.
	scope, err := realmscope.New("platform", cfg.Platform.RealmID)
	if err != nil {
		return nil, err
	}
	if deps.scope != scope {
		return nil, errors.New("operator dependencies require the matching platform scope")
	}
	security := realmSecurity{scope: scope}
	operator, err := operatorpostgres.New(deps.pool, operatordomain.RealmID(cfg.Platform.RealmID))
	if err != nil {
		return nil, err
	}
	if err := operator.CheckRuntime(ctx, cfg.InitialSetup.Enabled); err != nil {
		return nil, err
	}
	account, repo, err := security.assembleAccount(deps.pool, deps.redis, mail, cfg.Account, postgres.DeliveryConfig{})
	if err != nil {
		return nil, err
	}
	setup, err := security.assembleSetup(operator, deps.redis, mail, deps.hash, cfg, deps.log)
	if err != nil {
		return nil, err
	}
	sessions := sessionpostgres.New(deps.pool)
	tokens := tokengenerate.New()
	svc := sessionservice.New(clock.UTCClock{}, sessions, tokens, cfg.Session)
	mfa, err := security.assembleMFA(ctx, deps.pool, deps.redis, svc, tokens, mail, cfg, deps.log)
	if err != nil {
		return nil, err
	}
	credentials := passwordpostgres.New(deps.pool)
	policy := settingsservice.New(settingspostgres.New(deps.pool))
	password, err := security.assemblePassword(credentials, deps.redis, mfa.sessions, deps.hash, policy, mail, cfg)
	if err != nil {
		return nil, err
	}
	handler, err := router.NewOperator(router.Handlers{
		Config: cfg, Logger: deps.log, Setup: setup, MFA: mfa.handler,
		PasswordHandler:  passwordhttp.New(password.service, deps.log),
		Recovery:         passwordhttp.NewRecovery(password.recovery, deps.log),
		Middleware:       sessionhttp.New(svc, deps.log),
		Session:          sessionhttp.NewHandler(sessionservice.NewManagement(sessions), deps.log),
		Activity:         sessionhttp.NewActivity(sessionservice.NewActivity(sessions), deps.log),
		Rotation:         sessionhttp.NewRotation(sessionservice.NewRotation(sessions, tokens), deps.log),
		Reauthentication: passwordhttp.NewReauthentication(passwordservice.NewReauthentication(credentials, sessions, deps.hash, password.loginLimit, tokens, cfg.Session.FreshAuthTTL), deps.log),
		ReadyCheck: func(ctx context.Context) error {
			if err := deps.pool.Ping(ctx); err != nil {
				return err
			}
			return deps.redis.Ping(ctx).Err()
		},
	})
	if err != nil {
		return nil, err
	}
	return &realm{
		handler: handler, resources: &resources{},
		retention: accountservice.NewRetention(repo, cfg.Retention),
		workers:   realmDeliveryWorkers(password.recovery, account, mfa.delivery, nil),
	}, nil
}
