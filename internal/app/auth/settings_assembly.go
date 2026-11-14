package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	settingsapp "github.com/Inforberi/financial-intelligence/internal/app/auth/settings"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
	"github.com/Inforberi/financial-intelligence/internal/config"
)

type standaloneSettings struct {
	links            *settingshttp.LinkLifetimePolicyHandler
	credentials      *settingshttp.CredentialLifetimePolicyHandler
	budgets          *settingshttp.LoginBudgetPolicyHandler
	operationBudgets *settingshttp.OperationBudgetsPolicyHandler
	frontend         *settingshttp.FrontendPolicyHandler
	sessions         *settingshttp.BrowserSessionPolicyHandler
}

func assembleStandaloneSettings(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, log *zap.Logger) (standaloneSettings, error) {
	repo := settingspostgres.New(pool)
	linkLifetimePolicy, err := settingsapp.AssembleLinkLifetimePolicy(ctx, repo, cfg, log)
	if err != nil {
		return standaloneSettings{}, fmt.Errorf("assemble link lifetime policy: %w", err)
	}
	credentialLifetimePolicy, err := settingsapp.AssembleCredentialLifetimePolicy(ctx, repo, cfg, log)
	if err != nil {
		return standaloneSettings{}, fmt.Errorf("assemble credential lifetime policy: %w", err)
	}
	loginBudgetPolicy, err := settingsapp.AssembleLoginBudgetPolicy(ctx, repo, cfg, log)
	if err != nil {
		return standaloneSettings{}, fmt.Errorf("assemble login budget policy: %w", err)
	}
	operations, err := settingsapp.AssembleOperationBudgetsPolicy(ctx, repo, cfg, log)
	if err != nil {
		return standaloneSettings{}, fmt.Errorf("assemble operation budgets policy: %w", err)
	}
	frontendPolicy, err := settingsapp.AssembleFrontendPolicy(ctx, repo, cfg, log)
	if err != nil {
		return standaloneSettings{}, fmt.Errorf("assemble frontend policy: %w", err)
	}
	sessions, err := settingsapp.AssembleBrowserSessionPolicy(ctx, repo, cfg.Session, cfg.SettingsSource.Mode, log)
	if err != nil {
		return standaloneSettings{}, fmt.Errorf("assemble browser session policy: %w", err)
	}
	return standaloneSettings{links: linkLifetimePolicy, credentials: credentialLifetimePolicy, budgets: loginBudgetPolicy, operationBudgets: operations, frontend: frontendPolicy, sessions: sessions}, nil
}
