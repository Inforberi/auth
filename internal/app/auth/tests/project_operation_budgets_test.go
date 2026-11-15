package auth_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspg "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
)

func TestProjectOperationBudgetsUseStoredLimits(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })

	baseline := settings.OperationBudgetsPolicy{
		GoogleIP: 20, GoogleGlobal: 100, TelegramIP: 20, TelegramGlobal: 100,
		MFAUser: 10, MFAIP: 20, MFAGlobal: 100, BindingRequest: 10, BindingConfirm: 20,
		InvitationActor: 10, InvitationGlobal: 100, ActivationGlobal: 100,
		TemporaryActor: 10, TemporaryGlobal: 100, TemporarySetup: 100,
		JWTActor: 10, JWTSession: 10, JWTIP: 20, JWTGlobal: 100, JWTConsumer: 100, JWTIntrospection: 200,
	}
	require.NoError(t, baseline.Validate(baseline))
	store := settingspg.New(db)
	got, err := store.ProjectOperationBudgets(ctx, baseline)
	require.NoError(t, err)
	require.Equal(t, baseline, got)

	configured := baseline
	configured.MFAUser--
	require.NoError(t, configured.Validate(baseline))
	require.NoError(t, pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		_, err := store.OperationBudgetsPolicy().ApplyProject(ctx, tx, "23400000-0000-4000-8000-000000000001", 1, baseline, configured)
		return err
	}))
	got, err = store.ProjectOperationBudgets(ctx, baseline)
	require.NoError(t, err)
	require.Equal(t, configured, got)
}
