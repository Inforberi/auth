package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sessionpostgres "github.com/Inforberi/financial-intelligence/internal/auth/session/repository/postgres"
	sessionservice "github.com/Inforberi/financial-intelligence/internal/auth/session/service"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/infra/tokengenerate"
)

func TestBrowserSessionPolicySchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })

	f := newStatusFixture(t, db, ctx, "session-policy")
	policy := sessionservice.BrowserPolicy{
		IdleSeconds: 600, AbsoluteSeconds: 1800, RefreshThresholdSeconds: 120,
		AdminIdleSeconds: 90, AdminAbsoluteSeconds: 300, AdminActivitySeconds: 5,
	}
	require.NoError(t, settingspostgres.New(db).BrowserSessionPolicy().Initialize(ctx, policy))
	accessExec(t, db, ctx, `UPDATE auth.settings_source SET initialized=true WHERE singleton`)
	repo := sessionpostgres.NewWithBrowserPolicy(db)
	params := f.params
	params.TokenHash = tokengenerate.New().Hash("configured-browser-session")
	expires, err := repo.CreateSession(ctx, params)
	require.NoError(t, err)
	issued, err := repo.FindSession(ctx, params.TokenHash)
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, expires.Sub(issued.CreatedAt))
	require.Equal(t, 30*time.Minute, issued.AbsoluteExpiresAt.Sub(issued.CreatedAt))
	require.EqualValues(t, 600, issued.BrowserIdleSeconds)
	require.EqualValues(t, 120, issued.BrowserRefreshSeconds)

	policy.IdleSeconds = 480
	accessExec(t, db, ctx, `UPDATE auth.browser_session_policy SET policy=$1 WHERE singleton`, policy)
	issued, err = repo.FindSession(ctx, params.TokenHash)
	require.NoError(t, err)
	require.EqualValues(t, 600, issued.BrowserIdleSeconds)
	legacy, err := repo.FindSession(ctx, f.params.TokenHash)
	require.NoError(t, err)
	require.Zero(t, legacy.BrowserIdleSeconds)
	require.Equal(t, 2*time.Hour, legacy.AbsoluteExpiresAt.Sub(legacy.CreatedAt))
}
