package postgres

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingsservice "github.com/Inforberi/financial-intelligence/internal/auth/settings/service"
)

func checkTelegramBotSettingsRaces(t *testing.T, db *pgxpool.Pool, ctx context.Context, svc *settingsservice.TelegramBotSettings, actor accessservice.Principal, hook *func(context.Context)) {
	t.Helper()
	t.Run("version changes during verification", func(t *testing.T) {
		before, err := svc.Credentials(ctx)
		require.NoError(t, err)
		*hook = func(ctx context.Context) { accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET version=version+1`) }
		t.Cleanup(func() { *hook = nil })
		_, err = svc.Update(ctx, settingsservice.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: before.Snapshot.Version, RotateWebhookSecret: true})
		require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
		after, err := svc.Credentials(ctx)
		require.NoError(t, err)
		require.Equal(t, before.WebhookSecret, after.WebhookSecret)
		require.Equal(t, before.Token.Value(), after.Token.Value())
	})
	t.Run("permission changes during verification", func(t *testing.T) {
		before, err := svc.Credentials(ctx)
		require.NoError(t, err)
		*hook = func(ctx context.Context) {
			accessExec(t, db, ctx, `DELETE FROM auth.role_permissions WHERE permission_key='auth.settings.manage'
 AND role_id IN(SELECT role_id FROM auth.user_roles WHERE user_id=$1)`, actor.UserID)
		}
		t.Cleanup(func() {
			*hook = nil
			accessExec(t, db, ctx, `INSERT INTO auth.role_permissions(role_id,permission_key)
 SELECT id,'auth.settings.manage' FROM auth.roles WHERE key='telegram_bot_manager' ON CONFLICT DO NOTHING`)
		})
		_, err = svc.Update(ctx, settingsservice.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: before.Snapshot.Version, RotateWebhookSecret: true})
		require.ErrorIs(t, err, accessdomain.ErrForbidden)
		after, err := svc.Credentials(ctx)
		require.NoError(t, err)
		require.Equal(t, before.Snapshot, after.Snapshot)
		require.Equal(t, before.WebhookSecret, after.WebhookSecret)
	})
	t.Run("session revoked during verification", func(t *testing.T) {
		before, err := svc.Credentials(ctx)
		require.NoError(t, err)
		login := renewAccessPrincipal(t, db, ctx, actor.UserID)
		*hook = func(ctx context.Context) {
			accessExec(t, db, ctx, `UPDATE auth.sessions SET revoked_at=clock_timestamp() WHERE token_hash=$1`, login.TokenHash)
		}
		t.Cleanup(func() { *hook = nil })
		_, err = svc.Update(ctx, settingsservice.TelegramBotUpdateInput{Actor: login, ExpectedVersion: before.Snapshot.Version, RotateWebhookSecret: true})
		require.ErrorIs(t, err, accessdomain.ErrFreshAuthRequired)
		after, err := svc.Credentials(ctx)
		require.NoError(t, err)
		require.Equal(t, before.Snapshot, after.Snapshot)
	})
	t.Run("two rotations have one winner", func(t *testing.T) {
		before, err := svc.Read(ctx, actor)
		require.NoError(t, err)
		var entered atomic.Int32
		release := make(chan struct{})
		*hook = func(ctx context.Context) {
			if entered.Add(1) == 2 {
				close(release)
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		t.Cleanup(func() { *hook = nil })
		rotate := func() error {
			_, err := svc.Update(ctx, settingsservice.TelegramBotUpdateInput{Actor: actor, ExpectedVersion: before.Version, RotateWebhookSecret: true})
			return err
		}
		a, b := protectionPair(rotate, rotate)
		if a == nil {
			require.ErrorIs(t, b, settingsdomain.ErrPolicyConflict)
		} else {
			require.NoError(t, b)
			require.ErrorIs(t, a, settingsdomain.ErrPolicyConflict)
		}
		after, err := svc.Read(ctx, actor)
		require.NoError(t, err)
		require.Equal(t, before.Version+1, after.Version)
	})
}
