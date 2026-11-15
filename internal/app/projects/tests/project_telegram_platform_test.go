package projects_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	operators "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policy "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	projectprofile "github.com/Inforberi/financial-intelligence/internal/auth/project/profile"
	settings "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
)

func checkPlatformWebhookDenials(t *testing.T, f emailMFAHTTPFixture, bot *telegramHTTPBot, version int64) {
	t.Helper()
	ctx := t.Context()
	repo, actor := isolationPlatformOperator(t, ctx, f.pair)
	backend := policy.NewRuntimeAuthPolicy(repo, f.projects.deps.Registry, settings.PolicyRuntime{}).
		WithSettingsProfile(func(ctx context.Context, key projectruntime.Key, origin string) (projectprofile.Endpoints, error) {
			profile, err := f.factory.Build(ctx, key, origin)
			if err != nil {
				return projectprofile.Endpoints{}, err
			}
			return profile.Endpoints()
		})
	key := f.projects.projects[0]
	target := domain.DirectoryTarget{ProjectID: key.Binding.ProjectID, ExpectedVersion: key.Version, ExpectedGeneration: key.Generation}
	origin := f.webs[0].origin + "/api/v1/auth/mfa/telegram/webhook"
	stored, err := backend.ReadProjectBot(ctx, actor, target)
	require.NoError(t, err)
	require.Equal(t, version, stored.Version)
	require.True(t, stored.TokenSet && stored.WebhookSecretSet)

	db := f.projects.databases[0]
	_, err = db.Exec(ctx, `UPDATE auth.settings_source SET mode='env',
		fingerprint=decode(repeat('ab',32),'hex'),key_binding=decode(repeat('cd',32),'hex') WHERE singleton`)
	require.NoError(t, err)
	_, envErr := backend.ActivateProjectWebhook(ctx, actor, target, version)
	_, err = db.Exec(ctx, `UPDATE auth.settings_source SET mode='api',fingerprint=NULL,key_binding=NULL WHERE singleton`)
	require.NoError(t, err)
	require.ErrorIs(t, envErr, settings.ErrSourceReadOnly)
	require.Empty(t, bot.secret(origin))

	_, err = f.pair.admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key=$2`, actor.UserID, operators.SettingsManage)
	require.NoError(t, err)
	_, err = backend.ActivateProjectWebhook(ctx, actor, target, version)
	require.ErrorIs(t, err, operators.ErrForbidden)
	require.Empty(t, bot.secret(origin))
}
