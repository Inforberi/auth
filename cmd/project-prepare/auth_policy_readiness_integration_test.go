package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/platform/project/runtime"
)

func authPolicyReadinessDrill(t *testing.T, admin, db *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal, base domain.RoleCreation, binding credentials.Binding, registry *projectruntime.Registry) {
	t.Helper()
	ctx := t.Context()
	available := true
	staleProvider, revoke := false, false
	slowNext := false
	probes := 0
	backend := catalog.NewRuntimeAuthPolicy(managed, registry, settingsdomain.PolicyRuntime{Configured: true}).WithReadiness(func(ctx context.Context, key projectruntime.Key, origin string) (domain.AuthPolicyReadiness, error) {
		probes++
		if slowNext {
			slowNext = false
			timer := time.NewTimer(3100 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return domain.AuthPolicyReadiness{}, ctx.Err()
			case <-timer.C:
			}
		}
		require.Equal(t, binding, key.Binding)
		require.NotEmpty(t, origin)
		var snapshot settingsdomain.Snapshot
		err := registry.UsePool(ctx, key, func(ctx context.Context, pool *pgxpool.Pool) error {
			var err error
			snapshot, err = settingspostgres.New(pool).Load(ctx)
			return err
		})
		if err != nil {
			return domain.AuthPolicyReadiness{}, err
		}
		if staleProvider {
			_, err = db.Exec(ctx, `UPDATE auth.provider_settings SET version=version+1 WHERE provider='google'`)
			if err != nil {
				return domain.AuthPolicyReadiness{}, err
			}
		}
		if revoke {
			_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_settings.manage'`, actor.UserID)
			if err != nil {
				return domain.AuthPolicyReadiness{}, err
			}
		}
		return domain.AuthPolicyReadiness{PolicyVersion: snapshot.Version, ObservedAt: time.Now().UTC(), Runtime: settingsdomain.PolicyRuntime{Configured: true, Methods: settingsdomain.PublicMethods{Password: available, Google: staleProvider}, Dependencies: &settingsdomain.DependencyVersions{Google: 1}}}, nil
	})
	target := domain.DirectoryTarget{ProjectID: base.ProjectID, ExpectedVersion: base.ExpectedVersion, ExpectedGeneration: base.ExpectedGeneration}
	bad := actor
	bad.TokenHash = strings.Repeat("0", 64)
	_, err := backend.ReadAuthPolicyView(ctx, bad, target)
	require.Error(t, err)
	require.Zero(t, probes, "no capability probe before current authority")
	view, err := backend.ReadAuthPolicyView(ctx, actor, target)
	require.NoError(t, err)
	require.True(t, view.Readiness.Runtime.Methods.Password)
	require.False(t, view.Snapshot.Policy.Methods.Password, "closed current method does not imply unavailable capability")
	command := func(n, version int64, policy settingsdomain.Policy) domain.AuthPolicyUpdate {
		return domain.AuthPolicyUpdate{OperationID: domain.ID(fmt.Sprintf("f9100000-0000-4000-8000-%012d", n)), ProjectID: base.ProjectID, ExpectedVersion: base.ExpectedVersion, ExpectedGeneration: base.ExpectedGeneration, ExpectedPolicyVersion: version, Policy: policy, Reason: "Dynamic readiness SQL fixture"}
	}
	password := settingsdomain.Policy{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled}
	request := command(1, view.Snapshot.Version, password)
	slowNext = true
	result, err := backend.UpdateAuthPolicy(ctx, actor, request)
	require.NoError(t, err)
	require.True(t, result.Changed)
	available = false
	replay, err := backend.UpdateAuthPolicy(ctx, actor, request)
	require.NoError(t, err)
	require.True(t, replay.Replayed, "replay does not depend on current method readiness")
	closed := settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationDisabled}
	result, err = backend.UpdateAuthPolicy(ctx, actor, command(2, result.Snapshot.Version, closed))
	require.NoError(t, err, "unavailable method can always be disabled")
	available = true
	mail := password
	mail.PasswordEmailVerification = settingsdomain.VerificationRequired
	_, err = backend.UpdateAuthPolicy(ctx, actor, command(3, result.Snapshot.Version, mail))
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady)
	_, err = db.Exec(ctx, `INSERT INTO auth.provider_settings(provider,version,client_id,secret,secret_set) VALUES('google',1,'synthetic-client',decode(repeat('00',28),'hex'),true)`)
	require.NoError(t, err)
	staleProvider = true
	google := closed
	google.Methods.Google = true
	_, err = backend.UpdateAuthPolicy(ctx, actor, command(4, result.Snapshot.Version, google))
	require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict, "stale credential revision must not enable method")
	current, err := backend.ReadAuthPolicy(ctx, actor, target)
	require.NoError(t, err)
	require.Equal(t, result.Snapshot, current)
	staleProvider, revoke = false, true
	_, err = backend.ReadAuthPolicyView(ctx, actor, target)
	require.Error(t, err, "authority loss during probe discards observation")
	_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_settings.manage')`, actor.UserID)
	require.NoError(t, err)
}
