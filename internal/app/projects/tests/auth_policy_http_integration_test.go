package projects_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	operatordomain "github.com/Inforberi/financial-intelligence/internal/admin/administrators/domain"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/credentials"
	"github.com/Inforberi/financial-intelligence/internal/admin/projects/domain"
	policypostgres "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/repository/postgres"
	policyhttp "github.com/Inforberi/financial-intelligence/internal/admin/projects/policy/transport/http"
	catalog "github.com/Inforberi/financial-intelligence/internal/admin/projects/repository/postgres"
	projectruntime "github.com/Inforberi/financial-intelligence/internal/admin/projects/runtime"
	settingsdomain "github.com/Inforberi/financial-intelligence/internal/auth/settings/domain"
	settingspostgres "github.com/Inforberi/financial-intelligence/internal/auth/settings/repository/postgres"
	settingshttp "github.com/Inforberi/financial-intelligence/internal/auth/settings/transport/http"
)

func authPolicyHTTPDrill(t *testing.T, admin *pgx.Conn, managed *catalog.Repository, actor operatordomain.Principal, base domain.RoleCreation, binding credentials.Binding, registry *projectruntime.Registry, call roleHTTPCall) {
	t.Helper()
	ctx := t.Context()
	cfg := admin.Config().Copy()
	var err error
	cfg.Database, _, err = (domain.PreparationReservation{ProjectID: binding.ProjectID, ReservationID: binding.ReservationID}).ResourceNames()
	require.NoError(t, err)
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, db.Close(cleanup))
	})
	var empty bool
	require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.platform_auth_policy_updates)`).Scan(&empty))
	require.True(t, empty, "this drill must own every policy receipt it removes")
	// Previous preparation drills may seed settings. Preserve their exact row for later drills.
	_, err = db.Exec(ctx, `CREATE TEMP TABLE policy_fixture_before AS TABLE auth.auth_settings; CREATE TEMP TABLE smtp_fixture_before AS TABLE auth.smtp_settings; CREATE TEMP TABLE providers_fixture_before AS TABLE auth.provider_settings`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.platform_auth_policy_updates;
 DELETE FROM auth.auth_settings; INSERT INTO auth.auth_settings SELECT * FROM policy_fixture_before;
 DELETE FROM auth.smtp_settings; INSERT INTO auth.smtp_settings SELECT * FROM smtp_fixture_before;
 DELETE FROM auth.provider_settings; INSERT INTO auth.provider_settings SELECT * FROM providers_fixture_before`)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM platform.project_auth_policy_admissions WHERE operation_id IN (SELECT operation_id FROM platform.project_auth_policy_intents WHERE project_id=$1)`, base.ProjectID)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM platform.project_auth_policy_intents WHERE project_id=$1`, base.ProjectID)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_settings.manage'`, actor.UserID)
		require.NoError(t, err)
	})
	_, err = db.Exec(ctx, `DELETE FROM auth.auth_settings; DELETE FROM auth.smtp_settings; DELETE FROM auth.provider_settings`)
	require.NoError(t, err)
	path := "/api/v1/platform/projects/" + string(base.ProjectID) + "/auth/settings"
	query := fmt.Sprintf("?expectedVersion=%d&expectedGeneration=%d", base.ExpectedVersion, base.ExpectedGeneration)
	closed := settingsdomain.Policy{PasswordEmailVerification: settingsdomain.VerificationDisabled}
	input := func(number, version int64, policy settingsdomain.Policy) policyhttp.UpdateProjectAuthPolicyRequest {
		b := func(v bool) *bool { return &v }
		return policyhttp.UpdateProjectAuthPolicyRequest{OperationID: domain.ID(fmt.Sprintf("f9000000-0000-4000-8000-%012d", number)), ExpectedVersion: base.ExpectedVersion, ExpectedGeneration: base.ExpectedGeneration, ExpectedPolicyVersion: version, Reason: "Policy SQL fixture", Policy: &settingshttp.PolicyRequest{
			Methods: &settingshttp.MethodsRequest{Password: b(policy.Methods.Password), EmailOTP: b(policy.Methods.EmailOTP), Google: b(policy.Methods.Google), Telegram: b(policy.Methods.Telegram)}, Registration: &settingshttp.RegistrationRequest{Enabled: b(policy.Registration.Enabled), Google: b(policy.Registration.Google), Telegram: b(policy.Registration.Telegram)}, PasswordEmailVerification: policy.PasswordEmailVerification, TokenIssuance: &settingshttp.TokenIssuanceRequest{SessionExchange: b(policy.TokenIssuance.SessionExchange), Native: b(policy.TokenIssuance.Native)},
		}}
	}
	command := func(number, version int64, policy settingsdomain.Policy) domain.AuthPolicyUpdate {
		return domain.AuthPolicyUpdate{OperationID: input(number, version, policy).OperationID, ProjectID: base.ProjectID, ExpectedVersion: base.ExpectedVersion, ExpectedGeneration: base.ExpectedGeneration, ExpectedPolicyVersion: version, Policy: policy, Reason: "Policy SQL fixture"}
	}
	call(t, "GET", path+query, nil, 403)
	_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_settings.manage')`, actor.UserID)
	require.NoError(t, err)
	call(t, "GET", path+query, nil, 409)
	tx, err := db.Begin(ctx)
	require.NoError(t, err)
	_, err = settingspostgres.InitializeInTransaction(ctx, tx, closed)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	var read settingshttp.SettingsResponse
	require.NoError(t, json.Unmarshal(call(t, "GET", path+query, nil, 200), &read))
	require.EqualValues(t, 1, read.Version)
	require.False(t, read.AvailableMethods.Password)
	var xmin string
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text FROM auth.auth_settings`).Scan(&xmin))
	var first, replay policyhttp.ProjectAuthPolicyResponse
	require.NoError(t, json.Unmarshal(call(t, "POST", path, input(1, 1, closed), 200), &first))
	require.False(t, *first.Changed)
	dormant := closed
	dormant.Registration.Google = true
	require.NoError(t, json.Unmarshal(call(t, "POST", path, input(2, 1, dormant), 200), &first))
	require.True(t, *first.Changed)
	require.EqualValues(t, 2, first.Settings.Version)
	require.NoError(t, json.Unmarshal(call(t, "POST", path, input(1, 1, closed), 200), &replay))
	require.True(t, replay.Replayed)
	require.EqualValues(t, 1, replay.Settings.Version)
	// Historical outcomes are not the current policy; replay precedes policy-version checks.
	require.NoError(t, json.Unmarshal(call(t, "GET", path+"/operations/"+string(input(2, 1, dormant).OperationID), nil, 200), &replay))
	require.True(t, replay.Replayed)
	require.EqualValues(t, 2, replay.Settings.Version)
	call(t, "POST", path, input(2, 1, closed), 409)
	call(t, "POST", path, input(3, 1, closed), 409)
	var unchanged bool
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text<>$1 FROM auth.auth_settings`, xmin).Scan(&unchanged))
	require.True(t, unchanged)
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text FROM auth.auth_settings`).Scan(&xmin))
	call(t, "POST", path, input(4, 2, dormant), 200)
	require.NoError(t, db.QueryRow(ctx, `SELECT xmin::text=$1 FROM auth.auth_settings`, xmin).Scan(&unchanged))
	require.True(t, unchanged, "no-op must not rewrite policy")
	for i, policy := range []settingsdomain.Policy{
		{Methods: settingsdomain.PublicMethods{Password: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled},
		{Methods: settingsdomain.PublicMethods{EmailOTP: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled},
		{Methods: settingsdomain.PublicMethods{Google: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled},
		{TokenIssuance: settingsdomain.TokenIssuance{Native: true}, PasswordEmailVerification: settingsdomain.VerificationDisabled},
	} {
		call(t, "POST", path, input(int64(10+i), 2, policy), 409)
	}
	missing := path + "/operations/f9000000-0000-4000-8000-999999999999"
	call(t, "GET", missing, nil, 404)
	call(t, "GET", "/api/v1/platform/projects/a2000000-0000-4000-8000-000000000099/auth/settings/operations/"+string(input(1, 1, closed).OperationID), nil, 404)
	// Synthetic trusted adapters test SQL semantics only, not production adapter assembly.
	capabilities := settingsdomain.PolicyRuntime{Configured: true, Methods: settingsdomain.PublicMethods{Password: true, EmailOTP: true, Google: true, Telegram: true}}
	ready := policypostgres.NewRuntimeAuthPolicy(managed, registry, capabilities)
	password := closed
	password.Methods.Password = true
	result, err := ready.UpdateAuthPolicy(ctx, actor, command(20, 2, password))
	require.NoError(t, err)
	require.True(t, result.Changed)
	require.EqualValues(t, 3, result.Snapshot.Version)
	require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.users) AND NOT EXISTS(SELECT 1 FROM auth.auth_settings_audit)
 AND EXISTS(SELECT 1 FROM auth.platform_auth_policy_updates WHERE operation_id=$1 AND actor_id=$2 AND changed AND (previous_policy->>'Version')::bigint=2 AND (next_policy->>'Version')::bigint=3)`, command(20, 2, password).OperationID, actor.UserID).Scan(&empty))
	require.True(t, empty, "no fake local actor; atomic attributed audit")
	google := password
	google.Methods.Google = true
	_, err = ready.UpdateAuthPolicy(ctx, actor, command(21, 3, google))
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady, "no project provider settings; never use ENV fallback")
	mail := password
	mail.PasswordEmailVerification = settingsdomain.VerificationRequired
	_, err = ready.UpdateAuthPolicy(ctx, actor, command(22, 3, mail))
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady, "delivery not assembled")
	capabilities.EmailDeliveryReady = true
	mailReady := policypostgres.NewRuntimeAuthPolicy(managed, registry, capabilities)
	_, err = mailReady.UpdateAuthPolicy(ctx, actor, command(23, 3, mail))
	require.ErrorIs(t, err, settingsdomain.ErrMethodNotReady, "delivery facts still require project SMTP configuration")
	// Policy and receipt are one transaction: an insert failure must roll back the update.
	_, err = db.Exec(ctx, `CREATE FUNCTION auth.policy_receipt_fixture_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture receipt failure'; END $$;
 CREATE TRIGGER policy_receipt_fixture_failure BEFORE INSERT ON auth.platform_auth_policy_updates FOR EACH ROW EXECUTE FUNCTION auth.policy_receipt_fixture_failure()`)
	require.NoError(t, err)
	_, err = ready.UpdateAuthPolicy(ctx, actor, command(24, 3, closed))
	require.Error(t, err)
	_, err = db.Exec(ctx, `DROP TRIGGER policy_receipt_fixture_failure ON auth.platform_auth_policy_updates; DROP FUNCTION auth.policy_receipt_fixture_failure()`)
	require.NoError(t, err)
	var version int64
	require.NoError(t, db.QueryRow(ctx, `SELECT version FROM auth.auth_settings`).Scan(&version))
	require.EqualValues(t, 3, version)
	// Already admitted commands retain their bounded authority after revocation.
	admission, err := managed.AdmitAuthPolicy(ctx, actor, command(25, 3, closed))
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `DELETE FROM platform.operator_permissions WHERE user_id=$1 AND permission_key='platform.project_settings.manage'`, actor.UserID)
	require.NoError(t, err)
	_, err = managed.AdmitAuthPolicy(ctx, actor, command(26, 3, closed))
	require.ErrorIs(t, err, operatordomain.ErrForbidden)
	result, err = admission.ExecuteWithRuntime(ctx, registry, capabilities)
	require.NoError(t, err)
	require.EqualValues(t, 4, result.Snapshot.Version)
	_, err = admission.ExecuteWithRuntime(ctx, registry, capabilities)
	require.ErrorIs(t, err, domain.ErrConflict)
	call(t, "GET", path+query, nil, 403)
	call(t, "GET", path+"/operations/"+string(command(25, 3, closed).OperationID), nil, 403)
	_, err = admin.Exec(ctx, `INSERT INTO platform.operator_permissions(user_id,permission_key) VALUES($1,'platform.project_settings.manage')`, actor.UserID)
	require.NoError(t, err)
	uncertain := command(27, 4, closed)
	admission, err = managed.AdmitAuthPolicy(ctx, actor, uncertain)
	require.NoError(t, err)
	err = registry.Use(ctx, projectruntime.Key{Binding: binding, Version: base.ExpectedVersion, Generation: base.ExpectedGeneration}, func(ctx context.Context, db projectruntime.Database) error {
		_, err := admission.Execute(ctx, lostPolicyCommitDatabase{db}, capabilities)
		return err
	})
	require.ErrorIs(t, err, domain.ErrOperationOutcomeUnknown)
	outcome, err := ready.ReadAuthPolicyOutcome(ctx, actor, base.ProjectID, uncertain.OperationID)
	require.NoError(t, err)
	require.True(t, outcome.Committed)
	require.False(t, outcome.Changed)
	result, err = ready.UpdateAuthPolicy(ctx, actor, uncertain)
	require.NoError(t, err)
	require.True(t, result.Replayed)
	t.Run("concurrent expected policy version", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, 2)
		for _, n := range []int64{30, 31} {
			wg.Go(func() { _, err := ready.UpdateAuthPolicy(t.Context(), actor, command(n, 4, password)); errors <- err })
		}
		wg.Wait()
		close(errors)
		successful, conflicted := 0, 0
		for err := range errors {
			if err == nil {
				successful++
			} else {
				require.ErrorIs(t, err, settingsdomain.ErrPolicyConflict)
				conflicted++
			}
		}
		require.Equal(t, 1, successful)
		require.Equal(t, 1, conflicted)
	})
	t.Run("concurrent identical operation", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan domain.AuthPolicyResult, 2)
		errors := make(chan error, 2)
		for range 2 {
			wg.Go(func() {
				result, err := ready.UpdateAuthPolicy(t.Context(), actor, command(32, 5, closed))
				results <- result
				errors <- err
			})
		}
		wg.Wait()
		close(errors)
		close(results)
		for err := range errors {
			require.NoError(t, err)
		}
		replayed := 0
		for result := range results {
			require.EqualValues(t, 6, result.Snapshot.Version)
			if result.Replayed {
				replayed++
			}
		}
		require.Equal(t, 1, replayed)
	})
	t.Run("dynamic readiness authority and dependency revisions", func(t *testing.T) {
		authPolicyReadinessDrill(t, admin, db, managed, actor, base, binding, registry)
	})
}

// Commit reaches PostgreSQL; only its acknowledgement is lost to the caller.
type lostPolicyCommitDatabase struct{ catalog.ProjectDatabase }

func (db lostPolicyCommitDatabase) BeginTx(ctx context.Context, options pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.ProjectDatabase.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return lostRoleCommitTransaction{tx}, nil
}
