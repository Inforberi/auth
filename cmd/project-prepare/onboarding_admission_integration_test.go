package main

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func onboardingAdmissionDrill(t *testing.T, admin, api, runtime *pgxpool.Pool, repo *catalog.PreparationRepository, project domain.Project, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec) {
	t.Helper()
	ctx := t.Context()
	admission, err := catalog.NewOnboardingAdmission(api, project, reservation, binding)
	require.NoError(t, err)
	allowed, err := admission.Check(ctx)
	require.NoError(t, err)
	require.False(t, allowed, "preparation and an open database alone do not grant HTTP admission")
	require.Error(t, repo.PermitOnboarding(ctx, reservation, binding, codec, nil))
	for _, statement := range []string{
		`UPDATE platform.project_preparations SET onboarding_admitted=true`,
		`SELECT ciphertext FROM platform.project_secrets`,
		`SELECT key_id FROM platform.project_secrets`,
	} {
		_, err := api.Exec(ctx, statement)
		require.Error(t, err, statement)
	}
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations ADD CONSTRAINT fail_onboarding_permission CHECK(NOT onboarding_admitted)`)
	require.NoError(t, err)
	require.Error(t, repo.PermitOnboarding(ctx, reservation, binding, codec, runtime))
	allowed, err = admission.Check(ctx)
	require.NoError(t, err)
	require.False(t, allowed, "failed permission commit must leave admission closed")
	_, err = admin.Exec(ctx, `ALTER TABLE platform.project_preparations DROP CONSTRAINT fail_onboarding_permission`)
	require.NoError(t, err)
	results := make(chan error, 2)
	for range 2 {
		go func() { results <- repo.PermitOnboarding(ctx, reservation, binding, codec, runtime) }()
	}
	for range 2 {
		require.NoError(t, <-results)
	}
	allowed, err = admission.Check(ctx)
	require.NoError(t, err)
	require.True(t, allowed)
	var before, after string
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text FROM platform.project_preparations WHERE project_id=$1`, project.ID).Scan(&before))
	require.NoError(t, repo.PermitOnboarding(ctx, reservation, binding, codec, runtime))
	require.NoError(t, admin.QueryRow(ctx, `SELECT xmin::text FROM platform.project_preparations WHERE project_id=$1`, project.ID).Scan(&after))
	require.Equal(t, before, after, "replay must not write the permission again")
	reopened, err := catalog.NewOnboardingAdmission(api, project, reservation, binding)
	require.NoError(t, err)
	allowed, err = reopened.Check(ctx)
	require.NoError(t, err)
	require.True(t, allowed, "permission survives a new reader, not only an in-memory callback")
	wrong := project
	wrong.Origin = "https://other.example.test"
	foreign, err := catalog.NewOnboardingAdmission(api, wrong, reservation, binding)
	require.NoError(t, err)
	allowed, err = foreign.Check(ctx)
	require.NoError(t, err)
	require.False(t, allowed)
	for _, statement := range []string{
		`UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`,
		`UPDATE platform.projects SET version=version+1 WHERE id=$1`,
		`UPDATE platform.projects SET generation=generation+1 WHERE id=$1`,
	} {
		_, err := admin.Exec(ctx, statement, project.ID)
		require.NoError(t, err)
		allowed, err := admission.Check(ctx)
		require.NoError(t, err)
		require.False(t, allowed, "stale descriptor must not authorize a new epoch")
		require.ErrorIs(t, repo.PermitOnboarding(ctx, reservation, binding, codec, runtime), domain.ErrConflict)
		// Restore only synthetic fixture state so the remaining bootstrap regression can run.
		_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled',version=$2,generation=$3 WHERE id=$1`, project.ID, project.Version, project.Generation)
		require.NoError(t, err)
	}
	lock, err := admin.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = lock.Rollback(ctx) }()
	_, err = lock.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended' WHERE id=$1`, project.ID)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	require.Error(t, repo.PermitOnboarding(bounded, reservation, binding, codec, runtime))
	require.NoError(t, lock.Rollback(ctx))
	_, err = admin.Exec(ctx, `REVOKE SELECT(onboarding_admitted) ON platform.project_preparations FROM auth_platform_api_secrets_test`)
	require.NoError(t, err)
	allowed, err = admission.Check(ctx)
	require.Error(t, err)
	require.False(t, allowed)
	_, err = admin.Exec(ctx, `GRANT SELECT(onboarding_admitted) ON platform.project_preparations TO auth_platform_api_secrets_test`)
	require.NoError(t, err)
	onboardingEpochDrill(t, admin, repo)
}

func onboardingEpochDrill(t *testing.T, admin *pgxpool.Pool, repo *catalog.PreparationRepository) {
	t.Helper()
	ctx := t.Context()
	const id = domain.ID("a2000000-0000-4000-8000-000000000002")
	_, err := admin.Exec(ctx, `INSERT INTO platform.projects(id,slug,name,origin,storage_target)
		VALUES($1,'admission-epoch','Epoch fixture','https://epoch.example.test','primary')`, id)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		_, err := admin.Exec(cleanup, `DELETE FROM platform.project_events WHERE project_id=$1`, id)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM platform.project_preparations WHERE project_id=$1`, id)
		require.NoError(t, err)
		_, err = admin.Exec(cleanup, `DELETE FROM platform.projects WHERE id=$1`, id)
		require.NoError(t, err)
	}()
	input := domain.PreparationRequest{ProjectID: id, OperationID: "b2000000-0000-4000-8000-000000000002", ExpectedVersion: 1, ExpectedGeneration: 1}
	first, err := repo.Reserve(ctx, input)
	require.NoError(t, err)
	// Only fixture metadata is advanced; this is not a substitute for lifecycle API acceptance.
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET secrets_created=true,onboarding_admitted=true WHERE project_id=$1`, id)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET phase='pending',version=version+1,generation=generation+1 WHERE id=$1`, id)
	require.NoError(t, err)
	input.OperationID, input.ExpectedVersion, input.ExpectedGeneration = "b2000000-0000-4000-8000-000000000003", first.Version+1, first.Generation+1
	second, err := repo.Reserve(ctx, input)
	require.NoError(t, err)
	require.Equal(t, first.ReservationID, second.ReservationID)
	var reset bool
	require.NoError(t, admin.QueryRow(ctx, `SELECT NOT onboarding_admitted AND secrets_created FROM platform.project_preparations WHERE project_id=$1`, id).Scan(&reset))
	require.True(t, reset, "a new preparation epoch must not inherit permission")
}
