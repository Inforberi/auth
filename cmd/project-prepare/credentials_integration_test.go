package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
	catalog "github.com/Inforberi/financial-intelligence/internal/platform/project/repository/postgres"
)

func credentialsReadDrill(t *testing.T, admin *pgx.Conn, repo *catalog.PreparationRepository, reservation domain.PreparationReservation, binding credentials.Binding, codec *credentials.Codec, payload []byte) {
	t.Helper()
	ctx := t.Context()
	first, err := repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.NoError(t, err)
	require.NotEmpty(t, first.Password())
	require.Equal(t, binding, first.Binding())
	second, err := repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.NoError(t, err)
	require.Equal(t, first.Password(), second.Password())
	for _, mutate := range []func(*domain.PreparationReservation, *credentials.Binding){
		func(r *domain.PreparationReservation, _ *credentials.Binding) { r.Generation++ },
		func(r *domain.PreparationReservation, _ *credentials.Binding) { r.Version++ },
		func(r *domain.PreparationReservation, _ *credentials.Binding) {
			r.OperationID = "b2000000-0000-4000-8000-000000000002"
		},
		func(_ *domain.PreparationReservation, b *credentials.Binding) { b.RuntimeOID++ },
		func(_ *domain.PreparationReservation, b *credentials.Binding) { b.StorageTarget = "other" },
		func(_ *domain.PreparationReservation, b *credentials.Binding) {
			b.ProjectID = "a2000000-0000-4000-8000-000000000002"
		},
	} {
		r, b := reservation, binding
		mutate(&r, &b)
		value, err := repo.ReadDatabaseCredential(ctx, r, b, codec)
		require.ErrorIs(t, err, domain.ErrConflict)
		require.Empty(t, value.Password())
	}
	wrong, err := credentials.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32)), "root-1")
	require.NoError(t, err)
	value, err := repo.ReadDatabaseCredential(ctx, reservation, binding, wrong)
	require.ErrorIs(t, err, credentials.ErrUnavailable)
	require.Empty(t, value.Password())
	tampered := append([]byte{}, payload...)
	tampered[len(tampered)-1] ^= 1
	_, err = admin.Exec(ctx, `UPDATE platform.project_secrets SET ciphertext=$1`, tampered)
	require.NoError(t, err)
	value, err = repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.ErrorIs(t, err, credentials.ErrUnavailable)
	require.Empty(t, value.Password())
	_, err = admin.Exec(ctx, `UPDATE platform.project_secrets SET ciphertext=$1`, payload)
	require.NoError(t, err)
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET secrets_created=false`)
	require.NoError(t, err)
	value, err = repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Empty(t, value.Password())
	_, err = admin.Exec(ctx, `UPDATE platform.project_preparations SET secrets_created=true`)
	require.NoError(t, err)
	tx, err := admin.Begin(ctx)
	require.NoError(t, err)
	defer func() {
		if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	_, err = tx.Exec(ctx, `UPDATE platform.projects SET desired_state='suspended'`)
	require.NoError(t, err)
	blocked, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	value, err = repo.ReadDatabaseCredential(blocked, reservation, binding, codec)
	require.Error(t, err)
	require.Empty(t, value.Password(), "blocked reader must not leak a stale credential")
	require.NoError(t, tx.Commit(ctx))
	value, err = repo.ReadDatabaseCredential(ctx, reservation, binding, codec)
	require.ErrorIs(t, err, domain.ErrConflict)
	require.Empty(t, value.Password())
	_, err = admin.Exec(ctx, `UPDATE platform.projects SET desired_state='enabled'`)
	require.NoError(t, err)
}
