package main

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
)

func TestConnectionConfig(t *testing.T) {
	t.Setenv("PGOPTIONS", "-c role=unsafe -c statement_timeout=0")
	for _, dsn := range []string{
		"postgres://executor:secret@db.example.test/maintenance?sslmode=verify-full",
		"postgres://executor@/maintenance?host=/var/run/postgresql&sslmode=disable",
	} {
		cfg, err := connectionConfig(dsn)
		require.NoError(t, err)
		require.Equal(t, "45000", cfg.RuntimeParams["statement_timeout"])
		require.NotContains(t, cfg.RuntimeParams, "options")
		require.NotContains(t, cfg.RuntimeParams, "role")
		require.Empty(t, cfg.Fallbacks)
	}
	for _, dsn := range []string{
		"", "host=localhost dbname=maintenance", "postgres://executor@localhost/maintenance?sslmode=disable",
		"postgres://executor@db.example.test/maintenance?sslmode=require",
		"postgres://executor@db.example.test/maintenance?sslmode=verify-ca",
		"postgres://executor@db.example.test/maintenance?sslmode=prefer",
		"postgres://executor@/maintenance", "postgres://executor@db.example.test/?sslmode=verify-full",
		"postgres://executor@db.example.test/maintenance?host=db1,db2&sslmode=verify-full",
	} {
		_, err := connectionConfig(dsn)
		require.Error(t, err, dsn)
		require.NotContains(t, err.Error(), "secret")
	}
}

func TestSecretsModeFailsBeforeConnections(t *testing.T) {
	env := func(key string) string {
		if key == "PROVISIONER_REALM_ID" {
			return "c2000000-0000-4000-8000-000000000001"
		}
		if key == "PROVISIONER_STORAGE_TARGET" {
			return "primary"
		}
		return ""
	}
	args := []string{"-project", "a2000000-0000-4000-8000-000000000001", "-operation", "b2000000-0000-4000-8000-000000000001", "-version", "1", "-generation", "1", "-secrets"}
	_, err := parseCommand(args, env, io.Discard)
	require.ErrorContains(t, err, "-secrets requires -schema")
	_, err = parseCommand(append(args[:len(args)-1:len(args)-1], "-password", "-schema"), env, io.Discard)
	require.ErrorContains(t, err, "-password requires -secrets")
	_, err = parseCommand(append(args[:len(args)-1:len(args)-1], "-schema", "-secrets", "-onboarding"), env, io.Discard)
	require.ErrorContains(t, err, "-onboarding requires -password")
	err = run(t.Context(), append(args, "-schema"), env, io.Discard, io.Discard)
	require.ErrorIs(t, err, credentials.ErrUnavailable)
}

func TestRunRejectsInvalidIntentBeforeConnections(t *testing.T) {
	err := run(context.Background(), []string{"-project", "not-a-uuid"}, func(string) string { return "secret" }, io.Discard, io.Discard)
	require.ErrorContains(t, err, "required")
	require.NotContains(t, err.Error(), "secret")
}
