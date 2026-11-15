package cli

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestManagedPreparationFlags(t *testing.T) {
	base := []string{"-project", "a2000000-0000-4000-8000-000000000001", "-operation", "b2000000-0000-4000-8000-000000000001", "-version", "1", "-generation", "1"}
	env := func(key string) string {
		return map[string]string{"PROVISIONER_REALM_ID": "c2000000-0000-4000-8000-000000000001", "PROVISIONER_STORAGE_TARGET": "primary"}[key]
	}
	for _, tc := range []struct {
		flags []string
		err   string
	}{
		{[]string{"-managed"}, "-managed requires -password"},
		{[]string{"-schema", "-secrets", "-password", "-managed", "-onboarding"}, "mutually exclusive"},
		{[]string{"-schema", "-secrets", "-password", "-managed"}, ""},
	} {
		args := append(append([]string{}, base...), tc.flags...)
		input, err := parseCommand(args, env, io.Discard)
		if tc.err != "" {
			require.ErrorContains(t, err, tc.err)
		} else {
			require.NoError(t, err)
			require.True(t, input.managed)
			require.False(t, input.onboarding)
		}
	}
}

func TestRequestedPreparationUsesCatalogInput(t *testing.T) {
	env := func(key string) string {
		return map[string]string{
			"PROVISIONER_REALM_ID":       "c2000000-0000-4000-8000-000000000001",
			"PROVISIONER_STORAGE_TARGET": "primary",
		}[key]
	}
	args := []string{"-requested", "-operation", "b2000000-0000-4000-8000-000000000001"}
	parsed, err := parseCommand(args, env, io.Discard)
	require.NoError(t, err)
	input := parsed.options()
	require.True(t, input.Requested && input.Schema && input.Secrets && input.Password && input.Managed)
	require.False(t, input.Onboarding)
	require.Empty(t, input.Request.ProjectID)
	watch, err := parseCommand([]string{"-watch"}, env, io.Discard)
	require.NoError(t, err)
	require.True(t, watch.options().Watch && watch.options().Requested)
	_, err = parseCommand(append([]string{"-watch"}, args...), env, io.Discard)
	require.Error(t, err)
	_, err = parseCommand(append(args, "-version", "1"), env, io.Discard)
	require.Error(t, err)
}
