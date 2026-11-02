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
