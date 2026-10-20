package postgres

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordVerifier(t *testing.T) {
	password := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))
	first, err := passwordVerifier(password)
	require.NoError(t, err)
	require.NotContains(t, first, password)
	require.True(t, strings.HasPrefix(first, "SCRAM-SHA-256$4096:"))
	second, err := passwordVerifier(password)
	require.NoError(t, err)
	require.NotEqual(t, first, second, "first installations use independent random salts")
	for _, invalid := range []string{"", "short", "' SQL injection", "пароль", base64.RawURLEncoding.EncodeToString(make([]byte, 31))} {
		verifier, err := passwordVerifier(invalid)
		require.Error(t, err)
		require.Empty(t, verifier)
		require.NotContains(t, err.Error(), "SQL injection")
	}
}
