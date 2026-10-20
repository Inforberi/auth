package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDatabaseCredentialReadAndRedaction(t *testing.T) {
	codec, err := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "root-1")
	require.NoError(t, err)
	binding := testBinding()
	payload, err := codec.Generate(binding)
	require.NoError(t, err)
	value, err := codec.OpenDatabase(binding, Version, "root-1", payload)
	require.NoError(t, err)
	require.Equal(t, binding, value.Binding())
	password, err := base64.RawURLEncoding.DecodeString(value.Password())
	require.NoError(t, err)
	require.Len(t, password, 32)
	repeated, err := codec.OpenDatabase(binding, Version, "root-1", payload)
	require.NoError(t, err)
	require.Equal(t, value.Password(), repeated.Password())
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		require.NotContains(t, fmt.Sprintf(format, value), value.Password())
		require.NotContains(t, fmt.Sprintf(format, &value), value.Password())
	}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.JSONEq(t, `"[REDACTED database credential]"`, string(encoded))
	mutated := binding
	mutated.RuntimeOID++
	empty, err := codec.OpenDatabase(mutated, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, empty.Password())
	for _, tc := range []struct {
		version int
		keyID   string
		payload []byte
	}{{Version + 1, "root-1", payload}, {Version, "root-2", payload}, {Version, "root-1", []byte("corrupt")}} {
		empty, err := codec.OpenDatabase(binding, tc.version, tc.keyID, tc.payload)
		require.ErrorIs(t, err, ErrUnavailable)
		require.Empty(t, empty.Password())
	}
}
