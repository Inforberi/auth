package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthKeyIsolationAndRedaction(t *testing.T) {
	codec, err := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "root-1")
	require.NoError(t, err)
	binding := testBinding()
	payload, err := codec.Generate(binding)
	require.NoError(t, err)
	key, err := codec.OpenAuth(binding, Version, "root-1", payload)
	require.NoError(t, err)
	require.Equal(t, binding, key.Binding())
	material, err := codec.open(binding, Version, "root-1", payload)
	require.NoError(t, err)
	defer clear(material.SigningPrivateKey)
	require.True(t, key.EncryptionKey() == material.EncryptionKey)
	require.NotEqual(t, material.DatabasePassword, key.EncryptionKey())
	require.NotEqual(t, material.SetupSecret, key.EncryptionKey())
	for _, value := range []any{key, &key} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			require.Equal(t, "[REDACTED auth key]", fmt.Sprintf(format, value))
		}
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `"[REDACTED auth key]"`, string(encoded))
	}
	other := binding
	other.ProjectID = "a2000000-0000-4000-8000-000000000002"
	wrong, err := codec.OpenAuth(other, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, wrong.EncryptionKey())
	otherPayload, err := codec.Generate(other)
	require.NoError(t, err)
	otherKey, err := codec.OpenAuth(other, Version, "root-1", otherPayload)
	require.NoError(t, err)
	require.NotEqual(t, key.EncryptionKey(), otherKey.EncryptionKey())
	for _, test := range []struct {
		version int
		keyID   string
		payload []byte
	}{
		{Version + 1, "root-1", payload}, {Version, "wrong-root", payload}, {Version, "root-1", []byte("corrupt")},
	} {
		empty, err := codec.OpenAuth(binding, test.version, test.keyID, test.payload)
		require.ErrorIs(t, err, ErrUnavailable)
		require.Empty(t, empty.EncryptionKey())
		require.Empty(t, empty.Binding().ProjectID)
	}
	payload[len(payload)-1] ^= 1
	empty, err := codec.OpenAuth(binding, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, empty.EncryptionKey())
}
