package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOnboardingKeys(t *testing.T) {
	codec, err := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "root-1")
	require.NoError(t, err)
	binding := testBinding()
	payload, err := codec.Generate(binding)
	require.NoError(t, err)
	keys, err := codec.OpenOnboarding(binding, Version, "root-1", payload)
	require.NoError(t, err)
	value, err := codec.open(binding, Version, "root-1", payload)
	require.NoError(t, err)
	defer clear(value.SigningPrivateKey)
	require.Equal(t, binding, keys.Binding())
	require.Equal(t, value.EncryptionKey, keys.EncryptionKey())
	require.Equal(t, value.SetupSecret, keys.SetupSecret())
	proof, err := codec.OpenSetup(binding, Version, "root-1", payload)
	require.NoError(t, err)
	require.Equal(t, proof, keys.Proof())
	for _, format := range []string{"%v", "%+v", "%#v"} {
		require.Equal(t, "[REDACTED onboarding keys]", fmt.Sprintf(format, keys))
	}
	encoded, err := json.Marshal(keys)
	require.NoError(t, err)
	require.JSONEq(t, `"[REDACTED onboarding keys]"`, string(encoded))
	wrong := binding
	wrong.ProjectID = "a2000000-0000-4000-8000-000000000002"
	empty, err := codec.OpenOnboarding(wrong, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, empty.EncryptionKey())
	require.Empty(t, empty.SetupSecret())
	require.Empty(t, empty.Proof().Digest())
	otherPayload, err := codec.Generate(wrong)
	require.NoError(t, err)
	other, err := codec.OpenOnboarding(wrong, Version, "root-1", otherPayload)
	require.NoError(t, err)
	require.NotEqual(t, keys.EncryptionKey(), other.EncryptionKey())
	require.NotEqual(t, keys.SetupSecret(), other.SetupSecret())
	payload[len(payload)-1] ^= 1
	empty, err = codec.OpenOnboarding(binding, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, empty.SetupSecret())
}
