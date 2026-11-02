package credentials

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupProof(t *testing.T) {
	codec, err := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32)), "root-1")
	require.NoError(t, err)
	binding := testBinding()
	payload, err := codec.Generate(binding)
	require.NoError(t, err)
	material, err := codec.open(binding, Version, "root-1", payload)
	require.NoError(t, err)
	defer clear(material.SigningPrivateKey)
	proof, err := codec.OpenSetup(binding, Version, "root-1", payload)
	require.NoError(t, err)
	expected := sha256.Sum256([]byte(material.SetupSecret))
	require.Equal(t, hex.EncodeToString(expected[:]), proof.Digest())
	require.Equal(t, binding, proof.Binding())
	for _, format := range []string{"%v", "%+v", "%#v"} {
		require.NotContains(t, fmt.Sprintf(format, proof), proof.Digest())
	}
	encoded, err := json.Marshal(proof)
	require.NoError(t, err)
	require.JSONEq(t, `"[REDACTED setup proof]"`, string(encoded))
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.ProjectID = "a2000000-0000-4000-8000-000000000002" },
		func(b *Binding) { b.RuntimeOID++ },
	} {
		wrong := binding
		mutate(&wrong)
		empty, err := codec.OpenSetup(wrong, Version, "root-1", payload)
		require.ErrorIs(t, err, ErrUnavailable)
		require.Empty(t, empty.Digest())
	}
	payload[len(payload)-1] ^= 1
	_, err = codec.OpenSetup(binding, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
}
