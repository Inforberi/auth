package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSigningKeyBoundRedactedAndConsumed(t *testing.T) {
	codec, err := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32)), "root-1")
	require.NoError(t, err)
	binding := testBinding()
	payload, err := codec.Generate(binding)
	require.NoError(t, err)
	key, err := codec.OpenSigning(binding, Version, "root-1", payload)
	require.NoError(t, err)
	for _, value := range []any{key, &key} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			require.Equal(t, "[REDACTED signing key]", fmt.Sprintf(format, value))
		}
		encoded, err := json.Marshal(value)
		require.NoError(t, err)
		require.JSONEq(t, `"[REDACTED signing key]"`, string(encoded))
	}
	failed := errors.New("synthetic construction failure")
	var buffer []byte
	err = key.Use(func(kid string, private []byte) error {
		require.Len(t, kid, 25)
		require.Contains(t, string(private), "BEGIN PRIVATE KEY")
		buffer = private
		return failed
	})
	require.ErrorIs(t, err, failed)
	require.Empty(t, key.private)
	require.Equal(t, make([]byte, len(buffer)), buffer)
	other := binding
	other.ProjectID = "a2000000-0000-4000-8000-000000000002"
	wrong, err := codec.OpenSigning(other, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Empty(t, wrong.private)
}
