package credentials

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func testBinding() Binding {
	return Binding{
		RealmID: "c2000000-0000-4000-8000-000000000001", ProjectID: "a2000000-0000-4000-8000-000000000001",
		ReservationID: "b2000000-0000-4000-8000-000000000001", StorageTarget: "primary", DatabaseOID: 101, OwnerOID: 102, RuntimeOID: 103, SchemaVersion: 1,
	}
}

func TestIndependentEncryptedBundle(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	codec, err := New(root, "root-1")
	require.NoError(t, err)
	binding := testBinding()
	first, err := codec.Generate(binding)
	require.NoError(t, err)
	second, err := codec.Generate(binding)
	require.NoError(t, err)
	require.NotEqual(t, first, second)
	require.NoError(t, codec.Verify(binding, Version, "root-1", first))
	cipher, err := codec.cipher(binding, Version, "root-1")
	require.NoError(t, err)
	plain, err := cipher.Open(first)
	require.NoError(t, err)
	defer clear(plain)
	var bundle material
	require.NoError(t, json.Unmarshal(plain, &bundle))
	require.True(t, bundle.valid())
	require.NotEqual(t, bundle.DatabasePassword, bundle.SetupSecret)
	require.NotEqual(t, root, bundle.EncryptionKey)
	for _, secret := range []string{bundle.DatabasePassword, bundle.EncryptionKey, bundle.SetupSecret, bundle.SigningKeyID, string(bundle.SigningPrivateKey)} {
		require.NotContains(t, string(first), secret)
	}
	other := binding
	other.ProjectID = "a2000000-0000-4000-8000-000000000002"
	payload, err := codec.Generate(other)
	require.NoError(t, err)
	otherCipher, err := codec.cipher(other, Version, "root-1")
	require.NoError(t, err)
	otherPlain, err := otherCipher.Open(payload)
	require.NoError(t, err)
	defer clear(otherPlain)
	var otherBundle material
	require.NoError(t, json.Unmarshal(otherPlain, &otherBundle))
	require.NotEqual(t, bundle.DatabasePassword, otherBundle.DatabasePassword)
	require.NotEqual(t, bundle.EncryptionKey, otherBundle.EncryptionKey)
	require.NotEqual(t, bundle.SigningPrivateKey, otherBundle.SigningPrivateKey)
}

func TestBindingTamperAndNoKeyFallback(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	codec, err := New(root, "root-1")
	require.NoError(t, err)
	binding := testBinding()
	payload, err := codec.Generate(binding)
	require.NoError(t, err)
	for _, change := range []func(*Binding){
		func(b *Binding) { b.RealmID = "c2000000-0000-4000-8000-000000000002" },
		func(b *Binding) { b.ProjectID = "a2000000-0000-4000-8000-000000000002" },
		func(b *Binding) { b.ReservationID = "b2000000-0000-4000-8000-000000000002" },
		func(b *Binding) { b.StorageTarget = "secondary" }, func(b *Binding) { b.DatabaseOID++ },
		func(b *Binding) { b.OwnerOID++ }, func(b *Binding) { b.RuntimeOID++ }, func(b *Binding) { b.SchemaVersion++ },
	} {
		mutated := binding
		change(&mutated)
		require.ErrorIs(t, codec.Verify(mutated, Version, "root-1", payload), ErrUnavailable)
	}
	tampered := append([]byte{}, payload...)
	tampered[len(tampered)-1] ^= 1
	require.ErrorIs(t, codec.Verify(binding, Version, "root-1", tampered), ErrUnavailable)
	require.ErrorIs(t, codec.Verify(binding, Version+1, "root-1", payload), ErrUnavailable)
	require.ErrorIs(t, codec.Verify(binding, Version, "root-2", payload), ErrUnavailable)
	wrong, err := New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{18}, 32)), "root-1")
	require.NoError(t, err)
	err = wrong.Verify(binding, Version, "root-1", payload)
	require.ErrorIs(t, err, ErrUnavailable)
	require.NotContains(t, err.Error(), root)
	require.ErrorIs(t, codec.Verify(binding, Version, "root-1", make([]byte, 8193)), ErrUnavailable)
	for _, invalid := range []string{"", root[:10], base64.StdEncoding.EncodeToString(make([]byte, 32))} {
		_, err := New(invalid, "root-1")
		require.ErrorIs(t, err, ErrUnavailable)
	}
}
