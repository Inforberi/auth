package signing

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Inforberi/financial-intelligence/pkg/authjwt"
)

func TestPreparedSignerUsesSuppliedKeyAndIssuer(t *testing.T) {
	_, private, public := signingFixture(t)
	defer clear(private)
	signer, err := FromPrepared("https://project.example.test", "current", private)
	require.NoError(t, err)
	require.JSONEq(t, string(public), string(signer.PublicJWKS()))
	now := time.Now().UTC().Truncate(time.Second)
	signed, err := signer.Sign(t.Context(), signingClaims(now), now)
	require.NoError(t, err)
	keys, err := authjwt.ParsePublicKeys(signer.PublicJWKS())
	require.NoError(t, err)
	verifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://project.example.test", Audience: "orders", Mode: authjwt.Strict}, keys, now)
	require.NoError(t, err)
	_, err = verifier.VerifySignature(t.Context(), signed.Raw, now)
	require.NoError(t, err)
	other, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://other.example.test", Audience: "orders", Mode: authjwt.Strict}, keys, now)
	require.NoError(t, err)
	_, err = other.VerifySignature(t.Context(), signed.Raw, now)
	require.Error(t, err)
	_, otherPrivate, otherPublic := signingFixture(t)
	defer clear(otherPrivate)
	foreignKeys, err := authjwt.ParsePublicKeys(otherPublic)
	require.NoError(t, err)
	foreignVerifier, err := authjwt.NewVerifier(authjwt.Expectations{Issuer: "https://project.example.test", Audience: "orders", Mode: authjwt.Strict}, foreignKeys, now)
	require.NoError(t, err)
	_, err = foreignVerifier.VerifySignature(t.Context(), signed.Raw, now)
	require.Error(t, err, "a foreign key must fail even with the same issuer and kid")
	_, err = FromPrepared("https://project.example.test", "current", []byte("invalid"))
	require.Error(t, err)
}
