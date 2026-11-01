package postgres

import (
	"testing"

	"github.com/stretchr/testify/require"

	mfadomain "github.com/Inforberi/financial-intelligence/internal/auth/mfa/domain"
	mfapostgres "github.com/Inforberi/financial-intelligence/internal/auth/mfa/repository/postgres"
	mfaservice "github.com/Inforberi/financial-intelligence/internal/auth/mfa/service"
)

func TestMFAPreferencesSchema(t *testing.T) {
	db, ctx := schemaFixture(t)
	migrateFixture(t, db, ctx, "up")
	t.Cleanup(func() { migrateFixture(t, db, ctx, "down") })
	f := newEmailPreparationFixture(t, db, ctx, "preference", true)
	repo := mfapostgres.New(db)
	prefs, err := mfaservice.NewPreferences(repo, f.cipher, mfaTestLimit{}, mfaservice.PreferenceConfig{UserChangesPerMinute: 100, ProjectChangesPerMinute: 1000})
	require.NoError(t, err)
	initial, err := prefs.Read(ctx, f.proof)
	require.NoError(t, err)
	require.Equal(t, mfadomain.Preference{}, initial)
	_, err = prefs.Read(ctx, mfaservice.Proof{})
	require.ErrorIs(t, err, mfadomain.ErrProofRequired)
	_, err = prefs.Update(ctx, mfaservice.PreferenceUpdate{Proof: f.proof, Method: "telegram"})
	require.ErrorIs(t, err, mfadomain.ErrInvalidPreference)
	_, err = prefs.Update(ctx, mfaservice.PreferenceUpdate{Proof: f.proof, Method: mfadomain.EmailCode})
	require.ErrorIs(t, err, mfadomain.ErrUnavailable)
	selectTOTP := func() error {
		_, err := prefs.Update(ctx, mfaservice.PreferenceUpdate{Proof: f.proof, Method: mfadomain.TOTP})
		return err
	}
	a, b := protectionPair(selectTOTP, selectTOTP)
	if a == nil {
		require.ErrorIs(t, b, mfadomain.ErrConflict)
	} else {
		require.NoError(t, b)
		require.ErrorIs(t, a, mfadomain.ErrConflict)
	}
	current, err := prefs.Read(ctx, f.proof)
	require.NoError(t, err)
	require.EqualValues(t, 1, current.Version)
	require.Equal(t, mfadomain.TOTP, current.Method)
	accessExec(t, db, ctx, `UPDATE auth.mfa_settings SET email_factor_allowed=true`)
	accessExec(t, db, ctx, `INSERT INTO auth.mfa_email(user_id,email_id) SELECT user_id,id FROM auth.user_emails WHERE user_id=$1`, f.user)
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit ADD CONSTRAINT reject_preference CHECK(event<>'factor_preference_changed') NOT VALID`)
	t.Cleanup(func() {
		accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT IF EXISTS reject_preference`)
	})
	_, err = prefs.Update(ctx, mfaservice.PreferenceUpdate{Proof: f.proof, ExpectedVersion: current.Version, Method: mfadomain.EmailCode})
	require.Error(t, err)
	afterFailure, err := prefs.Read(ctx, f.proof)
	require.NoError(t, err)
	require.Equal(t, current, afterFailure)
	accessExec(t, db, ctx, `ALTER TABLE auth.mfa_audit DROP CONSTRAINT reject_preference`)
	chosen, err := prefs.Update(ctx, mfaservice.PreferenceUpdate{Proof: f.proof, ExpectedVersion: current.Version, Method: mfadomain.EmailCode})
	require.NoError(t, err)
	beforeProof := f.proof
	factors, err := mfaservice.NewEmailFactors(repo, f.cipher, mfaTestLimit{})
	require.NoError(t, err)
	require.NoError(t, factors.Disable(ctx, f.proof))
	_, err = prefs.Read(ctx, beforeProof)
	require.ErrorIs(t, err, mfadomain.ErrProofRequired)
	f.proof = renewedEmailFactorProof(t, db, ctx, f.user)
	cleared, err := prefs.Read(ctx, f.proof)
	require.NoError(t, err)
	require.Empty(t, cleared.Method)
	require.Equal(t, chosen.Version+1, cleared.Version)
	_, err = prefs.Update(ctx, mfaservice.PreferenceUpdate{Proof: f.proof, ExpectedVersion: chosen.Version, Method: mfadomain.TOTP})
	require.ErrorIs(t, err, mfadomain.ErrConflict)
}
