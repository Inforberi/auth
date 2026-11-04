package projects_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/account/provisioning/service"
	passworddomain "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/domain"
	passwordprovisioning "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/provisioning/service"
	projectmethods "github.com/Inforberi/financial-intelligence/internal/auth/project/methods"
)

func checkInvitationTemporaryIsolation(t *testing.T, ctx context.Context, f *emailIsolationFixture) {
	t.Helper()
	var actors [2]accessservice.Principal
	var invitationTokens [2]string
	for i, db := range f.projects.databases {
		hash := strings.Repeat(string(rune('a'+i)), 64)
		seedEmailIsolationProof(t, ctx, db, httpOwnerID, hash)
		actors[i] = accessservice.Principal{UserID: accountdomain.UserID(httpOwnerID), TokenHash: hash}
	}
	const invitationEmail = "isolation-invite@example.test"
	for i, service := range f.services {
		input := accountprovisioning.ProvisionInput{Actor: actors[1-i], IdempotencyKey: "e8900000-0000-4000-8000-000000000001", Email: invitationEmail, Invite: true}
		_, err := service.ProvisionUser(ctx, input)
		require.ErrorIs(t, err, accessdomain.ErrFreshAuthRequired)
		input.Actor = actors[i]
		invited, err := service.ProvisionUser(ctx, input)
		require.NoError(t, err)
		f.users[i] = append(f.users[i], string(invited.UserID))
		payload := isolationEmailPayload(t, ctx, f.projects.databases[i], `SELECT o.payload FROM auth.invitation_outbox o JOIN auth.account_invitations v USING(digest) WHERE v.user_id=$1`, invited.UserID)
		invitationTokens[i] = isolationEmailToken(t, f.ciphers[i][0], payload, f.configs[i].Invitations.URL, invitationEmail)
	}
	require.NotEqual(t, f.users[0][0], f.users[1][0], "identical email and command key do not merge projects")
	for i, service := range f.services {
		require.ErrorIs(t, service.ActivateInvitation(ctx, invitationTokens[1-i], httpIsolationPassword, httpIsolationPassword, emailIsolationIP), accountdomain.ErrInvalidInvitation)
	}
	for i, service := range f.services {
		require.NoError(t, service.ActivateInvitation(ctx, invitationTokens[i], httpIsolationPassword, httpIsolationPassword, emailIsolationIP))
		require.ErrorIs(t, service.ActivateInvitation(ctx, invitationTokens[i], httpIsolationPassword, httpIsolationPassword, emailIsolationIP), accountdomain.ErrInvalidInvitation)
	}
	var passwords [2]*projectmethods.ProjectPassword
	var issued [2]*passwordprovisioning.TemporaryIssueResult
	var setup [2]*passwordprovisioning.TemporaryLoginResult
	for i, key := range f.projects.projects {
		cfg := f.projects.password
		cfg.TemporaryPassword = passwordprovisioning.TemporaryPasswordConfig{Enabled: true, TTL: time.Hour, SetupTTL: 5 * time.Minute, ReissueCooldown: time.Second, IssueActorAttemptsPerMinute: 30, IssueProjectAttemptsPerMinute: 100, SetupProjectAttemptsPerMinute: 100}
		var err error
		passwords[i], err = projectmethods.NewProjectPassword(ctx, key, cfg, projectmethods.ProjectPasswordDependencies{Registry: f.projects.deps.Registry, Reader: f.projects.deps.Reader, Redis: f.projects.deps.Redis, Hash: f.projects.deps.Hash})
		require.NoError(t, err)
		issued[i], err = passwords[i].ProvisionTemporaryPassword(ctx, passwordprovisioning.TemporaryProvisionInput{Actor: actors[i], IdempotencyKey: "e8900000-0000-4000-8000-000000000002", Email: "isolation-temp@example.test"})
		require.NoError(t, err)
		f.users[i] = append(f.users[i], string(issued[i].UserID))
	}
	for i, service := range passwords {
		_, err := service.BeginTemporaryPassword(ctx, "isolation-temp@example.test", issued[1-i].Password, emailIsolationIP)
		require.ErrorIs(t, err, passworddomain.ErrInvalidTemporaryPassword)
		setup[i], err = service.BeginTemporaryPassword(ctx, "isolation-temp@example.test", issued[i].Password, emailIsolationIP)
		require.NoError(t, err)
	}
	for i, service := range passwords {
		require.ErrorIs(t, service.CompleteTemporaryPassword(ctx, setup[1-i].Token, httpIsolationPassword, httpIsolationPassword, emailIsolationIP), passworddomain.ErrInvalidTemporaryPassword)
	}
	for i, service := range passwords {
		require.NoError(t, service.CompleteTemporaryPassword(ctx, setup[i].Token, httpIsolationPassword, httpIsolationPassword, emailIsolationIP))
		require.ErrorIs(t, service.CompleteTemporaryPassword(ctx, setup[i].Token, httpIsolationPassword, httpIsolationPassword, emailIsolationIP), passworddomain.ErrInvalidTemporaryPassword)
	}
}

// Explicit SQL proof isolates the project adapters; password login/step-up is covered by the HTTPS root.
func seedEmailIsolationProof(t *testing.T, ctx context.Context, db *pgx.Conn, user, tokenHash string) {
	t.Helper()
	_, err := db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,
 password_verified_at,primary_method,primary_verified_at,user_agent,ip_address)
 SELECT $1,id,auth_version,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours',
 clock_timestamp(),'password',clock_timestamp(),'email isolation SQL proof',$3 FROM auth.users WHERE id=$2`, tokenHash, user, emailIsolationIP)
	require.NoError(t, err)
}
