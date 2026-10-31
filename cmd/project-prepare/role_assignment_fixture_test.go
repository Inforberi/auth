package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/credentials"
	"github.com/Inforberi/financial-intelligence/internal/platform/project/domain"
)

const (
	assignmentActive  accountdomain.UserID = "f6000000-0000-4000-8000-000000000001"
	assignmentPending accountdomain.UserID = "f6000000-0000-4000-8000-000000000002"
	assignmentCapped  accountdomain.UserID = "f6000000-0000-4000-8000-000000000003"
	assignmentAdmin   accountdomain.UserID = "f6000000-0000-4000-8000-000000000004"
)

type assignmentFixture struct {
	db                  *pgx.Conn
	system, mfa, capped accessdomain.RoleID
}

func newAssignmentFixture(t *testing.T, catalog *pgx.Conn, binding credentials.Binding) assignmentFixture {
	t.Helper()
	ctx := t.Context()
	cfg := catalog.Config().Copy()
	var err error
	cfg.Database, _, err = (domain.PreparationReservation{ProjectID: binding.ProjectID, ReservationID: binding.ReservationID}).ResourceNames()
	require.NoError(t, err)
	// Only the isolated root fixture uses multi-statement setup/cleanup.
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	db, err := pgx.ConnectConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		require.NoError(t, db.Close(cleanup))
	})
	users := []string{string(assignmentActive), string(assignmentPending), string(assignmentCapped), string(assignmentAdmin)}
	var clean bool
	require.NoError(t, db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM auth.users WHERE id=ANY($1::uuid[]))
		AND NOT EXISTS(SELECT 1 FROM auth.roles WHERE key='super_admin' OR key LIKE 'bridge_http_assignment_%')`, users).Scan(&clean))
	require.True(t, clean, "refuse to replace pre-existing assignment fixture data")
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_, err := db.Exec(cleanup, `DELETE FROM auth.platform_role_assignments WHERE user_id=ANY($1::uuid[]);
		 DELETE FROM auth.access_audit WHERE actor_id=ANY($1::uuid[]) OR target_id=ANY($1::uuid[]);
		 DELETE FROM auth.sessions WHERE user_id=ANY($1::uuid[]);
		 DELETE FROM auth.user_roles WHERE user_id=ANY($1::uuid[]);
		 DELETE FROM auth.password_credentials WHERE user_id=ANY($1::uuid[]);
		 DELETE FROM auth.mfa_totp WHERE user_id=ANY($1::uuid[]);
		 DELETE FROM auth.user_emails WHERE user_id=ANY($1::uuid[]);
		 DELETE FROM auth.users WHERE id=ANY($1::uuid[]);
		 DELETE FROM auth.roles WHERE key='super_admin' OR key LIKE 'bridge_http_assignment_%'`, users)
		if err != nil {
			t.Error("assignment fixture cleanup", err)
		}
	})
	_, err = db.Exec(ctx, `INSERT INTO auth.users(id,status) VALUES($1,'active'),($2,'pending'),($3,'active'),($4,'active')`, assignmentActive, assignmentPending, assignmentCapped, assignmentAdmin)
	require.NoError(t, err)
	fixture := assignmentFixture{db: db}
	require.NoError(t, db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Fixture admin',true) RETURNING id`).Scan(&fixture.system))
	_, err = db.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT $1,unnest($2::text[]);
	 INSERT INTO auth.user_roles(user_id,role_id) VALUES($3,$1)`, fixture.system, []string{string(settings.AssignmentsManage), string(settings.UsersRead)}, assignmentAdmin)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.user_emails(id,user_id,email,verified_at) VALUES('f6000000-0000-4000-8000-000000000005',$1,'assignment-admin@example.test',clock_timestamp());
	 INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,'f6000000-0000-4000-8000-000000000005','sql-fixture-hash');
	 INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,decode(repeat('11',64),'hex'),0)`, assignmentAdmin)
	require.NoError(t, err)
	_, err = db.Exec(ctx, `INSERT INTO auth.sessions(token_hash,user_id,auth_version,created_at,expires_at,absolute_expires_at,primary_method,primary_verified_at,password_verified_at,mfa_verified_at,mfa_method,user_agent,ip_address)
	 VALUES($1,$2,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','password',clock_timestamp(),clock_timestamp(),clock_timestamp(),'totp','local admin SQL fixture','192.0.2.1'),
	 ($3,$4,1,clock_timestamp(),clock_timestamp()+interval '1 hour',clock_timestamp()+interval '2 hours','emailotp',clock_timestamp(),NULL,NULL,NULL,'pre-grant SQL fixture','192.0.2.2')`, strings.Repeat("b", 64), assignmentAdmin, strings.Repeat("a", 64), assignmentActive)
	require.NoError(t, err)
	require.NoError(t, db.QueryRow(ctx, `INSERT INTO auth.roles(key,name,mfa_required) VALUES('bridge_http_assignment_mfa','Existing MFA role',true) RETURNING id`).Scan(&fixture.mfa))
	_, err = db.Exec(ctx, `WITH roles AS (INSERT INTO auth.roles(key,name) SELECT 'bridge_http_assignment_cap_'||n,'Cap role' FROM generate_series(1,32) n RETURNING id)
	 INSERT INTO auth.user_roles(user_id,role_id) SELECT $1,id FROM roles`, assignmentCapped)
	require.NoError(t, err)
	require.NoError(t, db.QueryRow(ctx, `SELECT id FROM auth.roles WHERE key='bridge_http_assignment_cap_1'`).Scan(&fixture.capped))
	return fixture
}
