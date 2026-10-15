package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
)

func commitInitialAdministrator(ctx context.Context, tx pgx.Tx, account *domain.SetupAccount) error {
	if _, err := tx.Exec(ctx, `INSERT INTO auth.users(id) VALUES($1)`, account.UserID); err != nil {
		return err
	}
	var emailID string
	err := tx.QueryRow(ctx, `INSERT INTO auth.user_emails(user_id,email,verified_at) VALUES($1,$2,clock_timestamp()) RETURNING id`, account.UserID, account.Email).Scan(&emailID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return domain.ErrSetupConflict
		}
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.user_profile(user_id) VALUES($1)`, account.UserID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.password_credentials(user_id,email_id,password_hash) VALUES($1,$2,$3)`, account.UserID, emailID, account.PasswordHash); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_totp(user_id,secret,last_step) VALUES($1,$2,$3)`, account.UserID, account.Factor, account.LastStep); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_recovery_codes(user_id,digest) SELECT $1,unnest($2::text[])`, account.UserID, account.RecoveryDigests); err != nil {
		return err
	}
	var role string
	if err := tx.QueryRow(ctx, `INSERT INTO auth.roles(key,name,system) VALUES('super_admin','Супер-администратор',true) RETURNING id`).Scan(&role); err != nil {
		return err
	}
	permissions := []string{string(settings.RolesManage), string(settings.AssignmentsManage), string(settings.EmailBindingManage), string(settings.UsersManage), string(settings.UsersRead)}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.role_permissions(role_id,permission_key) SELECT $1,unnest($2::text[]) ON CONFLICT DO NOTHING`, role, permissions); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.user_roles(user_id,role_id) VALUES($1,$2)`, account.UserID, role); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.access_audit(actor_id,target_id,role_id,event,role_version,access_version,role_snapshot)
		SELECT $1,$1,id,'role_granted',version,1,jsonb_build_object('key',key,'name',name,'system',system,'permissions',$3::text[])
		FROM auth.roles WHERE id=$2`, account.UserID, role, permissions); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_audit(user_id,event) VALUES($1,'totp_enabled')`, account.UserID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE auth.initial_setup SET initialized_at=clock_timestamp(),administrator_id=$1,
		operator_hash=NULL,request_hash=NULL,payload=NULL,created_at=NULL,expires_at=NULL,attempts=0 WHERE singleton`, account.UserID)
	return err
}
