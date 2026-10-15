package postgres

import (
	"context"
	"encoding/json"
	"time"

	accessdomain "github.com/Inforberi/financial-intelligence/internal/access/domain"
	accessservice "github.com/Inforberi/financial-intelligence/internal/access/service"
	"github.com/Inforberi/financial-intelligence/internal/access/settings"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	"github.com/Inforberi/financial-intelligence/internal/auth/account/service"
)

func (r *Repository) ReadUser(ctx context.Context, actor accessservice.Principal, target domain.UserID) (service.UserDetail, error) {
	query := directoryActor + `SELECT a.allowed,u.id::text,COALESCE(u.status,''),u.created_at,p.display_name,email.email::text,(email.verified_at IS NOT NULL),
		COALESCE(u.auth_version,0),COALESCE(u.access_version,0),u.deleted_at,
		EXISTS(SELECT 1 FROM auth.password_credentials WHERE user_id=u.id),
		EXISTS(SELECT 1 FROM auth.account_provisions WHERE user_id=u.id AND password_change_required AND activated_at IS NULL),
		EXISTS(SELECT 1 FROM auth.mfa_totp WHERE user_id=u.id),
		COALESCE((SELECT jsonb_agg(jsonb_build_object('email',e.email,'verifiedAt',e.verified_at) ORDER BY e.id)
			FROM (SELECT id,email,verified_at FROM auth.user_emails WHERE user_id=u.id ORDER BY id LIMIT $5) e),'[]'::jsonb),
		ARRAY(SELECT issuer FROM auth.linked_identities WHERE user_id=u.id ORDER BY issuer LIMIT $5),
		COALESCE((SELECT jsonb_agg(jsonb_build_object('id',r.id,'key',r.key,'name',r.name,'system',r.system,'version',r.version) ORDER BY r.id)
			FROM (SELECT role_id FROM auth.user_roles WHERE user_id=u.id ORDER BY role_id LIMIT $6) ur
			JOIN auth.roles r ON r.id=ur.role_id),'[]'::jsonb)
		FROM directory_actor a LEFT JOIN auth.users u ON a.allowed AND u.id=$4
		LEFT JOIN auth.user_profile p ON p.user_id=u.id ` + directoryEmail
	var user service.UserDetail
	var allowed bool
	var id *string
	var created *time.Time
	var contacts, roles []byte
	err := r.db.QueryRow(ctx, query, actor.UserID, actor.TokenHash, settings.UsersRead, target, service.MaxDirectoryRelations+1, accessdomain.MaxUserRoles+1).Scan(
		&allowed, &id, &user.Status, &created, &user.DisplayName, &user.Email, &user.EmailVerified,
		&user.AuthVersion, &user.AccessVersion, &user.DeletedAt, &user.PasswordConfigured, &user.TemporaryPasswordRequired, &user.MFAEnrolled,
		&contacts, &user.ExternalIssuers, &roles,
	)
	if err != nil {
		return service.UserDetail{}, err
	}
	if !allowed {
		return service.UserDetail{}, accessdomain.ErrForbidden
	}
	if id == nil {
		return service.UserDetail{}, domain.ErrAccountNotFound
	}
	user.ID, user.CreatedAt = domain.UserID(*id), *created
	if err := json.Unmarshal(contacts, &user.Contacts); err != nil {
		return service.UserDetail{}, err
	}
	if err := json.Unmarshal(roles, &user.Roles); err != nil {
		return service.UserDetail{}, err
	}
	if len(user.Contacts) > service.MaxDirectoryRelations || len(user.ExternalIssuers) > service.MaxDirectoryRelations || len(user.Roles) > accessdomain.MaxUserRoles {
		return service.UserDetail{}, domain.ErrUserDirectoryConflict
	}
	return user, nil
}
