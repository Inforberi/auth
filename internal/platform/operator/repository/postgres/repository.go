package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	"github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
)

type Repository struct {
	db    *pgxpool.Pool
	realm domain.RealmID
	setup *accountpostgres.Repository
}

// realm comes from trusted installation configuration, never from request input.
func New(db *pgxpool.Pool, realm domain.RealmID) (*Repository, error) {
	if db == nil || !realm.Valid() {
		return nil, domain.ErrUnavailable
	}
	return &Repository{db: db, realm: realm, setup: accountpostgres.New(db)}, nil
}

func setupError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	for _, public := range []error{accountdomain.ErrSetupClosed, accountdomain.ErrSetupInvalid, accountdomain.ErrSetupConflict} {
		if errors.Is(err, public) {
			return public
		}
	}
	return errors.Join(accountdomain.ErrDependencyUnavailable, ctx.Err())
}
