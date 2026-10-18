package main

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	operatordomain "github.com/Inforberi/financial-intelligence/internal/platform/operator/domain"
	operatorpostgres "github.com/Inforberi/financial-intelligence/internal/platform/operator/repository/postgres"
)

func checkRecoveryRealm(ctx context.Context, pool *pgxpool.Pool, realm string, user accountdomain.UserID, mfa bool) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if realm == "" {
		var legacy bool
		if err := pool.QueryRow(ctx, `SELECT to_regnamespace('platform') IS NULL`).Scan(&legacy); err != nil || !legacy {
			return errors.New("platform recovery requires explicit -platform-realm and a dedicated offline login")
		}
		return nil
	}
	repo, err := operatorpostgres.New(pool, operatordomain.RealmID(realm))
	if err != nil {
		return errors.New("invalid platform recovery realm")
	}
	if err := repo.CheckRecovery(ctx, user, mfa); err != nil {
		return errors.New("platform recovery storage, target or offline privileges rejected")
	}
	return nil
}

func recoveryDestination(destination, realm string) string {
	if realm != "" {
		return destination + "[platform=" + realm + "]"
	}
	return destination
}
