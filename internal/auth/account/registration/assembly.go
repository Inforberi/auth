package registration

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	accountdomain "github.com/Inforberi/financial-intelligence/internal/auth/account/domain"
	accountemail "github.com/Inforberi/financial-intelligence/internal/auth/account/email/service"
	accountpostgres "github.com/Inforberi/financial-intelligence/internal/auth/account/repository/postgres"
	passwordpostgres "github.com/Inforberi/financial-intelligence/internal/auth/methods/password/repository/postgres"
)

func Assemble(pool *pgxpool.Pool, service *accountemail.Verification, repo *accountpostgres.Repository, loadTTL func(context.Context, pgx.Tx) (time.Duration, error), loadURL ...func(context.Context, pgx.Tx) (string, error)) *passwordpostgres.PasswordRepo {
	return passwordpostgres.NewWithRegistration(pool, func(ctx context.Context, tx pgx.Tx, user accountdomain.UserID, emailID accountdomain.AddressID, email string) error {
		var prepared accountdomain.Verification
		var err error
		if loadTTL == nil {
			prepared, err = service.PrepareVerification(email)
		} else {
			ttl, loadErr := loadTTL(ctx, tx)
			if loadErr != nil {
				return loadErr
			}
			if len(loadURL) == 0 || loadURL[0] == nil {
				prepared, err = service.PrepareVerificationWithTTL(email, ttl)
			} else {
				address, loadErr := loadURL[0](ctx, tx)
				if loadErr != nil {
					return loadErr
				}
				prepared, err = service.PrepareVerificationLink(email, address, ttl)
			}
		}
		if err != nil {
			return err
		}
		return repo.QueueInTransaction(ctx, tx, user, emailID, prepared)
	})
}
